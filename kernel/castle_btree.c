#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/fs.h>
#include <linux/bio.h>
#include <linux/hardirq.h>

#include "castle.h"
#include "castle_btree.h"
#include "castle_versions.h"
#include "castle_block.h"
#include "castle_cache.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)  ((void)0)
#else
#define debug(_f, _a...)  (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

static void castle_ftree_c2p_forget(c_bvec_t *c_bvec);
static void __castle_ftree_find(c_bvec_t *c_bvec,
                                c_disk_blk_t node_cdb);

static void castle_ftree_io_end(c_bvec_t *c_bvec,
                                c_disk_blk_t cdb,
                                int err)
{
    /* We allow:
       -   valid block and no error
       - invalid block and    error
       - invalid block and no error (reads from non-yet written block)
       We disallow:
       -   valid block and    error */
    BUG_ON((!DISK_BLK_INVAL(cdb)) && (err));
    /* Free the c2ps correctly. Call twice to release parent and child
       (if both exist) */
    castle_ftree_c2p_forget(c_bvec);
    castle_ftree_c2p_forget(c_bvec);
    /* Once buffers have been freed, save the cdb */
    c_bvec->cdb = cdb;
    /* Finish the IO (call _io_end directly on an error */
    if(err)
        castle_bio_data_io_end(c_bvec, err);
    else
        castle_bio_data_io(c_bvec);
}

static void castle_ftree_slot_normalize(struct castle_ftree_slot *slot)
{
    /* Look for 'last' slot, and if block is zero, assign the maximum value instead */
    if(FTREE_SLOT_IS_NODE_LAST(slot) &&
       (slot->block == 0))
    {
        slot->type  = FTREE_SLOT_NODE;
        slot->block = MAX_BLK;
    }
}

static int castle_ftree_node_normalize(struct castle_ftree_node *node)
{
    int i;

    if((node->capacity > FTREE_NODE_SLOTS) ||
       (node->used     > node->capacity) ||
       (node->used     == 0))
    {
        printk("Invalid ftree node capacity or/and used: (%d, %d)\n",
               node->capacity, node->used);
        return -EIO;
    }
    /* There is at least one slot in the node */ 
    node->is_leaf = FTREE_SLOT_IS_LEAF(&node->slots[0]);

    for(i=0; i < node->used; i++)
    {
        struct castle_ftree_slot *slot = &node->slots[i];
        /* Fail if node is_leaf doesn't match with the slot. ! needed 
           to guarantee canonical value for boolean true */
        if(!(node->is_leaf) != !(FTREE_SLOT_IS_LEAF(slot)))
            return -EIO;
        castle_ftree_slot_normalize(slot);
    }

    return 0;
}

static void castle_ftree_lub_find(struct castle_ftree_node *node,
                                  uint32_t block, 
                                  uint32_t version,
                                  int *lub_idx_p,
                                  int *insert_idx_p)
{
    struct castle_ftree_slot *slot;
    uint32_t block_lub, version_lub;
    int      lub_idx, insert_idx, i;

    debug("Looking for (b,v) = (0x%x, 0x%x), node->used=%d, capacity=%d\n",
            block, version, node->used, node->capacity);
        
    lub_idx   = -1;
    block_lub = INVAL_BLK; 
    for(i=node->used-1; i >= 0; i--)
    {
        slot = &node->slots[i];

        debug(" (b,v) = (0x%x, 0x%x)\n", 
               slot->block,
               slot->version);

        /* If the block is already too small, we must have gone past the least
           upper bound */
        if(slot->block < block)
            break;

        /* Do not consider versions which are not ancestral to the version we 
           are looking for.
           Also, don't update the LUB index if the block number doesn't change.
           This is because the most recent ancestor will be found first when
           scanning from right to left */
        if((block_lub != slot->block) &&
            castle_version_is_ancestor(slot->version, version))
        {
            block_lub   = slot->block;
            version_lub = slot->version;
            lub_idx = i;
            debug("  set b_lub=0x%x, lub_idx=%d\n", block_lub, lub_idx);
        }
    } 

    /* If we are insterting something into the node, work out where should it go */
    /* Case 1: (block_lub == block) && (version_lub == version)
               no need to insert, we have exactly the (b,v) we wanted
       Case 2: (block_lub == block) && (version_lub != version)
               but we know that is_ancestor(version_lub, version) == 1
               this means that 'version' is more recent than version_lub, and
               it needs to go (just) to the right of the LUB
               => insert_idx = lub_idx + 1
       Case 3: (block_lub > block)
               there is no (b_x, v_x) such that 
               (block <= b_x < block_lub) && (is_ancestor(v_x, version)) because then 
               (b_x, v_x) would be the LUB.
               Therefore, in the inclusive range [i+1, lub_idx-1] there are no 
               ancestors of 'version'. It follows that we should insert on the basis
               of block numbers only. Therefore i+1 will point to the correct place.
       Case 4: There is no LUB.
               This case is similar to Case 3, in that there is no (b_x, v_x) such
               that (block <= b_x) && (is_ancestor(v_x, version)).
               Insert at i+1.
       Cases are exhaustive, because either LUB doesn't exist (Case 4), or it does,
       in which case, block_lub > block (Case 3) or block_lub == block (Case 2 and Case 1).
    */
    if((lub_idx < 0) || (block_lub > block))
    /* Case 4 and Case 3 */
    {
        insert_idx = i+1;    
    }
    else
    if (version_lub != version)
    /* Case 2 */
    {
        BUG_ON(block_lub != block);
        insert_idx = lub_idx + 1;
    } else
    /* Case 1 */
    {
        BUG_ON(block_lub   != block);
        BUG_ON(version_lub != version);
        insert_idx = lub_idx;
    }

    if(lub_idx_p)    *lub_idx_p = lub_idx;
    if(insert_idx_p) *insert_idx_p = insert_idx;
}

static int castle_ftree_write_idx_find(c_bvec_t *c_bvec)
{
    struct castle_ftree_node *node = c_bvec_bnode(c_bvec);
    struct castle_ftree_slot *slot;
    uint32_t block = c_bvec->block;
    uint32_t version = c_bvec->version;
    int i, idx;
    
    idx = node->used;
    for(i=node->used-1; i >= 0; i--)
    {
        slot = &node->slots[i];
        
        /* We've went to far now */
        if(slot->block < block)
            break;

        /* Check versions if the block is the same */
        if(slot->block == block)
        {
            /* If we found our own ancestor we must have gone too far ... */
            if(castle_version_is_ancestor(slot->version, version)) 
            {
                /* ... unless we are looking at exactly the same version,
                       in which case we've got exactly the entry we were 
                       looking to insert */
                if(slot->version == version)
                    idx = i;
                break;
            }
        }    
        idx = i;
    }

    return idx;
}

static void castle_ftree_write_process(c_bvec_t *c_bvec)
{
    struct castle_ftree_node *node = c_bvec_bnode(c_bvec);
    struct castle_ftree_slot *lub_slot;
    uint32_t block = c_bvec->block;
    uint32_t version = c_bvec->version;
    int      lub_idx, insert_idx;

    castle_ftree_lub_find(node, block, version, &lub_idx, &insert_idx);
    if(lub_idx >= 0) lub_slot = &node->slots[lub_idx];

    /* Deal with non-leaf nodes first */
    if(!FTREE_NODE_IS_LEAF(node))
    {
        /* We should always find the LUB if we are not looking at a leaf node */
        BUG_ON(lub_idx < 0);
        printk("Following write down the tree.\n");
        __castle_ftree_find(c_bvec, lub_slot->cdb);
        return;
    }

    /* Deal with leaf nodes */
    BUG_ON(!FTREE_NODE_IS_LEAF(node));

    /* Insert an entry if LUB doesn't match our (b,v) precisely. */
    if(lub_idx < 0 || (lub_slot->block != block) || (lub_slot->version != version))
    {
        printk("Need to insert (0x%x, 0x%x) into node (used: 0x%x, capacity: 0x%x, leaf=%d).\n",
                block, version,
                node->used, node->capacity, FTREE_NODE_IS_LEAF(node));
        BUG_ON(castle_ftree_write_idx_find(c_bvec) != insert_idx);
        /* TODO: Insertion should happen here */
        castle_ftree_io_end(c_bvec, INVAL_DISK_BLK, -EINVAL);
        return;
    } 
    
    /* Final case: (b,v) found in the leaf node */
    BUG_ON((lub_slot->block != block) || (lub_slot->version != version));
    BUG_ON(lub_idx != insert_idx);
    BUG_ON(castle_ftree_write_idx_find(c_bvec) != insert_idx);

    printk("Block already exists, modifying in place.\n");
    castle_ftree_io_end(c_bvec, lub_slot->cdb, 0);
}

static void castle_ftree_read_process(c_bvec_t *c_bvec)
{
    struct castle_ftree_node *node = c_bvec_bnode(c_bvec);
    struct castle_ftree_slot *slot;
    uint32_t block = c_bvec->block;
    uint32_t version = c_bvec->version;
    int      lub_idx;

    castle_ftree_lub_find(node, block, version, &lub_idx, NULL);
    /* We should always find the LUB if we are not looking at a leaf node */
    BUG_ON((lub_idx < 0) && !FTREE_NODE_IS_LEAF(node));
    
    /* If we haven't found the LUB (in the leaf node), return early */
    if(lub_idx < 0)
    {
        debug(" Could not find the LUB for (b,v)=(0x%x, 0x%x)\n", 
            block, version);
        castle_ftree_io_end(c_bvec, INVAL_DISK_BLK, 0);
        return;
    }

    slot = &node->slots[lub_idx];
    /* If we found the LUB, either complete the ftree walk (if we are looking 
       at a leaf), or go to the next level */
    if(FTREE_SLOT_IS_LEAF(slot))
    {
        debug(" Is a leaf, found (b,v)=(0x%x, 0x%x)\n", 
            slot->block, slot->version);
        castle_ftree_io_end(c_bvec, slot->cdb, 0);
    }
    else
    {
        debug("Is not a leaf. Read and search (disk,blk#)=(0x%x, 0x%x)\n",
                slot->cdb.disk, slot->cdb.block);
        __castle_ftree_find(c_bvec, slot->cdb);
    }
}

void castle_ftree_process(struct work_struct *work)
{
    c_bvec_t *c_bvec = container_of(work, c_bvec_t, work);
    int write = (c_bvec_data_dir(c_bvec) == WRITE);

    if(write)
        castle_ftree_write_process(c_bvec);
    else
        castle_ftree_read_process(c_bvec);
}


static int castle_ftree_c2p_remember(c_bvec_t *c_bvec, c2_page_t *c2p)
{
    int ret = 0;

    /* Forget the parent node buffer first */
    castle_ftree_c2p_forget(c_bvec);
    
    /* Sanity check to make sure that the node fits in the buffer */
    BUG_ON(sizeof(struct castle_ftree_node) > PAGE_SIZE);

    /* Save the new node buffer */
    c_bvec->btree_node = c2p;

    /* Format the node to make sure everything is as expected by the rest of the code.
       Only need to do that on the IO read, ie. when updating the buffer. */
    BUG_ON(!c2p_locked(c2p));
    if(!c2p_uptodate(c2p))
        ret = castle_ftree_node_normalize(c_bvec_bnode(c_bvec));

    return ret; 
}

static void castle_ftree_c2p_forget(c_bvec_t *c_bvec)
{
    int write = (c_bvec_data_dir(c_bvec) == WRITE);
    c2_page_t *to_forget;

    /* We don't lock parent nodes on reads */
    BUG_ON(!write && c_bvec->btree_parent_node);
    /* On writes we forget the parent, on reads the node itself */
    to_forget = (write ? c_bvec->btree_parent_node : c_bvec->btree_node);
    /* Release the buffer if one exists */
    if(to_forget)
    {
        unlock_c2p(to_forget);
        put_c2p(to_forget);
    }
    /* Promote node to the parent on writes */
    if(write) c_bvec->btree_parent_node = c_bvec->btree_node;
    /* Forget */
    c_bvec->btree_node = NULL;
}

static void castle_ftree_find_io_end(c2_page_t *c2p, int uptodate)
{
    c_bvec_t *c_bvec = c2p->private;

    debug("Finished IO for: block 0x%lx, in version 0x%x\n", 
            c_bvec->block, c_bvec->version);
    
    /* Callback on error */
    if(!uptodate || castle_ftree_c2p_remember(c_bvec, c2p))
    {
        castle_ftree_io_end(c_bvec, INVAL_DISK_BLK, -EIO);
        return;
    }

    set_c2p_uptodate(c2p);
    /* Put on to the workqueue */
    INIT_WORK(&c_bvec->work, castle_ftree_process);
    queue_work(castle_wq, &c_bvec->work); 
}

static void __castle_ftree_find(c_bvec_t *c_bvec,
                                c_disk_blk_t node_cdb)
{
    c2_page_t *c2p;
    int ret;

    debug("Asked for block: 0x%lx, in version 0x%x, reading ftree node (0x%x, 0x%x)\n", 
            c_bvec->block, c_bvec->version, node_cdb.disk, node_cdb.block);
    ret = -ENOMEM;

    c2p = castle_cache_page_get(node_cdb);
    debug("Got the buffer, trying to lock it\n");
    lock_c2p(c2p);
    debug("Locked for ftree node (0x%x, 0x%x)\n", 
            node_cdb.disk, node_cdb.block);
    if(!c2p_uptodate(c2p))
    {
        /* If the buffer doesn't contain up to date data, schedule the IO */
        debug("Buffer not up to date. Scheduling a read.\n");
        c2p->private = c_bvec;
        c2p->end_io = castle_ftree_find_io_end;
        submit_c2p(READ, c2p);
    } else
    {
        debug("Buffer up to date. Processing!\n");
        /* If the buffer is up to date, copy data, and call the node processing
           function directly. c2p_remember should not return an error, because
           the Btree node had been normalized already. */
        BUG_ON(castle_ftree_c2p_remember(c_bvec, c2p) != 0);
        castle_ftree_process(&c_bvec->work);
    }
}

void castle_ftree_find(c_bvec_t *c_bvec,
                       c_disk_blk_t node_cdb)
{
    c_bvec->btree_node = NULL;
    c_bvec->btree_parent_node = NULL;
    __castle_ftree_find(c_bvec, node_cdb);
}

static void castle_version_node_print(struct castle_vtree_slot *slot)
{ 
    if(slot->type == VTREE_SLOT_LEAF)
    {
        printk("Version slot: ty= 0x%x\n"
               "              vn= 0x%x\n"
               "              di= 0x%x\n"
               "              bl= 0x%x\n"
               "              pa= 0x%x\n"
               "              si= 0x%x\n",
               slot->type,
               slot->leaf.version_nr,
               slot->leaf.cdb.disk,
               slot->leaf.cdb.block,
               slot->leaf.parent,
               slot->leaf.size);
    } else
    if((slot->type == VTREE_SLOT_NODE) ||
       (slot->type == VTREE_SLOT_NODE_LAST))
    {
        printk("Version slot: ty= 0x%x\n"
               "              vn= 0x%x\n"
               "              di= 0x%x\n"
               "              bl= 0x%x\n",
               slot->type,
               slot->node.version_nr,
               slot->node.cdb.disk,
               slot->node.cdb.block);
    }
}

static int __castle_vtree_read(c_disk_blk_t cdb)
{
    struct castle_slave *cs;
    struct castle_vtree_node *vtree_node;
    int i, ret;

    cs = castle_slave_find_by_block(cdb);
    if(cs == NULL) return -ENODEV; 

    vtree_node = kzalloc(sizeof(struct castle_vtree_node), GFP_KERNEL);
    if(!vtree_node) return -ENOMEM;

    ret = castle_sub_block_read(cs,
                                vtree_node,
                                disk_blk_to_offset(cdb),
                                NODE_HEADER,
                                NULL, NULL); 
    if(ret)
    {
        printk("Could not read version tree node.\n");
        kfree(vtree_node);
        return ret;
    }

    if((vtree_node->capacity > VTREE_NODE_SLOTS) ||
       (vtree_node->used     > vtree_node->capacity))
    {
        printk("Invalid vtree node capacity or/and used: (%d, %d)\n",
               vtree_node->capacity, vtree_node->used);
        kfree(vtree_node);
        return -EINVAL;
    }
    ret = castle_sub_block_read(cs,
                                vtree_node->slots,
                                disk_blk_to_offset(cdb) + NODE_HEADER,
                                vtree_node->used * sizeof(struct castle_vtree_slot),
                                NULL, NULL); 
    if(ret)
    {
        printk("Could not read version slots.\n");
        kfree(vtree_node);
        return ret;
    }
    for(i=0; i<vtree_node->used; i++)
    {
        if(VTREE_SLOT_IS_NODE(&vtree_node->slots[i])) 
        {
            /* Read the child node recursively */
            ret = __castle_vtree_read(vtree_node->slots[i].node.cdb); 
            if(ret) 
            {
                kfree(vtree_node);
                return ret;
            }
        } else
        {
            /* If we are looking at a leaf slot, add this to 
               the (non btree) version tree */
            castle_version_add(vtree_node->slots[i].leaf.version_nr, 
                               vtree_node->slots[i].leaf.parent,
                               vtree_node->slots[i].leaf.cdb,
                               vtree_node->slots[i].leaf.size);
        }
    }

    return 0;
}

int castle_vtree_read(c_disk_blk_t cdb)
{
    int ret = __castle_vtree_read(cdb);

    if(ret == 0)
        castle_versions_process();

    return ret;
}

/***** Init/fini functions *****/
int castle_btree_init(void)
{
    int ret = 0;

    return ret;
}

void castle_btree_free(void)
{
}
