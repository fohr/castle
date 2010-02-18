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

static void castle_ftree_node_print(struct castle_ftree_node *node)
{
    int i;

    printk("Printing node version=%d with (cap, use) = (%d, %d)\n",
        node->version, node->capacity, node->used);
    for(i=0; i<node->used; i++)
        printk("(0x%x, 0x%x) ", node->slots[i].block, node->slots[i].version);
    printk("\n");
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

static c2_page_t* castle_ftree_effective_node_create(struct castle_ftree_node *node,
                                                     uint32_t version)
{
    c_disk_blk_t cdb = castle_slaves_disk_block_get(); 
    c2_page_t   *c2p = castle_cache_page_get(cdb);
    struct castle_ftree_node *eff_node = pfn_to_kaddr(page_to_pfn(c2p->page));
    struct castle_ftree_slot *last_eff_slot, *slot;
    int i;

    lock_c2p(c2p);
    set_c2p_uptodate(c2p);
    eff_node->magic    = 0x0000cdab;
    eff_node->version  = version;
    eff_node->capacity = FTREE_NODE_SLOTS;
    eff_node->used     = 0;
    eff_node->is_leaf  = node->is_leaf;

    for(i=0, last_eff_slot = NULL; i<node->used; i++)
    {
        slot = &node->slots[i];

        BUG_ON(eff_node->used >= eff_node->capacity);
        /* Check if slot->version is ancestoral to version. If not,
           reject straigt away. */
        if(!castle_version_is_ancestor(slot->version, version))
            continue;

        if(!last_eff_slot || last_eff_slot->block != slot->block)
        {
            /* Allocate a new slot if the last eff slot doesn't exist
               or refers to a different block */
            last_eff_slot = &eff_node->slots[eff_node->used++]; 
        } else
        {
            /* last_eff_slot != NULL && last_eff_slot->block == slot->block
               => do not allocate a new slot, replace it instead.
               Since we are scanning from left to right, we should be
               looking on more recent versions of the block now. Check for that.
             */
            /* TODO: these asserts should really be turned into
                     'corrupt btree' exception. */
            BUG_ON(!castle_version_is_ancestor(last_eff_slot->version, 
                                               slot->version));
        }
        memcpy(last_eff_slot,
               slot,
               sizeof(struct castle_ftree_slot)); 
    }

    /* If effective node is the same size as the original node, throw it away,
       and return NULL */ 
    if(eff_node->used == node->used)
    {
        unlock_c2p(c2p);
        put_c2p(c2p);
        /* TODO: should also return the allocated disk block, but our allocator
                 is too simple to handle this ATM */
        return NULL;
    }

    /* Mark the node dirty, so that it'll get written out, even if nothing gets
       inserted into it */ 
    dirty_c2p(c2p);

    return c2p;
}

static c2_page_t* castle_ftree_node_split(struct castle_ftree_node *node)
{
    c_disk_blk_t cdb = castle_slaves_disk_block_get(); 
    c2_page_t   *c2p = castle_cache_page_get(cdb);
    struct castle_ftree_node *sec_node = pfn_to_kaddr(page_to_pfn(c2p->page));

    lock_c2p(c2p);
    set_c2p_uptodate(c2p);
    sec_node->magic    = 0x0000cdab;
    sec_node->version  = node->version;
    sec_node->capacity = FTREE_NODE_SLOTS;
    sec_node->used     = node->used >> 1;
    sec_node->is_leaf  = node->is_leaf;

    /* The original node needs to contain the elements from the right hand side
       because otherwise the key in it's parent would have to change. We want
       to avoid that */
    node->used -= sec_node->used;
    memcpy(sec_node->slots, 
           node->slots, 
           sec_node->used * sizeof(struct castle_ftree_slot));
    memmove( node->slots, 
            &node->slots[sec_node->used], 
             node->used * sizeof(struct castle_ftree_slot));
    /* c2p for node will be dirtied by the caller, we cannot work out its c2p from here */
    dirty_c2p(c2p);

    return c2p;
}

static void castle_ftree_slot_insert(struct castle_ftree_node *node,
                                     int index,
                                     uint32_t type,
                                     uint32_t block,
                                     uint32_t version,
                                     c_disk_blk_t cdb)
{
    struct castle_ftree_slot *slot;

    BUG_ON(index      >  node->used);
    BUG_ON(node->used >= node->capacity);
    
    /* Make space for the extra slot. */
    memmove(&node->slots[index+1],
            &node->slots[index],
            sizeof(struct castle_ftree_slot) * (node->used - index));
    slot = &node->slots[index]; 
    slot->type    = type;
    slot->block   = block;
    slot->version = version;
    slot->cdb     = cdb;
    node->used++;
}

static void castle_ftree_node_insert(c2_page_t *parent_c2p,
                                     c2_page_t *child_c2p)
{
    struct castle_ftree_node *parent
                     = pfn_to_kaddr(page_to_pfn(parent_c2p->page));
    struct castle_ftree_node *child
                     = pfn_to_kaddr(page_to_pfn(child_c2p->page));
    uint32_t block   = child->slots[child->used-1].block; 
    uint32_t version = child->version;
    int insert_idx;

    castle_ftree_lub_find(parent, block, version, NULL, &insert_idx);
    printk("Inserting child node into parent, will insert (b,v)=(0x%x, 0x%x) at idx=%d.\n",
            block, version, insert_idx);
    castle_ftree_slot_insert(parent, 
                             insert_idx, 
                             FTREE_SLOT_NODE,
                             block,
                             version,
                             child_c2p->cdb);
    dirty_c2p(parent_c2p);
}


static void castle_ftree_write_process(c_bvec_t *c_bvec)
{
    struct castle_ftree_node *node = c_bvec_bnode(c_bvec);
    struct castle_ftree_slot *lub_slot;
    uint32_t block = c_bvec->block;
    uint32_t version = c_bvec->version;
    int      lub_idx, insert_idx;

    /* Deal with non-leaf nodes first */
    if(!FTREE_NODE_IS_LEAF(node))
    {
        castle_ftree_lub_find(node, block, version, &lub_idx, NULL);
        /* We should always find the LUB if we are not looking at a leaf node */
        BUG_ON(lub_idx < 0);
        lub_slot = &node->slots[lub_idx];
        /* Should split the node if less than 2 empty slots available */
        BUG_ON(node->capacity - node->used < 2);
        printk("Following write down the tree.\n");
        __castle_ftree_find(c_bvec, lub_slot->cdb);
        return;
    }

    /* Deal with leaf nodes */
    BUG_ON(!FTREE_NODE_IS_LEAF(node));

    /* A leaf node only needs to be split if there are _no_ empty slots in it */ 
    if(node->used == node->capacity)
    {
        struct castle_ftree_node *eff_node;
        c2_page_t *eff_c2p;

        printk("Leaf node full while inserting (0x%x,0x%x), creating effective node for it.\n",
                block, version);
        castle_ftree_node_print(node);
        eff_c2p = castle_ftree_effective_node_create(node, version);
        /* eff_c2p will be NULL if the effective node is identical to the
           original node */
        if(!eff_c2p)
        {
            printk("Effective node is identical to the original node.\n");
            eff_c2p  = c_bvec->btree_node; 
            eff_node = node; 
        }
        else
        {
            printk("Effective node non identical to the original node.\n");
            /* Cast eff_c2p buffer to eff_node */
            eff_node = pfn_to_kaddr(page_to_pfn(eff_c2p->page));
            castle_ftree_node_print(eff_node);
            /* TODO: this means that there should be a new root node */
            BUG_ON(!c_bvec->btree_parent_node);
            castle_ftree_node_insert(c_bvec->btree_parent_node,
                                     eff_c2p);
            /* Unlock the original btree_node, and save the effective c2p instead */
            unlock_c2p(c_bvec->btree_node);
            put_c2p(c_bvec->btree_node);
            c_bvec->btree_node = eff_c2p;
        }
        /* Split the effective node if it's more than 75% full */
        if(eff_node->used > (eff_node->capacity >> 1) + (eff_node->capacity >> 2))
        {
            struct castle_ftree_node *split_node;
            c2_page_t *split_c2p, *retain_c2p, *reject_c2p;

            printk("Effective node too full, splitting.\n");
            split_c2p = castle_ftree_node_split(eff_node);
            /* Need to dirty the effective node here, since we are not passing the
               buffer to the split routine */
            dirty_c2p(eff_c2p);
            split_node = pfn_to_kaddr(page_to_pfn(split_c2p->page));
            printk("The effective node:\n");
            castle_ftree_node_print(eff_node);
            printk("The split node:\n");
            castle_ftree_node_print(split_node);
            /* TODO: this means that there should be a new root node */
            BUG_ON(!c_bvec->btree_parent_node);
            /* Insert into the parent node */
            castle_ftree_node_insert(c_bvec->btree_parent_node,
                                     split_c2p);
            /* Work out whether to retain effective node, or the split node
               for the further btree walk.
               Since in the effective & split node there is at most one version
               for each block, and this version is ancestoral to what we are
               looking for, it's enough to check if the last entry in the 
               split node (that's the node that contains left hand side elements
               from the original effective node) is greater-or-equal to the block
               we are looking for */
            printk("Last element in split node is (b,v)=(0x%x, 0x%x)\n",
                    split_node->slots[split_node->used-1].block,
                    split_node->slots[split_node->used-1].version);
            if(split_node->slots[split_node->used-1].block >= block)
            {
                printk("Retaing the split node.\n");
                retain_c2p = split_c2p;
                reject_c2p = eff_c2p;
            } else
            {
                printk("Retaing the effective node.\n");
                retain_c2p = eff_c2p;
                reject_c2p = split_c2p;
            }
            unlock_c2p(reject_c2p);
            put_c2p(reject_c2p);
            c_bvec->btree_node = retain_c2p;
        }
        /* Make sure that node now points to the correct node */
        node = c_bvec_bnode(c_bvec);
    }
    
    castle_ftree_lub_find(node, block, version, &lub_idx, &insert_idx);
    if(lub_idx >= 0) lub_slot = &node->slots[lub_idx];

    /* Insert an entry if LUB doesn't match our (b,v) precisely. */
    if(lub_idx < 0 || (lub_slot->block != block) || (lub_slot->version != version))
    {
        c_disk_blk_t cdb = castle_slaves_disk_block_get(); 
        printk("Need to insert (0x%x, 0x%x) into node (used: 0x%x, capacity: 0x%x, leaf=%d).\n",
                block, version,
                node->used, node->capacity, FTREE_NODE_IS_LEAF(node));
        BUG_ON(castle_ftree_write_idx_find(c_bvec) != insert_idx);
        castle_ftree_slot_insert(node,
                                 insert_idx,
                                 FTREE_SLOT_LEAF,
                                 block,
                                 version,
                                 cdb);
        dirty_c2p(c_bvec->btree_node);
        castle_ftree_io_end(c_bvec, cdb, 0);
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
        if(slot->block == block)
            castle_ftree_io_end(c_bvec, slot->cdb, 0);
        else
            castle_ftree_io_end(c_bvec, INVAL_DISK_BLK, 0);
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

/***** Init/fini functions *****/
int castle_btree_init(void)
{
    int ret = 0;

    return ret;
}

void castle_btree_free(void)
{
}
