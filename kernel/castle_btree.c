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

static int castle_ftree_lub_find(struct castle_ftree_node *node,
                                 uint32_t block, 
                                 uint32_t version)
{
    struct castle_ftree_slot *slot;
    uint32_t blk_lub;
    int      blk_lub_idx, i;

    debug("Looking for (b,v) = (0x%x, 0x%x), node->used=%d, capacity=%d\n",
            block, version, node->used, node->capacity);
        
    blk_lub_idx = -1;
    blk_lub     = INVAL_BLK; 
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
        if((blk_lub != slot->block) &&
            castle_version_is_ancestor(slot->version, version))
        {
            blk_lub     = slot->block;
            blk_lub_idx = i;
            debug("  set b_lub=0x%x, b_lub_idx=%d\n", blk_lub, blk_lub_idx);
        }
    } 

    return blk_lub_idx;
}

static void castle_ftree_write_process(c_bvec_t *c_bvec)
{
    struct castle_ftree_node *node = c_bvec->node;
    struct castle_ftree_slot *slot;
    uint32_t block = c_bvec->block;
    uint32_t version = c_bvec->version;
    int      blk_lub_idx;

    blk_lub_idx = castle_ftree_lub_find(node, block, version);
    /* We should always find the LUB if we are not looking at a leaf node */
    BUG_ON((blk_lub_idx < 0) && !FTREE_SLOT_IS_LEAF(&node->slots[0]));

    /* Only applies to leaf nodes after the check in the previous line */
    if(blk_lub_idx < 0)
    {
        printk("Could not find the LUB during write.\n");
        kfree(node);
        castle_bio_data_io_end(c_bvec, -EINVAL);
        return;
    } 
    
    slot = &node->slots[blk_lub_idx];
    if(FTREE_SLOT_IS_LEAF(slot))
    {
        /* Handle the 'easy' case, where the block already exists in the 
           correct version first */
        if((slot->block == block) ||
           (slot->version == version))
        {
            printk("Block already exists, modifying in place.\n");
            c_bvec->cdb = slot->cdb; 
            kfree(node);
            castle_bio_data_io(c_bvec);
            return;
        }

        printk("Could not find the exact (b,v).\n");
        kfree(node);
        castle_bio_data_io_end(c_bvec, -EINVAL);
        return;
    } else
    {
        printk("Following write down the tree.\n");
        castle_ftree_find(c_bvec, slot->cdb);
        return;
    }
}

static void castle_ftree_read_process(c_bvec_t *c_bvec)
{
    struct castle_ftree_node *node = c_bvec->node;
    struct castle_ftree_slot *slot;
    uint32_t block = c_bvec->block;
    uint32_t version = c_bvec->version;
    int      blk_lub_idx;

    blk_lub_idx = castle_ftree_lub_find(node, block, version);
    /* We should always find the LUB if we are not looking at a leaf node */
    BUG_ON((blk_lub_idx < 0) && !FTREE_SLOT_IS_LEAF(&node->slots[0]));
    
    /* If we haven't found the LUB (in the leaf node), return early */
    if(blk_lub_idx < 0)
    {
        debug(" Could not find the LUB for (b,v)=(0x%x, 0x%x)\n", 
            block, version);
        c_bvec->cdb = INVAL_DISK_BLK;
        kfree(c_bvec->node);
        castle_bio_data_io(c_bvec);
        return;
    }

    slot = &node->slots[blk_lub_idx];
    /* If we found the LUB, either complete the ftree walk (if we are looking 
       at a leaf), or go to the next level */
    if(FTREE_SLOT_IS_LEAF(slot))
    {
        debug(" Is a leaf, found (b,v)=(0x%x, 0x%x)\n", 
            slot->block, slot->version);
        c_bvec->cdb = slot->cdb; 
        kfree(node);
        castle_bio_data_io(c_bvec);
    }
    else
    {
        debug("Is not a leaf. Read and search (disk,blk#)=(0x%x, 0x%x)\n",
                slot->cdb.disk, slot->cdb.block);
        castle_ftree_find(c_bvec, slot->cdb);
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


static void castle_ftree_c2p_process(c_bvec_t *c_bvec, c2_page_t *c2p)
{
    struct castle_ftree_node *node = c_bvec->node;
    int i;

    /* Copy the data */
    /* TODO: let c_bvec reference c2p directly. Keep it locked for as long as needed */
    BUG_ON(sizeof(struct castle_ftree_node) > PAGE_SIZE);
    memcpy(node, 
           pfn_to_kaddr(page_to_pfn(c2p->page)),
           sizeof(struct castle_ftree_node));

    if((node->capacity > FTREE_NODE_SLOTS) ||
       (node->used     > node->capacity) ||
       (node->used     == 0))
    {
        printk("Invalid ftree node capacity or/and used: (%d, %d)\n",
               node->capacity, node->used);
        kfree(node);
        castle_bio_data_io_end(c_bvec, -EINVAL);
        return;
    }
 
    for(i=0; i < node->used; i++)
    {
        struct castle_ftree_slot *slot = &node->slots[i];
        castle_ftree_slot_normalize(slot);
    }

    /* Release the buffer */
    unlock_c2p(c2p);
    put_c2p(c2p);
}

void castle_ftree_find_io_end(c2_page_t *c2p, int uptodate)
{
    c_bvec_t *c_bvec = c2p->private;

    debug("Finished IO for: block 0x%lx, in version 0x%x\n", 
            c_bvec->block, c_bvec->version);
    /* Callback on error */
    if(!uptodate)
    {
        if(c_bvec->node) kfree(c_bvec->node);
        /* Release the buffer */
        unlock_c2p(c2p);
        put_c2p(c2p);
        castle_bio_data_io_end(c_bvec, -EIO);
        return;
    }

    set_c2p_uptodate(c2p);
    castle_ftree_c2p_process(c_bvec, c2p);
    /* Put on to the workqueue */
    INIT_WORK(&c_bvec->work, castle_ftree_process);
    queue_work(castle_wq, &c_bvec->work); 
}

void castle_ftree_find(c_bvec_t *c_bvec,
                       c_disk_blk_t node_cdb)
{
    c2_page_t *c2p;
    int ret;

    debug("Asked for block: 0x%lx, in version 0x%x, reading ftree node (0x%x, 0x%x)\n", 
            c_bvec->block, c_bvec->version, node_cdb.disk, node_cdb.block);
    ret = -ENOMEM;
    if(!c_bvec->node)
        c_bvec->node = kmalloc(sizeof(struct castle_ftree_node), GFP_KERNEL);
    if(!c_bvec->node) goto error_out;

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
           function directly */ 
        castle_ftree_c2p_process(c_bvec, c2p);
        castle_ftree_process(&c_bvec->work);
    }
    return;

error_out:
    if(c_bvec->node) kfree(c_bvec->node);
    castle_bio_data_io_end(c_bvec, ret);
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
