#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/fs.h>

#include "castle.h"
#include "castle_btree.h"
#include "castle_block.h"
#include "castle_cache.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)  ((void)0)
#else
#define debug(_f, _a...)  (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

#define debug_off(_f, ...)  ((void)0)

static int castle_is_ancestor(struct castle_vtree_node *root, uint32_t candidate, uint32_t version);

static void castle_ftree_slot_normalize(struct castle_ftree_slot *slot)
{
    /* Look for 'last' slot, and if block is zero, assign the maximum value instead */
    if(FTREE_SLOT_IS_NODE_LAST(slot) &&
       (slot->block == 0))
    {
        slot->type = FTREE_SLOT_NODE;
        slot->block = (uint32_t)-1;
    }
}

void castle_ftree_process(struct work_struct *work)
{
    c_bvec_t *c_bvec = container_of(work, c_bvec_t, work);
    struct castle_ftree_node *node = c_bvec->node;
    uint32_t block = c_bvec->block;
    uint32_t version = c_bvec->version;
    uint32_t blk_lub;
    int      blk_lub_idx, i;

    if((node->capacity > FTREE_NODE_SLOTS) ||
       (node->used     > node->capacity))
    {
        printk("Invalid ftree node capacity or/and used: (%d, %d)\n",
               node->capacity, node->used);
        kfree(node);
        castle_bio_data_io_end(c_bvec, -EINVAL);
        return;
    }
 
    debug("Looking for (b,v) = (0x%x, 0x%x), node->used=%d, capacity=%d\n",
            block, version, node->used, node->capacity);
    blk_lub_idx = node->used-1;
    blk_lub     = node->slots[blk_lub_idx].block;
    for(i=node->used-1; i >= 0; i--)
    {
        struct castle_ftree_slot *slot = &node->slots[i];
        castle_ftree_slot_normalize(slot);

        debug_off(" (b,v) = (0x%x, 0x%x)\n", 
               slot->block,
               slot->version);

        /* If the block is already too small, we must have gone past the least
           upper bound */
        if(slot->block < block)
            break;

        /* Update the blk_lub, but only if it's different to the current block.
           This would save an incorrect lub index */
        if(blk_lub != slot->block)
        {
            blk_lub     = slot->block;
            blk_lub_idx = i;
            debug_off("  set b_lub=0x%x, b_lub_idx=%d\n", blk_lub, blk_lub_idx);
        }
    } 
    
    debug_off("Version seach, blk_lub=0x%x, idx=%d.\n", blk_lub, blk_lub_idx);
    /* 
       Start at blk LUB, and scan left. Stop if:
       - blk number changes: 
            block not found
       - blk is still the lub, and version is an ancestor:
            if we looking at a leaf, the search is finished
            otherwise follow the pointer to the next level in the tree
       Skip over versions which are not ancestors of the version we are 
       looking for 
    */
    for(i=blk_lub_idx; i>=0; i--)
    {
        struct castle_ftree_slot *slot = &node->slots[i];
        
        debug_off(" (b,v) = (0x%x, 0x%x)\n", 
               slot->block,
               slot->version);

        if(slot->block != blk_lub)
        {
            debug("Not found\n");
            goto blk_not_found;
        }

        if(castle_is_ancestor(castle_vtree_root, slot->version, version))
        {
            debug_off(" Is an ancestor.\n");
            if(FTREE_SLOT_IS_LEAF(slot))
            {
                c_bvec->cdb = slot->cdb; 
                debug(" Is a leaf, found (b,v)=(0x%x, 0x%x)\n", 
                    slot->block, slot->version);
                kfree(node);
                castle_bio_data_io(c_bvec);
                return;
            } 
            else
            {
                debug("Is not a leaf. Read and search (disk,blk#)=(0x%x, 0x%x)\n",
                        slot->cdb.disk, slot->cdb.block);
                castle_ftree_find(c_bvec, slot->cdb);
                return;
            }
        }
    }
    debug(" No elements left. Blk not found\n");
blk_not_found:    
    c_bvec->cdb = INVAL_DISK_BLK;
    kfree(c_bvec->node);
    castle_bio_data_io(c_bvec);
}

static void castle_ftree_c2p_process(c_bvec_t *c_bvec, c2_page_t *c2p)
{
    /* Copy the data */
    BUG_ON(sizeof(struct castle_ftree_node) > PAGE_SIZE);
    memcpy(c_bvec->node, 
           pfn_to_kaddr(page_to_pfn(c2p->page)),
           sizeof(struct castle_ftree_node));
    /* Release the buffer */
    unlock_c2p(c2p);
    put_c2p(c2p);
}

void castle_ftree_find_io_end(c2_page_t *c2p, int uptodate)
{
    c_bvec_t *c_bvec = c2p->private;

    debug("====> Finished IO for: block 0x%lx, in version 0x%x\n", 
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

struct castle_vtree_leaf_slot* castle_vtree_leaf_find(struct castle_vtree_node *node, uint32_t version)
{
    int i;
    
    if(!node) return NULL;

    for(i=0; i<node->used; i++)
    {
        struct castle_vtree_slot *slot = &node->slots[i];
        struct castle_vtree_node *child = node->children[i];

        if(VTREE_SLOT_IS_NODE_LAST(slot))
        {
            return castle_vtree_leaf_find(child, version);
        } else
        if(VTREE_SLOT_IS_NODE(slot))
        {
            if(slot->node.version_nr >= version)
                return castle_vtree_leaf_find(child, version);
        } else
        if(VTREE_SLOT_IS_LEAF(slot))
        {
            if(slot->leaf.version_nr == version)
                return &slot->leaf;
        }
    }

    return NULL; 
} 

c_disk_blk_t castle_vtree_find(struct castle_vtree_node *node, uint32_t version)
{
    struct castle_vtree_leaf_slot *leaf;

    leaf = castle_vtree_leaf_find(node, version);
    if(!leaf) return INVAL_DISK_BLK;

    return leaf->cdb;
}

/* TODO: Inefficient. Fix */ 
static int castle_is_ancestor(struct castle_vtree_node *root, uint32_t candidate, uint32_t version)
{
    struct castle_vtree_leaf_slot *leaf;

again:    
    if(candidate == version) return 1;
    if(version == 0) return 0;

    leaf = castle_vtree_leaf_find(root, version);
    BUG_ON(!leaf);
    version = leaf->parent;
    goto again;
}

static void castle_version_node_destroy(struct castle_vtree_node *v_node)
{
    int i;

    for(i=0; i<v_node->used; i++)
        if(v_node->slots[i].type == VTREE_SLOT_NODE)
            castle_version_node_destroy(v_node->children[i]);
    kfree(v_node);
}

int castle_version_tree_read(c_disk_blk_t cdb, struct castle_vtree_node **v_node)
{
    struct castle_slave *cs;
    struct castle_vtree_node *vtree_node;
    int i, ret;

    vtree_node = kmalloc(sizeof(struct castle_vtree_node), GFP_KERNEL);
    if(vtree_node == NULL) return -ENOMEM;
    memset(vtree_node, 0, sizeof(struct castle_vtree_node));

    cs = castle_slave_find_by_block(cdb);
    if(cs == NULL) return -ENODEV; 

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
       (vtree_node->used > vtree_node->capacity))
    {
        printk("Invalid vtree node capacity or/and used: (%d, %d)\n",
               vtree_node->capacity, vtree_node->used);
        kfree(vtree_node);
        return ret;
    }
    ret = castle_sub_block_read(cs,
                               &vtree_node->slots,
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
            /* Read the child node */
            ret = castle_version_tree_read(vtree_node->slots[i].node.cdb, 
                                           &vtree_node->children[i]);
            /* If failed, cleanup all children read so far */
            if(ret < 0)
            {
                while(i > 0)
                {
                    i--;
                    /* This will decend recursively into sub-children */
                    castle_version_node_destroy(vtree_node->children[i]);
                }
                /* All children freed, free our node */
                kfree(vtree_node);
                return ret;
            }
        }
    }

    if(v_node) *v_node = vtree_node;
    return 0;
}


/***** Init/fini functions *****/
int castle_btree_init(void)
{
    int ret = 0;

#if 0
    ret = castle_btree_cache_init();
#endif
    
    return ret;
}

void castle_btree_free(void)
{
#if 0
    castle_btree_cache_free();
#endif
}




#if 0
struct castle_btree_cache_entry {
    struct c_bnode_hnd_t             hnd;
    struct castle_btree_cache_entry *next;
    void                            *data;
};

struct castle_btree_cache_entry** castle_btree_cache;

#define CASTLE_HASH_LENGTH  503


/***** BTree node cache *****/
static inline uint32_t castle_hash_hnd(c_bnode_hnd_t hnd)
{
    
}

static void *castle_btree_cache_get(c_bnode_hnd_t hnd)
{
     
}

static int castle_btree_cache_init(void)
{
    castle_btree_cache = kmalloc(
            CASTLE_HASH_LENGTH * sizeof(struct castle_btree_cache_entry), 
            GFP_KERNEL);
    if(!castle_btree_cache) return -ENOMEM;

    return 0;
}

static void castle_btree_cache_free(void)
{
    // TODO: free all cached entries
    free(castle_btree_cache);
}

/***** Generic BTree manipulations *****/
static void* castle_btree_node_get(c_bnode_hnd_t handle)
{

}


/***** Definition of various btree types *****/
struct castle_btree_type c_shdw_tree = 
{
    .on_disk_node_size  =   4096,
};

#endif

