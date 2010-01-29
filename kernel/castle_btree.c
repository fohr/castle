#include <linux/module.h>

#include "castle.h"
#include "castle_block.h"
#include "castle_btree.h"

#ifndef DEBUG
#define debug(_f, ...)  ((void)0)
#else
#define debug(_f, _a...)  (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif


static int castle_is_ancestor(struct castle_vtree_node *root, uint32_t candidate, uint32_t version);
static int castle_ftree_read(c_disk_blk_t cdb, 
                             void (*callback)(void *, 
                                              struct castle_ftree_node *node, 
                                              int err),
                             void *arg);

struct castle_ftree_io {
    void (*callback)(void *arg, struct castle_ftree_node *node, int err);
    void *arg;
    int payload_read;
    c_disk_blk_t cdb;
    struct castle_ftree_node *node;
};

static void castle_ftree_read_end(void *arg, int ret)
{
    struct castle_slave *cs;
    struct castle_ftree_io *iop = arg;
    struct castle_ftree_io io = *iop;
    struct castle_ftree_node *ftree_node = io.node;

    if(ret)
    {
        printk("Could not read ftree node.\n");
        kfree(ftree_node);
        kfree(iop);
        io.callback(io.arg, NULL, ret);
        return;
    }

    /* If we've already read the entire node, call the callback and exit */
    if(io.payload_read)
    {
        kfree(iop);
        io.callback(io.arg, ftree_node, 0); 
        return;
    }

    /* We'll only get here if we've just read the header, 
       and we have to read the rest of the node */ 
    if((ftree_node->capacity > FTREE_NODE_SLOTS) ||
       (ftree_node->used > ftree_node->capacity))
    {
        printk("Invalid ftree node capacity or/and used: (%d, %d)\n",
               ftree_node->capacity, ftree_node->used);
        kfree(ftree_node);
        kfree(iop);
        io.callback(io.arg, NULL, -EINVAL);
        return;
    }
    cs = castle_slave_find_by_block(io.cdb);
    if(!cs) 
    {
        kfree(ftree_node);
        kfree(iop);
        io.callback(io.arg, NULL, -ENODEV);
        return;
    }
    
    /* The next time around the entire node (= payload) will be read */
    iop->payload_read = 1;
    ret = castle_sub_block_read(cs,
                               &ftree_node->slots,
                                disk_blk_to_offset(io.cdb) + NODE_HEADER,
                                ftree_node->used * sizeof(struct castle_ftree_slot),
                                castle_ftree_read_end, 
                                iop); 
    if(ret)
    {
        printk("Could not read ftree node slots.\n");
        kfree(ftree_node);
        kfree(iop);
        io.callback(io.arg, NULL, ret);
    }
}

static int castle_ftree_read(c_disk_blk_t cdb, 
                             void (*callback)(void *, 
                                              struct castle_ftree_node *node, 
                                              int err),
                             void *arg)
{
    struct castle_slave *cs;
    struct castle_ftree_node *ftree_node; 
    struct castle_ftree_io *io;
    int ret;

    io = kmalloc(sizeof(struct castle_ftree_io), GFP_KERNEL);
    if(!io) return -ENOMEM;
    ftree_node = kmalloc(sizeof(struct castle_ftree_node), GFP_KERNEL);
    if(!ftree_node) 
    {
        kfree(io);
        return -ENOMEM;
    }
    memset(ftree_node, 0, sizeof(struct castle_ftree_node));
    io->cdb = cdb;
    io->node = ftree_node;
    io->callback = callback;
    io->arg = arg;
    io->payload_read = 0;

    cs = castle_slave_find_by_block(cdb);
    if(!cs) 
    {
        kfree(ftree_node);
        kfree(io);
        return -ENODEV;
    }

    ret = castle_sub_block_read(cs,
                                ftree_node,
                                disk_blk_to_offset(cdb),
                                NODE_HEADER,
                                castle_ftree_read_end, 
                                io);
    /* We won't get a callback, cleanup here */
    if(ret)
    {
        kfree(ftree_node);
        kfree(io);
    }

    return ret;
}

struct castle_ftree_find_io {
    void (*callback)(void *arg, c_disk_blk_t cdb, int err);
    void *arg;
    sector_t block;
    uint32_t version;
};

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

void castle_ftree_find_end(void *arg, struct castle_ftree_node *node, int err)
{
    struct castle_ftree_find_io *iop = arg;
    struct castle_ftree_find_io io = *iop;
    uint32_t block = (uint32_t)io.block;
    uint32_t version = io.version;
    uint32_t blk_lub;
    int      blk_lub_idx, i;

    if(err)
    {
        /* node should be null on error */
        BUG_ON(node);
        kfree(iop);
        io.callback(io.arg, INVAL_DISK_BLK, err);
        return;
    }

    debug("Looking for (b,v) = (0x%x, 0x%x)\n", block, version);
    blk_lub_idx = node->used-1;
    blk_lub     = node->slots[blk_lub_idx].block;
    for(i=node->used-1; i >= 0; i--)
    {
        struct castle_ftree_slot *slot = &node->slots[i];
        castle_ftree_slot_normalize(slot);

        debug(" (b,v) = (0x%x, 0x%x)\n", 
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
            debug("  set b_lub=0x%x, b_lub_idx=%d\n", blk_lub, blk_lub_idx);
        }
    } 
    
    debug("Version seach, blk_lub=0x%x, idx=%d.\n", blk_lub, blk_lub_idx);
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
        
        debug(" (b,v) = (0x%x, 0x%x)\n", 
               slot->block,
               slot->version);

        if(slot->block != blk_lub)
        {
            debug("Not found\n");
            goto blk_not_found;
        }

        if(castle_is_ancestor(castle_vtree_root, slot->version, version))
        {
            debug(" Is an ancestor.\n");
            if(FTREE_SLOT_IS_LEAF(slot))
            {
                debug(" Is a leaf, found (b,v)=(0x%x, 0x%x)\n", 
                    slot->block, slot->version);
                kfree(node);
                kfree(iop);
                io.callback(io.arg, slot->cdb, 0);
                return;
            } 
            else
            {
                int ret;

                debug("Is not a leaf. Read and search (disk,blk#)=(0x%x, 0x%x)\n",
                        slot->cdb.disk, slot->cdb.block);
                ret = castle_ftree_find(slot->cdb,
                                        (sector_t)block,
                                        version,
                                        io.callback, 
                                        io.arg);
                kfree(node);
                kfree(iop);
                /* If error return, callback from here */
                if(ret) io.callback(io.arg, INVAL_DISK_BLK, ret);
                return;
            }
        }
    }
    debug(" No elements left. Blk not found\n");
blk_not_found:    
    kfree(node);
    kfree(iop);
    io.callback(io.arg, INVAL_DISK_BLK, -ENOENT); 
}

int castle_ftree_find(c_disk_blk_t node_cdb,
                      sector_t block, 
                      uint32_t version,
                      void (*callback)(void *arg, c_disk_blk_t cdb, int err),
                      void *arg)
{
    struct castle_ftree_find_io *io;
    int ret;

    io = kmalloc(sizeof(struct castle_ftree_find_io), GFP_KERNEL);
    if(!io) return -ENOMEM;

    io->callback = callback;
    io->arg = arg;
    io->block = block;
    io->version = version;

    debug("Asked for block: 0x%lx, in version 0x%x\n", block, version);
    ret = castle_ftree_read(node_cdb, castle_ftree_find_end, io); 
    /* Free the continuation structure if we're not going to get the callback */
    if(ret) kfree(io);

    return ret;
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

