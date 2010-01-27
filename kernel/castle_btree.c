#include <linux/module.h>

#include "castle.h"
#include "castle_block.h"
#include "castle_btree.h"

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

c_disk_blk_t castle_version_find(struct castle_vtree_node *node, uint32_t version)
{
    int i;
    
    for(i=0; i<node->used; i++)
    {
        struct castle_vtree_slot *slot = &node->slots[i];
        struct castle_vtree_node *child = node->children[i];

        if(VTREE_SLOT_IS_NODE_LAST(slot))
        {
            return castle_version_find(child, version);
        } else
        if(VTREE_SLOT_IS_NODE(slot))
        {
            if(slot->node.version_nr >= version)
                return castle_version_find(child, version);
        } else
        if(VTREE_SLOT_IS_LEAF(slot))
        {
            if(slot->leaf.version_nr == version)
                return slot->leaf.cdb;
        }
    }

    return INVAL_DISK_BLK; 
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
                                NODE_HEADER); 
    if(ret)
    {
        printk("Could not read version tree root.\n");
        return ret;
    }

    if((vtree_node->capacity > VTREE_NODE_SLOTS) ||
       (vtree_node->used > vtree_node->capacity))
    {
        printk("Invalid vtree root capacity or/and used: (%d, %d)\n",
               vtree_node->capacity, vtree_node->used);
        return ret;
    }
    ret = castle_sub_block_read(cs,
                               &vtree_node->slots,
                                disk_blk_to_offset(cdb) + NODE_HEADER,
                                vtree_node->used * sizeof(struct castle_vtree_slot)); 
    if(ret)
    {
        printk("Could not read version slots.\n");
        return ret;
    }
    for(i=0; i<vtree_node->used; i++)
    {
        if((vtree_node->slots[i].type == VTREE_SLOT_NODE) ||
           (vtree_node->slots[i].type == VTREE_SLOT_NODE_LAST))
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

