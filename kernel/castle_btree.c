#include <linux/module.h>

#include "castle.h"
#include "castle_btree.h"

/***** Init/fini functions *****/
int castle_btree_init(void)
{
    int ret = 0;

    printk("Initialising Castle Btrees.\n");
#if 0
    ret = castle_btree_cache_init();
#endif
    
    return ret;
}

void castle_btree_free(void)
{
    printk("Freeing Castle BTree.\n");
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

