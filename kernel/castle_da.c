#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/fs.h>

#include "castle_public.h"
#include "castle_hash.h"
#include "castle.h"
#include "castle_cache.h"
#include "castle_freespace.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)  ((void)0)
#else
#define debug(_f, _a...)  (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

#define MAX_DA_LEVEL                    (10)

#define CASTLE_DA_HASH_SIZE             (1000)
static struct list_head  *castle_da_hash;
struct castle_mstore     *castle_da_store;
struct castle_mstore     *castle_tree_store;

struct castle_double_array {
    da_id_t          id;
    struct list_head trees[MAX_DA_LEVEL];
    struct list_head hash_list;
    c_mstore_key_t   mstore_key;
};

struct castle_component_tree {
    tree_seq_t       seq;
    uint8_t          level;
    c_disk_blk_t     first_node;
    struct list_head list;
    c_mstore_key_t   mstore_key;
};

DEFINE_HASH_TBL(castle_da, castle_da_hash, CASTLE_DA_HASH_SIZE, struct castle_double_array, hash_list, da_id_t, id);

static int castle_da_hash_dealloc(struct castle_double_array *da, void *unused) 
{
    list_del(&da->hash_list);
    kfree(da);

    return 0;
}

static void castle_da_hash_destroy(void)
{
   castle_da_hash_iterate(castle_da_hash_dealloc, NULL); 
   kfree(castle_da_hash);
}

static int castle_da_writeback(struct castle_double_array *da, void *unused) 
{
    struct castle_dlist_entry mstore_dentry;

    mstore_dentry.id = da->id;

    /* We get here with hash spinlock held. But since we're calling sleeping functions
       we need to drop it. Hash consitancy is guaranteed, because by this point 
       noone should be modifying it anymore */
    spin_unlock_irq(&castle_da_hash_lock);
    if(MSTORE_KEY_INVAL(da->mstore_key))
    {
        debug("Inserting a DA id=%d\n", da->id);
        da->mstore_key = 
            castle_mstore_entry_insert(castle_da_store, &mstore_dentry);
    }
    else
    {
        debug("Updating a DA id=%d.\n", da->id);
        castle_mstore_entry_update(castle_da_store, da->mstore_key, &mstore_dentry);
    }
    spin_lock_irq(&castle_da_hash_lock);

    return 0;
}

static void castle_da_hash_writeback(void)
{
   castle_da_hash_iterate(castle_da_writeback, NULL); 
}
     
int castle_double_array_read(void)
{
    struct castle_dlist_entry mstore_dentry;
    struct castle_mstore_iter *iterator;
    struct castle_double_array *da;
    c_mstore_key_t key;

    castle_da_store   = castle_mstore_open(MSTORE_DOUBLE_ARRAYS,
                                         sizeof(struct castle_dlist_entry));
    castle_tree_store = castle_mstore_open(MSTORE_COMPONENT_TREES,
                                         sizeof(struct castle_clist_entry));

    if(!castle_da_store || !castle_tree_store)
        return -ENOMEM;
    
    iterator = castle_mstore_iterate(castle_da_store);
    if(!iterator)
        return -EINVAL;
   
    while(castle_mstore_iterator_has_next(iterator))
    {
        castle_mstore_iterator_next(iterator, &mstore_dentry, &key);
        da = kmalloc(sizeof(struct castle_double_array), GFP_KERNEL);
        if(!da)
        {
            castle_mstore_iterator_destroy(iterator);
            return -ENOMEM;
        }
        da->id = mstore_dentry.id;
        da->mstore_key = key;
        castle_da_hash_add(da);
    }
    castle_mstore_iterator_destroy(iterator);

    return 0;
}

int castle_double_array_create(void)
{
    castle_da_store   = castle_mstore_init(MSTORE_DOUBLE_ARRAYS,
                                         sizeof(struct castle_double_array));
    castle_tree_store = castle_mstore_init(MSTORE_COMPONENT_TREES,
                                         sizeof(struct castle_component_tree));

    if(!castle_da_store || !castle_tree_store)
        return -ENOMEM;

    return 0;
}

int castle_double_array_init(void)
{
    printk("\n========= Double Array init ==========\n");
    castle_da_hash = castle_da_hash_alloc();
    if(!castle_da_hash)
        return -ENOMEM;
    castle_da_hash_init();

    return 0;
}

void castle_double_array_fini(void)
{
    printk("\n========= Double Array fini ==========\n");
    castle_da_hash_writeback();
    castle_da_hash_destroy();
}
