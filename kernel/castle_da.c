#include <linux/sched.h>

#include "castle_public.h"
#include "castle_utils.h"
#include "castle.h"
#include "castle_cache.h"
#include "castle_btree.h"
#include "castle_versions.h"
#include "castle_freespace.h"

#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)  ((void)0)
#else
#define debug(_f, _a...)  (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

#define MAX_DA_LEVEL                    (10)

#define CASTLE_DA_HASH_SIZE             (1000)
static struct list_head     *castle_da_hash;
static struct castle_mstore *castle_da_store;
static struct castle_mstore *castle_tree_store;
       da_id_t               castle_next_da_id    = 1; 
static tree_seq_t            castle_next_tree_seq = 1; 

struct castle_double_array {
    da_id_t          id;
    version_t        root_version;
    struct list_head trees[MAX_DA_LEVEL];
    struct list_head hash_list;
    c_mstore_key_t   mstore_key;
};

DEFINE_HASH_TBL(castle_da, castle_da_hash, CASTLE_DA_HASH_SIZE, struct castle_double_array, hash_list, da_id_t, id);

static int castle_da_ct_inc_cmp(struct list_head *l1, struct list_head *l2)
{
    struct castle_component_tree *ct1 = list_entry(l1, struct castle_component_tree, list);
    struct castle_component_tree *ct2 = list_entry(l2, struct castle_component_tree, list);

    return ct1->seq > ct2->seq ? 1 : -1;
}

static c_mstore_key_t castle_da_marshall(struct castle_dlist_entry *dam,
                                         struct castle_double_array *da)
{
    dam->id           = da->id;
    dam->root_version = da->root_version;

    return da->mstore_key;
}
 
static void castle_da_unmarshall(struct castle_double_array *da,
                                 struct castle_dlist_entry *dam,
                                 c_mstore_key_t key)
{
    int i;

    da->id           = dam->id;
    da->root_version = dam->root_version;
    da->mstore_key   = key;

    for(i=0; i<MAX_DA_LEVEL; i++)
        INIT_LIST_HEAD(&da->trees[i]);
}

static struct castle_component_tree *castle_da_rwct_get(struct castle_double_array *da)
{
    struct list_head *h, *l;

    h = &da->trees[0]; 
    l = h->next; 
    /* There should be precisely one entry in the list */
    BUG_ON((h == l) || (l->next != h));
        
    return list_entry(l, struct castle_component_tree, list);
}

static int castle_da_trees_sort(struct castle_double_array *da, void *unused)
{
    int i;

    for(i=0; i<MAX_DA_LEVEL; i++)
        list_sort(&da->trees[i], castle_da_ct_inc_cmp);

    return 0;
}

static c_mstore_key_t castle_da_ct_marshall(struct castle_clist_entry *ctm,
                                            struct castle_component_tree *ct)
{
    ctm->da_id      = ct->da; 
    ctm->item_count = atomic64_read(&ct->item_count);
    ctm->btree_type = ct->btree_type; 
    ctm->seq        = ct->seq;
    ctm->level      = ct->level;
    ctm->first_node = ct->first_node;

    return ct->mstore_key;
}

static da_id_t castle_da_ct_unmarshall(struct castle_component_tree *ct,
                                       struct castle_clist_entry *ctm,
                                       c_mstore_key_t key)
{
    ct->seq        = ctm->seq;
    atomic64_set(&ct->item_count, ctm->item_count);
    ct->btree_type = ctm->btree_type; 
    ct->da         = ctm->da_id; 
    ct->level      = ctm->level;
    ct->first_node = ctm->first_node;
    ct->mstore_key = key;
    INIT_LIST_HEAD(&ct->list);

    return ctm->da_id;
}

static void castle_da_foreach_tree(struct castle_double_array *da,
                                   int (*fn)(struct castle_double_array *da,
                                             struct castle_component_tree *ct,
                                             int level_cnt,
                                             void *token), 
                                   void *token)
{
    struct castle_component_tree *ct;
    struct list_head *lh, *t;
    int i, j;

    for(i=0; i<MAX_DA_LEVEL; i++)
    {
        j = 0;
        list_for_each_safe(lh, t, &da->trees[i])
        {
            ct = list_entry(lh, struct castle_component_tree, list); 
            if(fn(da, ct, j, token))
                return;
            j++;
        }
    }
}

static int castle_da_ct_dealloc(struct castle_double_array *da,
                                struct castle_component_tree *ct,
                                int level_cnt,
                                void *unused)
{
    list_del(&ct->list);
    kfree(ct);

    return 0;
}

static int castle_da_hash_dealloc(struct castle_double_array *da, void *unused) 
{
    castle_da_foreach_tree(da, castle_da_ct_dealloc, NULL);
    list_del(&da->hash_list);
    kfree(da);

    return 0;
}

static void castle_da_hash_destroy(void)
{
   castle_da_hash_iterate(castle_da_hash_dealloc, NULL); 
   kfree(castle_da_hash);
}

static int castle_da_tree_writeback(struct castle_double_array *da,
                                    struct castle_component_tree *ct,
                                    int level_cnt,
                                    void *unused)
{
    struct castle_clist_entry mstore_entry;
    c_mstore_key_t key;

    key = castle_da_ct_marshall(&mstore_entry, ct); 
    if(MSTORE_KEY_INVAL(key))
    {
        debug("Inserting CT seq=%d\n", ct->seq);
        ct->mstore_key = 
            castle_mstore_entry_insert(castle_tree_store, &mstore_entry);
    }
    else
    {
        debug("Updating CT seq=%d\n", ct->seq);
        castle_mstore_entry_update(castle_tree_store, key, &mstore_entry);
    }

    return 0;
}

static int castle_da_writeback(struct castle_double_array *da, void *unused) 
{
    struct castle_dlist_entry mstore_dentry;
    c_mstore_key_t key;

    key = castle_da_marshall(&mstore_dentry, da);

    /* We get here with hash spinlock held. But since we're calling sleeping functions
       we need to drop it. Hash consitancy is guaranteed, because by this point 
       noone should be modifying it anymore */
    spin_unlock_irq(&castle_da_hash_lock);
    castle_da_foreach_tree(da, castle_da_tree_writeback, NULL);
    if(MSTORE_KEY_INVAL(key))
    {
        debug("Inserting a DA id=%d\n", da->id);
        da->mstore_key = 
            castle_mstore_entry_insert(castle_da_store, &mstore_dentry);
    }
    else
    {
        debug("Updating a DA id=%d.\n", da->id);
        castle_mstore_entry_update(castle_da_store, key, &mstore_dentry);
    }
    spin_lock_irq(&castle_da_hash_lock);

    return 0;
}

static void castle_da_hash_writeback(void)
{
   castle_da_hash_iterate(castle_da_writeback, NULL); 
   castle_da_tree_writeback(NULL, &castle_global_tree, -1, NULL);
}
    
int castle_double_array_read(void)
{
    struct castle_dlist_entry mstore_dentry;
    struct castle_clist_entry mstore_centry;
    struct castle_mstore_iter *iterator;
    struct castle_component_tree *ct;
    struct castle_double_array *da;
    c_mstore_key_t key;
    da_id_t da_id;

    castle_da_store   = castle_mstore_open(MSTORE_DOUBLE_ARRAYS,
                                         sizeof(struct castle_dlist_entry));
    castle_tree_store = castle_mstore_open(MSTORE_COMPONENT_TREES,
                                         sizeof(struct castle_clist_entry));

    if(!castle_da_store || !castle_tree_store)
        return -ENOMEM;
    
    /* Read doubling arrays */
    iterator = castle_mstore_iterate(castle_da_store);
    if(!iterator)
        return -EINVAL;
    while(castle_mstore_iterator_has_next(iterator))
    {
        castle_mstore_iterator_next(iterator, &mstore_dentry, &key);
        da = kmalloc(sizeof(struct castle_double_array), GFP_KERNEL);
        if(!da) 
            goto out_iter_destroy;
        castle_da_unmarshall(da, &mstore_dentry, key);
        castle_da_hash_add(da);
        debug("Read DA id=%d\n", da->id);
        castle_next_da_id = (da->id >= castle_next_da_id) ? da->id + 1 : castle_next_da_id;
    }
    castle_mstore_iterator_destroy(iterator);

    /* Read component trees */
    iterator = castle_mstore_iterate(castle_tree_store);
    if(!iterator)
        return -EINVAL;
   
    while(castle_mstore_iterator_has_next(iterator))
    {
        castle_mstore_iterator_next(iterator, &mstore_centry, &key);
        /* Special case for castle_global_tree, it doesn't have a da associated with it. */
        if(TREE_GLOBAL(mstore_centry.seq))
        {
            da_id = castle_da_ct_unmarshall(&castle_global_tree, &mstore_centry, key);
            BUG_ON(!DA_INVAL(da_id));
            continue;
        }
        /* Otherwise allocate a ct structure */
        ct = kmalloc(sizeof(struct castle_component_tree), GFP_KERNEL);
        if(!ct)
            goto out_iter_destroy;
        da_id = castle_da_ct_unmarshall(ct, &mstore_centry, key);
        da = castle_da_hash_get(da_id);
        if(!da)
            goto out_iter_destroy;
        debug("Read CT seq=%d\n", ct->seq);
        list_add(&ct->list, &da->trees[ct->level]);
        castle_next_tree_seq = (ct->seq >= castle_next_tree_seq) ? ct->seq + 1 : castle_next_tree_seq;
    }
    castle_mstore_iterator_destroy(iterator);
    debug("castle_next_da_id = %d, castle_next_tree_id=%d\n", 
            castle_next_da_id, 
            castle_next_tree_seq);

    /* Sort all the tree lists by the sequence number */
    castle_da_hash_iterate(castle_da_trees_sort, NULL); 

    return 0;

out_iter_destroy:
    castle_mstore_iterator_destroy(iterator);
    return -EINVAL;
}

static int castle_da_rwct_make(struct castle_double_array *da)
{
    struct castle_component_tree *ct;
    c2_block_t *c2b;
    int ret;

    ct = kzalloc(sizeof(struct castle_component_tree), GFP_KERNEL); 
    if(!ct) 
        return -ENOMEM;
    
    /* TODO: work out locking for ALL of this! */

    /* Allocate an id for the tree, init the ct. */
    ct->seq         = castle_next_tree_seq++;
    atomic64_set(&ct->item_count, 0); 
    ct->btree_type  = MTREE_TYPE; 
    ct->da          = da->id;
    ct->level       = 0;
    ct->mstore_key  = INVAL_MSTORE_KEY; 

    /* Create a root node for this tree, and update the root version */
    c2b = castle_btree_node_create(da->root_version, 1 /* is_leaf */, MTREE_TYPE);
    ct->first_node = c2b->cdb; 
    unlock_c2b(c2b);
    put_c2b(c2b);
    castle_version_lock(da->root_version);
    ret = castle_version_root_update(da->root_version, ct->seq, ct->first_node);
    castle_version_unlock(da->root_version);
    if(ret)
    {
        /* TODO: free the block */
        printk("Could not write root node for version: %d\n", da->root_version);
        kfree(ct);
        return ret;
    }
    debug("Added component tree seq=%d, root_node=(0x%x, 0x%x), it's threaded onto da=%p, level=%d\n",
            ct->seq, c2b->cdb.disk, c2b->cdb.block, da, ct->level);
    /* Thread CT onto level 0 list */
    list_add(&ct->list, &da->trees[ct->level]);

    return 0;
}

int castle_double_array_make(da_id_t da_id, version_t root_version)
{
    struct castle_double_array *da;
    int ret, i;

    printk("Creating doubling array for da_id=%d, version=%d\n", da_id, root_version);
    da = kzalloc(sizeof(struct castle_double_array), GFP_KERNEL); 
    if(!da)
        return -ENOMEM;
    da->id = da_id;
    da->root_version = root_version;
    da->mstore_key = INVAL_MSTORE_KEY;
    for(i=0; i<MAX_DA_LEVEL; i++)
        INIT_LIST_HEAD(&da->trees[i]);
    ret = castle_da_rwct_make(da);
    if(ret)
    {
        printk("Exiting from failed ct create.\n");
        kfree(da);
        
        return ret;
    }
    printk("Successfully made a new doubling array, id=%d, for version=%d\n",
        da_id, root_version);
    castle_da_hash_add(da);

    return 0;
}

static struct castle_component_tree* castle_da_ct_next(struct castle_component_tree *ct)
{
    struct castle_double_array *da = castle_da_hash_get(ct->da);
    struct castle_component_tree *next_ct;
    struct list_head *ct_list;
    uint8_t level;

    debug("Asked for component tree after %d\n", ct->seq);
    BUG_ON(!da);
    for(level = ct->level, ct_list = &ct->list; 
        level < MAX_DA_LEVEL; 
        level++, ct_list = &da->trees[level])
    {
        if(!list_is_last(ct_list, &da->trees[level]))
        {
            next_ct = list_entry(ct_list->next, struct castle_component_tree, list); 
            debug("Found component tree %d\n", next_ct->seq);
            BUG_ON(next_ct->seq > ct->seq);

            return next_ct;
        }
    }     

    return NULL;
}

static void castle_da_bvec_complete(c_bvec_t *c_bvec, int err, c_disk_blk_t cdb)
{
    void (*callback) (struct castle_bio_vec *c_bvec, int err, c_disk_blk_t cdb);
    struct castle_component_tree *ct;
    
    callback = c_bvec->da_endfind;
    ct = c_bvec->tree;

    /* If the key hasn't been found, check in the next tree. */
    if(DISK_BLK_INVAL(cdb) && (!err) && (c_bvec_data_dir(c_bvec) == READ))
    {
        debug("Checking next ct.\n");
        ct = castle_da_ct_next(ct);
        if(!ct)
        {
            callback(c_bvec, err, INVAL_DISK_BLK); 
            return;
        }
        /* If there is the next tree, try searching in it now */
        c_bvec->tree = ct;
        debug("Scheduling btree read in the next tree.\n");
        castle_btree_find(c_bvec);
        return;
    }
    debug("Finished with DA, calling back.\n");
    callback(c_bvec, err, cdb);
}

void castle_double_array_find(c_bvec_t *c_bvec)
{
    struct castle_attachment *att = c_bvec->c_bio->attachment;
    struct castle_double_array *da;
    da_id_t da_id; 

    /* da_endfind should be null it is for our privte use */
    BUG_ON(c_bvec->da_endfind);

    down_read(&att->lock);
    /* Since the version is attached, it must be found */
    BUG_ON(castle_version_read(att->version, &da_id, NULL, NULL, NULL));
    up_read(&att->lock);

    debug("Doing DA %s for da_id=%d, for version=%d\n", 
           c_bvec_data_dir(c_bvec) == READ ? "read" : "write",
           da_id, att->version);

    da = castle_da_hash_get(da_id);
    BUG_ON(!da);

    c_bvec->tree       = castle_da_rwct_get(da);
    c_bvec->da_endfind = c_bvec->endfind;
    c_bvec->endfind    = castle_da_bvec_complete;

    debug("Looking up in ct=%d\n", c_bvec->tree->seq); 
    
    castle_btree_find(c_bvec);
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
