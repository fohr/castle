#include <linux/sched.h>

#include "castle_public.h"
#include "castle_utils.h"
#include "castle.h"
#include "castle_cache.h"
#include "castle_btree.h"
#include "castle_versions.h"
#include "castle_freespace.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)  ((void)0)
#else
#define debug(_f, _a...)  (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

#define MAX_DA_LEVEL                    (10)

#define CASTLE_DA_HASH_SIZE             (1000)
#define CASTLE_CT_HASH_SIZE             (4000)
static struct list_head     *castle_da_hash;
static struct list_head     *castle_ct_hash;
static struct castle_mstore *castle_da_store      = NULL;
static struct castle_mstore *castle_tree_store    = NULL;
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
DEFINE_HASH_TBL(castle_ct, castle_ct_hash, CASTLE_CT_HASH_SIZE, struct castle_component_tree, hash_list, tree_seq_t, seq);

/**********************************************************************************************/
/* Iterators */

typedef struct castle_modlist_iterator {
    struct castle_component_tree *tree;
    struct castle_btree_type *btree;
    struct castle_enumerator *enumerator;
    int err;
    uint32_t nr_nodes;          /* Number of nodes in the buffer   */
    void *node_buffer;          /* Buffer to store all the nodes   */
    uint32_t nr_items;          /* Number of items in the buffer   */
    uint32_t next_item;         /* Next item to return in iterator */ 
    struct item_idx {
        uint32_t node;          /* Which node                      */
        uint32_t node_offset;   /* Where in the node               */
    } *sort_idx;
} c_modlist_iter_t;

static int castle_kv_compare(struct castle_btree_type *btree,
                             void *k1, version_t v1,
                             void *k2, version_t v2)
{
    int ret = btree->key_compare(k1, k2);
    if(ret != 0)
        return ret;
    
    /* Reverse v achieved by inverting v1<->v2 given to version_compare() function */
    return castle_version_compare(v2, v1);
}

static void castle_ct_modlist_iter_buffer_init(struct castle_btree_type *btree,
                                               struct castle_btree_node *buffer)
{
    /* Buffers are proper btree nodes understood by castle_btree_node_type function sets.
       Initialise the required bits of the node, so that the types don't complain. */
    buffer->magic   = BTREE_NODE_MAGIC;
    buffer->type    = btree->magic;
    buffer->version = 0;
    buffer->used    = 0;
    buffer->is_leaf = 1;
}

static struct castle_btree_node* castle_ct_modlist_iter_buffer_get(c_modlist_iter_t *iter, 
                                                                   uint32_t idx)
{
    struct castle_btree_type *btree = iter->btree;
    char *buffer = iter->node_buffer;

    return (struct castle_btree_node *)(buffer + idx * btree->node_size * C_BLK_SIZE); 
}

static void castle_ct_modlist_iter_fill(c_modlist_iter_t *iter)
{
    struct castle_btree_type *btree = iter->btree;
    struct castle_btree_node *node;
    uint32_t node_idx, node_offset, item_idx;
    version_t version;
    c_disk_blk_t cdb;
    void *key;

    item_idx = node_idx = node_offset = 0;
    while(castle_btree_enum_has_next(iter->enumerator))
    {
        /* Check if we moved on to a new node. If so, init that. */
        if(node_offset == 0)
        {
            node = castle_ct_modlist_iter_buffer_get(iter, node_idx);
            castle_ct_modlist_iter_buffer_init(btree, node);
        } else
        {
            BUG_ON(btree->need_split(node, 0)); 
        }

        /* Get the next entry from the comparator */
        castle_btree_enum_next(iter->enumerator, &key, &version, &cdb);
        debug("In enum got next: k=%p, version=%d, cdb=(0x%x, 0x%x)\n",
                key, version, cdb.disk, cdb.block);
        debug("Dereferencing first 4 bytes of the key (should be length)=0x%x.\n",
                *((uint32_t *)key));
        debug("Inserting into the node=%d, under idx=%d\n", node_idx, node_offset);
        btree->entry_add(node, node_offset, key, version, 1, cdb);
        iter->sort_idx[item_idx].node        = node_idx;
        iter->sort_idx[item_idx].node_offset = node_offset;
        node_offset++;
        item_idx++;
        /* Check if the node is full */
        if(btree->need_split(node, 0))
        {
            debug("Node %d full, moving to the next one.\n", node_idx);
            node_idx++; 
            node_offset = 0;
        }
    }
    BUG_ON(item_idx != atomic64_read(&iter->tree->item_count));
    iter->nr_items = item_idx;
    iter->err = iter->enumerator->err;
}

static void castle_ct_modlist_iter_item_get(c_modlist_iter_t *iter, 
                                            uint32_t sort_idx,
                                            void **key_p,
                                            version_t *version_p,
                                            c_disk_blk_t *cdb_p)
{
    struct castle_btree_type *btree = iter->btree;
    struct castle_btree_node *node;
   
    debug("Node_idx=%d, offset=%d\n", 
            iter->sort_idx[sort_idx].node,
            iter->sort_idx[sort_idx].node_offset);
    node = castle_ct_modlist_iter_buffer_get(iter, iter->sort_idx[sort_idx].node);
    btree->entry_get(node,
                     iter->sort_idx[sort_idx].node_offset,
                     key_p,
                     version_p,
                     NULL,
                     cdb_p);
}

static void castle_ct_modlist_iter_sift_down(c_modlist_iter_t *iter, uint32_t start, uint32_t end)
{
    struct castle_btree_type *btree = iter->btree;
    version_t root_version, child_version;
    void *root_key, *child_key;
    uint32_t root, child;
   
    root = start;
    /* Work out root key and version */
    castle_ct_modlist_iter_item_get(iter, root, &root_key, &root_version, NULL);
    while(2*root + 1 <= end)
    {
        /* First child MUST exist */
        child = 2*root + 1;
        castle_ct_modlist_iter_item_get(iter, child, &child_key, &child_version, NULL);
        /* Check if the second child is greater than the first (MAX heap). If exists */
        if(child < end)
        {
            version_t child2_version;
            void *child2_key;

            castle_ct_modlist_iter_item_get(iter, child+1, &child2_key, &child2_version, NULL);
            if(castle_kv_compare(btree,
                                 child2_key, child2_version, 
                                 child_key, child_version) > 0)
            {
                child++;
                /* Adjust pointers to point to child2 */
                child_key = child2_key;
                child_version = child2_version;
            } 
        }
        /* Finally check whether greater child isn't greatest than the root */
        if(castle_kv_compare(btree,
                             child_key, child_version,
                             root_key, root_version) > 0)
        {
            struct item_idx tmp_idx;
            
            /* Swap root and child, by swapping the respective sort_idx-es */
            tmp_idx = iter->sort_idx[child];
            iter->sort_idx[child] = iter->sort_idx[root];
            iter->sort_idx[root] = tmp_idx;
            /* Adjust root idx to point to the child, this should now be considered
               for sifting down. 
               NOTE: root_key & root_version are still correct. i.e.
               castle_ct_modlist_iter_item_get(root) would still return the same values.
               This is because we swapped the indicies. Also, in sifting you have to
               keep perculating the SAME value down until it is in the right place.
             */
            root = child;
        } else
            return;
    }
}

static void castle_ct_modlist_iter_heapify(c_modlist_iter_t *iter)
{
    uint32_t start = (iter->nr_items - 2)/2;

    while(true)
    {
        castle_ct_modlist_iter_sift_down(iter, start, iter->nr_items - 1);
        /* Check for start == 0 here, beacuse it's unsigned, and we cannot check
           for < 0 in the loop condition */
        if(start-- == 0)
            return;
    }
}

static void castle_ct_modlist_iter_heapsort(c_modlist_iter_t *iter)
{
    uint32_t last;

    for(last = iter->nr_items-1; last > 0; last--)
    {
        struct item_idx tmp_idx;

        /* Head is the greatest item, swap with last, and sift down */
        tmp_idx = iter->sort_idx[last];
        iter->sort_idx[last] = iter->sort_idx[0];
        iter->sort_idx[0] = tmp_idx;
        castle_ct_modlist_iter_sift_down(iter, 0, last-1); 
    }
}

static void castle_ct_modlist_iter_free(c_modlist_iter_t *iter)
{
    if(iter->enumerator)
        kfree(iter->enumerator);
    if(iter->node_buffer)
        vfree(iter->node_buffer);
    if(iter->sort_idx)
        vfree(iter->sort_idx);
}

static USED int castle_ct_modlist_iter_has_next(c_modlist_iter_t *iter)
{
    return (!iter->err && (iter->next_item < iter->nr_items));
}

static USED void castle_ct_modlist_iter_next(c_modlist_iter_t *iter, 
                                             void **key_p, 
                                             version_t *version_p, 
                                             c_disk_blk_t *cdb_p)
{
    castle_ct_modlist_iter_item_get(iter, iter->next_item, key_p, version_p, cdb_p);
    iter->next_item++;
}

static USED void castle_ct_modlist_iter_init(c_modlist_iter_t *iter)
{
    struct castle_component_tree *ct = iter->tree;

    BUG_ON(atomic64_read(&ct->item_count) == 0);
    /* Component tree has to be provided */
    BUG_ON(!iter->tree);
    iter->err = 0;
    iter->btree = castle_btree_type_get(iter->tree->btree_type);
    iter->enumerator = kmalloc(sizeof(struct castle_enumerator), GFP_KERNEL);
    /* Allocate slighly more than number of nodes in the tree, to make sure everything
       fits, even if we unlucky, and waste parts of the node in each node */
    iter->nr_nodes = 1.1 * (atomic64_read(&ct->node_count) + 1);
    iter->node_buffer = vmalloc(iter->nr_nodes * iter->btree->node_size * C_BLK_SIZE);
    iter->sort_idx = vmalloc(atomic64_read(&ct->item_count) * sizeof(struct item_idx));
    if(!iter->enumerator || !iter->node_buffer || !iter->sort_idx)
    {
        castle_ct_modlist_iter_free(iter);       
        iter->err = -ENOMEM;
        return;
    }
    /* Start up the child enumerator */
    iter->enumerator->tree = ct;
    castle_btree_enum_init(iter->enumerator); 
    iter->next_item = 0;
    /* Run the enumerator, sort the output. */
    castle_ct_modlist_iter_fill(iter);
    /* Fill may fail if the enumerator underneath fails */
    if(iter->err)
        return;
    castle_ct_modlist_iter_heapify(iter);
    castle_ct_modlist_iter_heapsort(iter);
}

typedef struct castle_merged_iterator {
    int nr_iters;
    struct castle_btree_type *btree;
    int err;
    int non_empty_cnt;
    struct component_iterator {
        int     completed;
        void   *iterator;
        int   (*has_next_fn) (void *iter);
        void  (*next_fn)     (void *iter, 
                              void **key_p, 
                              version_t *version_p, 
                              c_disk_blk_t *cdb_p);
        int     cached;
        struct {
            void         *k;
            version_t     v;
            c_disk_blk_t  cdb;
        } cached_entry;
    } *iterators;
} c_merged_iter_t;

static USED void castle_ct_merged_iter_next(c_merged_iter_t *iter,
                                            void **key_p,
                                            version_t *version_p,
                                            c_disk_blk_t *cdb_p)
{
    struct component_iterator *comp_iter; 
    int i, smallest_idx;
    void *smallest_k;
    version_t smallest_v;
    c_disk_blk_t smallest_cdb;

    debug("Merged iterator next.\n");
    /* When next is called, we are free to call next on any of the 
       component iterators we do not have an entry cached for */
    for(i=0, smallest_idx=-1; i<iter->nr_iters; i++)
    {
        comp_iter = iter->iterators + i; 

        /* Replenish the cache */
        if(!comp_iter->completed && !comp_iter->cached)
        {
            debug("Reading next entry for iterator: %d.\n", i);
            comp_iter->next_fn( comp_iter->iterator,
                               &comp_iter->cached_entry.k,
                               &comp_iter->cached_entry.v,
                               &comp_iter->cached_entry.cdb);
            comp_iter->cached = 1;
        }

        /* If there is no cached entry by here, the compenennt iterator must be finished */ 
        if(!comp_iter->cached)
        {
            BUG_ON(comp_iter->has_next_fn(comp_iter->iterator));
            continue;
        }

        /* Check how does the smallest entry so far compare to this entry */
        if((smallest_idx < 0) ||
           (castle_kv_compare(iter->btree,
                              comp_iter->cached_entry.k,
                              comp_iter->cached_entry.v,
                              smallest_k,
                              smallest_v) < 0))
        {
            debug("So far the smallest entry is from iterator: %d.\n", i);
            smallest_idx = i;
            smallest_k = comp_iter->cached_entry.k;
            smallest_v = comp_iter->cached_entry.v;
            smallest_cdb = comp_iter->cached_entry.cdb;
        }
    }

    /* Smallest value should have been found by now */
    BUG_ON(smallest_idx < 0);

    debug("Smallest entry is from iterator: %d.\n", smallest_idx);
    /* The cache for smallest_idx iterator cached entry should be removed */ 
    comp_iter = iter->iterators + smallest_idx;
    comp_iter->cached = 0;
    if(!comp_iter->has_next_fn(comp_iter->iterator))
    {
        debug("Iterator: %d run out of stuff, we don't have anything cached either.\n", 
                smallest_idx);
        comp_iter->completed = 1;
        iter->non_empty_cnt--;
    }

    /* Return the smallest entry */
    if(key_p) *key_p = smallest_k;
    if(version_p) *version_p = smallest_v;
    if(cdb_p) *cdb_p = smallest_cdb;
}

static USED int castle_ct_merged_iter_has_next(c_merged_iter_t *iter)
{
    debug("Merged iterator has next, err=%d, non_empty_cnt=%d\n", 
            iter->err, iter->non_empty_cnt);
    return (!iter->err && (iter->non_empty_cnt > 0));
}

/* Constructs a merged iterator out of a set of iterator, and has_next(), next() function
   pointers. Arguments are:
   iterator, iter1, iter1_has_next, iter1_next, iter2, ... */
static USED void castle_ct_merged_iter_init(c_merged_iter_t *iter, 
                                       ...)
{
    va_list vl;
    int i;

    debug("Initing merged iterator for %d component iterators.\n", iter->nr_iters);
    /* nr_iters should be given in the iterator, and we expecting it to be in [1,10] range */
    BUG_ON((iter->nr_iters <= 0) || (iter->nr_iters > 10));
    BUG_ON(!iter->btree);
    iter->err = 0;
    iter->iterators = kmalloc(iter->nr_iters * sizeof(struct component_iterator), GFP_KERNEL);
    if(!iter->iterators)
    {
        printk("Failed to allocate memory for merged iterator.\n");
        iter->err = -ENOMEM;
        return;
    }
    /* Memory allocated for the iterators array, save whatever was given to us */
    iter->non_empty_cnt = 0; 
    va_start(vl, iter);
    for(i=0; i<iter->nr_iters; i++)
    {
        struct component_iterator *comp_iter = iter->iterators + i; 

        comp_iter->iterator     = va_arg(vl, void *);
        comp_iter->has_next_fn  = va_arg(vl, void *); 
        comp_iter->next_fn      = va_arg(vl, void *); 
        comp_iter->cached       = 0;
        /* Check if the iterator has at least one entry, so that we know what
           non_empty_count to start with. Otherwise first has_next() could fail */
        if(comp_iter->has_next_fn(comp_iter->iterator)) 
        {
            debug("Iterator %d has next.\n", i);
            comp_iter->completed = 0;
            iter->non_empty_cnt++;
        }
        else
            comp_iter->completed = 1;
    } 

    va_end(vl);
}

#ifdef DEBUG
c_modlist_iter_t test_iter1;
c_modlist_iter_t test_iter2;
c_merged_iter_t  test_miter;
static void castle_ct_sort(struct castle_component_tree *ct1,
                           struct castle_component_tree *ct2)
{
    version_t version;
    void *key;
    c_disk_blk_t cdb;
    int i=0;

    debug("Number of items in the component tree1: %ld, number of nodes: %ld, ct2=%ld, %ld\n", 
            atomic64_read(&ct1->item_count),
            atomic64_read(&ct1->node_count),
            atomic64_read(&ct2->item_count),
            atomic64_read(&ct2->node_count));

    test_iter1.tree = ct1;
    castle_ct_modlist_iter_init(&test_iter1);
    test_iter2.tree = ct2;
    castle_ct_modlist_iter_init(&test_iter2);

#if 0
    while(castle_ct_modlist_iter_has_next(&test_iter))
    {
        castle_ct_modlist_iter_next(&test_iter, &key, &version, &cdb); 
        debug("Sorted: %d: k=%p, version=%d, cdb=(0x%x, 0x%x)\n",
                i, key, version, cdb.disk, cdb.block);
        debug("Dereferencing first 4 bytes of the key (should be length)=0x%x.\n",
                *((uint32_t *)key));
        i++;
    }
#endif
    test_miter.nr_iters = 2;
    test_miter.btree = test_iter1.btree;
    castle_ct_merged_iter_init(&test_miter,
                               &test_iter1, 
                               castle_ct_modlist_iter_has_next,
                               castle_ct_modlist_iter_next,
                               &test_iter2, 
                               castle_ct_modlist_iter_has_next,
                               castle_ct_modlist_iter_next);
    debug("=============== SORTED ================\n");
    while(castle_ct_merged_iter_has_next(&test_miter))
    {
        castle_ct_merged_iter_next(&test_miter, &key, &version, &cdb); 
        debug("Sorted: %d: k=%p, version=%d, cdb=(0x%x, 0x%x)\n",
                i, key, version, cdb.disk, cdb.block);
        debug("Dereferencing first 4 bytes of the key (should be length)=0x%x.\n",
                *((uint32_t *)key));
        i++;
    }
}
#endif


/**********************************************************************************************/
/* Generic DA code */

static int castle_da_ct_inc_cmp(struct list_head *l1, struct list_head *l2)
{
    struct castle_component_tree *ct1 = list_entry(l1, struct castle_component_tree, da_list);
    struct castle_component_tree *ct2 = list_entry(l2, struct castle_component_tree, da_list);

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

struct castle_component_tree* castle_component_tree_get(tree_seq_t seq)
{
    return castle_ct_hash_get(seq);
}

static struct castle_component_tree* castle_da_rwct_get(struct castle_double_array *da)
{
    struct list_head *h, *l;

    h = &da->trees[0]; 
    l = h->next; 
    /* There should be precisely one entry in the list */
    BUG_ON((h == l) || (l->next != h));
        
    return list_entry(l, struct castle_component_tree, da_list);
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
    ctm->last_node  = ct->last_node;
    ctm->node_count = atomic64_read(&ct->node_count);

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
    ct->last_node  = ctm->last_node;
    init_MUTEX(&ct->mutex);
    atomic64_set(&ct->node_count, ctm->node_count);
    ct->mstore_key = key;
    INIT_LIST_HEAD(&ct->da_list);
    INIT_LIST_HEAD(&ct->roots_list);

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
            ct = list_entry(lh, struct castle_component_tree, da_list); 
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
    list_del(&ct->da_list);
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

static void castle_ct_hash_destroy(void)
{
    kfree(castle_ct_hash);
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
    /* Do not write back if the fs hasn't been inited */
    if(!castle_tree_store || !castle_da_store)
        return;
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
            castle_ct_hash_add(&castle_global_tree);
            continue;
        }
        /* Otherwise allocate a ct structure */
        ct = kmalloc(sizeof(struct castle_component_tree), GFP_KERNEL);
        if(!ct)
            goto out_iter_destroy;
        da_id = castle_da_ct_unmarshall(ct, &mstore_centry, key);
        castle_ct_hash_add(ct);
        da = castle_da_hash_get(da_id);
        if(!da)
            goto out_iter_destroy;
        debug("Read CT seq=%d\n", ct->seq);
        list_add(&ct->da_list, &da->trees[ct->level]);
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
    struct castle_component_tree *ct, *old_ct;
    c2_block_t *c2b;
    int ret;
    c_disk_blk_t cdb;

    ct = kzalloc(sizeof(struct castle_component_tree), GFP_KERNEL); 
    if(!ct) 
        return -ENOMEM;
    
    /* TODO: work out locking for ALL of this! */

    /* Allocate an id for the tree, init the ct. */
    ct->seq         = castle_next_tree_seq++;
    atomic64_set(&ct->item_count, 0); 
    ct->btree_type  = VLBA_TREE_TYPE; 
    ct->da          = da->id;
    ct->level       = 0;
    ct->mstore_key  = INVAL_MSTORE_KEY; 
    INIT_LIST_HEAD(&ct->da_list);
    INIT_LIST_HEAD(&ct->roots_list);
    castle_ct_hash_add(ct);

    atomic64_set(&ct->node_count, 0); 
    init_MUTEX(&ct->mutex);
    /* Create a root node for this tree, and update the root version */
    c2b = castle_btree_node_create(da->root_version, 1 /* is_leaf */, VLBA_TREE_TYPE, ct);
    cdb = c2b->cdb;
    unlock_c2b(c2b);
    put_c2b(c2b);
    castle_version_lock(da->root_version);
    ret = castle_version_root_update(da->root_version, ct->seq, cdb);
    castle_version_unlock(da->root_version);
    if(ret)
    {
        /* TODO: free the block */
        printk("Could not write root node for version: %d\n", da->root_version);
        castle_ct_hash_remove(ct);
        kfree(ct);
        return ret;
    }
    debug("Added component tree seq=%d, root_node=(0x%x, 0x%x), it's threaded onto da=%p, level=%d\n",
            ct->seq, c2b->cdb.disk, c2b->cdb.block, da, ct->level);
    /* Move the last rwct (if one exists) to level 1 */
    if(!list_empty(&da->trees[0]))
    {
        old_ct = list_entry(da->trees[0].next, struct castle_component_tree, da_list);
        list_del(&old_ct->da_list);
        old_ct->level = 1;
        list_add(&old_ct->da_list, &da->trees[old_ct->level]);
    }
    /* Thread CT onto level 0 list */
    list_add(&ct->da_list, &da->trees[ct->level]);

    return 0;
}

int castle_double_array_make(da_id_t da_id, version_t root_version)
{
    struct castle_double_array *da;
    int ret, i;

    debug("Creating doubling array for da_id=%d, version=%d\n", da_id, root_version);
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
    debug("Successfully made a new doubling array, id=%d, for version=%d\n",
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
    for(level = ct->level, ct_list = &ct->da_list; 
        level < MAX_DA_LEVEL; 
        level++, ct_list = &da->trees[level])
    {
        if(!list_is_last(ct_list, &da->trees[level]))
        {
            next_ct = list_entry(ct_list->next, struct castle_component_tree, da_list); 
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
    struct castle_component_tree *ct;
    struct castle_double_array *da;
    da_id_t da_id; 

#ifdef DEBUG
    /* For test only */
    static int first_time = 1;
#endif

    down_read(&att->lock);
    /* Since the version is attached, it must be found */
    BUG_ON(castle_version_read(att->version, &da_id, NULL, NULL, NULL));
    up_read(&att->lock);

    da = castle_da_hash_get(da_id);
    BUG_ON(!da);

    /* da_endfind should be null it is for our privte use */
    BUG_ON(c_bvec->da_endfind);
#ifdef DEBUG
if((c_bvec_data_dir(c_bvec) == READ) && (first_time) && !list_empty(&da->trees[1]))
{
    struct castle_component_tree *ct1, *ct2;

    first_time = 0;
    ct1 = list_entry(da->trees[1].next, struct castle_component_tree, da_list);
    ct2 = list_entry(da->trees[1].next->next, struct castle_component_tree, da_list);
    castle_ct_sort(ct1, ct2);
}
#endif
    debug("Doing DA %s for da_id=%d, for version=%d\n", 
           c_bvec_data_dir(c_bvec) == READ ? "read" : "write",
           da_id, att->version);

    ct = castle_da_rwct_get(da);
#ifdef DEBUG
    if(atomic_read(&ct->item_count) > 1000)
    {
        struct castle_double_array *da = castle_da_hash_get(ct->da);  

        BUG_ON(!da);
        debug("Number of items in component tree: %d greater than 1000 (%ld). Adding a new rwct.\n",
                ct->seq, atomic64_read(&ct->item_count));
        castle_da_rwct_make(da);
    }
#endif

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

    /* Make sure that the global tree is in the ct hash */
    INIT_LIST_HEAD(&castle_global_tree.roots_list);
    castle_ct_hash_add(&castle_global_tree);

    return 0;
}
    
int castle_double_array_init(void)
{
    printk("\n========= Double Array init ==========\n");
    castle_da_hash = castle_da_hash_alloc();
    if(!castle_da_hash)
        return -ENOMEM;
    castle_ct_hash = castle_ct_hash_alloc();
    if(!castle_ct_hash)
    {
        kfree(castle_da_hash);
        return -ENOMEM; 
    }
    castle_da_hash_init();
    castle_ct_hash_init();

    return 0;
}

void castle_double_array_fini(void)
{
    printk("\n========= Double Array fini ==========\n");
    castle_da_hash_writeback();
    castle_da_hash_destroy();
    castle_ct_hash_destroy();
}
