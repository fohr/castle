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
#define debug(_f, ...)            ((void)0)
#define debug_verbose(_f, ...)    ((void)0)
#else
#define debug(_f, _a...)          (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#define debug_verbose(_f, ...)    ((void)0)
//#define debug_verbose(_f, _a...)  (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

#define MAX_DA_LEVEL                    (20)
#define MAX_DYNAMIC_TREE_SIZE           (10000)

#define CASTLE_DA_HASH_SIZE             (1000)
#define CASTLE_CT_HASH_SIZE             (4000)
static struct list_head        *castle_da_hash       = NULL;
static struct list_head        *castle_ct_hash       = NULL;
static struct castle_mstore    *castle_da_store      = NULL;
static struct castle_mstore    *castle_tree_store    = NULL;
       da_id_t                  castle_next_da_id    = 1; 
static tree_seq_t               castle_next_tree_seq = 1; 
static struct workqueue_struct *castle_merge_wq;


/**********************************************************************************************/
/* Notes about the locking on doubling arrays & component trees.
   Each doubling array has a spinlock which protects the lists of component trees rooted in
   the trees array.
   Each component tree has a reference count, initialised to 1 at the tree creation. Each IO
   and other operation which uses the tree needs to take a reference to the tree. Reference
   should be taken under doubling array lock (which guarantees that the component tree is
   currently threaded onto the doubling array tree list, and vice versa. When a tree is 
   removed from the doubling array, no-one else will take references to it any more.
   Component trees are destroyed when reference count reaches 0. The only operation which
   causes trees to be destroyed is the merge process. It decrements the reference count by 1,
   if there are any outstanding IOs, the ref count will reach 0 when last IO completes.
   When a new RW component tree (rwct) is created, previous rwct is moved onto level one. There
   may be ongoing writes to this component tree. This is safe, because all further reads to 
   the tree (either doubling array reads, or merge) chain lock the tree nodes appropriately.
   RW tree creation and merges are serialised using the flags field.
 */

#define DOUBLE_ARRAY_GROWING_RW_TREE_BIT    (0)
#define DOUBLE_ARRAY_GROWING_RW_TREE_FLAG   (1 << DOUBLE_ARRAY_GROWING_RW_TREE_BIT)
#define DOUBLE_ARRAY_MERGING_BIT            (1)
#define DOUBLE_ARRAY_MERGING_FLAG           (1 << DOUBLE_ARRAY_MERGING_BIT)
struct castle_double_array {
    da_id_t          id;
    version_t        root_version;
    /* Lock protects the trees list */
    spinlock_t       lock;
    unsigned long    flags;
    int              nr_trees;
    struct list_head trees[MAX_DA_LEVEL];
    struct list_head hash_list;
    c_mstore_key_t   mstore_key;
};

DEFINE_HASH_TBL(castle_da, castle_da_hash, CASTLE_DA_HASH_SIZE, struct castle_double_array, hash_list, da_id_t, id);
DEFINE_HASH_TBL(castle_ct, castle_ct_hash, CASTLE_CT_HASH_SIZE, struct castle_component_tree, hash_list, tree_seq_t, seq);

/**********************************************************************************************/
/* Prototypes */
static struct castle_component_tree* castle_ct_alloc(struct castle_double_array *da, 
                                                     int dynamic, 
                                                     int level);
static inline void castle_da_lock(struct castle_double_array *da);
static inline void castle_da_unlock(struct castle_double_array *da);
static inline void castle_ct_get(struct castle_component_tree *ct);
static inline void castle_ct_put(struct castle_component_tree *ct);
static void castle_component_tree_add(struct castle_double_array *da,
                                      struct castle_component_tree *ct,
                                      int in_init);
static void castle_da_merge_check(struct castle_double_array *da);
struct castle_da_merge;
static void castle_da_merge_budget_consume(struct castle_da_merge *merge);

/**********************************************************************************************/
/* Utils */

/* DA merging is checked/set under DA lock, simple bit test/sets suffice. */
static inline int castle_da_merging(struct castle_double_array *da)
{
    return test_bit(DOUBLE_ARRAY_MERGING_BIT, &da->flags);
}

static inline void castle_da_merging_set(struct castle_double_array *da)
{
    set_bit(DOUBLE_ARRAY_MERGING_BIT, &da->flags);
}

static inline void castle_da_merging_clear(struct castle_double_array *da)
{
    clear_bit(DOUBLE_ARRAY_MERGING_BIT, &da->flags);
}

/* These need to be atomic */
static inline int castle_da_growing_rw_test_and_set(struct castle_double_array *da)
{
    return test_and_set_bit(DOUBLE_ARRAY_GROWING_RW_TREE_BIT, &da->flags);
}

static inline void castle_da_growing_rw_clear(struct castle_double_array *da)
{
    clear_bit(DOUBLE_ARRAY_GROWING_RW_TREE_BIT, &da->flags);
}

/**********************************************************************************************/
/* Iterators */
typedef struct castle_immut_iterator {
    struct castle_component_tree *tree;
    struct castle_btree_type     *btree;
    int                           completed;
    c2_block_t                   *curr_c2b;
    struct castle_btree_node     *curr_node;
    int                           curr_idx;
    c2_block_t                   *next_c2b;
} c_immut_iter_t;

static void castle_ct_immut_iter_next_node_find(c_immut_iter_t *iter, c_disk_blk_t cdb)
{
    struct castle_btree_node *node;
    c2_block_t *c2b;
     
    debug("Looking for next node starting with (0x%x, 0x%x)\n", cdb.disk, cdb.block);
    BUG_ON(iter->next_c2b);
    c2b=NULL;
    while(!DISK_BLK_INVAL(cdb))
    {
        /* Release c2b if we've got one */
        if(c2b)
            put_c2b(c2b);
        /* Get cache block for the current c2b */
        c2b = castle_cache_block_get(cdb, iter->btree->node_size); 
        debug("Node in immut iter.\n");
        lock_c2b(c2b);
        /* If c2b is not up to date, issue a blocking READ to update */
        if(!c2b_uptodate(c2b))
            BUG_ON(submit_c2b_sync(READ, c2b));
        unlock_c2b(c2b);
        node = c2b_bnode(c2b);
        BUG_ON(node->used == 0);
        if(node->is_leaf)
        {
            debug("Cdb (0x%x, 0x%x) is leaf, exiting.\n", cdb.disk, cdb.block);
            /* Found */
            iter->next_c2b = c2b;
            return;
        }
        cdb = node->next_node;
        debug("Not a leaf node, moving to (0x%x, 0x%x).\n", cdb.disk, cdb.block);
    } 
    /* Drop c2b if we failed to find a leaf node, but have an outstanding reference to 
       a non-leaf node */
    if(c2b)
        put_c2b(c2b);
}

static void castle_ct_immut_iter_next_node(c_immut_iter_t *iter)
{
    BUG_ON(!iter->next_c2b);
    /* Drop the current c2b, if one exists. */
    if(iter->curr_c2b)
    {
        debug("Moving to the next block after: (0x%x, 0x%x)\n", 
                iter->curr_c2b->cdb.disk, iter->curr_c2b->cdb.block);
        put_c2b(iter->curr_c2b);
    }
    /* next_c2b becomes curr_c2b */ 
    iter->curr_c2b  = iter->next_c2b;
    BUG_ON(!c2b_uptodate(iter->curr_c2b));
    iter->curr_node = c2b_bnode(iter->curr_c2b); 
    BUG_ON(!iter->curr_node->is_leaf ||
           (iter->curr_node->used == 0));
    iter->curr_idx  = 0;
    debug("Moved to cdb=(0x%x, 0x%x)\n", 
            iter->curr_c2b->cdb.disk, 
            iter->curr_c2b->cdb.block); 

    /* Find next c2b following the list pointers */
    iter->next_c2b = NULL;
    castle_ct_immut_iter_next_node_find(iter, iter->curr_node->next_node);
}

static void castle_ct_immut_iter_next(c_immut_iter_t *iter, 
                                      void **key_p, 
                                      version_t *version_p, 
                                      c_val_tup_t *cvt_p)
{
    int is_leaf_ptr;

    /* Check if we can read from the curr_node. If not move to the next node. */
    if(iter->curr_idx >= iter->curr_node->used) 
    {
        debug("No more entries in the current node. Asking for next.\n");
        BUG_ON(iter->curr_idx > iter->curr_node->used);
        castle_ct_immut_iter_next_node(iter);
        BUG_ON(iter->curr_idx >= iter->curr_node->used);
    }
    iter->btree->entry_get(iter->curr_node, iter->curr_idx, key_p, version_p, &is_leaf_ptr, cvt_p);
    BUG_ON(is_leaf_ptr);
    iter->curr_idx++;
    debug("Returned next, curr_idx is now=%d / %d.\n", iter->curr_idx, iter->curr_node->used);
}

static int castle_ct_immut_iter_has_next(c_immut_iter_t *iter)
{
    if(unlikely(iter->completed))
        return 0;

    if((iter->curr_idx >= iter->curr_node->used) && (!iter->next_c2b))
    {
        iter->completed = 1;
        BUG_ON(!iter->curr_c2b);
        put_c2b(iter->curr_c2b);

        return 0;
    }

    return 1;
} 

static void castle_ct_immut_iter_init(c_immut_iter_t *iter)
{
    debug("Initialising immut enumerator for ct id=%d\n", iter->tree->seq);
    iter->btree     = castle_btree_type_get(iter->tree->btree_type);
    iter->completed = 0;
    iter->curr_c2b  = NULL;
    iter->next_c2b  = NULL;
    castle_ct_immut_iter_next_node_find(iter, iter->tree->first_node);
    /* Check if we succeeded at finding at least a single node */
    BUG_ON(!iter->next_c2b);
    /* Init curr_c2b correctly */
    castle_ct_immut_iter_next_node(iter);
}

struct castle_iterator_type castle_ct_immut_iter = {
    .has_next = (castle_iterator_has_next_t)castle_ct_immut_iter_has_next,
    .next     = (castle_iterator_next_t)    castle_ct_immut_iter_next,
    .skip     = NULL,
};

typedef struct castle_modlist_iterator {
    struct castle_btree_type *btree;
    struct castle_component_tree *tree;
    struct castle_da_merge *merge;
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

static void castle_da_node_buffer_init(struct castle_btree_type *btree,
                                       struct castle_btree_node *buffer)
{
    debug("Resetting btree node buffer.\n");
    /* Buffers are proper btree nodes understood by castle_btree_node_type function sets.
       Initialise the required bits of the node, so that the types don't complain. */
    buffer->magic     = BTREE_NODE_MAGIC;
    buffer->type      = btree->magic;
    buffer->version   = 0;
    buffer->used      = 0;
    buffer->is_leaf   = 1;
    buffer->next_node = INVAL_DISK_BLK;
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
    c_val_tup_t cvt;
    void *key;

    item_idx = node_idx = node_offset = 0;
    while(castle_btree_enum.has_next(iter->enumerator))
    {
        if(iter->merge)
            castle_da_merge_budget_consume(iter->merge);
        /* Check if we moved on to a new node. If so, init that. */
        if(node_offset == 0)
        {
            node = castle_ct_modlist_iter_buffer_get(iter, node_idx);
            castle_da_node_buffer_init(btree, node);
        } else
        {
            BUG_ON(btree->need_split(node, 0)); 
        }

        /* Get the next entry from the comparator */
        castle_btree_enum.next(iter->enumerator, &key, &version, &cvt);
        debug("In enum got next: k=%p, version=%d, cdb=(0x%x, 0x%x)\n",
                key, version, cvt.cdb.disk, cvt.cdb.block);
        debug("Dereferencing first 4 bytes of the key (should be length)=0x%x.\n",
                *((uint32_t *)key));
        debug("Inserting into the node=%d, under idx=%d\n", node_idx, node_offset);
        btree->entry_add(node, node_offset, key, version, 1, cvt);
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
    if(item_idx != atomic64_read(&iter->tree->item_count))
    {
        printk("Error. Different number of items than expected. item_idx=%d, item_count=%ld\n",
            item_idx, atomic64_read(&iter->tree->item_count));
        BUG();
    }
    iter->nr_items = item_idx;
    iter->err = iter->enumerator->err;
}

static void castle_ct_modlist_iter_item_get(c_modlist_iter_t *iter, 
                                            uint32_t sort_idx,
                                            void **key_p,
                                            version_t *version_p,
                                            c_val_tup_t *cvt_p)
{
    struct castle_btree_type *btree = iter->btree;
    struct castle_btree_node *node;
   
    debug_verbose("Node_idx=%d, offset=%d\n", 
                  iter->sort_idx[sort_idx].node,
                  iter->sort_idx[sort_idx].node_offset);
    node = castle_ct_modlist_iter_buffer_get(iter, iter->sort_idx[sort_idx].node);
    btree->entry_get(node,
                     iter->sort_idx[sort_idx].node_offset,
                     key_p,
                     version_p,
                     NULL,
                     cvt_p);
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
        if(iter->merge)
            castle_da_merge_budget_consume(iter->merge);
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

        if(iter->merge)
            castle_da_merge_budget_consume(iter->merge);
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

static int castle_ct_modlist_iter_has_next(c_modlist_iter_t *iter)
{
    return (!iter->err && (iter->next_item < iter->nr_items));
}

static void castle_ct_modlist_iter_next(c_modlist_iter_t *iter, 
                                        void **key_p, 
                                        version_t *version_p, 
                                        c_val_tup_t *cvt_p)
{
    castle_ct_modlist_iter_item_get(iter, iter->next_item, key_p, version_p, cvt_p);
    iter->next_item++;
}

static void castle_ct_modlist_iter_init(c_modlist_iter_t *iter)
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

struct castle_iterator_type castle_ct_modlist_iter = {
    .has_next = (castle_iterator_has_next_t)castle_ct_modlist_iter_has_next,
    .next     = (castle_iterator_next_t)    castle_ct_modlist_iter_next,
    .skip     = NULL,
};

static inline void castle_ct_merged_iter_has_next_check(c_merged_iter_t *iter,
                                                        struct component_iterator *comp_iter)
{
    /* Should not be called if we've got something cached, or the iterator has completed */
    BUG_ON(comp_iter->cached || comp_iter->completed);
    /* If the iterator doesn't have more items, set it completed, and decrement non_empty_cnt. */ 
    if(!comp_iter->iterator_type->has_next(comp_iter->iterator))
    {
        comp_iter->completed = 1;
        iter->non_empty_cnt--;
        debug("A component iterator run out of stuff, we are left with %d iterators.\n",
                iter->non_empty_cnt);
    }
}

static void castle_ct_merged_iter_consume(c_merged_iter_t *iter,
                                          struct component_iterator *comp_iter)
{
    BUG_ON(!comp_iter->cached);
    /* This will effectively consume the cached entry */
    comp_iter->cached = 0;
    castle_ct_merged_iter_has_next_check(iter, comp_iter);
}

static void castle_ct_merged_iter_next(c_merged_iter_t *iter,
                                       void **key_p,
                                       version_t *version_p,
                                       c_val_tup_t *cvt_p)
{
    struct component_iterator *comp_iter; 
    int i, smallest_idx, kv_cmp;
    void *smallest_k;
    version_t smallest_v;
    c_val_tup_t smallest_cvt;

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
            comp_iter->iterator_type->next( comp_iter->iterator,
                                           &comp_iter->cached_entry.k,
                                           &comp_iter->cached_entry.v,
                                           &comp_iter->cached_entry.cvt);
            comp_iter->cached = 1;
        }

        /* If there is no cached entry by here, the compenennt iterator must be finished */ 
        if(!comp_iter->cached)
        {
            BUG_ON(comp_iter->iterator_type->has_next(comp_iter->iterator));
            continue;
        }

        /* Check how does the smallest entry so far compare to this entry */
        kv_cmp = (smallest_idx >= 0) ? castle_kv_compare(iter->btree,
                                                         comp_iter->cached_entry.k,
                                                         comp_iter->cached_entry.v,
                                                         smallest_k,
                                                         smallest_v)
                                     : -1;
        if(kv_cmp < 0)
        {
            debug("So far the smallest entry is from iterator: %d.\n", i);
            smallest_idx = i;
            smallest_k = comp_iter->cached_entry.k;
            smallest_v = comp_iter->cached_entry.v;
            smallest_cvt = comp_iter->cached_entry.cvt;
        }

        if(kv_cmp == 0)
        {
            debug("Duplicate entry found. Removing.\n");
            castle_ct_merged_iter_consume(iter, comp_iter);
        }
    }

    /* Smallest value should have been found by now */
    BUG_ON(smallest_idx < 0);

    debug("Smallest entry is from iterator: %d.\n", smallest_idx);
    /* The cache for smallest_idx iterator cached entry should be removed */ 
    comp_iter = iter->iterators + smallest_idx;
    castle_ct_merged_iter_consume(iter, comp_iter);
    /* Return the smallest entry */
    if(key_p) *key_p = smallest_k;
    if(version_p) *version_p = smallest_v;
    if(cvt_p) *cvt_p = smallest_cvt;
}

static int castle_ct_merged_iter_has_next(c_merged_iter_t *iter)
{
    debug("Merged iterator has next, err=%d, non_empty_cnt=%d\n", 
            iter->err, iter->non_empty_cnt);
    return (!iter->err && (iter->non_empty_cnt > 0));
}

static void castle_ct_merged_iter_skip(c_merged_iter_t *iter,
                                       void *key)
{
    struct component_iterator *comp_iter; 
    int i, skip_cached;

    /* Go through iterators, and do the following:
       * call skip in each of the iterators
       * check if we have something cached
       * if we do, and the cached k < key, flush it
     */
    for(i=0; i<iter->nr_iters; i++)
    {
        comp_iter = iter->iterators + i; 
        if(comp_iter->completed)
            continue;

        /* Check if the cached entry needs to be skipped AHEAD of the skip
           being called on the appropriate component iterator (which may 
           invalidate the cached key pointer */
        skip_cached = comp_iter->cached && 
                     (iter->btree->key_compare(comp_iter->cached_entry.k, key) < 0);
        /* Next skip in the component iterator */
        BUG_ON(!comp_iter->iterator_type->skip);
        comp_iter->iterator_type->skip(comp_iter->iterator, key);

        /* Flush cached entry if it was to small (this doesn't inspect the cached entry
           any more). */
        if(skip_cached)
            castle_ct_merged_iter_consume(iter, comp_iter);
        else
        /* Otherwise, if we don't have anything cached, check if the iterator still
           has something to return (this may have changed after the skip */
        if(!comp_iter->cached)
            castle_ct_merged_iter_has_next_check(iter, comp_iter);
    }
}

static void castle_ct_merged_iter_cancel(c_merged_iter_t *iter)
{
    kfree(iter->iterators);
}

/* Constructs a merged iterator out of a set of iterators. */
static void castle_ct_merged_iter_init(c_merged_iter_t *iter,
                                       void **iterators,
                                       struct castle_iterator_type **iterator_types)
{
    int i;

    debug("Initing merged iterator for %d component iterators.\n", iter->nr_iters);
    /* nr_iters should be given in the iterator, and we expecting it to be in [1,10] range */
    if(iter->nr_iters > 10)
        printk("Merged iterator for %d > 10 trees.\n", iter->nr_iters);
    BUG_ON(iter->nr_iters <= 0);
    BUG_ON(!iter->btree);
    iter->err = 0;
    iter->iterators = kmalloc(iter->nr_iters * sizeof(struct component_iterator), GFP_KERNEL);
    if(!iter->iterators)
    {
        printk("Failed to allocate memory for merged iterator.\n");
        iter->err = -ENOMEM;
        return;
    }
    /* Memory allocated for the iterators array, init the state. 
       Assume that all iterators have something in them, and let the has_next_check() 
       handle the opposite. */
    iter->non_empty_cnt = iter->nr_iters; 
    for(i=0; i<iter->nr_iters; i++)
    {
        struct component_iterator *comp_iter = iter->iterators + i; 

        comp_iter->iterator      = iterators[i];
        comp_iter->iterator_type = iterator_types[i];
        comp_iter->cached        = 0;
        comp_iter->completed     = 0;

        castle_ct_merged_iter_has_next_check(iter, comp_iter);
    } 
}

struct castle_iterator_type castle_ct_merged_iter = {
    .has_next = (castle_iterator_has_next_t)castle_ct_merged_iter_has_next,
    .next     = (castle_iterator_next_t)    castle_ct_merged_iter_next,
    .skip     = (castle_iterator_skip_t)    castle_ct_merged_iter_skip, 
    .cancel   = (castle_iterator_cancel_t)  castle_ct_merged_iter_cancel, 
};


#ifdef DEBUG
c_modlist_iter_t test_iter1;
c_modlist_iter_t test_iter2;
c_merged_iter_t  test_miter;
static USED void castle_ct_sort(struct castle_component_tree *ct1,
                                struct castle_component_tree *ct2)
{
    version_t version;
    void *key;
    c_val_tup_t cvt;
    int i=0;
    void *iters[2];
    struct castle_iterator_type *iter_types[2];

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
    iters[0] = &test_iter1;
    iters[1] = &test_iter2;
    iter_types[0] = &castle_ct_modlist_iter;
    iter_types[1] = &castle_ct_modlist_iter;
    castle_ct_merged_iter_init(&test_miter,
                               iters,
                               iter_types);
    debug("=============== SORTED ================\n");
    while(castle_ct_merged_iter_has_next(&test_miter))
    {
        castle_ct_merged_iter_next(&test_miter, &key, &version, &cvt); 
        debug("Sorted: %d: k=%p, version=%d, cdb=(0x%x, 0x%x)\n",
                i, key, version, cvt.cdb.disk, cvt.cdb.block);
        debug("Dereferencing first 4 bytes of the key (should be length)=0x%x.\n",
                *((uint32_t *)key));
        i++;
    }
}
#endif

/* Has next, next and skip only need to call the corresponding functions on
   the underlying merged iterator */
static int castle_da_rq_iter_has_next(c_da_rq_iter_t *iter)
{
    return castle_ct_merged_iter_has_next(&iter->merged_iter);
} 

static void castle_da_rq_iter_next(c_da_rq_iter_t *iter,
                                   void **key_p,
                                   version_t *version_p,
                                   c_val_tup_t *cvt_p)
{
    castle_ct_merged_iter_next(&iter->merged_iter, key_p, version_p, cvt_p);
}

static void castle_da_rq_iter_skip(c_da_rq_iter_t *iter, void *key)
{
    castle_ct_merged_iter_skip(&iter->merged_iter, key);
}

void castle_da_rq_iter_cancel(c_da_rq_iter_t *iter)
{
    int i;

    castle_ct_merged_iter_cancel(&iter->merged_iter);
    for(i=0; i<iter->nr_cts; i++)
    {
        struct ct_rq *ct_rq = iter->ct_rqs + i;
        castle_btree_rq_enum_cancel(&ct_rq->ct_rq_iter);
    }
    kfree(iter->ct_rqs);
}

void castle_da_rq_iter_init(c_da_rq_iter_t *iter,
                            version_t version,
                            da_id_t da_id,
                            void *start_key,
                            void *end_key)
{
    void **iters;
    struct castle_iterator_type **iter_types;
    struct castle_double_array *da;
    struct list_head *l;
    int i, j;

    da = castle_da_hash_get(da_id);
    BUG_ON(!da);
    BUG_ON(!castle_version_is_ancestor(da->root_version, version));
    iter->btree = NULL;
again:
    /* Try to allocate the right amount of memory, but remember that nr_trees
       may change, because we are not holding the da lock (cannot kmalloc holding
       a spinlock). */
    iter->nr_cts = da->nr_trees;
    iter->err    = 0;
    iter->ct_rqs = kzalloc(iter->nr_cts * sizeof(struct ct_rq), GFP_KERNEL);
    iters        = kmalloc(iter->nr_cts * sizeof(void *), GFP_KERNEL);
    iter_types   = kmalloc(iter->nr_cts * sizeof(struct castle_iterator_type *), GFP_KERNEL);
    if(!iter->ct_rqs || !iters || !iter_types)
    {
        iter->err = -ENOMEM;
        return;
    }

    castle_da_lock(da);
    /* Check the number of trees under lock. Retry again if # changed. */ 
    if(iter->nr_cts != da->nr_trees)
    {
        castle_da_unlock(da);
        printk("Warning. Untested path. # of cts changed while allocating memory for rq.\n");
        kfree(iter->ct_rqs);
        kfree(iters);
        kfree(iter_types);
        goto again;
    }
    /* Get refs to all the component trees, and release the lock */
    j=0;
    for(i=0; i<MAX_DA_LEVEL; i++)
    {
        list_for_each(l, &da->trees[i])
        {
            struct castle_component_tree *ct;

            BUG_ON(j >= iter->nr_cts);
            ct = list_entry(l, struct castle_component_tree, da_list);
            iter->ct_rqs[j].ct = ct; 
            castle_ct_get(ct);
            if(!iter->btree)
                iter->btree = castle_btree_type_get(ct->btree_type);
            BUG_ON(iter->btree->magic != ct->btree_type);
            j++;
        }
    }
    castle_da_unlock(da);
    BUG_ON(j != iter->nr_cts);

    /* Initialise range queries for individual cts */
    /* TODO: Better to re-organize the code, such that these iterators belong to
     * merged iterator. Easy to manage resources - Talk to Gregor */
    for(i=0; i<iter->nr_cts; i++)
    {
        struct ct_rq *ct_rq = iter->ct_rqs + i;

        castle_btree_rq_enum_init(&ct_rq->ct_rq_iter,
                                   version,
                                   ct_rq->ct,
                                   start_key,
                                   end_key);
        /* TODO: handle errors! Don't know how to destroy ct_rq_iter ATM. */
        BUG_ON(ct_rq->ct_rq_iter.err);
        iters[i]        = &ct_rq->ct_rq_iter;
        iter_types[i]   = &castle_btree_rq_iter;
    }

    /* Iterators have been initialised, now initialise the merged iterator */
    iter->merged_iter.nr_iters = iter->nr_cts;
    iter->merged_iter.btree    = iter->btree;
    castle_ct_merged_iter_init(&iter->merged_iter,
                                iters,
                                iter_types);
    kfree(iters);
    kfree(iter_types);
}

struct castle_iterator_type castle_da_rq_iter = {
    .has_next = (castle_iterator_has_next_t)castle_da_rq_iter_has_next,
    .next     = (castle_iterator_next_t)    castle_da_rq_iter_next,
    .skip     = (castle_iterator_skip_t)    castle_da_rq_iter_skip, 
    .cancel   = (castle_iterator_cancel_t)  castle_da_rq_iter_cancel, 
};

/**********************************************************************************************/
/* Merges */
struct castle_da_merge {
    struct castle_double_array   *da;
    struct castle_btree_type     *btree;
    struct castle_component_tree *in_tree1;
    struct castle_component_tree *in_tree2;
    void                         *iter1;
    void                         *iter2;
    c_merged_iter_t              *merged_iter;
    int                           root_depth;
    c2_block_t                   *last_node_c2b;
    c_disk_blk_t                  first_node;
    int                           completing;
    uint64_t                      nr_entries;
    uint64_t                      nr_nodes;
    struct castle_da_merge_level {
        /* Node we are currently generating, and book-keeping variables about the node. */
        c2_block_t               *node_c2b;
        void                     *last_key;
        int                       next_idx;
        int                       valid_end_idx;
        version_t                 valid_version;
        /* Buffer node used when completing a node (will contain spill-over entries). */
        struct castle_btree_node *buffer;
    } levels[MAX_BTREE_DEPTH];

    /* Deamortization variables */
    struct work_struct            work;
    int                           budget_cons_rate;
    int                           budget_cons_units;
};

/************************************/
/* Marge rate control functionality */
static DEFINE_SPINLOCK(merge_budget_lock);
static DECLARE_WAIT_QUEUE_HEAD(merge_budget_wq); 
static int merge_budget = 0;

static void castle_da_merge_budget_consume(struct castle_da_merge *merge)
{
    unsigned long flags;

    /* Check if we need to consume some merge budget */
    merge->budget_cons_units++;
    if(merge->budget_cons_units < merge->budget_cons_rate)
        return;

try_again:
    /* We need to consume a single unit from the budget, check if there is something there */
    spin_lock_irqsave(&merge_budget_lock, flags);
    if(merge_budget > 0)
    {
        merge_budget--;
        spin_unlock_irqrestore(&merge_budget_lock, flags);
        return;
    }
    spin_unlock_irqrestore(&merge_budget_lock, flags);
    /* We haven't found anything, sleep until next replenish. */
    printk("Run out of merge budget, waiting.\n");
    wait_event(merge_budget_wq, (merge_budget > 0));

    goto try_again;
}

static atomic_t epoch_ios = ATOMIC_INIT(0); 
static void castle_da_merge_budget_replenish(void)
{
#define MAX_IOS             (10000) /* Arbitrary constants */
#define MIN_BUDGET_DELTA    (500)
#define MAX_BUDGET          (1000000)
    int ios = atomic_read(&epoch_ios);
    int budget_delta = 0;

    atomic_set(&epoch_ios, 0);
    debug("Merge replenish, number of ios in last second=%d.\n", ios);
    if(ios < MAX_IOS) 
        budget_delta = MAX_IOS - ios;
    if(budget_delta < MIN_BUDGET_DELTA)
        budget_delta = MIN_BUDGET_DELTA;
    BUG_ON(budget_delta <= 0);
    spin_lock_irq(&merge_budget_lock);
    merge_budget += budget_delta;
    if(merge_budget > MAX_BUDGET)
        merge_budget = MAX_BUDGET;
    spin_unlock_irq(&merge_budget_lock);
    wake_up(&merge_budget_wq);
}

static inline void castle_da_merge_budget_io_end(struct castle_double_array *da)
{
    atomic_inc(&epoch_ios);
}

/************************************/
/* Marge rate timers */
static struct timer_list merge_rate_timer; 
static void castle_da_merge_budget_add(unsigned long first)
{
    unsigned long sleep = 1; /* In seconds */

    castle_da_merge_budget_replenish();
    /* Reschedule ourselves */
    setup_timer(&merge_rate_timer, castle_da_merge_budget_add, 0);
    mod_timer(&merge_rate_timer, jiffies + sleep * HZ);
}

/************************************/
/* Actual merges */
static void castle_da_iterator_destroy(struct castle_component_tree *tree,
                                       void *iter)
{
    if(!iter)
        return;
    /* TODO: this needs to be handled properly. */
    if(tree->dynamic)
    {
        BUG();
    } else
    {
        BUG();
    }
    kfree(iter);
}

static void castle_da_iterator_create(struct castle_da_merge *merge,
                                      struct castle_component_tree *tree,
                                      void **iter_p)
{
    if(tree->dynamic)
    {
        c_modlist_iter_t *iter = kmalloc(sizeof(c_modlist_iter_t), GFP_KERNEL);
        if(!iter)
            return;
        iter->tree = tree;
        iter->merge = merge; 
        castle_ct_modlist_iter_init(iter);
        if(iter->err)
        {
            castle_da_iterator_destroy(tree, iter);
            return;
        }
        /* Success */
        *iter_p = iter; 
    } else
    {
        c_immut_iter_t *iter = kmalloc(sizeof(c_immut_iter_t), GFP_KERNEL);
        if(!iter)
            return;
        iter->tree = tree;
        castle_ct_immut_iter_init(iter);
        /* TODO: after init errors? */
        *iter_p = iter;
    }
}
        
static struct castle_iterator_type* castle_da_iter_type_get(struct castle_component_tree *ct)
{
    if(ct->dynamic)
        return &castle_ct_modlist_iter;
    else
        return &castle_ct_immut_iter;
}

static int castle_da_iterators_create(struct castle_da_merge *merge)
{
    struct castle_btree_type *btree;
    int ret;
    void *iters[2];
    struct castle_iterator_type *iter_types[2];

    printk("Creating iterators for the merge.\n");
    BUG_ON( merge->iter1    ||  merge->iter2);
    BUG_ON(!merge->in_tree1 || !merge->in_tree2);
    btree = castle_btree_type_get(merge->in_tree1->btree_type);

    /* Create apprapriate iterators for both of the trees. */
    castle_da_iterator_create(merge, merge->in_tree1, &merge->iter1);
    castle_da_iterator_create(merge, merge->in_tree2, &merge->iter2);
    debug("Tree iterators created.\n");
    
    /* Check if the iterators got created properly. */
    ret = -EINVAL;
    if(!merge->iter1 || !merge->iter2)
        goto err_out;

    /* Init the merged iterator */
    ret = -ENOMEM;
    merge->merged_iter = kmalloc(sizeof(c_merged_iter_t), GFP_KERNEL);
    if(!merge->merged_iter)
        goto err_out;
    debug("Merged iterator allocated.\n");

    merge->merged_iter->nr_iters = 2;
    merge->merged_iter->btree    = btree;
    iters[0] = merge->iter1;
    iters[1] = merge->iter2;
    iter_types[0] = castle_da_iter_type_get(merge->in_tree1); 
    iter_types[1] = castle_da_iter_type_get(merge->in_tree2); 
    castle_ct_merged_iter_init(merge->merged_iter,
                               iters,
                               iter_types);
    ret = merge->merged_iter->err;
    debug("Merged iterator inited with ret=%d.\n", ret);
    if(ret)
        goto err_out;
    
    /* Success */
    return 0;

err_out:
    debug("Failed to create iterators. Ret=%d\n", ret);
    castle_da_iterator_destroy(merge->in_tree1, merge->iter1);
    castle_da_iterator_destroy(merge->in_tree2, merge->iter2);
    if(merge->merged_iter)
        /* TODO: this should call a destructor, rather than just free */
        kfree(merge->merged_iter);

    BUG_ON(!ret);
    return ret;
}

static inline void castle_da_entry_add(struct castle_da_merge *merge, 
                                       int depth,
                                       void *key, 
                                       version_t version, 
                                       c_val_tup_t cvt)
{
    struct castle_da_merge_level *level = merge->levels + depth;
    struct castle_btree_type *btree = merge->btree;
    struct castle_btree_node *node;
    int key_cmp;

    debug("Adding an entry at depth: %d\n", depth);
    BUG_ON(depth >= MAX_BTREE_DEPTH);
    /* Alloc a new block if we need one */
    if(!level->node_c2b)
    {
        c_disk_blk_t cdb;
        
        if(merge->root_depth < depth)
        {
            debug("Creating a new root level: %d\n", depth);
            BUG_ON(merge->root_depth != depth - 1);
            merge->root_depth = depth; 
        }
        BUG_ON(level->next_idx      != 0);
        BUG_ON(level->valid_end_idx >= 0);
        debug("Allocating a new node at depth: %d\n", depth);

        cdb = castle_freespace_block_get(0, btree->node_size);
        debug("Got (0x%x, 0x%x)\n", cdb.disk, cdb.block);

        level->node_c2b = castle_cache_block_get(cdb, btree->node_size);
        debug("Locking the c2b, and setting it up to date.\n");
        lock_c2b(level->node_c2b);
        set_c2b_uptodate(level->node_c2b);
        /* Init the node properly */
        node = c2b_bnode(level->node_c2b);
        castle_da_node_buffer_init(btree, node);
    }

    node = c2b_bnode(level->node_c2b);
    debug("Adding an idx=%d, key=%p, *key=%d, version=%d\n", 
            level->next_idx, key, *((uint32_t *)key), version);
    /* Add the entry to the node (this may get dropped later, but leave it here for now */
    btree->entry_add(node, level->next_idx, key, version, 0, cvt);
    /* Compare the current key to the last key. Should never be smaller */
    key_cmp = (level->next_idx != 0) ? btree->key_compare(key, level->last_key) : 0;
    debug("Key cmp=%d\n", key_cmp);
    BUG_ON(key_cmp < 0);

    /* Work out if the current/previous entry could be a valid node end.
       Case 1: We've just started a new node (node_idx == 0) => current must be a valid node entry */
    if(level->next_idx == 0)
    {
        debug("Node valid_end_idx=%d, Case1.\n", level->next_idx);
        BUG_ON(level->valid_end_idx >= 0);
        /* Save last_key, version as a valid_version, and init valid_end_idx.
           Note: last_key has to be taken from the node, bacuse current key pointer
                 may get invalidated on the iterator next() call. 
         */
        level->valid_end_idx = 0;
        btree->entry_get(node, level->next_idx, &level->last_key, NULL, NULL, NULL);
        level->valid_version = version;
    } else
    /* Case 2: We've moved on to a new key. Previous entry is a valid node end. */
    if(key_cmp > 0)
    {
        debug("Node valid_end_idx=%d, Case2.\n", level->next_idx);
        btree->entry_get(node, level->next_idx, &level->last_key, NULL, NULL, NULL);
        level->valid_end_idx = level->next_idx;
        level->valid_version = 0;
    } else
    /* Case 3: Version is STRONGLY ancestoral to valid_version. */
    if(castle_version_is_ancestor(version, level->valid_version))
    {
        debug("Node valid_end_idx=%d, Case3.\n", level->next_idx);
        BUG_ON(version == level->valid_version);
        level->valid_end_idx = level->next_idx;
        level->valid_version = version;
    }

    /* Node may be (over-)complete now, if it is full. Set next_idx to -1 (invalid) */
    if(btree->need_split(node, 0))
    {
        debug("Node now complete.\n");
        level->next_idx = -1;
    }
    else
        /* Go to the next node_idx */
        level->next_idx++;
}
            
static void castle_da_node_complete(struct castle_da_merge *merge, int depth)
{
    struct castle_da_merge_level *level = merge->levels + depth;
    struct castle_btree_type *btree = merge->btree;
    struct castle_btree_node *node, *prev_node, *buffer;
    int buffer_idx, node_idx;
    void *key;
    version_t version;
    int leaf_ptr;
    c_val_tup_t cvt, node_cvt;

    debug("Completing node at depth=%d\n", depth);
    BUG_ON(depth >= MAX_BTREE_DEPTH);
    node      = c2b_bnode(level->node_c2b);
    BUG_ON(!node);
    buffer  = level->buffer;
    /* Version of the node should be the last valid_version */
    debug("Node version=%d\n", level->valid_version);
    node->version = level->valid_version;
    if(depth > 0)
        node->is_leaf = 0;
    /* When a node is complete, we need to copy the entires after valid_end_idx to 
       the corresponding buffer */
    BUG_ON(buffer->used != 0);
    buffer_idx = 0;
    node_idx = level->valid_end_idx + 1;
    BUG_ON(node_idx <= 0 || node_idx > node->used);
    debug("Entries to be copied to the buffer are in range [%d, %d)\n",
            node_idx, node->used);
    while(node_idx < node->used) 
    {
        BUG_ON(buffer->used != buffer_idx);
        btree->entry_get(node,   node_idx,  &key, &version, &leaf_ptr, &cvt);
        BUG_ON(leaf_ptr);
        btree->entry_add(buffer, buffer_idx, key, version, 0, cvt);
        buffer_idx++;
        node_idx++;
    }
    debug("Dropping entries [%d, %d] from the original node\n",
            level->valid_end_idx + 1, node->used - 1);
    /* Now that entries are safely in the buffer, drop them from the node */ 
    if((level->valid_end_idx + 1) <= (node->used - 1))
        btree->entries_drop(node, level->valid_end_idx + 1, node->used - 1);

    BUG_ON(node->used != level->valid_end_idx + 1);
    btree->entry_get(node, level->valid_end_idx, &key, &version, &leaf_ptr, &cvt);
    debug("Inserting into parent key=%p, *key=%d, version=%d, buffer->used=%d\n",
            key, *((uint32_t*)key), node->version, buffer->used);
    BUG_ON(leaf_ptr);
 
    /* Insert correct pointer in the parent, unless we've just completed the
       root node at the end of the merge. */ 
    if(merge->completing && (merge->root_depth == depth) && (buffer->used == 0)) 
    {
        debug("Just completed the root node (depth=%d), at the end of the merge.\n",
                depth);
        goto release_node;
    }
    CDB_TO_CVT(node_cvt, level->node_c2b->cdb, level->node_c2b->nr_pages);
    castle_da_entry_add(merge, depth+1, key, node->version, node_cvt);
release_node:
    debug("Releasing c2b for cdb=(0x%x, 0x%x)\n", 
            level->node_c2b->cdb.disk,
            level->node_c2b->cdb.block);
    /* Write the list pointer into the previous node we've completed (if one exists).
       Then release it. */
    prev_node = merge->last_node_c2b ? c2b_bnode(merge->last_node_c2b) : NULL; 
    if(prev_node)
    {
        prev_node->next_node = level->node_c2b->cdb;
        dirty_c2b(merge->last_node_c2b);
        unlock_c2b(merge->last_node_c2b);
        put_c2b(merge->last_node_c2b);
    } else
    {
        /* We've just created the first node, save it */
        merge->first_node = level->node_c2b->cdb;
    }
    /* Save this node as the last node now */
    merge->last_node_c2b = level->node_c2b;
    /* Reset the variables to the correct state */
    level->node_c2b      = NULL;
    level->last_key      = NULL; 
    level->next_idx      = 0;
    level->valid_end_idx = -1;
    level->valid_version = INVAL_VERSION;  
    /* Increment node count */
    merge->nr_nodes++;
}
       
static inline int castle_da_nodes_complete(struct castle_da_merge *merge, int depth)
{
    struct castle_da_merge_level *level;
    struct castle_btree_node *buffer;
    int i, buffer_idx, leaf_ptr;
    version_t version;
    void *key;
    
    debug("Checking if we need to complete nodes starting at level: %d\n", depth);
    /* Check if the level 'depth' node has been completed, which may trigger a cascade of
       completes up the tree. */ 
    for(i=depth; i<MAX_BTREE_DEPTH-1; i++)
    {
        level = merge->levels + i;
        /* Complete if next_idx < 0 */
        if(level->next_idx < 0)
            castle_da_node_complete(merge, i);
        else
            /* As soon as we see an incomplete node, we need to break out: */
            goto fill_buffers;
    }
    /* If we reached the top of the tree, we must fail the merge */
    if(i == MAX_BTREE_DEPTH - 1)
        return -EINVAL;
fill_buffers:
    debug("We got as far as depth=%d\n", i);
    /* Go through all the nodes we've completed, and check re-add all the entries from 
       the buffers */
    for(i--; i>=0; i--)
    {
        level = merge->levels + i;
        buffer = level->buffer; 
        debug("Buffer at depth=%d, has %d entries\n", i, buffer->used);
        for(buffer_idx=0; buffer_idx<buffer->used; buffer_idx++) 
        {
            c_val_tup_t cvt;

            merge->btree->entry_get(buffer, buffer_idx, &key, &version,
                                    &leaf_ptr, &cvt);
            BUG_ON(leaf_ptr);
            castle_da_entry_add(merge, i, key, version, cvt);
            /* Check if the node completed, it should never do */
            BUG_ON(level->next_idx < 0);
        }
        /* Buffer now consumed, reset it */
        castle_da_node_buffer_init(merge->btree, buffer);
    } 

    return 0;
}
   
static struct castle_component_tree* castle_da_merge_package(struct castle_da_merge *merge)
{
    struct castle_component_tree *out_tree;

    out_tree = castle_ct_alloc(merge->da, 0 /* not-dynamic */, merge->in_tree1->level + 1);
    if(!out_tree)
        return NULL;

    debug("Allocated component tree id=%d\n", out_tree->seq);
    /* Root node is the last node that gets completed, and therefore will be saved in last_node */
    out_tree->root_node = merge->last_node_c2b->cdb; 
    out_tree->first_node = merge->first_node;
    out_tree->last_node = INVAL_DISK_BLK;
    debug("Root for that tree is: (0x%x, 0x%x)\n", 
            out_tree->root_node.disk, out_tree->root_node.block);
    /* Write counts out */
    atomic_set(&out_tree->ref_count, 1);
    atomic64_set(&out_tree->item_count, merge->nr_entries);
    atomic64_set(&out_tree->node_count, merge->nr_nodes);
    debug("Number of entries=%ld, number of nodes=%ld\n",
            atomic64_read(&out_tree->item_count),
            atomic64_read(&out_tree->node_count));
    /* Add the new tree to the doubling array */
    BUG_ON(merge->da->id != out_tree->da); 
    printk("Finishing merge of ct1=%d, ct2=%d, new tree=%d\n", 
            merge->in_tree1->seq, merge->in_tree2->seq, out_tree->seq);
    debug("Adding to doubling array, level: %d\n", out_tree->level);
    castle_da_lock(merge->da);
    BUG_ON((merge->da->id != merge->in_tree1->da) ||
           (merge->da->id != merge->in_tree2->da));
    /* Delete the old trees from DA list (note that it may still be used by
       a lot of IOs and will only be destroyed on the last ct_put()). But
       we want to remove it from the DA straight away. The out_tree now takes
       over their functionality. */
    list_del(&merge->in_tree1->da_list);
    list_del(&merge->in_tree2->da_list);
    merge->da->nr_trees -= 2;
    castle_component_tree_add(merge->da, out_tree, 0 /* not in init */);
    castle_da_merging_clear(merge->da);
    castle_da_merge_check(merge->da);
    castle_da_unlock(merge->da);
    /* Remove old cts from the DA */
    debug("Destroying old CTs.\n");
    castle_ct_put(merge->in_tree1);
    castle_ct_put(merge->in_tree2);

    return out_tree;
}

static void castle_da_max_path_complete(struct castle_da_merge *merge)
{
    struct castle_btree_type *btree = merge->btree;
    struct castle_btree_node *node;
    c2_block_t *root_c2b, *node_c2b, *next_node_c2b;

    BUG_ON(!merge->completing);
    /* Root stored in last_node_c2b at the end of the merge */
    root_c2b = merge->last_node_c2b;
    printk("Maxifying the right most path, starting with root_cdb=(0x%x, 0x%x)\n",
            root_c2b->cdb.disk, root_c2b->cdb.block);
    /* Start of with root node */
    node_c2b = root_c2b;
    node = c2b_bnode(node_c2b);
    while(!node->is_leaf)
    {
        void *k;
        version_t v;
        int is_leaf_ptr;
        c_val_tup_t cvt;

        /* Replace right-most entry with (k=max_key, v=0) */
        btree->entry_get(node, node->used-1, &k, &v, &is_leaf_ptr, &cvt);
        BUG_ON(!CVT_ONDISK(cvt) || is_leaf_ptr);
        debug("The node is non-leaf, replacing the right most entry with (max_key, 0).\n");
        btree->entry_replace(node, node->used-1, btree->max_key, 0, 0, cvt);
        /* Change the version of the node to 0 */
        node->version = 0;
        /* Dirty the c2b */
        dirty_c2b(node_c2b);
        /* Go to the next btree node */
        debug("Locking next node cdb=(0x%x, 0x%x)\n", 
                cvt.cdb.disk, cvt.cdb.block);
        next_node_c2b = castle_cache_block_get(cvt.cdb, btree->node_size);
        lock_c2b(next_node_c2b);
        /* We unlikely to need a blocking read, because we've just had these
           nodes in the cache. */
        if(!c2b_uptodate(next_node_c2b))
            BUG_ON(submit_c2b_sync(READ, next_node_c2b));
        /* Release the old node, if it's not the same as the root node */
        if(node_c2b != root_c2b) 
        {
            debug("Unlocking prev node cdb=(0x%x, 0x%x)\n", 
                    node_c2b->cdb.disk, node_c2b->cdb.block);
            unlock_c2b(node_c2b);
            put_c2b(node_c2b);
        }
        node_c2b = next_node_c2b;
        node = c2b_bnode(node_c2b);
    }
    /* Release the leaf node, if it's not the same as the root node */
    if(node_c2b != root_c2b) 
    {
        debug("Unlocking prev node cdb=(0x%x, 0x%x)\n", 
                node_c2b->cdb.disk, node_c2b->cdb.block);
        unlock_c2b(node_c2b);
        put_c2b(node_c2b);
    }
}

static struct castle_component_tree* castle_da_merge_complete(struct castle_da_merge *merge)
{
    struct castle_da_merge_level *level;
    int i;

    merge->completing = 1;
    /* Force the nodes to complete by setting next_idx negative. Deal with the
       leaf level first (this may require multiple node completes). Then move
       on to the second level etc. Prevent node overflows using nodes_complete(). */ 
    for(i=0; i<MAX_BTREE_DEPTH; i++)
    {
        level = merge->levels + i;
        debug("Flushing at depth: %d\n", i);
        while(level->next_idx > 0)
        {
            debug("Artificially completing the node at depth: %d\n", i);
            level->next_idx = -1;
            if(castle_da_nodes_complete(merge, i))
                goto err_out;
        } 
    }
    castle_da_max_path_complete(merge);

    return castle_da_merge_package(merge);

err_out:
    printk("Failed the merge in merge_complete().\n");
    return NULL;
}

static void castle_da_merge_dealloc(struct castle_da_merge *merge)
{
    int i;

    if(!merge)
        return;

    /* Release the last node c2b */
    if(merge->last_node_c2b)
    {
        dirty_c2b(merge->last_node_c2b);
        unlock_c2b(merge->last_node_c2b);
        put_c2b(merge->last_node_c2b);
    }
    
    /* Free all the buffers */
    for(i=0; i<MAX_BTREE_DEPTH; i++)
    {
        c2_block_t *c2b = merge->levels[i].node_c2b;
        if(c2b)
        {
            unlock_c2b(c2b);
            put_c2b(c2b);
        }
        if(merge->levels[i].buffer)
            vfree(merge->levels[i].buffer);
    }
    kfree(merge);
}


static void castle_da_merge_do(struct work_struct *work)
{
    struct castle_da_merge *merge = container_of(work, 
                                                 struct castle_da_merge, 
                                                 work);
    struct castle_component_tree *out_tree;
    void *key;
    version_t version;
    c_val_tup_t cvt;
    int i, ret;

    debug("Initialising the iterators.\n");
    /* Create an appropriate iterator for each of the trees */
    ret = castle_da_iterators_create(merge);
    if(ret)
        goto err_out;

    /* Do the merge by iterating through all the entries. */
    i = 0;
    debug("Starting the merge.\n");
    while(castle_ct_merged_iter_has_next(merge->merged_iter))
    {
        /* TODO: we never check iterator errors. We should! */
        /* TODO: we never destroy iterator. We may need to! */
        castle_ct_merged_iter_next(merge->merged_iter, &key, &version, &cvt); 
        debug("Merging entry id=%d: k=%p, *k=%d, version=%d, cdb=(0x%x, 0x%x)\n",
                i, key, *((uint32_t *)key), version, cvt.cdb.disk, cvt.cdb.block);
        castle_da_entry_add(merge, 0, key, version, cvt);
        merge->nr_entries++;
        if((ret = castle_da_nodes_complete(merge, 0)))
            goto err_out;
        castle_da_merge_budget_consume(merge);
        i++;
    }
    debug("Flushing the last nodes.\n");
    /* Complete the merge, by flushing all the buffered entries */
    out_tree = castle_da_merge_complete(merge);
    if(!out_tree)
        ret = -EFAULT;
    debug("============ Merge completed ============\n"); 

err_out:
    if(ret)
        printk("Merge failed with %d\n", ret);
    castle_da_merge_dealloc(merge);
}

static void castle_da_merge_schedule(struct castle_double_array *da,
                                     struct castle_component_tree *in_tree1,
                                     struct castle_component_tree *in_tree2)
{
    struct castle_btree_type *btree;
    struct castle_da_merge *merge;
    int i, ret;

    debug("============ Merging ct=%d (%d) with ct=%d (%d) ============\n", 
            in_tree1->seq, in_tree1->dynamic,
            in_tree2->seq, in_tree2->dynamic);

    /* Work out what type of trees are we going to be merging. Bug if in_tree1/2 don't match. */
    btree = castle_btree_type_get(in_tree1->btree_type);
    BUG_ON(btree != castle_btree_type_get(in_tree2->btree_type));
    /* Malloc everything ... */
    ret = -ENOMEM;
    merge = kzalloc(sizeof(struct castle_da_merge), GFP_KERNEL);
    if(!merge)
        goto error_out;
    merge->da                = da;
    merge->btree             = btree;
    merge->in_tree1          = in_tree1;
    merge->in_tree2          = in_tree2;
    merge->root_depth        = -1;
    merge->last_node_c2b     = NULL;
    merge->first_node        = INVAL_DISK_BLK;
    merge->completing        = 0;
    merge->nr_entries        = 0;
    merge->nr_nodes          = 0;
    merge->budget_cons_rate  = 1; 
    merge->budget_cons_units = 0; 
    for(i=0; i<MAX_BTREE_DEPTH; i++)
    {
        merge->levels[i].buffer        = vmalloc(btree->node_size * C_BLK_SIZE);
        if(!merge->levels[i].buffer)
            goto error_out;
        castle_da_node_buffer_init(btree, merge->levels[i].buffer);
        merge->levels[i].last_key      = NULL; 
        merge->levels[i].next_idx      = 0; 
        merge->levels[i].valid_end_idx = -1; 
        merge->levels[i].valid_version = INVAL_VERSION;  
    }

    CASTLE_INIT_WORK(&merge->work, castle_da_merge_do);
    queue_work(castle_merge_wq, &merge->work);
    return;

error_out:
    BUG_ON(!ret);
    castle_da_merge_dealloc(merge);
    printk("Failed a merge with ret=%d\n", ret);
}

static void castle_da_merge_check(struct castle_double_array *da)
/* Called with da->lock held */
{
    struct castle_component_tree *ct1, *ct2;
    struct list_head *l;
    int level;

    printk("Checking if to do a merge for da: %d\n", da->id);
    /* Return early if we are already doing a merge. */
    if(castle_da_merging(da))
        return;
    /* Go through all the levels >= 1, and check if there is more than one tree 
       there. Schedule the merge if so */
    for(level=1; level<MAX_DA_LEVEL; level++)
    {
        ct1 = ct2 = NULL;
        list_for_each_prev(l, &da->trees[level])
        {
            if(!ct2)
                ct2 = list_entry(l, struct castle_component_tree, da_list);
            else
            if(!ct1)
                ct1 = list_entry(l, struct castle_component_tree, da_list);
            if(ct1 && ct2)
            {
                printk("Found two trees for merge: ct1=%d, ct2=%d.\n",
                    ct1->seq, ct2->seq);
                /* Schedule the merge, but make sure the lock is not held then
                   (merge_schedule() calls a bunch of sleeping functions). Set merge flag
                   beforehand, which will stop further merges in this da being scheduled.
                 */
                castle_da_merging_set(da);
                castle_da_unlock(da);
                castle_da_merge_schedule(da, ct1, ct2);
                castle_da_lock(da);
                return;
            }
        }
    }
}

/**********************************************************************************************/
/* Generic DA code */

static int castle_da_ct_dec_cmp(struct list_head *l1, struct list_head *l2)
{
    struct castle_component_tree *ct1 = list_entry(l1, struct castle_component_tree, da_list);
    struct castle_component_tree *ct2 = list_entry(l2, struct castle_component_tree, da_list);
    BUG_ON(ct1->seq == ct2->seq);

    return ct1->seq > ct2->seq ? -1 : 1;
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
    spin_lock_init(&da->lock);
    da->flags        = 0;
    da->nr_trees     = 0;

    for(i=0; i<MAX_DA_LEVEL; i++)
        INIT_LIST_HEAD(&da->trees[i]);
}

struct castle_component_tree* castle_component_tree_get(tree_seq_t seq)
{
    return castle_ct_hash_get(seq);
}

static void castle_component_tree_add(struct castle_double_array *da,
                                      struct castle_component_tree *ct,
                                      int in_init)
/* Needs to be called with da->lock held */
{
    struct castle_component_tree *next_ct; 

    BUG_ON(da->id != ct->da);
    BUG_ON(ct->level >= MAX_DA_LEVEL);
    /* If there is something on the list, check that the sequence number 
       of the tree we are inserting is greater (i.e. enforce rev seq number
       ordering in component trees in a given level). Don't check that during
       init (when we are storting the trees afterwards). */
    if(!in_init && !list_empty(&da->trees[ct->level]))
    {
        next_ct = list_entry(da->trees[ct->level].next, 
                             struct castle_component_tree,
                             da_list);
        BUG_ON(next_ct->seq >= ct->seq);
    }
    list_add(&ct->da_list, &da->trees[ct->level]);
    da->nr_trees++;
}

static inline void castle_da_lock(struct castle_double_array *da)
{
    spin_lock(&da->lock);
}

static inline void castle_da_unlock(struct castle_double_array *da)
{
    spin_unlock(&da->lock);
}

static inline void castle_ct_get(struct castle_component_tree *ct)
{
    atomic_inc(&ct->ref_count);
}

static inline void castle_ct_put(struct castle_component_tree *ct)
{
    if(likely(!atomic_dec_and_test(&ct->ref_count)))
        return;

    debug("Ref count for ct id=%d went to 0, releasing.\n", ct->seq);

    /* Destroy the component tree */
    BUG_ON(TREE_GLOBAL(ct->seq) || TREE_INVAL(ct->seq));
    castle_ct_hash_remove(ct);
    /* TODO: FREE */
    printk("Should release freespace occupied by ct=%d\n", ct->seq);
    /* Poison ct (note this will be repoisoned by kfree on kernel debug build. */
    memset(ct, 0xde, sizeof(struct castle_component_tree));
    kfree(ct);
}

static struct castle_component_tree* castle_da_rwct_get(struct castle_double_array *da)
{
    struct castle_component_tree *ct;
    struct list_head *h, *l;

    castle_da_lock(da);
    h = &da->trees[0]; 
    l = h->next; 
    /* There should be precisely one entry in the list */
    BUG_ON((h == l) || (l->next != h));
    ct = list_entry(l, struct castle_component_tree, da_list);
    /* Get a ref to this tree so that it doesn't go away while we are doing an IO on it */
    castle_ct_get(ct);
    castle_da_unlock(da);
        
    return ct; 
}

static int castle_da_trees_sort(struct castle_double_array *da, void *unused)
{
    int i;

    castle_da_lock(da);
    for(i=0; i<MAX_DA_LEVEL; i++)
        list_sort(&da->trees[i], castle_da_ct_dec_cmp);
    castle_da_unlock(da);

    return 0;
}

static c_mstore_key_t castle_da_ct_marshall(struct castle_clist_entry *ctm,
                                            struct castle_component_tree *ct)
{
    ctm->da_id       = ct->da; 
    ctm->item_count  = atomic64_read(&ct->item_count);
    ctm->btree_type  = ct->btree_type; 
    ctm->dynamic     = ct->dynamic;
    ctm->seq         = ct->seq;
    ctm->level       = ct->level;
    ctm->root_node   = ct->root_node;
    ctm->first_node  = ct->first_node;
    ctm->last_node   = ct->last_node;
    ctm->node_count  = atomic64_read(&ct->node_count);

    return ct->mstore_key;
}

static da_id_t castle_da_ct_unmarshall(struct castle_component_tree *ct,
                                       struct castle_clist_entry *ctm,
                                       c_mstore_key_t key)
{
    ct->seq         = ctm->seq;
    atomic_set(&ct->ref_count, 1);
    atomic64_set(&ct->item_count, ctm->item_count);
    ct->btree_type  = ctm->btree_type; 
    ct->dynamic     = ctm->dynamic;
    ct->da          = ctm->da_id; 
    ct->level       = ctm->level;
    ct->root_node   = ctm->root_node;
    ct->first_node  = ctm->first_node;
    ct->last_node   = ctm->last_node;
    init_rwsem(&ct->lock);
    atomic64_set(&ct->node_count, ctm->node_count);
    ct->mstore_key  = key;
    INIT_LIST_HEAD(&ct->da_list);

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

    castle_da_lock(da);
    for(i=0; i<MAX_DA_LEVEL; i++)
    {
        j = 0;
        list_for_each_safe(lh, t, &da->trees[i])
        {
            ct = list_entry(lh, struct castle_component_tree, da_list); 
            if(fn(da, ct, j, token))
                goto out;
            j++;
        }
    }
out:
    castle_da_unlock(da);
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
        castle_da_lock(da);
        castle_component_tree_add(da, ct, 1 /* in init */);
        castle_da_unlock(da);
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

static struct castle_component_tree* castle_ct_alloc(struct castle_double_array *da, 
                                                     int dynamic,
                                                     int level)
{
    struct castle_component_tree *ct;

    ct = kzalloc(sizeof(struct castle_component_tree), GFP_KERNEL); 
    if(!ct) 
        return NULL;
    
    /* Allocate an id for the tree, init the ct. */
    ct->seq         = castle_next_tree_seq++;
    atomic_set(&ct->ref_count, 1);
    atomic64_set(&ct->item_count, 0); 
    ct->btree_type  = VLBA_TREE_TYPE; 
    ct->dynamic     = dynamic;
    ct->da          = da->id;
    ct->level       = level;
    ct->root_node   = INVAL_DISK_BLK;
    ct->first_node  = INVAL_DISK_BLK;
    ct->last_node   = INVAL_DISK_BLK;
    init_rwsem(&ct->lock);
    atomic64_set(&ct->node_count, 0); 
    INIT_LIST_HEAD(&ct->da_list);
    INIT_LIST_HEAD(&ct->hash_list);
    castle_ct_hash_add(ct);
    ct->mstore_key  = INVAL_MSTORE_KEY; 

    return ct;
}
    
static int castle_da_rwct_make(struct castle_double_array *da)
{
    struct castle_component_tree *ct, *old_ct;
    c2_block_t *c2b;
    int ret;

    ret = -ENOMEM;
    ct = castle_ct_alloc(da, 1 /* dynamic tree */, 0 /* level */);
    if(!ct)
        goto out;

    /* Create a root node for this tree, and update the root version */
    c2b = castle_btree_node_create(0, 1 /* is_leaf */, VLBA_TREE_TYPE, ct);
    ct->root_node = c2b->cdb;
    unlock_c2b(c2b);
    put_c2b(c2b);
    debug("Added component tree seq=%d, root_node=(0x%x, 0x%x), it's threaded onto da=%p, level=%d\n",
            ct->seq, c2b->cdb.disk, c2b->cdb.block, da, ct->level);
    /* Move the last rwct (if one exists) to level 1 */
    castle_da_lock(da);
    if(!list_empty(&da->trees[0]))
    {
        old_ct = list_entry(da->trees[0].next, struct castle_component_tree, da_list);
        list_del(&old_ct->da_list);
        da->nr_trees--;
        old_ct->level = 1;
        castle_component_tree_add(da, old_ct, 0 /* not in init */);
    }
    /* Thread CT onto level 0 list */
    castle_component_tree_add(da, ct, 0 /* not in init */);
    castle_da_merge_check(da);
    castle_da_unlock(da);
    ret = 0;

out:
    castle_da_growing_rw_clear(da);
    return ret;
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
    da->mstore_key   = INVAL_MSTORE_KEY;
    spin_lock_init(&da->lock);
    da->flags        = 0;
    da->nr_trees     = 0;
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

    debug_verbose("Asked for component tree after %d\n", ct->seq);
    BUG_ON(!da);
    castle_da_lock(da);
    for(level = ct->level, ct_list = &ct->da_list; 
        level < MAX_DA_LEVEL; 
        level++, ct_list = &da->trees[level])
    {
        if(!list_is_last(ct_list, &da->trees[level]))
        {
            next_ct = list_entry(ct_list->next, struct castle_component_tree, da_list); 
            debug_verbose("Found component tree %d\n", next_ct->seq);
            castle_ct_get(next_ct);
            castle_da_unlock(da);

            return next_ct;
        }
    }     
    castle_da_unlock(da);

    return NULL;
}

static void castle_da_bvec_complete(c_bvec_t *c_bvec, int err, c_val_tup_t cvt)
{
    void (*callback) (struct castle_bio_vec *c_bvec, int err, c_val_tup_t cvt);
    struct castle_component_tree *ct, *next_ct;
    
    callback = c_bvec->da_endfind;
    ct = c_bvec->tree;
    
    /* If the key hasn't been found, check in the next tree. */
    if(CVT_INVALID(cvt) && (!err) && (c_bvec_data_dir(c_bvec) == READ))
    {
        debug_verbose("Checking next ct.\n");
        next_ct = castle_da_ct_next(ct);
        castle_ct_put(ct);
        if(!next_ct)
        {
            callback(c_bvec, err, INVAL_VAL_TUP); 
            return;
        }
        /* If there is the next tree, try searching in it now */
        c_bvec->tree = next_ct;
        debug_verbose("Scheduling btree read in %s tree: %d.\n", 
                ct->dynamic ? "dynamic" : "static", ct->seq);
        castle_btree_find(c_bvec);
        return;
    }
    debug_verbose("Finished with DA, calling back.\n");
    castle_da_merge_budget_io_end(castle_da_hash_get(ct->da));
    castle_ct_put(ct);
    callback(c_bvec, err, cvt);
}

void castle_double_array_find(c_bvec_t *c_bvec)
{
    struct castle_attachment *att = c_bvec->c_bio->attachment;
    struct castle_component_tree *ct;
    struct castle_double_array *da;
    da_id_t da_id; 

    
    down_read(&att->lock);
    /* Since the version is attached, it must be found */
    BUG_ON(castle_version_read(att->version, &da_id, NULL, NULL, NULL));
    up_read(&att->lock);

    da = castle_da_hash_get(da_id);
    BUG_ON(!da);
    /* da_endfind should be null it is for our privte use */
    BUG_ON(c_bvec->da_endfind);
    debug_verbose("Doing DA %s for da_id=%d, for version=%d\n", 
                  c_bvec_data_dir(c_bvec) == READ ? "read" : "write",
                  da_id, att->version);

    ct = castle_da_rwct_get(da);
    if((atomic_read(&ct->item_count) > MAX_DYNAMIC_TREE_SIZE) && 
       !castle_da_growing_rw_test_and_set(da))
    {
        struct castle_double_array *da = castle_da_hash_get(ct->da);  

        BUG_ON(!da);
        debug("Number of items in component tree: %d greater than %d (%ld). "
              "Adding a new rwct.\n",
                ct->seq, MAX_DYNAMIC_TREE_SIZE, atomic64_read(&ct->item_count));
        castle_da_rwct_make(da);
    }

    c_bvec->tree       = ct; 
    c_bvec->da_endfind = c_bvec->endfind;
    c_bvec->endfind    = castle_da_bvec_complete;

    debug_verbose("Looking up in ct=%d\n", c_bvec->tree->seq); 
    castle_btree_find(c_bvec);
}

int castle_double_array_create(void)
{
    castle_da_store   = castle_mstore_init(MSTORE_DOUBLE_ARRAYS,
                                         sizeof(struct castle_dlist_entry));
    castle_tree_store = castle_mstore_init(MSTORE_COMPONENT_TREES,
                                         sizeof(struct castle_clist_entry));

    if(!castle_da_store || !castle_tree_store)
        return -ENOMEM;

    /* Make sure that the global tree is in the ct hash */
    castle_ct_hash_add(&castle_global_tree);

    return 0;
}
    
int castle_double_array_init(void)
{
    int ret;

    printk("\n========= Double Array init ==========\n");
    /* Start up the timer which replenishes merge budget */
    castle_da_merge_budget_add(1); 
    ret = -ENOMEM;
    castle_da_hash = castle_da_hash_alloc();
    if(!castle_da_hash)
        goto err_out;
    castle_ct_hash = castle_ct_hash_alloc();
    if(!castle_ct_hash)
        goto err_out;
    castle_merge_wq = create_workqueue("castle_merge");
    if(!castle_merge_wq)
        goto err_out;

    castle_da_hash_init();
    castle_ct_hash_init();

    return 0;
 
err_out:
    BUG_ON(!ret);
    del_singleshot_timer_sync(&merge_rate_timer);
    if(castle_ct_hash)
        kfree(castle_ct_hash);
    if(castle_da_hash)
        kfree(castle_da_hash);

    return ret;
}

void castle_double_array_fini(void)
{
    printk("\n========= Double Array fini ==========\n");
    destroy_workqueue(castle_merge_wq);
    del_singleshot_timer_sync(&merge_rate_timer);
    castle_da_hash_writeback();
    castle_da_hash_destroy();
    castle_ct_hash_destroy();
}
