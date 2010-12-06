#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/kthread.h>

#include "castle_public.h"
#include "castle_utils.h"
#include "castle.h"
#include "castle_cache.h"
#include "castle_btree.h"
#include "castle_time.h"
#include "castle_versions.h"
#include "castle_extent.h"
#include "castle_ctrl.h"
#include "castle_da.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)            ((void)0)
#define debug_verbose(_f, ...)    ((void)0)
#define merg_itr_dbg(_f, ...)      ((void)0)
#else
#define debug(_f, _a...)          (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#define debug_verbose(_f, ...)    ((void)0)
#define merg_itr_dbg(_f, _a...)     (printk(_f, ##_a))
//#define debug_verbose(_f, _a...)  (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

#define MAX_DA_LEVEL                    (20)
#define MAX_DYNAMIC_TREE_SIZE           (100) /* In C_CHK_SIZE. */ 
#define MAX_DYNAMIC_DATA_SIZE           (100) /* In C_CHK_SIZE. */ 

#define CASTLE_DA_HASH_SIZE             (1000)
#define CASTLE_CT_HASH_SIZE             (4000)
static struct list_head        *castle_da_hash       = NULL;
static struct list_head        *castle_ct_hash       = NULL;
static struct castle_mstore    *castle_da_store      = NULL;
static struct castle_mstore    *castle_tree_store    = NULL;
static struct castle_mstore    *castle_lo_store      = NULL;
       da_id_t                  castle_next_da_id    = 1; 
static tree_seq_t               castle_next_tree_seq = 1; 
static int                      castle_da_exiting    = 0;


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

   For DAs, only an attached DA is guaranteed to be in the hash.
 */

#define DOUBLE_ARRAY_GROWING_RW_TREE_BIT    (0)
#define DOUBLE_ARRAY_GROWING_RW_TREE_FLAG   (1 << DOUBLE_ARRAY_GROWING_RW_TREE_BIT)
#define DOUBLE_ARRAY_DELETED_BIT            (1)
#define DOUBLE_ARRAY_DELETED_FLAG           (1 << DOUBLE_ARRAY_DELETED_BIT)
struct castle_double_array {
    da_id_t                 id;
    version_t               root_version;
    /* Lock protects the trees list */
    spinlock_t              lock;
    unsigned long           flags;
    int                     nr_trees;
    struct {
        int                 nr_trees;
        struct list_head    trees;
        /* Merge related veriables. */
        struct {
            uint32_t            units_commited; 
            struct task_struct *thread;
        } merge;
    } levels[MAX_DA_LEVEL];
    struct list_head        hash_list;
    atomic_t                ref_cnt;
    uint32_t                attachment_cnt;
    /* Queue of write IOs queued up on this DA. */
    struct list_head        ios_waiting;
    int                     ios_waiting_cnt;
    uint32_t                ios_budget;
    uint32_t                ios_rate;
    struct work_struct      queue_restart;
    /* Merge deamortisation */
    wait_queue_head_t       merge_waitq;
    int                     max_merge_level;
    /* Merge throttling. DISABLED ATM. */
    atomic_t                epoch_ios;
    atomic_t                merge_budget;
    wait_queue_head_t       merge_budget_waitq;
};

DEFINE_HASH_TBL(castle_da, castle_da_hash, CASTLE_DA_HASH_SIZE, struct castle_double_array, hash_list, da_id_t, id);
DEFINE_HASH_TBL(castle_ct, castle_ct_hash, CASTLE_CT_HASH_SIZE, struct castle_component_tree, hash_list, tree_seq_t, seq);
static LIST_HEAD(castle_deleted_das);

/**********************************************************************************************/
/* Prototypes */
static struct castle_component_tree* castle_ct_alloc(struct castle_double_array *da, 
                                                     btree_t type, 
                                                     int level);
static inline void castle_da_lock(struct castle_double_array *da);
static inline void castle_da_unlock(struct castle_double_array *da);
static inline int castle_da_is_locked(struct castle_double_array *da);
void castle_ct_get(struct castle_component_tree *ct, int write);
void castle_ct_put(struct castle_component_tree *ct, int write);
static void castle_component_tree_add(struct castle_double_array *da,
                                      struct castle_component_tree *ct,
                                      int in_init);
static void castle_component_tree_del(struct castle_double_array *da,
                                      struct castle_component_tree *ct);
struct castle_da_merge;
static void castle_da_merge_check(struct castle_double_array *da);
void castle_double_array_merges_fini(void);
static void castle_da_merge_budget_consume(struct castle_da_merge *merge);
static void castle_da_queue_restart(struct work_struct *work);
static void castle_da_queue_kick(struct castle_double_array *da);
static void castle_da_bvec_start(struct castle_double_array *da, c_bvec_t *c_bvec);
static void castle_da_get(struct castle_double_array *da);
static void castle_da_put(struct castle_double_array *da);

/**********************************************************************************************/
/* Utils */

static inline int castle_da_growing_rw_test_and_set(struct castle_double_array *da)
{
    return test_and_set_bit(DOUBLE_ARRAY_GROWING_RW_TREE_BIT, &da->flags);
}

static inline int castle_da_growing_rw_test(struct castle_double_array *da)
{
    return test_bit(DOUBLE_ARRAY_GROWING_RW_TREE_BIT, &da->flags);
}

static inline void castle_da_growing_rw_clear(struct castle_double_array *da)
{
    clear_bit(DOUBLE_ARRAY_GROWING_RW_TREE_BIT, &da->flags);
}


static inline int castle_da_deleted(struct castle_double_array *da)
{
    return test_bit(DOUBLE_ARRAY_DELETED_BIT, &da->flags);
}

static inline void castle_da_deleted_set(struct castle_double_array *da)
{
    set_bit(DOUBLE_ARRAY_DELETED_BIT, &da->flags);
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
    int                           next_idx;
} c_immut_iter_t;

static int castle_ct_immut_iter_entry_find(c_immut_iter_t *iter,
                                           struct castle_btree_node *node,
                                           int start_idx) 
{
    int disabled;
    c_val_tup_t cvt;

    for(; start_idx<node->used; start_idx++)
    {
        disabled = iter->btree->entry_get(node, start_idx, NULL, NULL, &cvt);
        if(!CVT_LEAF_PTR(cvt) && !disabled)
            return start_idx; 
    }

    return -1;
}


static int castle_ct_immut_iter_next_node_init(c_immut_iter_t *iter,
                                               struct castle_btree_node *node)
{
    /* Non-leaf nodes do not contain any entries for the enumerator, continue straight through */
    if(!node->is_leaf)
        return 0;

    /* Non-dynamic trees do not contain leaf pointers => the node must be non-empty, 
       and will not contain leaf pointers */
    if(!iter->tree->dynamic)
    {
        iter->next_idx = 0;
        BUG_ON(castle_ct_immut_iter_entry_find(iter, node, 0 /* start_idx */) != iter->next_idx);
        BUG_ON(node->used == 0);
        return 1;
    }

    /* Finally, for dynamic trees, check if we have at least non-leaf pointer */
    iter->next_idx = castle_ct_immut_iter_entry_find(iter, node, 0 /* start_idx */);
    if(iter->next_idx >= 0)
        return 1;

    return 0;
}

static void castle_ct_immut_iter_next_node_find(c_immut_iter_t *iter, c_ext_pos_t  cep)
{
    struct castle_btree_node *node;
    c2_block_t *c2b;
     
    debug("Looking for next node starting with "cep_fmt_str_nl, cep2str(cep));
    BUG_ON(iter->next_c2b);
    c2b=NULL;
    while(!EXT_POS_INVAL(cep))
    {
        /* Release c2b if we've got one */
        if(c2b)
            put_c2b(c2b);
        /* Get cache block for the current c2b */
        c2b = castle_cache_block_get(cep, iter->btree->node_size); 
        debug("Node in immut iter.\n");
        castle_cache_block_advise(c2b, C2B_PREFETCH_FRWD);
        write_lock_c2b(c2b);
        /* If c2b is not up to date, issue a blocking READ to update */
        if(!c2b_uptodate(c2b))
            BUG_ON(submit_c2b_sync(READ, c2b));
        write_unlock_c2b(c2b);
        node = c2b_bnode(c2b);
        if(castle_ct_immut_iter_next_node_init(iter, node))
        {
            debug("Cep "cep_fmt_str " will be used next, exiting.\n",
                   cep2str(cep));
            /* Found */
            iter->next_c2b = c2b;
            return;
        }
        cep = node->next_node;
        debug("Node non-leaf or no non-leaf-ptr entries, moving to " cep_fmt_str_nl, 
               cep2str(cep));
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
        debug("Moving to the next block after: "cep_fmt_str_nl, 
               cep2str(iter->curr_c2b->cep));
        put_c2b(iter->curr_c2b);
    }
    /* next_c2b becomes curr_c2b */ 
    iter->curr_c2b  = iter->next_c2b;
    BUG_ON(!c2b_uptodate(iter->curr_c2b));
    iter->curr_node = c2b_bnode(iter->curr_c2b); 
    if(!iter->curr_node->is_leaf ||
           (iter->curr_node->used <= iter->next_idx))
    {
        printk("curr_node=%d, used=%d, next_idx=%d\n",
                iter->curr_node->is_leaf,
                iter->curr_node->used,
                iter->next_idx);
    }
    BUG_ON(!iter->curr_node->is_leaf ||
           (iter->curr_node->used <= iter->next_idx));
    iter->curr_idx  = iter->next_idx;
    debug("Moved to cep="cep_fmt_str_nl, cep2str(iter->curr_c2b->cep));

    /* Find next c2b following the list pointers */
    iter->next_c2b = NULL;
    castle_ct_immut_iter_next_node_find(iter, iter->curr_node->next_node);
}

static void castle_ct_immut_iter_next(c_immut_iter_t *iter, 
                                      void **key_p, 
                                      version_t *version_p, 
                                      c_val_tup_t *cvt_p)
{
    int disabled;

    /* Check if we can read from the curr_node. If not move to the next node. 
       Make sure that if entries exist, they are not leaf pointers. */
    if(iter->curr_idx >= iter->curr_node->used || iter->curr_idx < 0) 
    {
        debug("No more entries in the current node. Asking for next.\n");
        BUG_ON((iter->curr_idx >= 0) && (iter->curr_idx > iter->curr_node->used));
        castle_ct_immut_iter_next_node(iter);
        BUG_ON((iter->curr_idx >= 0) && (iter->curr_idx >= iter->curr_node->used));
    }
    disabled = iter->btree->entry_get(iter->curr_node, 
                                      iter->curr_idx, 
                                      key_p, 
                                      version_p, 
                                      cvt_p);
    /* curr_idx should have been set to a non-leaf pointer */
    BUG_ON(CVT_LEAF_PTR(*cvt_p) || disabled);
    iter->curr_idx = castle_ct_immut_iter_entry_find(iter, iter->curr_node, iter->curr_idx + 1);
    debug("Returned next, curr_idx is now=%d / %d.\n", iter->curr_idx, iter->curr_node->used);
}

static int castle_ct_immut_iter_has_next(c_immut_iter_t *iter)
{
    if(unlikely(iter->completed))
        return 0;

    if((iter->curr_idx >= iter->curr_node->used || iter->curr_idx < 0) && (!iter->next_c2b))
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
    .register_cb = NULL,
    .prep_next   = NULL,
    .has_next    = (castle_iterator_has_next_t)castle_ct_immut_iter_has_next,
    .next        = (castle_iterator_next_t)    castle_ct_immut_iter_next,
    .skip        = NULL,
};

typedef struct castle_modlist_iterator {
    struct castle_btree_type *btree;
    struct castle_component_tree *tree;
    struct castle_da_merge *merge;
    c_immut_iter_t *enumerator;
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
    buffer->next_node = INVAL_EXT_POS;
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
    struct castle_btree_node *node = NULL;
    uint32_t node_idx, node_offset, item_idx;
    version_t version;
    c_val_tup_t cvt;
    void *key;

    item_idx = node_idx = node_offset = 0;
    while(castle_ct_immut_iter.has_next(iter->enumerator))
    {
        might_resched();
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
        castle_ct_immut_iter.next(iter->enumerator, &key, &version, &cvt);
        debug("In enum got next: k=%p, version=%d, %u/%llu, cep="cep_fmt_str_nl,
                key, version, (uint32_t)cvt.type, cvt.length, cep2str(cvt.cep));
        debug("Dereferencing first 4 bytes of the key (should be length)=0x%x.\n",
                *((uint32_t *)key));
        debug("Inserting into the node=%d, under idx=%d\n", node_idx, node_offset);
        BUG_ON(CVT_LEAF_PTR(cvt));
        btree->entry_add(node, node_offset, key, version, cvt);
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
        printk("Error. Different number of items than expected in CT=%d (dynamic=%d). "
               "Item_idx=%d, item_count=%ld\n",
            iter->tree->seq, iter->tree->dynamic,
            item_idx, atomic64_read(&iter->tree->item_count));
        WARN_ON(1);
    }
    iter->nr_items = item_idx;
    //iter->err = iter->enumerator->err;
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
        might_resched();
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

        might_resched();
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
        castle_free(iter->enumerator);
    if(iter->node_buffer)
        castle_vfree(iter->node_buffer);
    if(iter->sort_idx)
        castle_vfree(iter->sort_idx);
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
    iter->enumerator = castle_malloc(sizeof(c_immut_iter_t), GFP_KERNEL);
    /* Allocate slighly more than number of nodes in the tree, to make sure everything
       fits, even if we unlucky, and waste parts of the node in each node */
    iter->nr_nodes = 1.1 * (atomic64_read(&ct->node_count) + 1);
    iter->node_buffer = castle_vmalloc(iter->nr_nodes * iter->btree->node_size * C_BLK_SIZE);
    iter->sort_idx = castle_vmalloc(atomic64_read(&ct->item_count) * sizeof(struct item_idx));
    if(!iter->enumerator || !iter->node_buffer || !iter->sort_idx)
    {
        castle_ct_modlist_iter_free(iter);       
        iter->err = -ENOMEM;
        return;
    }
    /* Start up the child enumerator */
    iter->enumerator->tree = ct;
    castle_ct_immut_iter_init(iter->enumerator); 
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
    .register_cb = NULL,
    .prep_next   = NULL,
    .has_next    = (castle_iterator_has_next_t)castle_ct_modlist_iter_has_next,
    .next        = (castle_iterator_next_t)    castle_ct_modlist_iter_next,
    .skip        = NULL,
};

static int _castle_ct_merged_iter_prep_next(c_merged_iter_t *iter,
                                            int sync_call)
{
    int i;
    struct component_iterator *comp_iter;

    merg_itr_dbg("No of comp_iters: %u\n", iter->nr_iters);
    for(i=0; i<iter->nr_iters; i++)
    {
        comp_iter = iter->iterators + i; 

        merg_itr_dbg("%s:%p:%d\n", __FUNCTION__, iter, i);
        /* Replenish the cache */
        if(!comp_iter->completed && !comp_iter->cached)
        {
            debug("Reading next entry for iterator: %d.\n", i);
            if (!sync_call &&
                !comp_iter->iterator_type->prep_next(comp_iter->iterator)) {
                merg_itr_dbg("%s:%p:%p:%d - schedule\n", __FUNCTION__, iter, comp_iter->iterator, i);
                return 0;
            }
            if (comp_iter->iterator_type->has_next(comp_iter->iterator))
            {
                comp_iter->iterator_type->next(comp_iter->iterator,
                                               &comp_iter->cached_entry.k,
                                               &comp_iter->cached_entry.v,
                                               &comp_iter->cached_entry.cvt);
                comp_iter->cached = 1;
                iter->src_items_completed++;
                merg_itr_dbg("%s:%p:%d - cached\n", __FUNCTION__, iter, i);
            }
            else
            {
                merg_itr_dbg("%s:%p:%d - nothing left\n", __FUNCTION__, iter, i);
                comp_iter->completed = 1;
                iter->non_empty_cnt--;
                debug("A component iterator run out of stuff, we are left with"
                      "%d iterators.\n",
                      iter->non_empty_cnt);
            }
        }
    }

    return 1;
}

static void castle_ct_merged_iter_register_cb(c_merged_iter_t *iter,
                                              castle_iterator_end_io_t cb,
                                              void *data)
{
    iter->end_io  = cb;
    iter->private = data;
}

static int castle_ct_merged_iter_prep_next(c_merged_iter_t *iter)
{
    merg_itr_dbg("%s:%p\n", __FUNCTION__, iter);
    return _castle_ct_merged_iter_prep_next(iter, 0);
}

static void castle_ct_merged_iter_end_io(void *rq_enum_iter, int err)
{
    c_merged_iter_t *iter = ((c_rq_enum_t *) rq_enum_iter)->private;

    merg_itr_dbg("%s:%p\n", __FUNCTION__, iter);
    if (castle_ct_merged_iter_prep_next(iter))
    {
        merg_itr_dbg("%s:%p - Done\n", __FUNCTION__, iter);
        iter->end_io(iter, 0);
        return;
    }
}

static int castle_ct_merged_iter_has_next(c_merged_iter_t *iter)
{
    merg_itr_dbg("%s:%p\n", __FUNCTION__, iter);
    BUG_ON(!_castle_ct_merged_iter_prep_next(iter, 1));
    debug("Merged iterator has next, err=%d, non_empty_cnt=%d\n", 
            iter->err, iter->non_empty_cnt);
    return (!iter->err && (iter->non_empty_cnt > 0));
}

static void castle_ct_merged_iter_next(c_merged_iter_t *iter,
                                       void **key_p,
                                       version_t *version_p,
                                       c_val_tup_t *cvt_p)
{
    struct component_iterator *comp_iter; 
    int i, smallest_idx, kv_cmp;
    void *smallest_k = NULL;
    version_t smallest_v = 0;
    c_val_tup_t smallest_cvt;

    merg_itr_dbg("%s:%p\n", __FUNCTION__, iter);
    debug("Merged iterator next.\n");
    /* When next is called, we are free to call next on any of the 
       component iterators we do not have an entry cached for */
    for(i=0, smallest_idx=-1; i<iter->nr_iters; i++)
    {
        comp_iter = iter->iterators + i; 

        /* Replenish the cache */
        BUG_ON(!comp_iter->completed && !comp_iter->cached);
        
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
            if (iter->each_skip)
                iter->each_skip(iter, comp_iter);
            comp_iter->cached = 0;
        }
    }

    /* Smallest value should have been found by now */
    BUG_ON(smallest_idx < 0);

    debug("Smallest entry is from iterator: %d.\n", smallest_idx);
    /* The cache for smallest_idx iterator cached entry should be removed */ 
    comp_iter = iter->iterators + smallest_idx;
    comp_iter->cached = 0;
    /* Return the smallest entry */
    if(key_p) *key_p = smallest_k;
    if(version_p) *version_p = smallest_v;
    if(cvt_p) *cvt_p = smallest_cvt;
}

static void castle_ct_merged_iter_skip(c_merged_iter_t *iter,
                                       void *key)
{
    struct component_iterator *comp_iter; 
    int i, skip_cached;

    merg_itr_dbg("%s:%p\n", __FUNCTION__, iter);
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
        {
            BUG_ON(iter->each_skip);
            comp_iter->cached = 0;
        }
    }
}

static void castle_ct_merged_iter_cancel(c_merged_iter_t *iter)
{
    castle_free(iter->iterators);
}

/* Constructs a merged iterator out of a set of iterators. */
static void castle_ct_merged_iter_init(c_merged_iter_t *iter,
                                       void **iterators,
                                       struct castle_iterator_type **iterator_types,
                                       castle_merged_iterator_each_skip each_skip)
{
    int i;

    debug("Initing merged iterator for %d component iterators.\n", iter->nr_iters);
    /* nr_iters should be given in the iterator, and we expecting it to be in [1,10] range */
    if(iter->nr_iters > 10)
        printk("Merged iterator for %d > 10 trees.\n", iter->nr_iters);
    BUG_ON(iter->nr_iters <= 0);
    BUG_ON(!iter->btree);
    iter->err = 0;
    iter->src_items_completed = 0;
    iter->end_io = NULL;
    iter->iterators = castle_malloc(iter->nr_iters * sizeof(struct component_iterator), GFP_KERNEL);
    if(!iter->iterators)
    {
        printk("Failed to allocate memory for merged iterator.\n");
        iter->err = -ENOMEM;
        return;
    }
    iter->each_skip = each_skip;
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

        if (comp_iter->iterator_type->register_cb)
            comp_iter->iterator_type->register_cb(comp_iter->iterator,
                                                  castle_ct_merged_iter_end_io,
                                                  (void *)iter);
    } 
}

struct castle_iterator_type castle_ct_merged_iter = {
    .register_cb = (castle_iterator_register_cb_t)castle_ct_merged_iter_register_cb,
    .prep_next   = (castle_iterator_prep_next_t)  castle_ct_merged_iter_prep_next,
    .has_next    = (castle_iterator_has_next_t)   castle_ct_merged_iter_has_next,
    .next        = (castle_iterator_next_t)       castle_ct_merged_iter_next,
    .skip        = (castle_iterator_skip_t)       castle_ct_merged_iter_skip, 
    .cancel      = (castle_iterator_cancel_t)     castle_ct_merged_iter_cancel, 
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
        castle_ct_modlist_iter_next(&test_iter, &key, &version, &cep); 
        debug("Sorted: %d: k=%p, version=%d, cep=(0x%x, 0x%x)\n",
                i, key, version, cep.ext_id, cep.offset);
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
                               iter_types, 
                               NULL);
    debug("=============== SORTED ================\n");
    while(castle_ct_merged_iter_has_next(&test_miter))
    {
        castle_ct_merged_iter_next(&test_miter, &key, &version, &cvt); 
        debug("Sorted: %d: k=%p, version=%d, cep=" cep_fmt_str_nl,
                i, key, version, cep2str(cvt.cep));
        debug("Dereferencing first 4 bytes of the key (should be length)=0x%x.\n",
                *((uint32_t *)key));
        i++;
    }
}
#endif

/* Has next, next and skip only need to call the corresponding functions on
   the underlying merged iterator */

static void castle_da_rq_iter_register_cb(c_da_rq_iter_t *iter,
                                          castle_iterator_end_io_t cb,
                                          void *data)
{
    iter->end_io  = cb;
    iter->private = data;
}

static int castle_da_rq_iter_prep_next(c_da_rq_iter_t *iter)
{
    return castle_ct_merged_iter_prep_next(&iter->merged_iter);
} 


static int castle_da_rq_iter_has_next(c_da_rq_iter_t *iter)
{
    return castle_ct_merged_iter_has_next(&iter->merged_iter);
} 

static void castle_da_rq_iter_end_io(void *merged_iter, int err)
{
    c_da_rq_iter_t *iter = ((c_merged_iter_t *)merged_iter)->private;

    if (castle_da_rq_iter_prep_next(iter))
    {
        iter->end_io(iter, 0);
        return;
    }
    else
        BUG();
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
        castle_ct_put(ct_rq->ct, 0);
    }
    castle_free(iter->ct_rqs);
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
again:
    /* Try to allocate the right amount of memory, but remember that nr_trees
       may change, because we are not holding the da lock (cannot kmalloc holding
       a spinlock). */
    iter->nr_cts = da->nr_trees;
    iter->err    = 0;
    iter->end_io = NULL;
    iter->ct_rqs = castle_zalloc(iter->nr_cts * sizeof(struct ct_rq), GFP_KERNEL);
    iters        = castle_malloc(iter->nr_cts * sizeof(void *), GFP_KERNEL);
    iter_types   = castle_malloc(iter->nr_cts * sizeof(struct castle_iterator_type *), GFP_KERNEL);
    if(!iter->ct_rqs || !iters || !iter_types)
    {
        if(iter->ct_rqs)
            castle_free(iter->ct_rqs);
        if(iters)
            castle_free(iters);
        if(iter_types)
            castle_free(iter_types);
        iter->err = -ENOMEM;
        return;
    }

    castle_da_lock(da);
    /* Check the number of trees under lock. Retry again if # changed. */ 
    if(iter->nr_cts != da->nr_trees)
    {
        castle_da_unlock(da);
        printk("Warning. Untested path. # of cts changed while allocating memory for rq.\n");
        castle_free(iter->ct_rqs);
        castle_free(iters);
        castle_free(iter_types);
        goto again;
    }
    /* Get refs to all the component trees, and release the lock */
    j=0;
    for(i=0; i<MAX_DA_LEVEL; i++)
    {
        list_for_each(l, &da->levels[i].trees)
        {
            struct castle_component_tree *ct;

            BUG_ON(j >= iter->nr_cts);
            ct = list_entry(l, struct castle_component_tree, da_list);
            iter->ct_rqs[j].ct = ct; 
            castle_ct_get(ct, 0);
            BUG_ON((castle_btree_type_get(ct->btree_type)->magic != RW_VLBA_TREE_TYPE) &&
                   (castle_btree_type_get(ct->btree_type)->magic != RO_VLBA_TREE_TYPE));
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
    iter->merged_iter.btree    = castle_btree_type_get(RO_VLBA_TREE_TYPE);
    castle_ct_merged_iter_init(&iter->merged_iter,
                                iters,
                                iter_types,
                                NULL);
    castle_ct_merged_iter_register_cb(&iter->merged_iter, 
                                      castle_da_rq_iter_end_io,
                                      iter);
    castle_free(iters);
    castle_free(iter_types);
}

struct castle_iterator_type castle_da_rq_iter = {
    .register_cb= (castle_iterator_register_cb_t)castle_da_rq_iter_register_cb,
    .prep_next  = (castle_iterator_prep_next_t)  castle_da_rq_iter_prep_next,
    .has_next   = (castle_iterator_has_next_t)   castle_da_rq_iter_has_next,
    .next       = (castle_iterator_next_t)       castle_da_rq_iter_next,
    .skip       = (castle_iterator_skip_t)       castle_da_rq_iter_skip,
    .cancel     = (castle_iterator_cancel_t)     castle_da_rq_iter_cancel, 
};

/**********************************************************************************************/
/* Merges */
struct castle_da_merge {
    struct castle_double_array   *da;
    struct castle_btree_type     *out_btree;
    int                           level;
    struct castle_component_tree *in_tree1;
    struct castle_component_tree *in_tree2;
    void                         *iter1;
    void                         *iter2;
    c_merged_iter_t              *merged_iter;
    int                           root_depth;
    c2_block_t                   *last_node_c2b;
    c_ext_pos_t                   first_node;
    int                           completing;
    uint64_t                      nr_entries;
    uint64_t                      nr_nodes;
    uint64_t                      large_chunks; 
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
    c_ext_fs_t                    tree_ext_fs;
    c_ext_fs_t                    data_ext_fs;
    struct list_head              large_objs;
};

/************************************/
/* Marge rate control functionality */
static void castle_da_merge_budget_consume(struct castle_da_merge *merge)
{
    struct castle_double_array *da;

    if(castle_da_exiting)
        return;

    /* Check if we need to consume some merge budget */
    merge->budget_cons_units++;
    if(merge->budget_cons_units < merge->budget_cons_rate)
        return;

    da = merge->da;
    /* Consume a single unit of budget. */
    while(atomic_dec_return(&da->merge_budget) < 0)
    {
        /* We failed to get merge budget, readd the unit, and wait for some to appear. */
        atomic_inc(&da->merge_budget);
        //printk("Throttling merge. Unexpected.\n");
        //wait_event(da->merge_budget_waitq, atomic_read(&da->merge_budget) > 0);
    }
}

#define REPLENISH_FREQUENCY (10)        /* Replenish budgets every 100ms. */
static int castle_da_merge_budget_replenish(struct castle_double_array *da, void *unused)
{
#define MAX_IOS             (1000) /* Arbitrary constants */
/* TODO: Merges are now effectively always full throughput, because MIN is set high. */ 
#define MIN_BUDGET_DELTA    (100000)
#define MAX_BUDGET          (1000000)
    int ios = atomic_read(&da->epoch_ios);
    int budget_delta = 0, merge_budget;

    atomic_set(&da->epoch_ios, 0);
    debug("Merge replenish, number of ios in last second=%d.\n", ios);
    if(ios < MAX_IOS) 
        budget_delta = MAX_IOS - ios;
    if(budget_delta < MIN_BUDGET_DELTA)
        budget_delta = MIN_BUDGET_DELTA;
    BUG_ON(budget_delta <= 0);
    merge_budget = atomic_add_return(budget_delta, &da->merge_budget);
    if(merge_budget > MAX_BUDGET)
        atomic_sub(merge_budget - MAX_BUDGET, &da->merge_budget);
    wake_up(&da->merge_budget_waitq);

    return 0;
}

static void castle_merge_budgets_replenish(void)
{
   castle_da_hash_iterate(castle_da_merge_budget_replenish, NULL); 
}

static void castle_da_queue_restart(struct work_struct *work)
{
    struct castle_double_array *da = container_of(work, struct castle_double_array, queue_restart);

    castle_da_lock(da);
    da->ios_budget = da->ios_rate;
    castle_da_unlock(da);

    castle_da_queue_kick(da);
    castle_da_put(da);
} 

static int castle_da_ios_budget_replenish(struct castle_double_array *da, void *unused)
{
    castle_da_get(da);
    queue_work(castle_wq, &da->queue_restart);

    return 0;
}

static void castle_ios_budgets_replenish(void)
{
   castle_da_hash_iterate(castle_da_ios_budget_replenish, NULL); 
}

static inline void castle_da_merge_budget_io_end(struct castle_double_array *da)
{
    atomic_inc(&da->epoch_ios);
}

/************************************/
/* Throttling timers */
static struct timer_list throttle_timer; 
static void castle_throttle_timer_fire(unsigned long first)
{
    castle_merge_budgets_replenish();
    castle_ios_budgets_replenish();
    /* Reschedule ourselves */
    setup_timer(&throttle_timer, castle_throttle_timer_fire, 0);
    mod_timer(&throttle_timer, jiffies + HZ/REPLENISH_FREQUENCY);
}

/************************************/
/* Actual merges */
static void castle_da_iterator_destroy(struct castle_component_tree *tree,
                                       void *iter)
{
    if(!iter)
        return;

    if(tree->dynamic)
    {
        /* For dynamic trees we are using modlist iterator. */ 
        castle_ct_modlist_iter_free(iter);
        castle_free(iter);
    } else
    {
        /* For static trees, we are using immut iterator. It's enough to free it */
        /* TODO: do we need to do better resource release here? */
        castle_free(iter);
    }
}

static void castle_da_iterator_create(struct castle_da_merge *merge,
                                      struct castle_component_tree *tree,
                                      void **iter_p)
{
    if(tree->dynamic)
    {
        c_modlist_iter_t *iter = castle_malloc(sizeof(c_modlist_iter_t), GFP_KERNEL);
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
        c_immut_iter_t *iter = castle_malloc(sizeof(c_immut_iter_t), GFP_KERNEL);
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

static void castle_da_each_skip(c_merged_iter_t *iter,  
                                struct component_iterator *comp_iter)
{
    BUG_ON(!comp_iter->cached);

    if (CVT_LARGE_OBJECT(comp_iter->cached_entry.cvt))
    {
        /* No need to remove this large object, it gets deleted part of Tree
         * deletion. */
    }
}

static int castle_da_iterators_create(struct castle_da_merge *merge)
{
    struct castle_btree_type *btree;
    int ret;
    void *iters[2];
    struct castle_iterator_type *iter_types[2];
    c_byte_off_t size;

    printk("Creating iterators for the merge.\n");
    BUG_ON( merge->iter1    ||  merge->iter2);
    BUG_ON(!merge->in_tree1 || !merge->in_tree2);
    btree = castle_btree_type_get(merge->in_tree1->btree_type);

    /* Wait until there are no outstanding writes on the trees */
    while(atomic_read(&merge->in_tree1->write_ref_count) || 
          atomic_read(&merge->in_tree2->write_ref_count) )
    {
        debug("Found non-zero write ref count on a tree scheduled for merge (%d, %d)\n",
                atomic_read(&merge->in_tree1->write_ref_count), 
                atomic_read(&merge->in_tree2->write_ref_count));
        msleep(10);
    }
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
    merge->merged_iter = castle_malloc(sizeof(c_merged_iter_t), GFP_KERNEL);
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
                               iter_types,
                               castle_da_each_skip);
    ret = merge->merged_iter->err;
    debug("Merged iterator inited with ret=%d.\n", ret);
    if(ret)
        goto err_out;
    
    /* Allocate an extent for merged tree for the size equal to sum of both the
     * trees. */
    BUG_ON(!castle_ext_fs_consistent(&merge->in_tree1->tree_ext_fs));
    BUG_ON(!castle_ext_fs_consistent(&merge->in_tree2->tree_ext_fs));
    size = (atomic64_read(&merge->in_tree1->tree_ext_fs.used) +
            atomic64_read(&merge->in_tree2->tree_ext_fs.used));
    BUG_ON(size % (btree->node_size * C_BLK_SIZE));
    size = MASK_CHK_OFFSET(size + C_CHK_SIZE);
    if ((ret = castle_ext_fs_init(&merge->tree_ext_fs, merge->da->id, size,
                                  (btree->node_size * C_BLK_SIZE))))
    {
        printk("Merge failed due to space constraint\n");
        goto err_out;
    }

    /* Allocate an extent for medium objects of merged tree for the size equal to 
     * sum of both the trees. */
    BUG_ON(!castle_ext_fs_consistent(&merge->in_tree1->data_ext_fs));
    BUG_ON(!castle_ext_fs_consistent(&merge->in_tree2->data_ext_fs));
    size = (atomic64_read(&merge->in_tree1->data_ext_fs.used) +
            atomic64_read(&merge->in_tree2->data_ext_fs.used));
    size = MASK_CHK_OFFSET(size + C_CHK_SIZE);
    if ((ret = castle_ext_fs_init(&merge->data_ext_fs, merge->da->id, size, 
                                  C_BLK_SIZE)))
    {
        printk("Merge failed due to space constraint\n");
        goto err_out;
    }

    /* Success */
    return 0;

err_out:
    debug("Failed to create iterators. Ret=%d\n", ret);

    BUG_ON(!ret);
    return ret;
}

static c_val_tup_t castle_da_medium_obj_copy(struct castle_da_merge *merge,
                                             c_val_tup_t old_cvt)
{
    c_ext_pos_t old_cep, new_cep;
    c_val_tup_t new_cvt;
    uint32_t i, nr_blocks;
    c2_block_t *s_c2b, *c_c2b;

    old_cep = old_cvt.cep;
    /* Old cvt needs to be a medium object. */
    BUG_ON(!CVT_MEDIUM_OBJECT(old_cvt));
    /* It needs to be of the right size. */
    BUG_ON((old_cvt.length <= MAX_INLINE_VAL_SIZE) || (old_cvt.length > MEDIUM_OBJECT_LIMIT));
    /* It must belong to one of the in_trees data extent. */
    BUG_ON((old_cvt.cep.ext_id != merge->in_tree1->data_ext_fs.ext_id) &&
           (old_cvt.cep.ext_id != merge->in_tree2->data_ext_fs.ext_id));
    /* We assume objects are page aligned. */
    BUG_ON(BLOCK_OFFSET(old_cep.offset) != 0);

    /* Allocate space for the new copy. */
    nr_blocks = (old_cvt.length - 1) / C_BLK_SIZE + 1;
    BUG_ON(castle_ext_fs_get(&merge->data_ext_fs,
                              nr_blocks * C_BLK_SIZE,
                              0,
                              &new_cep) < 0);
    BUG_ON(BLOCK_OFFSET(new_cep.offset) != 0);
    /* Save the cep to return later. */
    new_cvt = old_cvt;
    new_cvt.cep = new_cep;

    /* Do the actual copy. */
    debug("Copying "cep_fmt_str" to "cep_fmt_str_nl,
            cep2str(old_cep), cep2str(new_cep));
    for(i=0; i<nr_blocks; i++)
    {
        /* Get the block, and schedule prefetch asap. */
        s_c2b = castle_cache_page_block_get(old_cep);
        castle_cache_block_advise(s_c2b, C2B_PREFETCH_FRWD);
        c_c2b = castle_cache_page_block_get(new_cep); 
        /* Make sure that we lock _after_ prefetch call. */
        write_lock_c2b(s_c2b);
        write_lock_c2b(c_c2b);
        if(!c2b_uptodate(s_c2b))
            BUG_ON(submit_c2b_sync(READ, s_c2b));
        update_c2b(c_c2b);
        memcpy(c2b_buffer(c_c2b), c2b_buffer(s_c2b), PAGE_SIZE);
        dirty_c2b(c_c2b);
        write_unlock_c2b(c_c2b);
        write_unlock_c2b(s_c2b);
        put_c2b(c_c2b);
        put_c2b(s_c2b);
        old_cep.offset += PAGE_SIZE;
        new_cep.offset += PAGE_SIZE;
    }
    debug("Finished copy, i=%d\n", i);
    
    return new_cvt;
}

static inline void castle_da_entry_add(struct castle_da_merge *merge, 
                                       int depth,
                                       void *key, 
                                       version_t version, 
                                       c_val_tup_t cvt)
{
    struct castle_da_merge_level *level = merge->levels + depth;
    struct castle_btree_type *btree = merge->out_btree;
    struct castle_btree_node *node;
    int key_cmp;


    /* Deal with medium and large objects first. For medium objects, we need to copy them
       into our new medium object extent. For large objects, we need to save the aggregate
       size. plus take refs to extents? */
    if(CVT_MEDIUM_OBJECT(cvt))
        cvt = castle_da_medium_obj_copy(merge, cvt);
    if(CVT_LARGE_OBJECT(cvt))
    {
        merge->large_chunks += castle_extent_size_get(cvt.cep.ext_id);
        /* No need to add Large Objects under lock as merge is done in
         * sequence. No concurrency issues on the tree. */
        castle_ct_large_obj_add(cvt.cep.ext_id, cvt.length, &merge->large_objs, NULL);
        castle_extent_get(cvt.cep.ext_id);
    }

    debug("Adding an entry at depth: %d\n", depth);
    BUG_ON(depth >= MAX_BTREE_DEPTH);
    /* Alloc a new block if we need one */
    if(!level->node_c2b)
    {
        c_ext_pos_t  cep;
        
        if(merge->root_depth < depth)
        {
            debug("Creating a new root level: %d\n", depth);
            BUG_ON(merge->root_depth != depth - 1);
            merge->root_depth = depth; 
        }
        BUG_ON(level->next_idx      != 0);
        BUG_ON(level->valid_end_idx >= 0);
        debug("Allocating a new node at depth: %d\n", depth);

        BUG_ON(castle_ext_fs_get(&merge->tree_ext_fs, 
                                 (btree->node_size * C_BLK_SIZE),
                                 0, 
                                 &cep) < 0);
        debug("Got "cep_fmt_str_nl, cep2str(cep));

        level->node_c2b = castle_cache_block_get(cep, btree->node_size);
        debug("Locking the c2b, and setting it up to date.\n");
        write_lock_c2b(level->node_c2b);
        update_c2b(level->node_c2b);
        /* Init the node properly */
        node = c2b_bnode(level->node_c2b);
        castle_da_node_buffer_init(btree, node);
    }

    node = c2b_bnode(level->node_c2b);
    debug("Adding an idx=%d, key=%p, *key=%d, version=%d\n", 
            level->next_idx, key, *((uint32_t *)key), version);
    /* Add the entry to the node (this may get dropped later, but leave it here for now */
    BUG_ON(CVT_LEAF_PTR(cvt));
    btree->entry_add(node, level->next_idx, key, version, cvt);
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
        btree->entry_get(node, level->next_idx, &level->last_key, NULL, NULL);
        level->valid_version = version;
    } else
    /* Case 2: We've moved on to a new key. Previous entry is a valid node end. */
    if(key_cmp > 0)
    {
        debug("Node valid_end_idx=%d, Case2.\n", level->next_idx);
        btree->entry_get(node, level->next_idx, &level->last_key, NULL, NULL);
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
    struct castle_btree_type *btree = merge->out_btree;
    struct castle_btree_node *node, *prev_node, *buffer;
    int buffer_idx, node_idx;
    void *key;
    version_t version;
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
        btree->entry_get(node,   node_idx,  &key, &version, &cvt);
        BUG_ON(CVT_LEAF_PTR(cvt));
        btree->entry_add(buffer, buffer_idx, key, version, cvt);
        buffer_idx++;
        node_idx++;
    }
    debug("Dropping entries [%d, %d] from the original node\n",
            level->valid_end_idx + 1, node->used - 1);
    /* Now that entries are safely in the buffer, drop them from the node */ 
    if((level->valid_end_idx + 1) <= (node->used - 1))
        btree->entries_drop(node, level->valid_end_idx + 1, node->used - 1);

    BUG_ON(node->used != level->valid_end_idx + 1);
    btree->entry_get(node, level->valid_end_idx, &key, &version, &cvt);
    debug("Inserting into parent key=%p, *key=%d, version=%d, buffer->used=%d\n",
            key, *((uint32_t*)key), node->version, buffer->used);
    BUG_ON(CVT_LEAF_PTR(cvt));
 
    /* Insert correct pointer in the parent, unless we've just completed the
       root node at the end of the merge. */ 
    if(merge->completing && (merge->root_depth == depth) && (buffer->used == 0)) 
    {
        debug("Just completed the root node (depth=%d), at the end of the merge.\n",
                depth);
        goto release_node;
    }
    CVT_NODE_SET(node_cvt, (level->node_c2b->nr_pages * C_BLK_SIZE), level->node_c2b->cep);
    castle_da_entry_add(merge, depth+1, key, node->version, node_cvt);
release_node:
    debug("Releasing c2b for cep=" cep_fmt_str_nl, cep2str(level->node_c2b->cep));
    /* Write the list pointer into the previous node we've completed (if one exists).
       Then release it. */
    prev_node = merge->last_node_c2b ? c2b_bnode(merge->last_node_c2b) : NULL; 
    if(prev_node)
    {
        prev_node->next_node = level->node_c2b->cep;
        dirty_c2b(merge->last_node_c2b);
        write_unlock_c2b(merge->last_node_c2b);
        put_c2b(merge->last_node_c2b);
    } else
    {
        /* We've just created the first node, save it */
        merge->first_node = level->node_c2b->cep;
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
    int i, buffer_idx;
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

            merge->out_btree->entry_get(buffer, buffer_idx, &key, &version, &cvt);
            BUG_ON(CVT_LEAF_PTR(cvt));
            castle_da_entry_add(merge, i, key, version, cvt);
            /* Check if the node completed, it should never do */
            BUG_ON(level->next_idx < 0);
        }
        /* Buffer now consumed, reset it */
        castle_da_node_buffer_init(merge->out_btree, buffer);
    } 

    return 0;
}
   
static struct castle_component_tree* castle_da_merge_package(struct castle_da_merge *merge)
{
    struct castle_component_tree *out_tree;

    out_tree = castle_ct_alloc(merge->da, RO_VLBA_TREE_TYPE, merge->in_tree1->level + 1);
    if(!out_tree)
        return NULL;

    debug("Allocated component tree id=%d\n", out_tree->seq);
    /* Root node is the last node that gets completed, and therefore will be saved in last_node */
    out_tree->root_node = merge->last_node_c2b->cep;
    out_tree->first_node = merge->first_node;
    out_tree->last_node = INVAL_EXT_POS;

    /* Release the last node c2b */
    if(merge->last_node_c2b)
    {
        dirty_c2b(merge->last_node_c2b);
        write_unlock_c2b(merge->last_node_c2b);
        put_c2b(merge->last_node_c2b);
        merge->last_node_c2b = NULL;
    }
    
    debug("Root for that tree is: " cep_fmt_str_nl, cep2str(out_tree->root_node));
    /* Write counts out */
    atomic_set(&out_tree->ref_count, 1);
    atomic_set(&out_tree->write_ref_count, 0);
    atomic64_set(&out_tree->item_count, merge->nr_entries);
    atomic64_set(&out_tree->node_count, merge->nr_nodes);
    atomic64_set(&out_tree->large_ext_chk_cnt, merge->large_chunks);
    out_tree->tree_ext_fs = merge->tree_ext_fs;
    out_tree->data_ext_fs = merge->data_ext_fs;
    atomic64_set(&out_tree->tree_ext_fs.used, 
                 atomic64_read(&merge->tree_ext_fs.used));
    atomic64_set(&out_tree->data_ext_fs.used, 
                 atomic64_read(&merge->data_ext_fs.used));
    atomic64_set(&out_tree->tree_ext_fs.blocked, 
                 atomic64_read(&merge->tree_ext_fs.blocked));
    atomic64_set(&out_tree->data_ext_fs.blocked, 
                 atomic64_read(&merge->data_ext_fs.blocked));

    /* Add list of large objects to CT. */
    list_replace(&merge->large_objs, &out_tree->large_objs);
    merge->large_objs.prev = merge->large_objs.next = NULL;

    debug("Number of entries=%ld, number of nodes=%ld\n",
            atomic64_read(&out_tree->item_count),
            atomic64_read(&out_tree->node_count));

    /* Add the new tree to the doubling array */
    BUG_ON(merge->da->id != out_tree->da); 
    printk("Finishing merge of ct1=%d, ct2=%d, new tree=%d\n", 
            merge->in_tree1->seq, merge->in_tree2->seq, out_tree->seq);
    debug("Adding to doubling array, level: %d\n", out_tree->level);

    FAULT(MERGE_FAULT);

    CASTLE_TRANSACTION_BEGIN;

    castle_da_lock(merge->da);
    BUG_ON((merge->da->id != merge->in_tree1->da) ||
           (merge->da->id != merge->in_tree2->da));
    /* Delete the old trees from DA list (note that it may still be used by
       a lot of IOs and will only be destroyed on the last ct_put()). But
       we want to remove it from the DA straight away. The out_tree now takes
       over their functionality. */
    /* Note: Control lock works as transaction lock. DA structure modifications
     * don't race with checkpointing. */
    castle_component_tree_del(merge->da, merge->in_tree1);
    castle_component_tree_del(merge->da, merge->in_tree2);
    castle_component_tree_add(merge->da, out_tree, 0 /* not in init */);

    CASTLE_TRANSACTION_END;
    /* We are holding ref to this DA, therefore it is safe to schedule the check. */
    castle_da_unlock(merge->da);
    castle_da_merge_check(merge->da);

    return out_tree;
}

static void castle_da_max_path_complete(struct castle_da_merge *merge)
{
    struct castle_btree_type *btree = merge->out_btree;
    struct castle_btree_node *node;
    c2_block_t *root_c2b, *node_c2b, *next_node_c2b;

    BUG_ON(!merge->completing);
    /* Root stored in last_node_c2b at the end of the merge */
    root_c2b = merge->last_node_c2b;
    printk("Maxifying the right most path, starting with root_cep="cep_fmt_str_nl,
            cep2str(root_c2b->cep));
    /* Start of with root node */
    node_c2b = root_c2b;
    node = c2b_bnode(node_c2b);
    while(!node->is_leaf)
    {
        void *k;
        version_t v;
        c_val_tup_t cvt;

        /* Replace right-most entry with (k=max_key, v=0) */
        btree->entry_get(node, node->used-1, &k, &v, &cvt);
        BUG_ON(!CVT_NODE(cvt) || CVT_LEAF_PTR(cvt));
        debug("The node is non-leaf, replacing the right most entry with (max_key, 0).\n");
        btree->entry_replace(node, node->used-1, btree->max_key, 0, cvt);
        /* Change the version of the node to 0 */
        node->version = 0;
        /* Dirty the c2b */
        dirty_c2b(node_c2b);
        /* Go to the next btree node */
        debug("Locking next node cep=" cep_fmt_str_nl,
              cep2str(cvt.cep));
        next_node_c2b = castle_cache_block_get(cvt.cep, btree->node_size);
        write_lock_c2b(next_node_c2b);
        /* We unlikely to need a blocking read, because we've just had these
           nodes in the cache. */
        if(!c2b_uptodate(next_node_c2b))
            BUG_ON(submit_c2b_sync(READ, next_node_c2b));
        /* Release the old node, if it's not the same as the root node */
        if(node_c2b != root_c2b) 
        {
            debug("Unlocking prev node cep=" cep_fmt_str_nl, 
                   cep2str(node_c2b->cep));
            write_unlock_c2b(node_c2b);
            put_c2b(node_c2b);
        }
        node_c2b = next_node_c2b;
        node = c2b_bnode(node_c2b);
    }
    /* Release the leaf node, if it's not the same as the root node */
    if(node_c2b != root_c2b) 
    {
        debug("Unlocking prev node cep="cep_fmt_str_nl, 
               cep2str(node_c2b->cep));
        write_unlock_c2b(node_c2b);
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

static void castle_da_merge_dealloc(struct castle_da_merge *merge, int err)
{
    int i;

    if(!merge)
        return;

    /* Release the last node c2b */
    if(merge->last_node_c2b)
    {
        dirty_c2b(merge->last_node_c2b);
        write_unlock_c2b(merge->last_node_c2b);
        put_c2b(merge->last_node_c2b);
    }
    
    /* Free all the buffers */
    for(i=0; i<MAX_BTREE_DEPTH; i++)
    {
        c2_block_t *c2b = merge->levels[i].node_c2b;
        if(c2b)
        {
            write_unlock_c2b(c2b);
            put_c2b(c2b);
        }
        if(merge->levels[i].buffer)
            castle_vfree(merge->levels[i].buffer);
    }
    castle_da_iterator_destroy(merge->in_tree1, merge->iter1);
    castle_da_iterator_destroy(merge->in_tree2, merge->iter2);
    castle_ct_merged_iter_cancel(merge->merged_iter);
    /* If succeeded at merging, old trees need to be destroyed (they've already been removed
       from the DA by castle_da_merge_package(). */
    if(!err)
    {
        debug("Destroying old CTs.\n");
        castle_ct_put(merge->in_tree1, 0);
        castle_ct_put(merge->in_tree2, 0);
    }
    else
    {
        castle_ext_fs_fini(&merge->tree_ext_fs);
        castle_ext_fs_fini(&merge->data_ext_fs);
    }
    castle_free(merge->merged_iter);
    castle_free(merge);
}

static int castle_da_merge_progress_update(struct castle_da_merge *merge, uint32_t unit_nr)
{
    uint64_t items_completed, total_items, unit_items;
    uint32_t total_units;

    total_units = 1 << merge->level;
    /* Don't stop the last merge unit, let it run out of iterator. */
    if(unit_nr >= total_units)
        return 0;
    /* Otherwise, check whether we've got far enough. */
    total_items  = atomic64_read(&merge->in_tree1->item_count);
    total_items += atomic64_read(&merge->in_tree2->item_count);
    unit_items   = total_items * (uint64_t)unit_nr / (uint64_t)total_units;
    items_completed = merge->merged_iter->src_items_completed;
    if(items_completed >= unit_items)
        return 1;
    return 0;
}

static int castle_da_merge_unit_do(struct castle_da_merge *merge, uint32_t unit_nr)
{
    void *key;
    version_t version;
    c_val_tup_t cvt;
    int ret;

    while(castle_ct_merged_iter_has_next(merge->merged_iter))
    {
        might_resched();
        /* TODO: we never check iterator errors. We should! */
        castle_ct_merged_iter_next(merge->merged_iter, &key, &version, &cvt); 
        debug("Merging entry id=%lld: k=%p, *k=%d, version=%d, cep="cep_fmt_str_nl,
                i, key, *((uint32_t *)key), version, cep2str(cvt.cep));
        BUG_ON(CVT_INVALID(cvt));
        /* Add entry to level 0 node (and recursively up the tree). */
        castle_da_entry_add(merge, 0, key, version, cvt);
        /* Increment the number of entries stored in the output tree. */
        merge->nr_entries++;
        /* Try to complete node. */
        if((ret = castle_da_nodes_complete(merge, 0)))
            goto err_out;
        castle_da_merge_budget_consume(merge);
        /* Update the progress, returns non-zero if we've completed the current unit. */
        if(castle_da_merge_progress_update(merge, unit_nr))
            return EAGAIN;

        FAULT(MERGE_FAULT);
    }

    /* Return success, if we are finished with the merge. */
    return EXIT_SUCCESS;

err_out:
    if(ret)
        printk("Merge failed with %d\n", ret);
    castle_da_merge_dealloc(merge, ret);

    return ret; 
}

static inline uint32_t castle_da_merge_units_inc_return(struct castle_double_array *da, int level)
{
    return (++da->levels[level].merge.units_commited); 
}

static struct castle_da_merge* castle_da_merge_init(struct castle_double_array *da,
                                                    int level,
                                                    struct castle_component_tree *in_tree1,
                                                    struct castle_component_tree *in_tree2)
{
    struct castle_btree_type *btree;
    struct castle_da_merge *merge = NULL;
    int i, ret;

    debug("============ Merging ct=%d (%d) with ct=%d (%d) ============\n", 
            in_tree1->seq, in_tree1->dynamic,
            in_tree2->seq, in_tree2->dynamic);

    /* Set DA merge variables. */
    da->levels[level].merge.units_commited = 0;
    /* Make sure that the level is correct. */
    BUG_ON(in_tree1->level != level);
    BUG_ON(in_tree2->level != level);
    /* Note: There could be outstanding read/write I/O going on. */ 
    /* Work out what type of trees are we going to be merging. Bug if in_tree1/2 don't match. */
    btree = castle_btree_type_get(in_tree1->btree_type);
    BUG_ON(btree != castle_btree_type_get(in_tree2->btree_type));
    /* Malloc everything ... */
    ret = -ENOMEM;
    merge = castle_zalloc(sizeof(struct castle_da_merge), GFP_KERNEL);
    if(!merge)
        goto error_out;
    merge->da                = da;
    merge->out_btree         = castle_btree_type_get(RO_VLBA_TREE_TYPE);
    merge->level             = level;
    merge->in_tree1          = in_tree1;
    merge->in_tree2          = in_tree2;
    merge->root_depth        = -1;
    merge->last_node_c2b     = NULL;
    merge->first_node        = INVAL_EXT_POS;
    merge->completing        = 0;
    merge->nr_entries        = 0;
    merge->nr_nodes          = 0;
    merge->large_chunks      = 0;
    merge->budget_cons_rate  = 1; 
    merge->budget_cons_units = 0; 
    for(i=0; i<MAX_BTREE_DEPTH; i++)
    {
        merge->levels[i].buffer        = castle_vmalloc(btree->node_size * C_BLK_SIZE);
        if(!merge->levels[i].buffer)
            goto error_out;
        castle_da_node_buffer_init(btree, merge->levels[i].buffer);
        merge->levels[i].last_key      = NULL; 
        merge->levels[i].next_idx      = 0; 
        merge->levels[i].valid_end_idx = -1; 
        merge->levels[i].valid_version = INVAL_VERSION;  
    }
    merge->tree_ext_fs.ext_id = INVAL_EXT_ID;
    merge->data_ext_fs.ext_id = INVAL_EXT_ID;
    INIT_LIST_HEAD(&merge->large_objs);

    ret = castle_da_iterators_create(merge);
    if(ret)
        goto error_out;
    
    return merge;

error_out:
    BUG_ON(!ret);
    castle_da_merge_dealloc(merge, ret);
    printk("Failed a merge with ret=%d\n", ret);

    return NULL;
}


static int castle_da_merge_run(void *da_p)
{
    struct castle_double_array *da = (struct castle_double_array *)da_p;
    struct castle_component_tree *in_tree1, *in_tree2, *out_tree;
    struct castle_da_merge *merge;
    struct list_head *l;
    int level, ret;

#define exit_cond (castle_da_exiting || castle_da_deleted(da))
    /* Work out the level at which we are supposed to be doing merges.
       Do that by working out where is this thread in threads array. */
    for(level=1; level<MAX_DA_LEVEL; level++)
        if(da->levels[level].merge.thread == current)
            break;
    BUG_ON(level >= MAX_DA_LEVEL);
    printk("Starting merge thread for DA=%d, level=%d\n", da->id, level);
    do {
        /* Wait for 2+ trees to appear at this level. */
        wait_event(da->merge_waitq, exit_cond || (da->levels[level].nr_trees >= 2));
        /* Exit without doing a merge, if we are stopping execution, or da has been deleted. */ 
        if(exit_cond)
            break;

        /* Otherwise do a merge. */
        in_tree1 = in_tree2 = NULL;
        castle_da_lock(da);
        list_for_each_prev(l, &da->levels[level].trees)
        {
            if(!in_tree2)
                in_tree2 = list_entry(l, struct castle_component_tree, da_list);
            else
            if(!in_tree1)
                in_tree1 = list_entry(l, struct castle_component_tree, da_list);
        }
        castle_da_unlock(da);
        /* We should only get here, if we are supposed to do a merge => we have in_trees. */
        BUG_ON(!in_tree1 || !in_tree2);
            
        printk("Doing merge for DA=%d, level=%d\n", da->id, level);
        perf_event("m-%d-beg", level);
        merge = castle_da_merge_init(da, level, in_tree1, in_tree2);
        if(!merge)
        {
            printk("Could not start a merge for DA=%d, level=%d.\n", da->id, level);
            /* Retry after 10s. */
            msleep(10000);
            continue;
        }
        
        /* Do the merge. */
        do {
            uint32_t units_cnt;
           
            units_cnt = castle_da_merge_units_inc_return(da, level);
            ret = castle_da_merge_unit_do(merge, units_cnt);
            if(ret < 0)
                goto merge_failed;
            /* Only ret>0 we are expecting is to continue, i.e. EAGAIN. */
            BUG_ON(ret && (ret != EAGAIN));
        } while(ret);
        /* Package up the merge into the new tree. */
        out_tree = castle_da_merge_complete(merge);
        if(!out_tree)
            ret = -EINVAL;
merge_failed:
        castle_da_merge_dealloc(merge, ret);
        perf_event("m-%d-end", level);
        printk("Done merge for DA=%d, level=%d\n", da->id, level);
        if(ret)
        {
            printk("Merge for DA=%d, level=%d, failed to merge err=%d.\n", da->id, level, ret);
            /* Retry after 10s. */
            msleep(10000);
        }
    } while(1);

    printk("Merge thread for DA=%d, at level=%d exiting.\n", da->id, level);

    castle_da_lock(da);
    /* Remove ourselves from the da merge threads array to indicate that we are finished. */  
    da->levels[level].merge.thread = NULL;
    castle_da_unlock(da);
    /* castle_da_alloc() took a reference for us, we have to drop it now. */
    castle_da_put(da);

    return 0;
}

static int castle_da_merge_stop(struct castle_double_array *da, void *unused)
{
    int i;

    /* castle_da_exiting should have been set by now. */
    BUG_ON(!castle_da_exiting);
    wake_up(&da->merge_waitq);
    for(i=1; i<MAX_DA_LEVEL; i++)
    {
        while(da->levels[i].merge.thread)
            msleep(10);
        printk("Stopped merge thread for DA=%d, level=%d\n", da->id, i);
    }

    return 0;
}

static int castle_da_merge_restart(struct castle_double_array *da, void *unused)
{
    printk("Restarting merge for DA=%d\n", da->id);
    wake_up(&da->merge_waitq);

    return 0;
}

static void castle_da_merge_check(struct castle_double_array *da)
{
    struct list_head *l;
    int max_level, max_level_mergable, level, merge_measure, merge_measure_threashold, nr_trees;

    BUG_ON(castle_da_is_locked(da));
    debug("Checking if to do a merge for da: %d\n", da->id);
    printk("Checking if to do a merge for da: %d\n", da->id);
    merge_measure = 0;
    merge_measure_threashold = 0;
    max_level = 0;
    max_level_mergable = 0;

    castle_da_lock(da);
    for(level=1; level<MAX_DA_LEVEL; level++)
    {
        nr_trees = 0;
        list_for_each_prev(l, &da->levels[level].trees)
        {
            /* max_level == level iff there are at least 2 trees at this level. 
               This means that max_level is mergable. */
            max_level_mergable = (max_level == level);
            max_level = level;
            nr_trees++;
        }
        /* Merge measure for the level (non-zero iff there is at least one outstanding merge). */
        if(nr_trees > 1)
            merge_measure        += level * nr_trees * nr_trees;
        /* We stop when there is an outstanding merge at each level. */
        merge_measure_threashold += level * 4; 
    }
    /* Set the max merge level variable. This either equals to max_level, if it is mergable,
       or max_level-1 otherwise. */
    da->max_merge_level = max_level_mergable ? max_level : max_level - 1;
    /* Set the write throughput allowed on the DA. */
    if(merge_measure == 0)
    {
        if(da->ios_rate == 0)
            printk("Reenabling inserts on da=%d.\n", da->id);
        /* Effectively no limit. */
        da->ios_rate = (uint32_t)-1;   
    } 
    else
    if(merge_measure < merge_measure_threashold)
    {
        uint32_t old_rate = da->ios_rate;
        /* Constant of 50000 was chosen to give 1M ios rate for a single 
           outstanding level 1 merge. */
        da->ios_rate = 50000 * (merge_measure_threashold / merge_measure - 1) / REPLENISH_FREQUENCY;
        if((old_rate == 0) && (da->ios_rate != 0))
            printk("Reenabling inserts on da=%d.\n", da->id);
        if((old_rate != 0) && (da->ios_rate == 0))
            printk("Disabling inserts on da=%d.\n", da->id);
    }
    else
    {
        if(da->ios_rate != 0)
            printk("Disabling inserts on da=%d\n\n", da->id);
        da->ios_rate = 0;
    }
    debug("Setting rate to %u\n", da->ios_rate);
    castle_da_unlock(da);

    castle_da_merge_restart(da, NULL);
}

/**********************************************************************************************/
/* Generic DA code */

static inline void castle_da_lock(struct castle_double_array *da)
{
    spin_lock(&da->lock);
}

static inline void castle_da_unlock(struct castle_double_array *da)
{
    spin_unlock(&da->lock);
}

static inline int castle_da_is_locked(struct castle_double_array *da)
{
    return spin_is_locked(&da->lock);
}

static int castle_da_ct_dec_cmp(struct list_head *l1, struct list_head *l2)
{
    struct castle_component_tree *ct1 = list_entry(l1, struct castle_component_tree, da_list);
    struct castle_component_tree *ct2 = list_entry(l2, struct castle_component_tree, da_list);
    BUG_ON(ct1->seq == ct2->seq);

    return ct1->seq > ct2->seq ? -1 : 1;
}

static struct castle_double_array* castle_da_alloc(da_id_t da_id)
{
    struct castle_double_array *da;
    int i;

    da = castle_zalloc(sizeof(struct castle_double_array), GFP_KERNEL); 
    if(!da)
        return NULL; 

    printk("Allocating DA=%d\n", da_id);
    da->id              = da_id; 
    da->root_version    = INVAL_VERSION;
    spin_lock_init(&da->lock);
    da->flags           = 0;
    da->nr_trees        = 0;
    atomic_set(&da->ref_cnt, 1);
    da->attachment_cnt  = 0;
    INIT_LIST_HEAD(&da->ios_waiting);
    da->ios_waiting_cnt = 0;
    da->ios_budget      = 0;
    da->ios_rate        = 0;
    CASTLE_INIT_WORK(&da->queue_restart, castle_da_queue_restart);
    da->max_merge_level = -1;
    atomic_set(&da->epoch_ios, 0);
    atomic_set(&da->merge_budget, 0);
    init_waitqueue_head(&da->merge_waitq);
    init_waitqueue_head(&da->merge_budget_waitq);
    for(i=0; i<MAX_DA_LEVEL; i++)
    {
        INIT_LIST_HEAD(&da->levels[i].trees);
        da->levels[i].nr_trees             = 0;
        da->levels[i].merge.units_commited = 0;
        da->levels[i].merge.thread         = NULL;
        /* Create merge threads, and take da ref for all levels >= 1. */
        if(i>0)
        {
            castle_da_get(da);
            da->levels[i].merge.thread = 
                kthread_create(castle_da_merge_run, da, "castle-m-%d-%.2d", da_id, i);
            if(!da->levels[i].merge.thread)
                goto err_out;
        }
    }
    printk("Allocated DA=%d successfully.\n", da_id);
    /* Start all of the merge threads. */
    for(i=1; i<MAX_DA_LEVEL; i++)
        wake_up_process(da->levels[i].merge.thread);

    return da;

err_out:
    for(i--; i>0; i--)
    {
        kthread_stop(da->levels[i].merge.thread);
        /* Doesn't really need to be done, since we are going to free the structure anyway. */
        BUG_ON(atomic_read(&da->ref_cnt) < 2);
        castle_da_put(da);
    }
    castle_free(da);

    return NULL;
}

void castle_da_marshall(struct castle_dlist_entry *dam,
                        struct castle_double_array *da)
{
    dam->id           = da->id;
    dam->root_version = da->root_version;
}
 
static void castle_da_unmarshall(struct castle_double_array *da,
                                 struct castle_dlist_entry *dam)
{
    da->id           = dam->id;
    da->root_version = dam->root_version;
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
    BUG_ON(!castle_da_is_locked(da));
    BUG_ON(!CASTLE_IN_TRANSACTION);
    /* If there is something on the list, check that the sequence number 
       of the tree we are inserting is greater (i.e. enforce rev seq number
       ordering in component trees in a given level). Don't check that during
       init (when we are storting the trees afterwards). */
    if(!in_init && !list_empty(&da->levels[ct->level].trees))
    {
        next_ct = list_entry(da->levels[ct->level].trees.next, 
                             struct castle_component_tree,
                             da_list);
        BUG_ON(next_ct->seq >= ct->seq);
    }
    list_add(&ct->da_list, &da->levels[ct->level].trees);
    da->levels[ct->level].nr_trees++;
    da->nr_trees++;
}

static void castle_component_tree_del(struct castle_double_array *da,
                                      struct castle_component_tree *ct)
{
    BUG_ON(da->id != ct->da);
    BUG_ON(!castle_da_is_locked(da));
    BUG_ON(!CASTLE_IN_TRANSACTION);
   
    list_del(&ct->da_list); 
    ct->da_list.next = NULL;
    ct->da_list.prev = NULL;
    da->levels[ct->level].nr_trees--;
    da->nr_trees--;
}

static void castle_ct_large_obj_writeback(struct castle_large_obj_entry *lo, 
                                          struct castle_component_tree *ct)
{
    struct castle_lolist_entry mstore_entry;

    mstore_entry.ext_id = lo->ext_id;
    mstore_entry.length = lo->length;
    mstore_entry.ct_seq = ct->seq;

    castle_mstore_entry_insert(castle_lo_store, &mstore_entry);
}

static void castle_ct_large_objs_remove(struct castle_component_tree *ct)
{
    struct list_head *lh, *tmp;

    list_for_each_safe(lh, tmp, &ct->large_objs)
    {
        struct castle_large_obj_entry *lo = 
                            list_entry(lh, struct castle_large_obj_entry, list);

        /* No need of locks as it is done in the removal context of CT. */
        list_del(&lo->list);
        castle_extent_put(lo->ext_id);
        castle_free(lo);
    }
}

int castle_ct_large_obj_add(c_ext_id_t              ext_id, 
                            uint64_t                length, 
                            struct list_head       *head,
                            struct mutex           *mutex)
{
    struct castle_large_obj_entry *lo;

    if (EXT_ID_INVAL(ext_id))
        return -EINVAL;

    lo = castle_malloc(sizeof(struct castle_large_obj_entry), GFP_KERNEL);
    if (!lo)
        return -ENOMEM;

    lo->ext_id = ext_id;
    lo->length = length;

    if (mutex) mutex_lock(mutex);
    list_add(&lo->list, head);
    if (mutex) mutex_unlock(mutex);

    return 0;
}

/* Note: Should be called with castle_da_lock held. */
void castle_ct_get(struct castle_component_tree *ct, int write)
{
    atomic_inc(&ct->ref_count);
    if(write)
        atomic_inc(&ct->write_ref_count);
}

void castle_ct_put(struct castle_component_tree *ct, int write)
{
    BUG_ON(in_atomic());
    if(write)
        atomic_dec(&ct->write_ref_count);

    if(likely(!atomic_dec_and_test(&ct->ref_count)))
        return;

    debug("Ref count for ct id=%d went to 0, releasing.\n", ct->seq);
    /* If the ct still on the da list, this must be an error. */
    if(ct->da_list.next != NULL)
    {
        printk("CT=%d, still on DA list, but trying to remove.\n", ct->seq);
        BUG();
    }
    /* Destroy the component tree */
    BUG_ON(TREE_GLOBAL(ct->seq) || TREE_INVAL(ct->seq));
    castle_ct_hash_remove(ct);

    printk("Releasing freespace occupied by ct=%d\n", ct->seq);
    /* Freeing all large objects. */
    castle_ct_large_objs_remove(ct);

    if (!EXT_ID_INVAL(ct->tree_ext_fs.ext_id))
        castle_extent_free(ct->tree_ext_fs.ext_id);
    if (!EXT_ID_INVAL(ct->data_ext_fs.ext_id))
        castle_extent_free(ct->data_ext_fs.ext_id);

    /* Poison ct (note this will be repoisoned by kfree on kernel debug build. */
    memset(ct, 0xde, sizeof(struct castle_component_tree));
    castle_free(ct);
}

static int castle_da_trees_sort(struct castle_double_array *da, void *unused)
{
    int i;

    castle_da_lock(da);
    for(i=0; i<MAX_DA_LEVEL; i++)
        list_sort(&da->levels[i].trees, castle_da_ct_dec_cmp);
    castle_da_unlock(da);

    return 0;
}

void castle_da_ct_marshall(struct castle_clist_entry *ctm,
                           struct castle_component_tree *ct)
{
    ctm->da_id       		= ct->da; 
    ctm->item_count  		= atomic64_read(&ct->item_count);
    ctm->btree_type  		= ct->btree_type; 
    ctm->dynamic     		= ct->dynamic;
    ctm->seq         		= ct->seq;
    ctm->level       		= ct->level;
    ctm->tree_depth  		= ct->tree_depth;
    ctm->root_node   		= ct->root_node;
    ctm->first_node  		= ct->first_node;
    ctm->last_node   		= ct->last_node;
    ctm->node_count  		= atomic64_read(&ct->node_count);
    ctm->large_ext_chk_cnt	= atomic64_read(&ct->large_ext_chk_cnt);

    castle_ext_fs_marshall(&ct->tree_ext_fs, &ctm->tree_ext_fs_bs);
    castle_ext_fs_marshall(&ct->data_ext_fs, &ctm->data_ext_fs_bs);
}

static da_id_t castle_da_ct_unmarshall(struct castle_component_tree *ct,
                                       struct castle_clist_entry *ctm)
{
    ct->seq         		= ctm->seq;
    atomic_set(&ct->ref_count, 1);
    atomic_set(&ct->write_ref_count, 0);
    atomic64_set(&ct->item_count, ctm->item_count);
    ct->btree_type  		= ctm->btree_type; 
    ct->dynamic     		= ctm->dynamic;
    ct->da          		= ctm->da_id; 
    ct->level       		= ctm->level;
    ct->tree_depth  		= ctm->tree_depth;
    ct->root_node   		= ctm->root_node;
    ct->first_node  		= ctm->first_node;
    ct->last_node   		= ctm->last_node;
    ct->new_ct              = 0;
    atomic64_set(&ct->large_ext_chk_cnt, ctm->large_ext_chk_cnt);
    init_rwsem(&ct->lock);
    mutex_init(&ct->lo_mutex);
    atomic64_set(&ct->node_count, ctm->node_count);
    castle_ext_fs_unmarshall(&ct->tree_ext_fs, &ctm->tree_ext_fs_bs);
    castle_ext_fs_unmarshall(&ct->data_ext_fs, &ctm->data_ext_fs_bs);
    castle_extent_mark_live(ct->tree_ext_fs.ext_id);
    castle_extent_mark_live(ct->data_ext_fs.ext_id);
    ct->da_list.next = NULL;
    ct->da_list.prev = NULL;
    INIT_LIST_HEAD(&ct->large_objs);

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
        list_for_each_safe(lh, t, &da->levels[i].trees)
        {
            ct = list_entry(lh, struct castle_component_tree, da_list); 
            if(fn(da, ct, j, token))
            {
                goto out;
                return;
            }
            j++;
        }
    }
out:
    castle_da_unlock(da);
}

static int castle_ct_hash_destroy_check(struct castle_component_tree *ct, void *ct_hash)
{
    struct list_head *lh, *t;
    int    err = 0;

    /* Only the global component tree should remain when we destroy DA hash. */ 
    if(((unsigned long)ct_hash > 0) && !TREE_GLOBAL(ct->seq))
    {
        printk("Error: Found CT=%d not on any DA's list, it claims DA=%d\n", 
            ct->seq, ct->da);
        err = -1;
    }

   /* All CTs apart of global are expected to be on a DA list. */
   if(!TREE_GLOBAL(ct->seq) && (ct->da_list.next == NULL))
   {
       printk("Error: CT=%d is not on DA list, for DA=%d\n", 
               ct->seq, ct->da);
       err = -2;
   }

   if(TREE_GLOBAL(ct->seq) && (ct->da_list.next != NULL))
   {
       printk("Error: Global CT=%d is on DA list, for DA=%d\n", 
               ct->seq, ct->da);
       err = -3;
   }

   /* Ref count should be 1 by now. */
   if(atomic_read(&ct->ref_count) != 1)
   {
       printk("Error: Bogus ref count=%d for ct=%d, da=%d when exiting.\n", 
               atomic_read(&ct->ref_count), ct->seq, ct->da);
       err = -4;
   }

   BUG_ON(err);

   /* Free large object structures. */
   list_for_each_safe(lh, t, &ct->large_objs)
   {
       struct castle_large_obj_entry *lo = 
                list_entry(lh, struct castle_large_obj_entry, list);
       list_del(lh);
       castle_free(lo);
   }
   
    return 0;
}

static int castle_da_ct_dealloc(struct castle_double_array *da,
                                struct castle_component_tree *ct,
                                int level_cnt,
                                void *unused)
{
    castle_ct_hash_destroy_check(ct, (void*)0UL);
    list_del(&ct->da_list);
    list_del(&ct->hash_list);
    castle_free(ct);

    return 0;
}

static int castle_da_hash_dealloc(struct castle_double_array *da, void *unused) 
{
    castle_da_foreach_tree(da, castle_da_ct_dealloc, NULL);
    list_del(&da->hash_list);
    castle_free(da);

    return 0;
}

static void castle_da_hash_destroy(void)
{
   castle_da_hash_iterate(castle_da_hash_dealloc, NULL); 
   castle_free(castle_da_hash);
}

static void castle_ct_hash_destroy(void)
{
    castle_ct_hash_iterate(castle_ct_hash_destroy_check, (void *)1UL);
    castle_free(castle_ct_hash);
}

static int castle_da_tree_writeback(struct castle_double_array *da,
                                    struct castle_component_tree *ct,
                                    int level_cnt,
                                    void *unused)
{
    struct castle_clist_entry mstore_entry;
    struct list_head *lh, *tmp;

    /* For periodic checkpoints flush component trees onto disk. */
    if (!castle_da_exiting)
    {
        /* Always writeback Global tree structure but, dont writeback. */
        /* Note: Global Tree is not Crash-Consistent. */
        if (TREE_GLOBAL(ct->seq))
            goto mstore_writeback;

        /* Don't write back T0. */
        if (ct->level == 0)
            return 0;

        /* Don't write back trees with outstanding writes. */
        if (atomic_read(&ct->write_ref_count) != 0)
            return 0;

        /* Mark new trees for flush. */
        if (ct->new_ct)
        {
            /* Schedule flush of new CT onto disk. */
            castle_cache_extent_flush_schedule(ct->tree_ext_fs.ext_id, 0,
                                               atomic64_read(&ct->tree_ext_fs.used));
            castle_cache_extent_flush_schedule(ct->data_ext_fs.ext_id, 0,
                                               atomic64_read(&ct->data_ext_fs.used));
            ct->new_ct = 0;
        }
    }

mstore_writeback:

    /* Never writeback T0 in periodic checkpoints. */
    BUG_ON((ct->level == 0) && !castle_da_exiting);

    if (da) castle_da_unlock(da);

    mutex_lock(&ct->lo_mutex);
    list_for_each_safe(lh, tmp, &ct->large_objs)
    {
        struct castle_large_obj_entry *lo = 
                            list_entry(lh, struct castle_large_obj_entry, list);

        castle_ct_large_obj_writeback(lo, ct);
    }
    mutex_unlock(&ct->lo_mutex);

    castle_da_ct_marshall(&mstore_entry, ct); 
    castle_mstore_entry_insert(castle_tree_store, &mstore_entry);

    if (da) castle_da_lock(da);

    return 0;
}

static int castle_da_writeback(struct castle_double_array *da, void *unused) 
{
    struct castle_dlist_entry mstore_dentry;

    castle_da_marshall(&mstore_dentry, da);

    /* We get here with hash spinlock held. But since we're calling sleeping functions
       we need to drop it. Hash consitancy is guaranteed, because by this point 
       noone should be modifying it anymore */
    spin_unlock_irq(&castle_da_hash_lock);

    castle_da_foreach_tree(da, castle_da_tree_writeback, NULL);

    debug("Inserting a DA id=%d\n", da->id);
    castle_mstore_entry_insert(castle_da_store, &mstore_dentry);

    spin_lock_irq(&castle_da_hash_lock);

    return 0;
}

void castle_double_arrays_writeback(void)
{
    BUG_ON(castle_da_store || castle_tree_store || castle_lo_store);

    castle_da_store   = castle_mstore_init(MSTORE_DOUBLE_ARRAYS,
                                         sizeof(struct castle_dlist_entry));
    castle_tree_store = castle_mstore_init(MSTORE_COMPONENT_TREES,
                                         sizeof(struct castle_clist_entry));
    castle_lo_store   = castle_mstore_init(MSTORE_LARGE_OBJECTS,
                                         sizeof(struct castle_lolist_entry));

    if(!castle_da_store || !castle_tree_store || !castle_lo_store)
        goto out;

    castle_da_hash_iterate(castle_da_writeback, NULL); 
    castle_da_tree_writeback(NULL, &castle_global_tree, -1, NULL);

out:
    if (castle_lo_store)    castle_mstore_fini(castle_lo_store);
    if (castle_tree_store)  castle_mstore_fini(castle_tree_store);
    if (castle_da_store)    castle_mstore_fini(castle_da_store);

    castle_da_store = castle_tree_store = castle_lo_store = NULL;
}

static int castle_da_rwct_make(struct castle_double_array *da, int in_tran);

static int castle_da_t0_create(struct castle_double_array *da, void *unused)
{
    castle_da_lock(da);
    if (list_empty(&da->levels[0].trees))
    {
        castle_da_unlock(da);
        printk("Creating new T0 for da: %u\n", da->id);
        if (castle_da_rwct_make(da, 1))
        {
            printk("Failed to create T0 for DA: %u\n", da->id);
            return -EINVAL;
        }
        printk("Done with T0\n");

        return 0;
    }
    castle_da_unlock(da);

    return 0;
}

int castle_double_array_start(void)
{
    /* Create T0, if it doesn't exist. */
    castle_da_hash_iterate(castle_da_t0_create, NULL);

    /* Check if any merges need to be done. */
    castle_da_hash_iterate(castle_da_merge_restart, NULL); 

    return 0;
}

int castle_double_array_read(void)
{
    struct castle_dlist_entry mstore_dentry;
    struct castle_clist_entry mstore_centry;
    struct castle_lolist_entry mstore_loentry;
    struct castle_mstore_iter *iterator = NULL;
    struct castle_component_tree *ct;
    struct castle_double_array *da;
    c_mstore_key_t key;
    da_id_t da_id;
    int ret = 0;

    castle_da_store   = castle_mstore_open(MSTORE_DOUBLE_ARRAYS,
                                         sizeof(struct castle_dlist_entry));
    castle_tree_store = castle_mstore_open(MSTORE_COMPONENT_TREES,
                                         sizeof(struct castle_clist_entry));
    castle_lo_store   = castle_mstore_open(MSTORE_LARGE_OBJECTS,
                                         sizeof(struct castle_lolist_entry));

    if(!castle_da_store || !castle_tree_store || !castle_lo_store)
        goto error_out;
    
    /* Read doubling arrays */
    iterator = castle_mstore_iterate(castle_da_store);
    if(!iterator)
        goto error_out;

    while(castle_mstore_iterator_has_next(iterator))
    {
        castle_mstore_iterator_next(iterator, &mstore_dentry, &key);
        da = castle_da_alloc(mstore_dentry.id); 
        if(!da) 
            goto error_out;
        castle_da_unmarshall(da, &mstore_dentry);
        castle_da_hash_add(da);
        debug("Read DA id=%d\n", da->id);
        castle_next_da_id = (da->id >= castle_next_da_id) ? da->id + 1 : castle_next_da_id;
    }
    castle_mstore_iterator_destroy(iterator);

    /* Read component trees */
    iterator = castle_mstore_iterate(castle_tree_store);
    if(!iterator)
        goto error_out;
   
    while(castle_mstore_iterator_has_next(iterator))
    {
        castle_mstore_iterator_next(iterator, &mstore_centry, &key);
        /* Special case for castle_global_tree, it doesn't have a da associated with it. */
        if(TREE_GLOBAL(mstore_centry.seq))
        {
            da_id = castle_da_ct_unmarshall(&castle_global_tree, &mstore_centry);
            BUG_ON(!DA_INVAL(da_id));
            castle_ct_hash_add(&castle_global_tree);
            continue;
        }
        /* Otherwise allocate a ct structure */
        ct = castle_malloc(sizeof(struct castle_component_tree), GFP_KERNEL);
        if(!ct)
            goto error_out;
        da_id = castle_da_ct_unmarshall(ct, &mstore_centry);
        castle_ct_hash_add(ct);
        da = castle_da_hash_get(da_id);
        if(!da)
            goto error_out;
        debug("Read CT seq=%d\n", ct->seq);
        castle_da_lock(da);
        castle_component_tree_add(da, ct, 1 /* in init */);
        castle_da_unlock(da);
        castle_next_tree_seq = (ct->seq >= castle_next_tree_seq) ? ct->seq + 1 : castle_next_tree_seq;
    }
    castle_mstore_iterator_destroy(iterator);
    iterator = NULL;
    debug("castle_next_da_id = %d, castle_next_tree_id=%d\n", 
            castle_next_da_id, 
            castle_next_tree_seq);

    /* Read all Large Objects lists. */
    iterator = castle_mstore_iterate(castle_lo_store);
    if(!iterator)
        goto error_out;

    while(castle_mstore_iterator_has_next(iterator))
    {
        struct castle_component_tree *ct;

        castle_mstore_iterator_next(iterator, &mstore_loentry, &key);
        ct = castle_component_tree_get(mstore_loentry.ct_seq);
        if (!ct)
        {
            printk("Found zombi Large Object(%llu, %u)\n",
                    mstore_loentry.ext_id, mstore_loentry.ct_seq);
            BUG();
        }
        if (castle_ct_large_obj_add(mstore_loentry.ext_id,
                                    mstore_loentry.length,
                                    &ct->large_objs, NULL))
        {
            printk("Failed to add Large Object %llu to CT: %u\n", 
                    mstore_loentry.ext_id,
                    mstore_loentry.ct_seq);
            goto error_out;
        }
        castle_extent_mark_live(mstore_loentry.ext_id);
    }
    castle_mstore_iterator_destroy(iterator);
    iterator = NULL;

    /* Sort all the tree lists by the sequence number */
    castle_da_hash_iterate(castle_da_trees_sort, NULL); 
    goto out;

error_out:
    /* The doubling arrays we've created so far should be destroyed by the module fini code. */
    ret = -EINVAL;
out:
    if (iterator)           castle_mstore_iterator_destroy(iterator);
    if (castle_da_store)    castle_mstore_fini(castle_da_store);
    if (castle_tree_store)  castle_mstore_fini(castle_tree_store);
    if (castle_lo_store)    castle_mstore_fini(castle_lo_store);
    castle_da_store = castle_tree_store = castle_lo_store = NULL;
    
    return ret;
}

static struct castle_component_tree* castle_ct_alloc(struct castle_double_array *da, 
                                                     btree_t type,  
                                                     int level)
{
    struct castle_component_tree *ct;

    BUG_ON((type != RO_VLBA_TREE_TYPE) && (type != RW_VLBA_TREE_TYPE));
    ct = castle_zalloc(sizeof(struct castle_component_tree), GFP_KERNEL); 
    if(!ct) 
        return NULL;
    
    /* Allocate an id for the tree, init the ct. */
    ct->seq         = castle_next_tree_seq++;
    atomic_set(&ct->ref_count, 1);
    atomic_set(&ct->write_ref_count, 0);
    atomic64_set(&ct->item_count, 0); 
    atomic64_set(&ct->large_ext_chk_cnt, 0);
    ct->btree_type  = type; 
    ct->dynamic     = type == RW_VLBA_TREE_TYPE ? 1 : 0;
    ct->da          = da->id;
    ct->level       = level;
    ct->tree_depth  = -1;
    ct->root_node   = INVAL_EXT_POS;
    ct->first_node  = INVAL_EXT_POS;
    ct->last_node   = INVAL_EXT_POS;
    ct->new_ct      = 1;
    init_rwsem(&ct->lock);
    mutex_init(&ct->lo_mutex);
    atomic64_set(&ct->node_count, 0); 
    ct->da_list.next = NULL;
    ct->da_list.prev = NULL;
    INIT_LIST_HEAD(&ct->hash_list);
    INIT_LIST_HEAD(&ct->large_objs);
    castle_ct_hash_add(ct);
    ct->tree_ext_fs.ext_id = INVAL_EXT_ID;
    ct->data_ext_fs.ext_id = INVAL_EXT_ID;

    return ct;
}
    
static int castle_da_rwct_make(struct castle_double_array *da, int in_tran)
{
    struct castle_component_tree *ct, *old_ct;
    c2_block_t *c2b;
    int ret;
    struct castle_btree_type *btree;

    /* Only allow one rwct_make() at any point in time. If we fail to acquire the bit lock
       wait for whoever is doing it, to create the RWCT.
       TODO: use bit wait instead of msleep here. */ 
    if(castle_da_growing_rw_test_and_set(da))
    {
        debug("Racing RWCT make on da=%d\n", da->id);
        while(castle_da_growing_rw_test(da))
            msleep(1);
        return -EAGAIN; 
    }

    /* We've acquired the 'growing' lock. Proceed. */
    ret = -ENOMEM;
    ct = castle_ct_alloc(da, RW_VLBA_TREE_TYPE, 0 /* level */);
    if(!ct)
        goto out;

    btree = castle_btree_type_get(ct->btree_type);
    if ((ret = castle_ext_fs_init(&ct->tree_ext_fs, 
                                  da->id, 
                                  MAX_DYNAMIC_TREE_SIZE * C_CHK_SIZE, 
                                  btree->node_size * C_BLK_SIZE)))
        goto error;

    if ((ret = castle_ext_fs_init(&ct->data_ext_fs, 
                                  da->id, 
                                  MAX_DYNAMIC_DATA_SIZE * C_CHK_SIZE, 
                                  C_BLK_SIZE)))
        goto error;

    /* Create a root node for this tree, and update the root version */
    c2b = castle_btree_node_create(0, 1 /* is_leaf */, ct, 0);
    castle_btree_node_save_prepare(ct, c2b->cep);
    ct->root_node = c2b->cep;
    ct->tree_depth = 1;
    write_unlock_c2b(c2b);
    put_c2b(c2b);
    debug("Added component tree seq=%d, root_node="cep_fmt_str", it's threaded onto da=%p, level=%d\n",
            ct->seq, cep2str(c2b->cep), da, ct->level);
    /* Move the last rwct (if one exists) to level 1 */
    if (!in_tran) CASTLE_TRANSACTION_BEGIN;
    castle_da_lock(da);
    if(!list_empty(&da->levels[0].trees))
    {
        old_ct = list_entry(da->levels[0].trees.next, struct castle_component_tree, da_list);
        castle_component_tree_del(da, old_ct);
        old_ct->level = 1;
        castle_component_tree_add(da, old_ct, 0 /* not in init */);
    }
    /* Thread CT onto level 0 list */
    castle_component_tree_add(da, ct, 0 /* not in init */);

    FAULT(MERGE_FAULT);

    if (!in_tran) CASTLE_TRANSACTION_END;
    /* DA is attached, therefore we must be holding a ref, therefore it is safe to schedule
       the merge check. */
    castle_da_unlock(da);
    castle_da_merge_check(da);
    ret = 0;
    goto out;

error:
    if (ct)
        castle_ct_put(ct, 0);
out:
    castle_da_growing_rw_clear(da);
    return ret;
}

int castle_double_array_make(da_id_t da_id, version_t root_version)
{
    struct castle_double_array *da;
    int ret;

    debug("Creating doubling array for da_id=%d, version=%d\n", da_id, root_version);
    da = castle_da_alloc(da_id);
    if(!da)
        return -ENOMEM;
    /* Write out the id, and the root version. */
    da->id = da_id;
    da->root_version = root_version;
    /* Make RW tree. */
    ret = castle_da_rwct_make(da, 1);
    if(ret)
    {
        printk("Exiting from failed ct create.\n");
        castle_free(da);
        
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
    /* Start from the current list, from wherever the current ct is in the da_list. */
    level = ct->level;
    ct_list = &ct->da_list;
    /* CT may have got removed from the DA (da_list is NULL-ified then).
       We can then safely move on to the next level, because merge always 
       removes two _oldest_ trees. So there are no trees in the current level
       for us to inspect. */
    if(ct_list->next == NULL)
    {
        BUG_ON(ct_list->prev != NULL);
        /* Advance to the next level. */
        level++;
        ct_list = &da->levels[level].trees;
    }
    /* Loop through all levels trying to find a tree. */
    while(level < MAX_DA_LEVEL)
    {
        if(!list_is_last(ct_list, &da->levels[level].trees))
        {
            next_ct = list_entry(ct_list->next, struct castle_component_tree, da_list); 
            debug_verbose("Found component tree %d\n", next_ct->seq);
            castle_ct_get(next_ct, 0);
            castle_da_unlock(da);

            return next_ct;
        }
        /* Advance to the next level. */
        level++;
        ct_list = &da->levels[level].trees;
    }     
    castle_da_unlock(da);

    return NULL;
}

static struct castle_component_tree* castle_da_rwct_get(struct castle_double_array *da, 
                                                        int write)
{
    struct castle_component_tree *ct;
    struct list_head *h, *l;

    castle_da_lock(da);
    h = &da->levels[0].trees; 
    l = h->next; 
    /* There should be precisely one entry in the list */
    BUG_ON((h == l) || (l->next != h));
    ct = list_entry(l, struct castle_component_tree, da_list);
    /* Get a ref to this tree so that it doesn't go away while we are doing an IO on it */
    castle_ct_get(ct, write);
    castle_da_unlock(da);
        
    return ct; 
}

static struct castle_component_tree* castle_da_rwct_acquire(struct castle_double_array *da,
                                                            c_bvec_t *c_bvec)
{
    uint64_t value_len, req_btree_space, req_medium_space;
    struct castle_component_tree *ct;
    struct castle_btree_type *btree;
    int write, nr_nodes, ret;

    write = (c_bvec_data_dir(c_bvec) == WRITE);
again:
    ct = castle_da_rwct_get(da, write);
    /* For reads, this is the right starting point. Exit immediately. */ 
    if(!write)
        return ct;

    /* For writes, try to preallocate space in the btree and medium object extents.
       B-Tree first. */
    btree = castle_btree_type_get(ct->btree_type);
    /* Allocate the worst case number of nodes we may have to create handling this
       write. */
    nr_nodes = (2 * ct->tree_depth + 3);
    req_btree_space = nr_nodes * btree->node_size * C_BLK_SIZE;
    if (castle_ext_fs_pre_alloc(&ct->tree_ext_fs, req_btree_space) < 0)
        goto new_ct;
    /* Save how many nodes we've pre-allocated. */
    atomic_set(&c_bvec->reserv_nodes, nr_nodes);

    /* Pre-allocate space for Medium objects. */
    value_len = c_bvec->c_bio->replace->value_len;
    /* If not a medium object, we are done. */
    if ((value_len <= MAX_INLINE_VAL_SIZE) || (value_len > MEDIUM_OBJECT_LIMIT))
        return ct;

    /* Preallocate (ceil to C_BLK_SIZE) space for the medium object. */
    req_medium_space = ((value_len - 1) / C_BLK_SIZE + 1) * C_BLK_SIZE;
    if (castle_ext_fs_pre_alloc(&ct->data_ext_fs, req_medium_space) >= 0)
        return ct;

    /* We failed to preallocate space for the medium object. Free the space in btree extent. */
    castle_ext_fs_free(&ct->tree_ext_fs, req_btree_space);

new_ct:
    /* Drop the old tree reference, try to allocate a new RWCT. */
    da = castle_da_hash_get(ct->da);  
    BUG_ON(!da);
    debug("Number of items in component tree %d, # items %ld. Trying to add a new rwct.\n",
            ct->seq, atomic64_read(&ct->item_count));
    ret = castle_da_rwct_make(da, 0);
    if((ret == 0) || (ret == -EAGAIN))
    {
        castle_ct_put(ct, write);
        goto again;
    }
    
    printk("Warning: failed to create RWCT with errno=%d\n", ret);
    return NULL;
}

static void castle_da_bvec_queue(struct castle_double_array *da, c_bvec_t *c_bvec)
{
    castle_da_lock(da);
    list_add_tail(&c_bvec->io_list, &da->ios_waiting);
    da->ios_waiting_cnt++;
    castle_da_unlock(da);
}

static void castle_da_queue_kick(struct castle_double_array *da)
{
    LIST_HEAD(submit_list);
    struct list_head *l, *t;
    c_bvec_t *bvec; 

    /* Get as many bvec as we have the budget for onto the submit list. */
    castle_da_lock(da);
    while(!list_empty(&da->ios_waiting) && (da->ios_budget > 0))
    {
        bvec = list_first_entry(&da->ios_waiting, c_bvec_t, io_list); 
        list_del(&bvec->io_list);
        list_add(&bvec->io_list, &submit_list);
        da->ios_waiting_cnt--;
        da->ios_budget--;
    } 
    castle_da_unlock(da);

    /* Submit them all. */
    list_for_each_safe(l, t, &submit_list)
    {
        bvec = list_entry(l, c_bvec_t, io_list);
        /* Remove from the list (the bvec may get freed by the time we return
           from the submit call. */
        list_del(&bvec->io_list);
        castle_da_bvec_start(da, bvec);
    }
}

static void castle_da_ct_walk_complete(c_bvec_t *c_bvec, int err, c_val_tup_t cvt)
{
    void (*callback) (struct castle_bio_vec *c_bvec, int err, c_val_tup_t cvt);
    struct castle_component_tree *ct, *next_ct;
    struct castle_double_array *da;
    int read; 
    
    callback = c_bvec->da_endfind;
    ct = c_bvec->tree;
    da = castle_da_hash_get(ct->da);

    read = (c_bvec_data_dir(c_bvec) == READ);
    BUG_ON(read && atomic_read(&c_bvec->reserv_nodes));
    /* For reads, if the key hasn't been found, check in the next tree. */
    if(read && CVT_INVALID(cvt) && (!err))
    {
        debug_verbose("Checking next ct.\n");
        next_ct = castle_da_ct_next(ct);
        /* We've finished looking through all the trees. */
        if(!next_ct)
        {
            callback(c_bvec, err, INVAL_VAL_TUP); 
            return;
        }
        /* Put the previous tree, now that we know we've got a ref to the next. */
        castle_ct_put(ct, 0);
        c_bvec->tree = next_ct;
        debug_verbose("Scheduling btree read in %s tree: %d.\n", 
                ct->dynamic ? "dynamic" : "static", ct->seq);
        castle_btree_submit(c_bvec);
        return;
    }
    castle_request_timeline_checkpoint_stop(c_bvec->timeline);
    castle_request_timeline_destroy(c_bvec->timeline);
    debug_verbose("Finished with DA, calling back.\n");
    castle_da_merge_budget_io_end(castle_da_hash_get(ct->da));
    /* Release the preallocated space in the btree extent. */
    if (atomic_read(&c_bvec->reserv_nodes))
    {
        struct castle_btree_type *btree = castle_btree_type_get(ct->btree_type);

        castle_ext_fs_free(&ct->tree_ext_fs, 
                           atomic_read(&c_bvec->reserv_nodes) * btree->node_size * C_BLK_SIZE);
    }
    BUG_ON(CVT_MEDIUM_OBJECT(cvt) && (cvt.cep.ext_id != c_bvec->tree->data_ext_fs.ext_id));

    /* Don't release the ct reference in order to hold on to medium objects array, etc. */
    callback(c_bvec, err, cvt);
}

static void castle_da_bvec_start(struct castle_double_array *da, c_bvec_t *c_bvec)
{ 
    struct castle_component_tree *ct;

    debug_verbose("Doing DA %s for da_id=%d\n", write ? "write" : "read", da_id);
    BUG_ON(atomic_read(&c_bvec->reserv_nodes) != 0);
    /* This will get a reference to current RW tree, or create a new one if neccessary.
       It also preallocates space in that tree. */
    ct = castle_da_rwct_acquire(da, c_bvec);
    /* If RW component tree does not exist, exit with error. */
    if(!ct)
    {
        c_bvec->endfind(c_bvec, -ENOSPC, INVAL_VAL_TUP);
        return;
    }
    /* Otherwise, replace endfind function pointer, and start the btree walk. */
    c_bvec->tree       = ct; 
    c_bvec->da_endfind = c_bvec->endfind;
    c_bvec->endfind    = castle_da_ct_walk_complete;

    //castle_request_timeline_create(c_bvec->timeline);
    castle_request_timeline_checkpoint_start(c_bvec->timeline);
    debug_verbose("Looking up in ct=%d\n", c_bvec->tree->seq); 
    castle_btree_submit(c_bvec);
}

void castle_double_array_submit(c_bvec_t *c_bvec)
{
    struct castle_attachment *att = c_bvec->c_bio->attachment;
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
    /* Always submit writes to the queue, reads get started immediately. */
    if(c_bvec_data_dir(c_bvec) == WRITE)
    {
        castle_da_bvec_queue(da, c_bvec);
        castle_da_queue_kick(da);
    }
    else
        castle_da_bvec_start(da, c_bvec);
}
 

/**************************************/
/* Double Array Management functions. */

int castle_double_array_create(void)
{
    /* Make sure that the global tree is in the ct hash */
    castle_ct_hash_add(&castle_global_tree);

    return 0;
}
    
int castle_double_array_init(void)
{
    int ret;

    ret = -ENOMEM;
    castle_da_hash = castle_da_hash_alloc();
    if(!castle_da_hash)
        goto err_out;
    castle_ct_hash = castle_ct_hash_alloc();
    if(!castle_ct_hash)
        goto err_out;

    castle_da_hash_init();
    castle_ct_hash_init();
    /* Start up the timer which replenishes merge and write IOs budget */
    castle_throttle_timer_fire(1); 

    return 0;
 
err_out:
    BUG_ON(!ret);
    if(castle_ct_hash)
        castle_free(castle_ct_hash);
    if(castle_da_hash)
        castle_free(castle_da_hash);

    return ret;
}

void castle_double_array_merges_fini(void)
{
    int deleted_das;

    castle_da_exiting = 1;
    del_singleshot_timer_sync(&throttle_timer);
    /* This is happening at the end of execution. No need for the hash lock. */
    __castle_da_hash_iterate(castle_da_merge_stop, NULL);
    /* Also, wait for merges on deleted DAs. Merges will hold the last references to those DAs. */
    do {
        CASTLE_TRANSACTION_BEGIN;
        deleted_das = !list_empty(&castle_deleted_das);
        CASTLE_TRANSACTION_END;
        if(deleted_das)
            msleep(10);
    } while(deleted_das);
}

void castle_double_array_fini(void)
{
    castle_da_hash_destroy();
    castle_ct_hash_destroy();
}

void castle_da_destroy_complete(struct castle_double_array *da)
{ /* Called with lock held. */
    int i;

    /* Sanity Checks. */
    BUG_ON(!castle_da_deleted(da));

    printk("Cleaning DA: %u\n", da->id);

    /* Destroy Component Trees. */
    for(i=0; i<MAX_DA_LEVEL; i++)
    {
        struct list_head *l, *lt;

        list_for_each_safe(l, lt, &da->levels[i].trees)
        {
            struct castle_component_tree *ct;
 
            ct = list_entry(l, struct castle_component_tree, da_list);
            /* No out-standing merges and active attachments. Componenet Tree
             * shouldn't be referenced any-where. */
            BUG_ON(atomic_read(&ct->ref_count) != 1);
            BUG_ON(atomic_read(&ct->write_ref_count));
            list_del(&ct->da_list);
            ct->da_list.next = ct->da_list.prev = NULL;
            castle_ct_put(ct, 0);
        }
    }

    /* Destroy Version and Rebuild Version Tree. */
    castle_version_tree_delete(da->root_version);

    /* Delete the DA from the list of deleted DAs. */
    list_del(&da->hash_list);

    /* Poison and free (may be repoisoned on debug kernel builds). */
    memset(da, 0xa7, sizeof(struct castle_double_array));
    castle_free(da);
}

static void castle_da_get(struct castle_double_array *da)
{
    /* Increment ref count, it should never be zero when we get here. */
    BUG_ON(atomic_inc_return(&da->ref_cnt) <= 1);
}

static void castle_da_put(struct castle_double_array *da)
{
    if(atomic_dec_return(&da->ref_cnt) == 0)
    {
        /* Ref count dropped to zero -> delete. There should be no outstanding attachments. */
        BUG_ON(da->attachment_cnt != 0);
        BUG_ON((da->hash_list.next != NULL) || (da->hash_list.prev != NULL));
        BUG_ON(!castle_da_deleted(da));
        CASTLE_TRANSACTION_BEGIN;
        castle_da_destroy_complete(da);
        CASTLE_TRANSACTION_END;
    }
}

static void castle_da_put_locked(struct castle_double_array *da)
{
    BUG_ON(!CASTLE_IN_TRANSACTION);
    if(atomic_dec_return(&da->ref_cnt) == 0)
    {
        /* Ref count dropped to zero -> delete. There should be no outstanding attachments. */
        BUG_ON(da->attachment_cnt != 0);
        BUG_ON((da->hash_list.next != NULL) || (da->hash_list.prev != NULL));
        BUG_ON(!castle_da_deleted(da));
        castle_da_destroy_complete(da);
    }
}

static struct castle_double_array* castle_da_ref_get(da_id_t da_id)
{
    struct castle_double_array *da;
    unsigned long flags;

    spin_lock_irqsave(&castle_da_hash_lock, flags);
    da = __castle_da_hash_get(da_id);
    if(!da)
        goto out;
    castle_da_get(da);
out:
    spin_unlock_irqrestore(&castle_da_hash_lock, flags);

    return da;
}

int castle_double_array_get(da_id_t da_id)
{
    struct castle_double_array *da;
    unsigned long flags;

    spin_lock_irqsave(&castle_da_hash_lock, flags);
    da = __castle_da_hash_get(da_id);
    if(!da)
        goto out;
    castle_da_get(da);
    da->attachment_cnt++;
out:
    spin_unlock_irqrestore(&castle_da_hash_lock, flags);

    return (da == NULL ? -EINVAL : 0);
}

void castle_double_array_put(da_id_t da_id)
{
    struct castle_double_array *da;

    /* We only call this for attached DAs which _must_ be in the hash. */
    da = castle_da_hash_get(da_id);
    BUG_ON(!da);
    /* DA allocated + our ref count on it. */
    BUG_ON(atomic_read(&da->ref_cnt) < 2);
    castle_da_lock(da);
    da->attachment_cnt--;
    castle_da_unlock(da);
    /* Put the ref cnt too. */
    castle_da_put(da);
}

int castle_double_array_destroy(da_id_t da_id)
{
    struct castle_double_array *da;
    unsigned long flags;
    int ret;

    spin_lock_irqsave(&castle_da_hash_lock, flags);
    da = __castle_da_hash_get(da_id);
    /* Fail if we cannot find the da in the hash. */
    if(!da)
    {
        ret = -EINVAL;
        goto err_out;
    }
    BUG_ON(da->attachment_cnt < 0);
    /* Fail if there are attachments to the DA. */
    if(da->attachment_cnt > 0)
    {
        ret = -EBUSY;
        goto err_out;
    }
    /* Now we are happy to delete the DA. Remove it from the hash. */ 
    BUG_ON(castle_da_deleted(da));
    __castle_da_hash_remove(da); 
    da->hash_list.next = da->hash_list.prev = NULL;
    spin_unlock_irqrestore(&castle_da_hash_lock, flags);

    printk("Marking DA %u for deletion\n", da_id);
    /* Set the destruction bit, which will stop further merges. */
    castle_da_deleted_set(da);
    /* Restart the merge threads, so that they get to exit, and drop their da refs. */
    castle_da_merge_restart(da, NULL);
    /* Add it to the list of deleted DAs. */
    list_add(&da->hash_list, &castle_deleted_das);
    /* Put the (usually) last reference to the DA. */
    castle_da_put_locked(da);

    return 0;

err_out:
    spin_unlock_irqrestore(&castle_da_hash_lock, flags);
    return ret;
}

static int castle_da_size_get(struct castle_double_array *da, 
                              struct castle_component_tree *ct, 
                              int level_cnt, 
                              void *token)
{
    c_byte_off_t *size = (c_byte_off_t *)token;
    *size += castle_extent_size_get(ct->tree_ext_fs.ext_id);
    *size += castle_extent_size_get(ct->data_ext_fs.ext_id);
    *size += atomic64_read(&ct->large_ext_chk_cnt);

    return 0;
}

int castle_double_array_size_get(da_id_t da_id, c_byte_off_t *size)
{
    struct castle_double_array *da;
    int err_code = 0;
    c_byte_off_t s = 0;

    da = castle_da_ref_get(da_id);
    if (!da)
    {
        err_code = -EINVAL;
        goto out;
    }

    castle_da_foreach_tree(da, castle_da_size_get, (void *)&s);

    castle_da_put(da);

out:
    *size = s;
    return err_code;
}
