#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/kthread.h>

#include "castle_public.h"
#include "castle_defines.h"
#include "castle_utils.h"
#include "castle.h"
#include "castle_cache.h"
#include "castle_btree.h"
#include "castle_time.h"
#include "castle_versions.h"
#include "castle_extent.h"
#include "castle_ctrl.h"
#include "castle_da.h"
#include "castle_trace.h"
#include "castle_sysfs.h"
#include "castle_objects.h"
#include "castle_bloom.h"
#include "castle_events.h"
#include "castle_mstore.h"
#include "castle_ctrl_prog.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)            ((void)0)
#define debug_verbose(_f, ...)    ((void)0)
#define debug_iter(_f, ...)       ((void)0)
#define debug_gn(_f, ...)         ((void)0)
#if 1
#define debug_merges(_f, ...)     ((void)0)
#else
#define debug_merges(_f, _a...)   (castle_printk(LOG_DEBUG, "%s:%.4d: DA=%d, level=%d: " \
                                        _f, __FILE__, __LINE__ , da->id, level, ##_a))
#endif
#define debug_dexts(_f, _a...)    ((void)0)
#define debug_res_pools(_f, _a...)  ((void)0)
#else
#define debug(_f, _a...)          (castle_printk(LOG_DEBUG, "%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#define debug_verbose(_f, ...)    (castle_printk(LOG_DEBUG, "%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#define debug_iter(_f, _a...)     (castle_printk(LOG_DEBUG, "%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#define debug_gn(_f, _a...)       (castle_printk(LOG_DEBUG, "%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#define debug_merges(_f, _a...)   (castle_printk(LOG_DEBUG, "%s:%.4d: DA=%d, level=%d: " \
                                        _f, __FILE__, __LINE__ , da->id, level, ##_a))
#define debug_dexts(_f, _a...)    (castle_printk(LOG_DEBUG, _f, ##_a))
#define debug_res_pools(_f, _a...)  (castle_printk(LOG_DEBUG, _f, ##_a))
#endif

#if 0
#undef debug_dexts
#define debug_dexts(_f, _a...)    (castle_printk(LOG_DEBUG, _f, ##_a))
#endif

#if 0
#undef debug_gn
#define debug_gn(_f, _a...)       (castle_printk(LOG_DEBUG, "%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

#if 0
#undef debug_res_pools
#define debug_res_pools(_f, _a...)  (castle_printk(LOG_DEBUG, _f, ##_a))
#endif

#define MAX_DYNAMIC_INTERNAL_SIZE       (5)     /* In C_CHK_SIZE. */
#define MAX_DYNAMIC_TREE_SIZE           (20)    /* In C_CHK_SIZE. */
#define MAX_DYNAMIC_DATA_SIZE           (20)    /* In C_CHK_SIZE. */

#define CASTLE_DA_HASH_SIZE             (1000)
#define CASTLE_CT_HASH_SIZE             (4000)
#define CASTLE_DATA_EXTS_HASH_SIZE      (1000)
static struct list_head        *castle_da_hash       = NULL;
static struct list_head        *castle_ct_hash       = NULL;
static struct list_head        *castle_data_exts_hash= NULL;
       c_da_t                   castle_next_da_id    = 1;
static atomic64_t               castle_next_tree_seq = ATOMIC64(0);
static atomic64_t               castle_next_tree_data_age = ATOMIC64(0);
static int                      castle_da_exiting    = 0;

static int                      castle_merge_max_work_id = 0;

static int                      castle_merges_abortable = 1; /* 0 or 1, default=enabled */
static DECLARE_WAIT_QUEUE_HEAD (castle_da_promote_wq);  /**< castle_da_level0_modified_promote()  */

module_param(castle_merges_abortable, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(castle_merges_abortable, "Allow on-going merges to abort upon exit condition");

/* We don't need to set upper/lower bounds for the promotion frequency as values
 * < 2 will all results in RWCTs being promoted every checkpoint, while very
 * large values will result in RWCTs 'never' being promoted. */
int                             castle_rwct_checkpoint_frequency = 10;  /**< Number of checkpoints
                                                                             before RWCTs are
                                                                             promoted to level 1. */
module_param(castle_rwct_checkpoint_frequency, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(castle_rwct_checkpoint_frequency, "Number checkpoints before RWCTs are promoted.");

static struct
{
    int                     cnt;    /**< Size of cpus array.                        */
    int                    *cpus;   /**< Array of CPU ids for handling requests.    */
} request_cpus;

/* set to 0 to disable using SSDs for btree leaf nodes */
static int                      castle_use_ssd_leaf_nodes = 0;

module_param(castle_use_ssd_leaf_nodes, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(castle_use_ssd_leaf_nodes, "Use SSDs for btree leaf nodes");

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

DEFINE_HASH_TBL(castle_da, castle_da_hash, CASTLE_DA_HASH_SIZE, struct castle_double_array, hash_list, c_da_t, id);
DEFINE_HASH_TBL(castle_ct, castle_ct_hash, CASTLE_CT_HASH_SIZE, struct castle_component_tree, hash_list, tree_seq_t, seq);
DEFINE_HASH_TBL(castle_data_exts, castle_data_exts_hash, CASTLE_DATA_EXTS_HASH_SIZE, struct castle_data_extent, hash_list, c_ext_id_t, ext_id);

atomic_t castle_zombie_da_count = ATOMIC(0);

typedef enum {
    DAM_MARSHALL_ALL = 0,  /**< Marshall all merge state          */
    DAM_MARSHALL_ITERS,    /**< Marshall only iterator state      */
    DAM_MARSHALL_OUTTREE   /**< Marshall only output cct state    */
} c_da_merge_marshall_set_t;

/**********************************************************************************************/
/* Prototypes */
static struct castle_component_tree * castle_ct_init(struct castle_double_array *da,
                                                     uint32_t nr_data_exts);
static void castle_component_tree_add(struct castle_double_array *da,
                                      struct castle_component_tree *ct,
                                      struct list_head *head);
static void castle_component_tree_del(struct castle_double_array *da,
                                      struct castle_component_tree *ct);
static void castle_component_tree_promote(struct castle_double_array *da,
                                          struct castle_component_tree *ct);
struct castle_da_merge;
//static USED void castle_da_merges_print(struct castle_double_array *da);
static int castle_da_merge_restart(struct castle_double_array *da, void *unused);
static int castle_da_merge_start(struct castle_double_array *da, void *unused);
void castle_double_array_merges_fini(void);
static struct castle_component_tree* castle_da_rwct_get(struct castle_double_array *da,
                                                        int cpu_index);
static struct castle_da_cts_proxy* castle_da_cts_proxy_get(struct castle_double_array *da);
static void castle_da_queue_kick(struct work_struct *work);
static void castle_da_queues_kick(struct castle_double_array *da);
static void castle_da_read_bvec_start(struct castle_double_array *da, c_bvec_t *c_bvec);
static void castle_da_write_bvec_start(struct castle_double_array *da, c_bvec_t *c_bvec);
static void castle_da_reserve(struct castle_double_array *da, c_bvec_t *c_bvec);
static void castle_da_get(struct castle_double_array *da);
static void castle_da_put(struct castle_double_array *da);
static void castle_da_merge_serialise(struct castle_da_merge *merge, int using_tvr, int tvr_new_key);
static void castle_da_merge_marshall(struct castle_da_merge *merge,
                                     c_da_merge_marshall_set_t partial_marshall);
/* out_tree_check checks only output tree state */
static void castle_da_merge_serdes_out_tree_check(struct castle_dmserlist_entry *merge_mstore,
                                                  struct castle_double_array *da,
                                                  int level);
/* checks things like making sure the merge has the right input trees */
static void castle_da_merge_deser_check(struct castle_da_merge *merge, struct castle_double_array *da,
                                      int level, int nr_trees,
                                      struct castle_component_tree **in_trees);
static void castle_da_merge_struct_deser(struct castle_da_merge *merge,
                                         struct castle_double_array *da, int level);
static int castle_da_ct_bloom_build_param_deserialise(struct castle_component_tree *ct,
                                                      struct castle_bbp_entry *bbpm);
void castle_da_ct_marshall(struct castle_clist_entry *ctm, struct castle_component_tree *ct);
static struct castle_component_tree* castle_da_ct_unmarshall(struct castle_clist_entry *ctm);
/* partial merges: partition handling */
static void castle_da_merge_new_partition_update(struct castle_da_merge *merge,
                                                 c2_block_t *node_c2b,
                                                 void *key);
static void castle_da_cts_proxy_invalidate(struct castle_double_array *da);
static int _castle_da_rwct_create(struct castle_double_array *da,
                                  int cpu_index,
                                  int in_tran,
                                  c_lfs_vct_type_t lfs_type);
static int castle_da_rwct_create(struct castle_double_array *da,
                                 int cpu_index,
                                 int in_tran);
static int castle_da_no_disk_space(struct castle_double_array *da);
static int castle_da_all_rwcts_create(struct castle_double_array *da,
                                      int in_tran,
                                      c_lfs_vct_type_t lfs_type);
void castle_da_next_ct_read(c_bvec_t *c_bvec);

struct workqueue_struct *castle_da_wqs[NR_CASTLE_DA_WQS];
char *castle_da_wqs_names[NR_CASTLE_DA_WQS] = {"castle_da0"};

static int castle_da_merge_check(struct castle_da_merge *merge, void *da);
static void castle_ct_stats_commit(struct castle_component_tree *ct);
static signed int castle_data_ext_should_drain(c_ext_id_t ext_id, struct castle_da_merge *merge);
static signed int castle_tree_ext_index_lookup(struct castle_component_tree *ct,
                                               struct castle_da_merge *merge);
static void castle_data_ext_size_get(c_ext_id_t ext_id, uint64_t *nr_bytes,
                                     uint64_t *nr_drain_bytes, uint64_t *nr_entries);
static int castle_merge_thread_create(c_thread_id_t *thread_id, struct castle_double_array *da);
static int castle_merge_thread_attach(c_merge_id_t merge_id, c_thread_id_t thread_id);
static void castle_da_lfs_all_rwcts_callback(void *data);
static int castle_da_nodes_complete(struct castle_da_merge *merge);

static atomic_t castle_da_merge_thread_count = ATOMIC(0);

static struct list_head        *castle_merge_threads_hash = NULL;

#define CASTLE_MERGE_THREADS_HASH_SIZE            (100)

DEFINE_HASH_TBL(castle_merge_threads, castle_merge_threads_hash, CASTLE_MERGE_THREADS_HASH_SIZE, struct castle_merge_thread, hash_list, c_thread_id_t, id);

uint32_t castle_merge_threads_count = 0;

static struct list_head        *castle_merges_hash = NULL;

#define CASTLE_MERGES_HASH_SIZE                   (100)

DEFINE_HASH_TBL(castle_merges, castle_merges_hash, CASTLE_MERGES_HASH_SIZE, struct castle_da_merge, hash_list, c_merge_id_t, id);

atomic_t castle_da_max_merge_id = ATOMIC(0);


tree_seq_t castle_da_next_ct_seq(void);

/**********************************************************************************************/
/* Merges */
#define MAX_IOS             (1000) /* Arbitrary constants */
/* @TODO: Merges are now effectively always full throughput, because MIN is set high. */
#define MIN_BUDGET_DELTA    (1000000)
#define MAX_BUDGET          (1000000)

/**********************************************************************************************/
/* Utils */

/**
 * Compare component trees based on their data age. (this is similar to seq_no - smaller the number
 * older the tree is).
 *
 * FIXME: Probably should change the name of data_age.
 *
 * if the age of two trees equal (can happen only for trees that are being merged or T0s.)
 *
 * For T0s:
 *      Compare two component trees sequence numbers and decide which one is older.
 *
 * For merging trees - output tree should come after all input trees. We took this approach as output
 * of level1 goes to level2 etc..
 */
static int castle_da_ct_compare(struct castle_component_tree *ct1,
                                struct castle_component_tree *ct2)
{
    /* Data age takes priority in sorting. */
    if(ct1->data_age != ct2->data_age)
        return ct1->data_age > ct2->data_age ? 1 : -1;

    /* Age of two trees could be equal only if they are T0s or if they are participating in a
     * merge. If they are T0, compare based on seq_id. */
    if (ct1->level == 0)
    {
        /* Sequence numbers are 64bit unsigned values, be careful about subtracting them
           and casting to int. Explicit comparisons are safer. */
        return  ct1->seq == ct2->seq ? 0 :
               (ct1->seq >  ct2->seq ? 1 : -1);
    }

    /* If not T0s, one of them should be output of a merge and other should be input of the same
     * merge. */
    BUG_ON(ct1->merge != ct2->merge);

    /* Treat output tree as the latest. We want it to be added before all input trees. */
    if (test_bit(CASTLE_CT_MERGE_OUTPUT_BIT, &ct1->flags))
    {
        BUG_ON(!test_bit(CASTLE_CT_MERGE_INPUT_BIT, &ct2->flags));
        return -1;
    }
    else if (test_bit(CASTLE_CT_MERGE_OUTPUT_BIT, &ct2->flags))
    {
        BUG_ON(!test_bit(CASTLE_CT_MERGE_INPUT_BIT, &ct1->flags));
        return 1;
    }
    else
        BUG();
}

/* Update component tree size stats. We do maintain two counters. nr_bytes counter gets updated
 * during tree creation. nr_drained_bytes gets updated, when the tree is getting merged. */
int castle_tree_size_stats_update(void                            *key,
                                  c_val_tup_t                     *cvt_p,
                                  struct castle_component_tree    *ct,
                                  int                              op)
{
    uint32_t entry_size;

    BUG_ON(CVT_INVALID(*cvt_p));

    /* Find key length. */
    entry_size = castle_btree_type_get(ct->btree_type)->key_size(key);

    /* Find inline value length. Treat all counters of size 16, for the sake of simplicity. */
    entry_size += CVT_ANY_COUNTER(*cvt_p)? 16: CVT_INLINE_VAL_LENGTH(*cvt_p);

    /* Update tree-size. */
    switch (op)
    {
        case  1: /* Add. */
            atomic64_add(entry_size, &ct->nr_bytes);
            break;
        case -1: /* Deduct. */
            atomic64_sub(entry_size, &ct->nr_bytes);
            BUG_ON(0 > atomic64_read(&ct->nr_bytes));
            break;
        case  0: /* Drain. */
            /* nr_drained_bytes is accessed by single merge thread only, no need of atomic. */
            if (entry_size + ct->nr_drained_bytes <= atomic64_read(&ct->nr_bytes))
                ct->nr_drained_bytes += entry_size;
            break;
        default:
            BUG();
    }

    return entry_size;
}

/**
 * Set DA's growing bit and return previous state.
 *
 * @return  0   DA was not being grown (but is now)
 * @return  1   DA was already being grown
 */
static inline int castle_da_growing_rw_test_and_set(struct castle_double_array *da)
{
    return test_and_set_bit(DOUBLE_ARRAY_GROWING_RW_TREE_BIT, &da->flags);
}

/**
 * Is the growing bit set on DA?
 *
 * @return  0   DA is currently growing
 * @return  1   DA is not currently being grown
 */
static inline int castle_da_growing_rw_test(struct castle_double_array *da)
{
    return test_bit(DOUBLE_ARRAY_GROWING_RW_TREE_BIT, &da->flags);
}

/**
 * Clear DA's growing bit.
 */
static inline void castle_da_growing_rw_clear(struct castle_double_array *da)
{
    clear_bit(DOUBLE_ARRAY_GROWING_RW_TREE_BIT, &da->flags);
}

#define MERGE_CHECKPOINTABLE(_merge) ((_merge->level >= MIN_DA_SERDES_LEVEL))

static inline int castle_da_deleted(struct castle_double_array *da)
{
    return test_bit(DOUBLE_ARRAY_DELETED_BIT, &da->flags);
}

static inline void castle_da_deleted_set(struct castle_double_array *da)
{
    set_bit(DOUBLE_ARRAY_DELETED_BIT, &da->flags);
}

#ifdef CASTLE_DEBUG
#define print_merge_state(_f, _a...) (castle_printk(LOG_DEBUG, "%s::[%p] " _f, __FUNCTION__, (void *)merge, ##_a))
static void castle_da_merge_debug_lock_state_query(struct castle_da_merge *merge)
{
    uint8_t i;
    BUG_ON(!merge);
    print_merge_state("id = %u\n", merge->id);

    /* output tree stuff */
    for(i=0; i<MAX_BTREE_DEPTH; i++)
    {
        if (merge->levels[i].node_c2b)
        {
            if (c2b_write_locked(merge->levels[i].node_c2b))
                print_merge_state("level %u node c2b %p locked by %s:%u\n",
                                  i,
                                  merge->levels[i].node_c2b,
                                  merge->levels[i].node_c2b->file,
                                  merge->levels[i].node_c2b->line);
            else
                print_merge_state("level %u node c2b %p not locked\n",
                                  i,
                                  merge->levels[i].node_c2b);

        }
    }

    /* bloom filter stuff */
    if (merge->out_tree->bloom_exists)
    {
        struct castle_bloom_build_params *bf_bp = merge->out_tree->bloom.private;
        if (bf_bp)
        {
            if (bf_bp->chunk_c2b)
            {
                if (c2b_write_locked(bf_bp->chunk_c2b))
                    print_merge_state("bloom chunk_c2b %p locked by %s:%u\n",
                                      bf_bp->chunk_c2b,
                                      bf_bp->chunk_c2b->file,
                                      bf_bp->chunk_c2b->line);
                else
                    print_merge_state("bloom chunk_c2b %p not locked\n",
                                      bf_bp->chunk_c2b);
            }
            else
                print_merge_state("bloom chunk_c2b %p\n", bf_bp->chunk_c2b);

            if (bf_bp->node_c2b)
            {
                if (c2b_write_locked(bf_bp->node_c2b))
                    print_merge_state("bloom node_c2b %p locked by %s:%u\n",
                                      bf_bp->node_c2b,
                                      bf_bp->node_c2b->file,
                                      bf_bp->node_c2b->line);
                else
                    print_merge_state("bloom node_c2b %p not locked\n",
                                      bf_bp->node_c2b);
            }
            else
                print_merge_state("bloom node_c2b %p\n", bf_bp->node_c2b);
        }
        else
            print_merge_state("no bloom build params (weird...?)\n");
    }
    else
        print_merge_state("no bloom filter\n");
}
#undef print_merge_state
/* Place this anywhere that merge might go to sleep, to see what locks are taken. */
#define castle_merge_debug_locks(_m)                                                               \
do{                                                                                                \
    castle_printk(LOG_DEBUG,                                                                       \
            "%s::calling castle_da_merge_debug_lock_state_query on merge %p from ln %u\n",         \
            __FUNCTION__, _m, __LINE__);                                                           \
    castle_da_merge_debug_lock_state_query(_m);                                                    \
} while(0);
#else
#define castle_merge_debug_locks(_f, ...) ((void)0)
#endif

/**********************************************************************************************/
/* Iterators */
struct castle_immut_iterator;

typedef void (*castle_immut_iter_node_start) (struct castle_immut_iterator *);

typedef struct castle_immut_iterator {
    c_async_iterator_t            async_iter;
    struct castle_component_tree *tree;
    struct castle_btree_type     *btree;
    int                           completed;  /**< set to 1 when iterator is exhausted            */
    c2_block_t                   *curr_c2b;   /**< node c2b currently providing entries           */
    struct castle_btree_node     *curr_node;  /**< btree node (curr_c2b->buffer)                  */
    int32_t                       curr_idx;   /**< offset within curr_node of current entry
                                                   (where current is really next())               */
    int32_t                       cached_idx; /**< this is needed for merge SERDES because curr_idx
                                                   is moved ahead after the iterator value is
                                                   cached; if the call to iter_entry_find was moved
                                                   before the entry_get within immut_iter_next, it
                                                   will be unnecessary to save cached_idx         */
    c2_block_t                   *next_c2b;   /**< node c2b to provide next entries               */
    int32_t                       next_idx;   /**< offset within next_c2b of first entry to return*/
    castle_immut_iter_node_start  node_start; /**< callback handler to fire whenever iterator moves
                                                   to a new node within the btree                 */
    void                         *private;

    struct castle_da_merge *merge; /* use this pointer to determine if the merge is
                                      doing partial merges */
} c_immut_iter_t;

/**
 * Check if ext_id is drainable, and if so return an array index according to merge->drain_exts
 * ordering.
 *
 * @param [in]  ext_id    Data extent ID.
 * @param [in]  merge     merge structure pointer, which contains drain_exts list.
 *
 * @return >= 0 index
 *         -1   extent not found in drain_exts list
 */
static signed int castle_data_ext_should_drain(c_ext_id_t ext_id,
                                               struct castle_da_merge *merge)
{
    int i;

    /* The list contains all extents that are not to be merged. */
    for (i=0; i<merge->nr_drain_exts; i++)
        if (merge->drain_exts[i] == ext_id)
            return i;

    return -1;
}

/**
 * Check if ct is on the merge->in_trees list, and if so return the array index.
 *
 * @param [in]  ct        cct pointer.
 * @param [in]  merge     merge structure pointer, which contains in_trees list.
 *
 * @return >= 0 index
 *         -1   ct not found in in_trees list
 *
 * @note   Currently this function is only used by an iterator to identify the
 *         array index to use to propagate a valid extent boundary for the purpose
 *         of eventual shrinking. Though this resulted in less data structure sprawl,
 *         we could avoid calling this function by saving the index id somewhere because
 *         it would never change. Nevertheless, in practical terms, the cost of this
 *         is not high because we only call this on iter_next_node, and the size of the
 *         list is usually quite small (typically 4 entries).
 */
static signed int castle_tree_ext_index_lookup(struct castle_component_tree *ct,
                                               struct castle_da_merge *merge)
{
    int i;

    for (i=0; i<merge->nr_trees; i++)
        if (merge->in_trees[i] == ct)
            return i;

    return -1;
}

static int castle_ct_immut_iter_entry_find(c_immut_iter_t *iter,
                                           struct castle_btree_node *node,
                                           int start_idx)
{
    int disabled;
    c_val_tup_t cvt;
    c_ver_t version;

    for(; start_idx<node->used; start_idx++)
    {

        disabled = iter->btree->entry_get(node, start_idx, NULL, &version, &cvt);
        if(!disabled && castle_version_is_ancestor(node->version, version))
            return start_idx;
    }

    return -1;
}

/**
 * Update iterator with new btree node.
 *
 * @param iter  Iterator to update
 * @param node  Proposed next node
 *
 * @return 0    Node has no entries.
 * @return 1    Node has entries.
 */
static int castle_ct_immut_iter_next_node_init(c_immut_iter_t *iter,
                                               struct castle_btree_node *node)
{
    /* We should never encounter a non-leaf node. */
    BUG_ON(!BTREE_NODE_IS_LEAF(node));

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

/**
 * Returns the extent position of the next leaf node after the cep specified.
 * If one isn't available it returns the invalid position.
 */
static c_ext_pos_t castle_ct_immut_iter_next_node_cep_find(c_immut_iter_t *iter,
                                                           c_ext_pos_t cep,
                                                           uint16_t node_size)
{
    uint16_t btree_node_size;

    if(EXT_POS_INVAL(cep))
        return INVAL_EXT_POS;

    /* We should only be inspecting leaf nodes, work out the node size. */
    btree_node_size = iter->tree->node_sizes[0];

    /* Work out the position of the next node. */
    cep.offset += ((c_byte_off_t)btree_node_size) * C_BLK_SIZE;

    /* If this cep is past the extent allocation end, return invalid cep. */
    if(cep.offset >= atomic64_read(&iter->tree->tree_ext_free.used))
        return INVAL_EXT_POS;

    /* Make sure that node size provided agrees with leaf node size worked out. */
    BUG_ON(btree_node_size != node_size);

    /* Otherwise return the cep. */
    return cep;
}

/**
 * Find the next leaf node starting from cep.
 *
 * iter->next_c2b==NULL on failure, else success
 *
 * @also castle_ct_immut_iter_next_node_init()
 */
static void castle_ct_immut_iter_next_node_find(c_immut_iter_t *iter,
                                                c_ext_pos_t cep,
                                                uint16_t node_size)
{
    struct castle_btree_node *node;
    c2_block_t *c2b;

    debug("%s::Looking for next node starting with "cep_fmt_str_nl,
            __FUNCTION__, cep2str(cep));
    BUG_ON(iter->next_c2b);
    c2b=NULL;
    while(!EXT_POS_INVAL(cep))
    {
        /* Release c2b if we've got one */
        if(c2b)
            put_c2b(c2b);
        /* Get cache block for the current c2b */
        c2b = castle_cache_block_get(cep, node_size, MERGE_IN);
        castle_cache_advise(c2b->cep, C2_ADV_PREFETCH, MERGE_IN, 0);
        BUG_ON(castle_cache_block_sync_read(c2b));
        node = c2b_bnode(c2b);
        /* Determine if this is a leaf-node with entries */
        BUG_ON(node->magic != BTREE_NODE_MAGIC); //see trac #2844
        if(castle_ct_immut_iter_next_node_init(iter, node))
        {
            /* It is */
            debug("%s::Cep "cep_fmt_str " will be used next, exiting.\n",
                   __FUNCTION__,
                   cep2str(cep));
            iter->next_c2b = c2b;
            return;
        }
        cep = castle_ct_immut_iter_next_node_cep_find(iter, cep, node_size);
        castle_printk(LOG_DEBUG, "%s::Node non-leaf or no non-leaf-ptr entries, moving to " cep_fmt_str_nl,
               __FUNCTION__, cep2str(cep));
    }
    debug("%s::no leaf node found.\n", __FUNCTION__);
    /* Drop c2b if we failed to find a leaf node, but have an outstanding reference to
       a non-leaf node */
    if(c2b)
        put_c2b(c2b);
}

/**
 * Find the next leaf node for iter.
 *
 * @also castle_ct_immut_iter_next_node_find()
 * @note updates the shrinkable_ext_boundary
 */
static void castle_ct_immut_iter_next_node(c_immut_iter_t *iter)
{
    uint16_t node_size;
    struct castle_da_merge *merge;

    BUG_ON(!iter->next_c2b);
    /* Drop the current c2b, if one exists. */
    if(iter->curr_c2b)
    {
        debug("Moving to the next block after: "cep_fmt_str_nl,
               cep2str(iter->curr_c2b->cep));
        put_c2b_and_demote(iter->curr_c2b);
    }
    /* next_c2b becomes curr_c2b */
    iter->curr_c2b = iter->next_c2b;
    node_size = iter->curr_c2b->nr_pages;
    BUG_ON(!c2b_uptodate(iter->curr_c2b));
    iter->curr_node = c2b_bnode(iter->curr_c2b);
    if (!BTREE_NODE_IS_LEAF(iter->curr_node) || (iter->curr_node->used <= iter->next_idx))
    {
        castle_printk(LOG_INFO, "curr_node=%d, used=%d, next_idx=%d\n",
                      iter->curr_node->flags, iter->curr_node->used, iter->next_idx);
        BUG();
    }
    iter->curr_idx  = iter->next_idx;
    debug("%s::Moved to cep="cep_fmt_str_nl, __FUNCTION__, cep2str(iter->curr_c2b->cep));

    /* Fire the node_start callback. */
    if (iter->node_start)
        iter->node_start(iter);

    /* Find next c2b following the extent order. */
    iter->next_c2b = NULL;
    castle_ct_immut_iter_next_node_find(iter,
                                        castle_ct_immut_iter_next_node_cep_find(
                                            iter,
                                            iter->curr_c2b->cep,
                                            node_size),
                                        node_size);

    /* update valid extent boundary for shrinking */
    merge = iter->merge;
    if(!merge)
        return;
    if(MERGE_CHECKPOINTABLE(merge))
    {
        /* set tree valid extent boundaries */
        int index = castle_tree_ext_index_lookup(iter->tree, iter->merge);
        BUG_ON(index < 0); /* Must have found the ct in the merge list */
        iter->merge->shrinkable_extent_boundaries.tree[index] = iter->curr_c2b->cep;

        /* propagate latest MO ceps as valid extent boundaries */
        memcpy(merge->shrinkable_extent_boundaries.data,
               merge->latest_mo_cep,
               sizeof(c_ext_pos_t) * merge->nr_drain_exts);
    }
}

static int castle_ct_immut_iter_prep_next(c_immut_iter_t *iter)
{
    /* Check if we can read from the curr_node. If not move to the next node.
       Make sure that if entries exist, they are not leaf pointers. */
    if(iter->curr_idx >= iter->curr_node->used || iter->curr_idx < 0)
    {
        if (!iter->next_c2b)
        {
            iter->completed = 1;
            BUG_ON(!iter->curr_c2b);
            put_c2b(iter->curr_c2b);
            iter->curr_c2b = NULL;

            return 1;
        }

        debug("No more entries in the current node. Asking for next.\n");
        BUG_ON((iter->curr_idx >= 0) && (iter->curr_idx > iter->curr_node->used));
        castle_ct_immut_iter_next_node(iter);
        BUG_ON((iter->curr_idx >= 0) && (iter->curr_idx >= iter->curr_node->used));
    }

    return 1;
}

static void castle_ct_immut_iter_next(c_immut_iter_t *iter,
                                      void **key_p,
                                      c_ver_t *version_p,
                                      c_val_tup_t *cvt_p)
{
    struct castle_da_merge *merge = iter->merge;
    int disabled;

    /* Check if we can read from the curr_node. If not move to the next node.
       Make sure that if entries exist, they are not leaf pointers. */
    BUG_ON(iter->curr_idx >= iter->curr_node->used || iter->curr_idx < 0);

    disabled = iter->btree->entry_get(iter->curr_node,
                                      iter->curr_idx,
                                      key_p,
                                      version_p,
                                      cvt_p);
    /* curr_idx should have been set to a non-leaf pointer */
    BUG_ON(disabled);
    iter->cached_idx = iter->curr_idx;
    iter->curr_idx = castle_ct_immut_iter_entry_find(iter, iter->curr_node, iter->curr_idx + 1);
    debug("Returned next, curr_idx is now=%d / %d.\n", iter->curr_idx, iter->curr_node->used);

    /* update the MO pointer so that we can find the most recent MO cep for extent shrinking */
    if(!merge)
        return;

    /* Update merge stats. */
    merge->nr_bytes += castle_tree_size_stats_update(*key_p, cvt_p, iter->tree,
                                                      0 /* Drain. */);

    if( (MERGE_CHECKPOINTABLE(merge)) && (CVT_MEDIUM_OBJECT(*cvt_p)) )
    {
        int index = castle_data_ext_should_drain(cvt_p->cep.ext_id, iter->merge);
        if (likely(index >= 0))
            iter->merge->latest_mo_cep[index] = cvt_p->cep;
    }

}

static int castle_ct_immut_iter_has_next(c_immut_iter_t *iter)
{
    if(unlikely(iter->completed))
        return 0;

    BUG_ON(iter->curr_idx >= iter->curr_node->used || iter->curr_idx < 0);

    return 1;
}

static void castle_ct_immut_iter_cancel(c_immut_iter_t *iter)
{
    debug("Cancelling immut enumerator for ct id=%d\n", iter->tree->seq);
    if (iter->curr_c2b)
        put_c2b(iter->curr_c2b);
    if (iter->next_c2b)
        put_c2b(iter->next_c2b);
}

struct castle_iterator_type castle_ct_immut_iter = {
    .register_cb = NULL,
    .prep_next   = (castle_iterator_prep_next_t)    castle_ct_immut_iter_prep_next,
    .has_next    = (castle_iterator_has_next_t)     castle_ct_immut_iter_has_next,
    .next        = (castle_iterator_next_t)         castle_ct_immut_iter_next,
    .skip        = NULL,
    .cancel      = (castle_iterator_cancel_t)       castle_ct_immut_iter_cancel,
};

/**
 * Initialise iterator for immutable btrees.
 *
 * @param iter          Iterator to initialise
 * @param node_start    CB handler when iterator moves to a new btree node
 * @param private       Private data to pass to CB handler
 * @param resume_merge_node_cep  When re-initialising an iterator for a deserialising
 *                               merge, start from the provided cep instead of the start
 *                               of the extent.
 * @param already_complete       When re-initialising an iterator for a deserialising
 *                               merge, where the iterator had already completed, set the
 *                               completed flag and skip the node_find()
 */
static void castle_ct_immut_iter_init(c_immut_iter_t *iter,
                                      castle_immut_iter_node_start node_start,
                                      void *private,
                                      c_ext_pos_t *resume_merge_node_cep,
                                      int already_completed)
{
    c_ext_pos_t first_node_cep;
    uint16_t first_node_size;

    iter->btree     = castle_btree_type_get(iter->tree->btree_type);
    iter->completed = 0;
    iter->curr_c2b  = NULL;
    iter->next_c2b  = NULL;
    iter->node_start= node_start;
    iter->private   = private;
    iter->async_iter.end_io = NULL;
    iter->async_iter.iter_type = &castle_ct_immut_iter;

    first_node_cep.ext_id = iter->tree->tree_ext_free.ext_id;
    first_node_cep.offset = 0;

    if(resume_merge_node_cep)
    {
        BUG_ON(resume_merge_node_cep->ext_id != first_node_cep.ext_id);
        first_node_cep.offset = resume_merge_node_cep->offset;
    }

    if(already_completed)
    {
        castle_printk(LOG_DEBUG, "%s::Initialising immut enumerator (iter %p)"
                " in COMPLETED state for ct id=%d\n",
                __FUNCTION__, iter, iter->tree->seq);
        iter->completed = 1;
        return;
    }

    first_node_size = iter->tree->node_sizes[0];
    castle_printk(LOG_DEBUG, "%s::first_node_cep = "cep_fmt_str"\n",
            __FUNCTION__, cep2str(first_node_cep));
    castle_ct_immut_iter_next_node_find(iter,
                                        first_node_cep,
                                        first_node_size);
    /* Check if we succeeded at finding at least a single node */
    BUG_ON(!iter->next_c2b);
    /* Init curr_c2b correctly */
    castle_ct_immut_iter_next_node(iter);
}

/**
 * Compare verion tuples k1,v1 against k2,v2.
 *
 * @param btree Source btree (for compare function)
 * @param k1    Key to compare against
 * @param v1    Version to compare against
 * @param k2    Key to compare with
 * @param v2    Version to compare with
 *
 * @return -1   (k1, v1) <  (k2, v2)
 * @return  0   (k1, v1) == (k2, v2)
 * @return  1   (k1, v1) >  (k2, v2)
 */
static int castle_kv_compare(struct castle_btree_type *btree,
                             void *k1, c_ver_t v1,
                             void *k2, c_ver_t v2)
{
    int ret = btree->key_compare(k1, k2);
    if(ret != 0)
        return ret;

    /* Reverse v achieved by inverting v1<->v2 given to version_compare() function */
    return castle_version_compare(v2, v1);
}

/**
 * Modlist B-tree iterator structure.
 *
 * @also castle_ct_modlist_iter_init()
 */
typedef struct castle_modlist_iterator {
    c_async_iterator_t async_iter;
    struct castle_btree_type *btree;
    struct castle_component_tree *tree;
    uint16_t leaf_node_size;
    struct castle_da_merge *merge;
    c_immut_iter_t *enumerator;
    uint8_t enum_advanced;          /**< Set if enumerator has advanced to a new node             */
    int err;
    uint32_t nr_nodes;              /**< Number of nodes in the buffer                            */
    void *node_buffer;              /**< Buffer to store all the nodes                            */
    uint32_t nr_items;              /**< Number of items in the buffer                            */
    uint32_t next_item;             /**< Next item to return in iterator                          */
    struct item_idx {
        uint32_t node;              /**< Which btree node                                         */
        uint32_t node_offset;       /**< Offset within btree node                                 */
    } *src_entry_idx;               /**< 1 of 2 arrays of entry pointers (used for sort)          */
    struct item_idx *dst_entry_idx; /**< 2nd array of entry pointers                              */
    struct entry_range {            /**< Entry range describes start,end within *_entry_idx       */
        uint32_t start;
        uint32_t end;
    } *ranges;
    uint32_t nr_ranges;             /**< Number of elements in node_ranges                        */
} c_modlist_iter_t;

struct mutex    castle_da_level1_merge_init;            /**< For level 1 merges serialise entry to
                                                             castle_da_merge_init()               */
atomic_t        castle_ct_modlist_iter_byte_budget;     /**< Byte budget remaining for in-flight
                                                             sorted modlist iter node buffers.    */

/**
 * Free memory allocated by iterator and replenish byte budget.
 */
static void castle_ct_modlist_iter_free(c_modlist_iter_t *iter)
{
    int buffer_size;

    if(iter->enumerator)
    {
        castle_ct_immut_iter.cancel(iter->enumerator);
        castle_free(iter->enumerator);
    }
    castle_check_free(iter->node_buffer);
    castle_check_free(iter->src_entry_idx);
    castle_check_free(iter->dst_entry_idx);
    castle_check_free(iter->ranges);

    /* Replenish the budget - no need to serialise. */
    buffer_size = iter->nr_nodes * iter->leaf_node_size * C_BLK_SIZE;
    atomic_add(buffer_size, &castle_ct_modlist_iter_byte_budget);
}

/**
 * Get requested btree node from the node_buffer.
 */
static struct castle_btree_node* castle_ct_modlist_iter_buffer_get(c_modlist_iter_t *iter,
                                                                   uint32_t idx)
{
    char *buffer = iter->node_buffer;

    return (struct castle_btree_node *)(buffer + idx * iter->leaf_node_size * C_BLK_SIZE);
}

/**
 * Return key, version, cvt for entry sort_idx within iter->src_entry_idx[].
 */
static void castle_ct_modlist_iter_item_get(c_modlist_iter_t *iter,
                                            uint32_t sort_idx,
                                            void **key_p,
                                            c_ver_t *version_p,
                                            c_val_tup_t *cvt_p)
{
    struct castle_btree_type *btree = iter->btree;
    struct castle_btree_node *node;

    debug_verbose("Node_idx=%d, offset=%d\n",
                  iter->sort_idx[sort_idx].node,
                  iter->sort_idx[sort_idx].node_offset);
    node = castle_ct_modlist_iter_buffer_get(iter, iter->src_entry_idx[sort_idx].node);
    btree->entry_get(node,
                     iter->src_entry_idx[sort_idx].node_offset,
                     key_p,
                     version_p,
                     cvt_p);
}

/**
 * Return the next entry from the iterator.
 *
 * - Uses the final sorted src_entry_idx[].
 *
 * @also castle_ct_modlist_iter_fill()
 * @also castle_ct_modlist_iter_mergesort()
 */
static void castle_ct_modlist_iter_next(c_modlist_iter_t *iter,
                                        void **key_p,
                                        c_ver_t *version_p,
                                        c_val_tup_t *cvt_p)
{
    castle_ct_modlist_iter_item_get(iter, iter->next_item, key_p, version_p, cvt_p);
    iter->next_item++;

    /* Update merge stats. */
    iter->merge->nr_bytes += castle_tree_size_stats_update(*key_p, cvt_p, iter->tree,
                                                            0 /* Drain. */);
}

/**
 * Does the iterator have further entries.
 *
 * @return 1    Entry has more entries
 * @return 0    No further entries
 */
static int castle_ct_modlist_iter_has_next(c_modlist_iter_t *iter)
{
    return (!iter->err && (iter->next_item < iter->nr_items));
}

/**
 * Prepare the iterator for next key. This is a NOP for modlist_iter as the data is completely
 * in buffer.
 *
 * @return 1    Always
 */
static int castle_ct_modlist_iter_prep_next(c_modlist_iter_t *iter)
{
    return 1;
}

/**
 * Fill count entry pointers in dst_entry_idx from src_entry_idx.
 *
 * @param iter  Modlist iterator (provides src_entry_idx, dst_entry_idx)
 * @param src   Starting src_entry_idx entry to source entry pointers from
 * @param dst   Starting dst_entry_idx entry to populate from
 * @param count Number of entries to populate
 */
static inline void castle_ct_modlist_iter_merge_index_fill(c_modlist_iter_t *iter,
                                                           uint32_t src,
                                                           uint32_t dst,
                                                           uint32_t count)
{
    uint32_t i;

    for (i = 0; i < count; i++, src++, dst++)
    {
        iter->dst_entry_idx[dst].node        = iter->src_entry_idx[src].node;
        iter->dst_entry_idx[dst].node_offset = iter->src_entry_idx[src].node_offset;
    }
}

/**
 * Mergesort two contiguous entry ptr ranges (r1, r2) from src_entry_idx into dst_entry_idx.
 *
 * @param iter  Modlist iterator (provides src_entry_idx, dst_entry_idx)
 * @param r1    First range of node entry pointers
 * @param r2    Second range of node entry pointers
 *
 * - Iterate over entries pointed to by r1->start,r1->end and r2->start,r2->end
 *   from src_entry_idx[]
 * - Write out entry pointers in smallest to largest order into dst_entry_idx[]
 *   starting at index r1->start
 * - Result is that dst_entry_idx[r1->start] to dst_entry_idx[r2->end] will be
 *   sorted in smallest to largest order
 *
 * @also castle_ct_modlist_iter_mergesort()
 */
static void castle_ct_modlist_iter_merge_ranges(c_modlist_iter_t *iter,
                                                struct entry_range *r1,
                                                struct entry_range *r2)
{
    uint32_t r1_idx = r1->start;    /* current index for r1 */
    uint32_t r2_idx = r2->start;    /* current index for r2 */
    uint32_t dst_idx = r1->start;   /* output index */
    uint32_t src_idx = 0;           /* index of next smallest entry (from r1 or r2) */
    void *r1_key, *r2_key;
    c_ver_t r1_ver, r2_ver;

    BUG_ON(r1->end+1 != r2->start); /* ranges *MUST* be contiguous */

    for (dst_idx = r1->start; dst_idx <= r2->end; dst_idx++)
    {
        might_resched();

        /* Both ranges have more entries if their indexes lie within the range. */
        if (r1_idx <= r1->end && r2_idx <= r2->end)
        {
            /* Both ranges have more entries, we need to do a comparison to
             * determine which range has the next smallest value. */
            castle_ct_modlist_iter_item_get(iter, r1_idx, &r1_key, &r1_ver, NULL);
            castle_ct_modlist_iter_item_get(iter, r2_idx, &r2_key, &r2_ver, NULL);

            if (castle_kv_compare(iter->btree, r1_key, r1_ver, r2_key, r2_ver) < 0)
            {
                /* r1 smaller than r2. */
                src_idx = r1_idx;
                r1_idx++;
            }
            else
            {
                /* r1 larger than or equal to r2. */
                src_idx = r2_idx;
                r2_idx++;
            }

            /* Update dst_entry_idx with the smallest available entry pointer. */
            castle_ct_modlist_iter_merge_index_fill(iter, src_idx, dst_idx, 1);

            continue;
        }

        /* If we reached here then one of the two entry ranges has been
         * exhausted.  We need do no more comparisons and can just populate
         * the remainder of the output index with the entries from the range
         * that has not yet been exhausted. */

        if (r1_idx <= r1->end)
            castle_ct_modlist_iter_merge_index_fill(iter, r1_idx, dst_idx, r1->end-r1_idx+1);
        else if (r2_idx <= r2->end)
            castle_ct_modlist_iter_merge_index_fill(iter, r2_idx, dst_idx, r2->end-r2_idx+1);
        else
            BUG();

        /* We're done. */
        break;
    }
}

/**
 * Handler called when immutable iterator advances to a new source btree node.
 *
 * - Set modlist_iter->enum_advanced
 * - Provides a mechanism for the modlist iterator to know when the immutable
 *   iterator has advanced to a new node
 * - Used for sorting efficiency
 *
 * @also castle_ct_modlist_iter_fill()
 */
static void castle_ct_modlist_iter_next_node(c_immut_iter_t *immut_iter)
{
    c_modlist_iter_t *modlist_iter = immut_iter->private;
    modlist_iter->enum_advanced = 1;
}

/**
 * Populate node_buffer with leaf btree nodes, set up entry indexes and node ranges.
 *
 * - Using immutable iterator (iter->enumerator) iterate over entries in the
 *   unsorted btree
 * - Immutable iterator has a callback when it advances to a new btree node.
 *   castle_ct_modlist_iter_next_node() is registered as the callback handler
 *   and sets iter->enum_advanced whenever a new source node is used
 * - Get a new buffer btree node whenever the source iterator node advances
 * - Keep getting (unsorted) entries from the immutable iterator and store them
 *   in the node_buffer.  Put an entry in dst_entry_idx[] pointing to the node
 *   and node_offset
 * - As we move to a new node when the immutable iterator moves, we are
 *   guaranteed that individual btree nodes are sorted.  Fill ranges[] with
 *   start and end index within dst_entry_idx[]
 *
 * @also castle_ct_modlist_iter_mergesort()
 */
static void castle_ct_modlist_iter_fill(c_modlist_iter_t *iter)
{
    struct castle_btree_type *btree = iter->btree;
    struct castle_btree_node *node = NULL;
    uint32_t node_idx, item_idx, node_offset;
    c_ver_t version;
    c_val_tup_t cvt;
    void *key;

    node_idx = item_idx = node_offset = 0;
    while (castle_iterator_has_next_sync(&castle_ct_immut_iter, iter->enumerator))
    {
        might_resched();

        /* Get the next (unsorted) entry from the immutable iterator. */
        castle_ct_immut_iter.next(iter->enumerator, &key, &version, &cvt);
        debug("In enum got next: k=%p, version=%d, %u/%llu, cep="cep_fmt_str_nl,
                key, version, (uint32_t)cvt.type, cvt.length, cep2str(cvt.cep));
        debug("Dereferencing first 4 bytes of the key (should be length)=0x%x.\n",
                *((uint32_t *)key));
        debug("Inserting into the node=%d, under idx=%d\n", node_idx, node_offset);
        if(CVT_ACCUM_COUNTER(cvt))
            CVT_COUNTER_ACCUM_ONEV_TO_LOCAL(cvt, cvt);

        /* Advance to a new node if the immutable iterator has moved on.  This
         * is handled via the immutable iterator callback.  We rely on source
         * nodes being identically sized to our destination nodes. */
        if (iter->enum_advanced)
        {
            /* Set end entry for node range we just completed. */
            if (likely(node_idx))
                iter->ranges[node_idx-1].end = item_idx-1;
            /* Set start entry for node range we're moving to. */
            iter->ranges[node_idx].start = item_idx;

            /* Get a new node. */
            node = castle_ct_modlist_iter_buffer_get(iter, node_idx);
            castle_btree_node_init(iter->tree, node, 0, iter->tree->node_sizes[0], 0);

            /* We've advance, initialise a good state. */
            iter->enum_advanced = 0;
            node_offset = 0;
            node_idx++;
        }

        /* Insert entry into node. */
        btree->entry_add(node, node_offset, key, version, cvt);
        iter->dst_entry_idx[item_idx].node        = node_idx-1;
        iter->dst_entry_idx[item_idx].node_offset = node_offset;
        node_offset++;
        item_idx++;
    }

    if (likely(node_idx))
        iter->ranges[node_idx-1].end = item_idx-1;    /* @TODO this should be tidier */

    if (item_idx != atomic64_read(&iter->tree->item_count))
    {
        castle_printk(LOG_WARN, "Error. Different number of items than expected in CT=%d "
               "(dynamic=%d). Item_idx=%d, item_count=%ld\n",
               iter->tree->seq, iter->tree->dynamic,
               item_idx, atomic64_read(&iter->tree->item_count));
        WARN_ON(1);
    }
    iter->nr_items = item_idx;
    iter->nr_ranges = node_idx;
    //iter->err = iter->enumerator->err;
}

/**
 * Mergesort the underlying component tree into smallest->largest k,<-v order.
 *
 * L1 btrees are in insertion order but individual nodes have entries sorted in
 * k,<-v order.  To iterate over the btree we must first sort the whole tree.
 * This is done by merging leaf-nodes together repeatedly until we have a single
 * large k,<-v sorted set of entries.
 *
 * Internally the iterator uses:
 *
 * - node_buffer: contiguous buffer of btree leaf-nodes with entries
 * - src_entry_idx[], dst_entry_idx[]: two indirect indexes of entries within
 *   node_buffer.  We sort the data indirectly and hence for simplicity
 *   alternate src_entry_idx[] and dst_entry_idx[] for each round of merges
 * - ranges: ranges of entries within src_entry_idx[] that are guaranteed to
 *   be k,<-v sorted
 * - nr_ranges: number of ranges in src_entry_idx[]
 *
 * Mergesort implementation as follows:
 *
 * castle_ct_modlist_iter_fill() fills iter->entry_buffer with leaf-nodes from
 * the source btree.  For each entry that gets inserted into the buffer a
 * pointer to that entry goes into dst_entry_idx[].  Individual source btree
 * nodes are k,<-v sorted so we define ranges of entries on top of
 * dst_entry_idx[].  Each range encompasses the entries from a single source
 * btree node.  iter->nr_ranges contains the number of active ranges in
 * src_entry_idx[] (except after a fill when it is valid for dst_entry_idx[]).
 *
 * We go through the main mergesort loop until nr_ranges has reached 1 (single
 * sorted range of entries).  Each time we go through the loop we swap the src
 * and dst entry_idx[] such that src_entry_idx[] contains the most up-to-date
 * sorted data we have available.
 *
 * Take two ranges of entries and merge them together in _merge_ranges().  This
 * takes the entries from src_entry_idx[] and writes out sorted entries into
 * dst_entry_idx[].
 *
 * Update ranges[] with the new range start and end (new range start will be
 * range1.start and end will be range2.end - ranges must be contiguous).
 *
 * If we have an uneven number of ranges move the entry pointers from src_
 * to dst_entry_idx[] and ensure the range points to the correct entries.  No
 * merge is performed in this instance.  @TODO this is inefficient
 *
 * Update the total number of ranges and go again if necessary.
 *
 * @also castle_ct_modlist_iter_fill()
 * @also castle_ct_modlist_iter_merge_ranges()
 * @also castle_ct_modlist_iter_init()
 */
static void castle_ct_modlist_iter_mergesort(c_modlist_iter_t *iter)
{
    uint32_t src_range, dst_range;
    void *tmp_entry_idx;

    /* Populate internal entry buffer and initialise dst_entry_idx[] and the
     * initial node ranges for sorting. */
    castle_ct_modlist_iter_fill(iter);

    /* Repeatedly merge ranges of entry pointers until we have a single
     * all-encompassing smallest->largest sorted range we can use to return
     * entries when the iterator .has_next(), .next() functions are called. */
    while (iter->nr_ranges > 1)
    {
        /* Another merge.  Swap the src and dst entry indexes around.
         * We will now be sourcing from the previous iteration's dst_entry_idx
         * (also used by castle_ct_modlist_iter_fill()) and writing our values
         * out to our previous source. */
        tmp_entry_idx = iter->src_entry_idx;
        iter->src_entry_idx = iter->dst_entry_idx;  /* src = dst */
        iter->dst_entry_idx = tmp_entry_idx;        /* dst = src */

        src_range = dst_range = 0;

        /* So long as we have two remaining entry ranges, mergesort the entries
         * together to create a single range spanning the capacity of both. */
        while (src_range+1 < iter->nr_ranges)
        {
            /* Mergesort. */
            castle_ct_modlist_iter_merge_ranges(iter,
                                                &iter->ranges[src_range],
                                                &iter->ranges[src_range+1]);

            /* Update the destination range. */
            iter->ranges[dst_range].start = iter->ranges[src_range].start;
            iter->ranges[dst_range].end   = iter->ranges[src_range+1].end;

            src_range += 2;
            dst_range++;
        }

        /* Above we merged pairs of ranges.  Part of the merge process (handled
         * within castle_ct_modlist_iter_merge_ranges() is to populate the
         * dst_entry_idx.  If we started with an odd number of ranges we must
         * deal with the straggling range as a special case. */
        if (src_range < iter->nr_ranges)
        {
            /* We only have one range to merge so we fake up a range that
             * castle_ct_modlist_iter_merge_ranges() will determine to be
             * exhausted and therefore will populate dst_entry_idx with only
             * those entries from our one remaining src_range. */
            struct entry_range null_range;

            /* Mergesort. */
            null_range.start = iter->ranges[src_range].end+1;
            null_range.end   = iter->ranges[src_range].end;
            castle_ct_modlist_iter_merge_ranges(iter,
                                                &iter->ranges[src_range],
                                                &null_range);

            /* Update the destination range. */
            iter->ranges[dst_range].start = iter->ranges[src_range].start;
            iter->ranges[dst_range].end   = iter->ranges[src_range].end;

            src_range++;
            dst_range++;
        }
        /* else even number of source ranges */

        iter->nr_ranges = dst_range;
    }

    /* Finally ensure dst_entry_idx points to the final sorted index and free
     * the other temporary index right now. */
    castle_free(iter->src_entry_idx);
    iter->src_entry_idx = iter->dst_entry_idx;
    iter->dst_entry_idx = NULL;
}

struct castle_iterator_type castle_ct_modlist_iter = {
    .register_cb = NULL,
    .prep_next   = (castle_iterator_prep_next_t)    castle_ct_modlist_iter_prep_next,
    .has_next    = (castle_iterator_has_next_t)     castle_ct_modlist_iter_has_next,
    .next        = (castle_iterator_next_t)         castle_ct_modlist_iter_next,
    .skip        = NULL,
};

/**
 * Initialise modlist btree iterator.
 *
 * See castle_ct_modlist_iter_mergesort() for full implementation details.
 *
 * - Initialise members
 * - Consume bytes from the global modlist iter byte budget
 * - Allocate memory for node_buffer, src_ and dst_entry_idx[] and ranges
 * - Initialise immutable iterator (for sort)
 * - Kick off mergesort
 *
 * NOTE: Caller must hold castle_da_level1_merge_init mutex.
 *
 * @also castle_ct_modlist_iter_mergesort()
 */
static void castle_ct_modlist_iter_init(c_modlist_iter_t *iter)
{
    struct castle_component_tree *ct = iter->tree;
    int buffer_size;

    BUG_ON(!mutex_is_locked(&castle_da_level1_merge_init));
    BUG_ON(atomic64_read(&ct->item_count) == 0);
    BUG_ON(!ct); /* component tree must be provided */

    iter->err = 0;
    iter->btree = castle_btree_type_get(ct->btree_type);
    iter->leaf_node_size = ct->node_sizes[0];
    iter->async_iter.end_io = NULL;
    iter->async_iter.iter_type = &castle_ct_modlist_iter;

    /* To prevent sudden kernel memory ballooning we impose a modlist byte
     * budget for all DAs.  Size the node buffer based on leaf nodes only. */
    buffer_size = atomic64_read(&ct->tree_ext_free.used);
    iter->nr_nodes = buffer_size / (iter->leaf_node_size * C_BLK_SIZE);
    if (atomic_sub_return(buffer_size, &castle_ct_modlist_iter_byte_budget) < 0)
    {
        castle_printk(LOG_INFO,
                "Couldn't allocate enough bytes for _modlist_iter_init from bytes budget.\n");
        atomic_add(buffer_size, &castle_ct_modlist_iter_byte_budget);
        iter->err = -ENOMEM;
        return;
    }

    /* Allocate immutable iterator.
     * For iterating over source entries during sort. */
    iter->enumerator = castle_alloc(sizeof(c_immut_iter_t));
    iter->enumerator->merge = NULL;

    /* Allocate btree-entry buffer, two indexes for the buffer (for sorting)
     * and space to define ranges of sorted nodes within the index. */
    iter->node_buffer = castle_alloc(buffer_size);
    iter->src_entry_idx = castle_alloc(atomic64_read(&ct->item_count) * sizeof(struct item_idx));
    iter->dst_entry_idx = castle_alloc(atomic64_read(&ct->item_count) * sizeof(struct item_idx));
    iter->ranges = castle_alloc(iter->nr_nodes * sizeof(struct entry_range));

    /* Return ENOMEM if we failed any of our allocations. */
    if(!iter->enumerator || !iter->node_buffer || !iter->src_entry_idx || !iter->dst_entry_idx)
    {
        castle_ct_modlist_iter_free(iter);
        iter->err = -ENOMEM;
        return;
    }

    /* Initialise the immutable iterator */
    iter->enumerator->tree = ct;
    castle_ct_immut_iter_init(iter->enumerator, castle_ct_modlist_iter_next_node, iter, NULL, 0);

    /* Finally, sort the data so we can return sorted entries to the caller. */
    castle_ct_modlist_iter_mergesort(iter);

    /* Good state before we accept requests. */
    iter->err = 0;
    iter->next_item = 0;
}

/**
 * Insert a component iterator (with cached (k,v)) into the RB-tree.
 *
 * In case of duplicate (k,v) tuples maintain only store the most recent iterator in the tree.
 * All other iterators in the list rooted at that newest iterator.same_kv_head.
 *
 * Each_skip callback will be used to notify the client about older CVTs with matching (k,v).
 * But only if they are non-counter types.
 *
 * @param iter [in]         Merged iterator that the RB tree belongs to
 * @param comp_iter [in]    Component iterator that the new kv pair belongs to
 *
 * @also _each_skip() callbacks
 */
static void castle_ct_merged_iter_rbtree_insert(c_merged_iter_t *iter,
                                                struct component_iterator *comp_iter)
{
    struct rb_root *root = &iter->rb_root;
    struct rb_node **p = &root->rb_node;
    struct rb_node *parent = NULL;
    struct rb_node *node = &comp_iter->rb_node;
    int nr_cmps = 0;

    /* Init the same_kv_head when the iterator is getting added to the tree.
       This guarantees that its going to be read for use, when we detect (k,v) collision(s). */
    INIT_LIST_HEAD(&comp_iter->same_kv_head);

    /* Go until end of the tree. */
    while (*p)
    {
        struct component_iterator *c_iter, *dup_iter = NULL, *new_iter = NULL;
        int kv_cmp;

        parent = *p;
        c_iter = rb_entry(parent, struct component_iterator, rb_node);

        BUG_ON(!c_iter->cached);
        BUG_ON(c_iter == comp_iter);

        /* Compare the entry in RB Tree with new entry. */
        kv_cmp = castle_kv_compare(iter->btree,
                                   comp_iter->cached_entry.k,
                                   comp_iter->cached_entry.v,
                                   c_iter->cached_entry.k,
                                   c_iter->cached_entry.v);
        nr_cmps++;

        /* New (key,version) is smaller than key in tree.  Traverse left. */
        if (kv_cmp < 0)
            p = &(*p)->rb_left;
        /* New (key,version) is bigger than key in tree.  Traverse right. */
        else if (kv_cmp > 0)
            p = &(*p)->rb_right;
        else
        {
            /* Both (key,version) pairs are equal. Here is how we deal with those:
             *
             * 1. Put the newest iterator (i.e. from the latest tree) in the rb_tree.
             *    Older iterators with same (k,v) will _not_ be accessible in the tree directly.
             * 2. Construct a list of iterators which cache same (k,v), rooted at the newest
             *    component iterator.same_kv_head. This list may contain both counter and
             *    non-counter CVTs.
             * 3. Call each_skip (if registered) for all iterators, except of the newest
             *    one (i.e. from the latest tree).
             *
             * Component iterators are threaded onto a list headed by the newset iterator
             * (same_kv list). This list is later used to construct response for
             * counters. Otherwise its thrown away.
             *
             * Component iterator pointers are used to determine the recency order.
             */
            if(c_iter > comp_iter)
            {
                /* The current iterator is more recent than the one in the tree.
                   (Re-)splice the same_kv list onto current iterator head. */
                list_splice_init(&c_iter->same_kv_head, &comp_iter->same_kv_head);
                /* Replace the rb node. */
                rb_replace_node(&c_iter->rb_node, &comp_iter->rb_node, root);
                /* Add the older iterator onto same_kv list. */
                list_add(&c_iter->same_kv_list, &comp_iter->same_kv_head);

                /* Save which iterator is newer and older. */
                dup_iter = c_iter;
                new_iter = comp_iter;

            } else
            {
                /* The current iterator is less recent that the one in the tree.
                   Add the current iterator to the same_kv list (rooted at the most
                   recent iterator). */
                list_add(&comp_iter->same_kv_list, &c_iter->same_kv_head);

                /* Save which iterator is newer and older. */
                dup_iter = comp_iter;
                new_iter = c_iter;
            }

            /* The rb_tree and same_kv list have all been updated, return now. */
            return;
        }
    }

    /* Link the node to tree. */
    rb_link_node(node, parent, p);
    /* Set color and in turn balance the tree. */
    rb_insert_color(node, root);
}

static inline struct component_iterator* castle_ct_merged_iter_rbtree_min_get(
                                                                      c_merged_iter_t *iter)
{
    struct rb_root *root = &iter->rb_root;
    struct rb_node *min;

    /* Get the first element in the sorted order(minimum). */
    min = rb_first(root);
    if(!min)
        return NULL;

    /* Return the iterator. */
    return rb_entry(min, struct component_iterator, rb_node);
}

/**
 * Removes the iterator specified from the rbtree.
 */
static inline void castle_ct_merged_iter_rbtree_del(c_merged_iter_t *iter,
                                                    struct component_iterator *comp_iter)
{
    /* Erase the element from tree. */
    rb_erase(&comp_iter->rb_node, &iter->rb_root);
}

/**
 * Determines and removes+returns the component iterator which provided the smallest
 * key.
 */
static struct component_iterator* castle_ct_merge_iter_rbtree_min_del(c_merged_iter_t *iter)
{
    struct component_iterator *comp_iter;

    /* Get the smallest iter from the tree. */
    comp_iter = castle_ct_merged_iter_rbtree_min_get(iter);
    BUG_ON(!comp_iter);

    /* Delete from the rbtree. */
    castle_ct_merged_iter_rbtree_del(iter, comp_iter);

    /* Return the iterator. */
    return comp_iter;
}

void castle_iterator_sync_end_io(void *iter, int err)
{
    c_async_iterator_t          *async_iter = (c_async_iterator_t *)iter;
    struct castle_iterator_type *iter_type = async_iter->iter_type;

    /* Don't expect any errors. */
    BUG_ON(err);

    /* prep_next() should succeed now. */
    BUG_ON(iter_type->prep_next(iter));

    /* Mark the task as completed and invoke the thread. */
    complete((struct completion *)async_iter->private);
}

int castle_iterator_has_next_sync(struct castle_iterator_type *iter_type, void *iter)
{
    c_async_iterator_t *async_iter = (c_async_iterator_t *)iter;
    struct completion completion;

    /* Make sure the iterator type matches the type in iterator. */
    BUG_ON(async_iter->iter_type != iter_type);

    /* Set end_io(). It will overwrite any default callback. */
    /* FIXME: This might lead to a problem, if we mix has_next_sync() and prep_next() calls. */
    async_iter->end_io = castle_iterator_sync_end_io;

    /* Initialise completion structure. Need to wait for the iterator to fill its buffer. */
    init_completion(&completion);
    async_iter->private = (void *)&completion;

    /* If prep_next() fails, then wait for it to fill the buffer. */
    if (!iter_type->prep_next(iter))
        wait_for_completion(&completion);

    /* Return with has_next() response. */
    return iter_type->has_next(iter);
}

/* @TODO: This function only issues I/O on one component iterator at a time.
 * If one iterator goes asynchronous, we do not kick other component iterators
 * at the same time, which makes the RQ essentially synchronous.
 * If we fix this, iter_running would need to become a counter. */
static int castle_ct_merged_iter_prep_next(c_merged_iter_t *iter)
{
    int i;
    struct component_iterator *comp_iter;

    debug_iter("%s:%p\n", __FUNCTION__, iter);

    debug_iter("No of comp_iters: %u\n", iter->nr_iters);
    for (i = 0; i < iter->nr_iters; i++)
    {
        comp_iter = iter->iterators + i;

        debug_iter("%s:%p:%d\n", __FUNCTION__, iter, i);
        /* Replenish the cache */
        if(!comp_iter->completed && !comp_iter->cached)
        {
            debug("Reading next entry for iterator: %d.\n", i);
            /* #4324: Mark iter as running before calling prep_next() to prevent
             * any possibility of racing with castle_ct_merged_iter_end_io(). */
            iter->iter_running = 1;
            if (!comp_iter->iterator_type->prep_next(comp_iter->iterator))
            {
                /* Component iterator went asynchronous (due to I/O). */
                debug_iter("%s:%p:%p:%d - schedule\n", __FUNCTION__, iter, comp_iter->iterator, i);
                return 0;
            }
            else
                iter->iter_running = 0;
            if (comp_iter->iterator_type->has_next(comp_iter->iterator))
            {
                comp_iter->iterator_type->next(comp_iter->iterator,
                                               &comp_iter->cached_entry.k,
                                               &comp_iter->cached_entry.v,
                                               &comp_iter->cached_entry.cvt);
                comp_iter->cached = 1;
                iter->src_items_completed++;
                debug_iter("%s:%p:%d - cached\n", __FUNCTION__, iter, i);
                /* Insert the kv pair into RB tree. */
                /* It is possible that. this call could delete kv pairs of the component
                 * iterators (which is fine, as we go through that component iterator anyway)
                 * coming after this or it could delete the current kv pair itself. */
                castle_ct_merged_iter_rbtree_insert(iter, comp_iter);
            }
            else
            {
                debug_iter("%s:%p:%d - nothing left\n", __FUNCTION__, iter, i);
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
    iter->async_iter.end_io  = cb;
    iter->async_iter.private = data;
}

static void castle_ct_merged_iter_end_io(void *rq_iter, int err)
{
    c_merged_iter_t *iter = ((c_rq_iter_t *) rq_iter)->async_iter.private;

    debug_iter("%s:%p\n", __FUNCTION__, iter);
    if (castle_ct_merged_iter_prep_next(iter))
    {
        debug_iter("%s:%p - Done\n", __FUNCTION__, iter);

        iter->iter_running = 0;
        iter->async_iter.end_io(iter, 0);

        return;
    }
}

static int castle_ct_merged_iter_has_next(c_merged_iter_t *iter)
{
    debug_iter("%s:%p\n", __FUNCTION__, iter);

    /* Iterator shouldn't be running(waiting for prep_next to complete) now. */
    BUG_ON(iter->iter_running);

    debug("Merged iterator has next, err=%d, non_empty_cnt=%d\n",
            iter->err, iter->non_empty_cnt);

    return (!iter->err && (iter->non_empty_cnt > 0));
}

/**
 * Consumes the current key from the component iterator provided, and from all
 * all iterators in same_kv list.
 * Additionally, skip can be performed in all the iterators mentioned, by setting
 * 'skip' argument to true, and providing the skip key.
 */
static void castle_ct_merged_iter_consume(c_merged_iter_t *merged_iter,
                                          struct component_iterator *iter,
                                          int skip,
                                          void *skip_key)
{
    struct component_iterator *other_iter;
    struct list_head *l;
    c_val_tup_t prev_cvt;
    c_ver_t prev_version;

    /* If each_skip() callback isn't provided, skip straight through to draining the cached
       entries. */
    if(!merged_iter->each_skip)
        goto drain_cached;

    /*
     * Walk the list backwards, and call each_skip() (if provided) for each pair of iterators.
     * This way we guarantee that each of the iterators will be supplied as the duplicate
     * iterator precisely once (important for version stats accounting in castle_da_each_skip()).
     */
    prev_cvt = INVAL_VAL_TUP;
    prev_version = INVAL_VERSION;
    list_for_each_prev(l, &iter->same_kv_head)
    {
        other_iter = list_entry(l, struct component_iterator, same_kv_list);
        /* Each of the component iterators should have something cached. */
        BUG_ON(!other_iter->cached);
        /* Head should be newest. */
        BUG_ON(iter > other_iter);

        /* If previous CVT is valid, callback. */
        if(!CVT_INVALID(prev_cvt))
        {
            BUG_ON(VERSION_INVAL(prev_version));
            BUG_ON(prev_version != other_iter->cached_entry.v);
            merged_iter->each_skip(merged_iter,
                                   prev_version,
                                   prev_cvt,
                                   other_iter->cached_entry.cvt);
        }
        prev_cvt = other_iter->cached_entry.cvt;
        prev_version = other_iter->cached_entry.v;
    }
    /* Finally, if prev_cvt set, call each_skip for that (providing CVT from 'iter'). */
    if(!CVT_INVALID(prev_cvt))
    {
        BUG_ON(VERSION_INVAL(prev_version));
        BUG_ON(prev_version != iter->cached_entry.v);
        merged_iter->each_skip(merged_iter, prev_version, prev_cvt, iter->cached_entry.cvt);
    }

drain_cached:
    /* Drain the entries stored in 'cached_entry', by setting the cached flag to false.
       If we are skipping, call skip on all component iterators. */
    list_for_each(l, &iter->same_kv_head)
    {
        other_iter = list_entry(l, struct component_iterator, same_kv_list);
        if(skip)
            other_iter->iterator_type->skip(other_iter->iterator, skip_key);
        other_iter->cached = 0;
    }

    /* Skip and clear cached flag for the min iterator too. */
    if(skip)
        iter->iterator_type->skip(iter->iterator, skip_key);
    iter->cached = 0;
}

/**
 * Sort a list of iterators (with same kv) according to iter order, which is
 * implicitly ct seq order.
 */
static void castle_ct_merged_iter_same_kv_iters_sort(struct list_head *same_kv_head,
                                                     struct rb_root *rb_root_p)
{
    struct list_head *l, *t;
    struct rb_node **p, *parent;

    /* The same_kv list isn't sorted. Insert sort it. */
    *rb_root_p = RB_ROOT;
    list_for_each_safe(l, t, same_kv_head)
    {
        struct component_iterator *current_iter;

        /* Work ot the iterator structure pointer, and delete list entry. */
        current_iter = list_entry(l, struct component_iterator, same_kv_list);
        list_del(l);

        /* Insert into rb tree. */
        parent = NULL;
        p = &rb_root_p->rb_node;
        while(*p)
        {
            struct component_iterator *tree_iter;

            parent = *p;
            tree_iter = rb_entry(parent, struct component_iterator, rb_node);

            BUG_ON(!CVT_LEAF_VAL(tree_iter->cached_entry.cvt));

            /* We never expect to see the same iterator twice. */
            BUG_ON(tree_iter == current_iter);
            if(tree_iter > current_iter)
                p = &(*p)->rb_left;
            else
                p = &(*p)->rb_right;
        }
        rb_link_node(&current_iter->rb_node, parent, p);
        rb_insert_color(&current_iter->rb_node, rb_root_p);
    }
}

/**
 * Accumulates and returns counter (wrapped into a cvt) from the component iterator
 * specified and older iterators present in the same_kv list.
 *
 * The function uses O(n*log(n)) sort on same_kv list.
 */
static c_val_tup_t castle_ct_merged_iter_counter_reduce(struct component_iterator *iter)
{
    c_val_tup_t accumulator;
    struct rb_root rb_root;
    struct rb_node *rb_entry;

    /* We expecting for the list head of the same_kv list to be a counter (at least). */
    BUG_ON(!CVT_ANY_COUNTER(iter->cached_entry.cvt));

    /* Prepare the accumulator. */
    CVT_COUNTER_LOCAL_ADD_INIT(accumulator, 0);
    /* we don't support timestamped counters but let's explicitly set the timestamp field anyway */
    accumulator.user_timestamp = 0;

    /* Deal with the list head. */
    if(castle_counter_simple_reduce(&accumulator, iter->cached_entry.cvt))
        return accumulator;

    /* If the list same_kv list is empty, return too. */
    if(list_empty(&iter->same_kv_head))
        return accumulator;

    /* The same_kv list isn't sorted. Insert sort it. */
    castle_ct_merged_iter_same_kv_iters_sort(&iter->same_kv_head, &rb_root);

    /* Now accumulate the results one iterator at the time. */
    rb_entry = rb_first(&rb_root);
    /* There was a check for empty same_kv list, so there should be something in the tree. */
    BUG_ON(!rb_entry);
    do {
        iter = rb_entry(rb_entry, struct component_iterator, rb_node);
        /* Continue iterating until a terminating cvt (e.g. a counter set) is found. */
        if(castle_counter_simple_reduce(&accumulator, iter->cached_entry.cvt))
            return accumulator;
    } while((rb_entry = rb_next(&iter->rb_node)));

    /* Never reached a terminating cvt, assume implicit set 0. */
    return accumulator;
}

/**
 * Picks the entry with largest user timestamp (wrapped into a cvt) from the component iterator
 * specified and older iterators present in the same_kv list.
 *
 * The function does O(n) search on the same_kv list looking for entries with larger user
 * timestamp, and if there are m entries with a larger timestamp, it does O(m*log(m)) sort on
 * a subset of the same_kv list. If m == 0, it returns immediately. Therefore in the common case
 * where user timestamps are in iter order, the expense is O(n).
 *
 * (based on castle_ct_merged_iter_counter_reduce)
 */
static c_val_tup_t castle_ct_merged_iter_timestamp_select(struct component_iterator *iter)
{
    c_val_tup_t                most_recent_object; /* most recent in terms of user timestamp */
    struct component_iterator *most_recent_iter;
    struct list_head *l, *t;

    most_recent_iter   = iter;
    most_recent_object = iter->cached_entry.cvt;
    BUG_ON(!CVT_LEAF_VAL(most_recent_object));

    /* if the most recent object by iter order is a counter, we should have done counter resolution
       instead of this */
    BUG_ON(CVT_ANY_COUNTER(most_recent_object));

    /* If the list same_kv list is empty, return now. */
    if(list_empty(&iter->same_kv_head))
        return most_recent_object;

    /* Walk same_kv list looking for a deprecating entry; sort order is timestamp then iter */
    list_for_each_safe(l, t, &iter->same_kv_head)
    {
        int more_recent_entry_found = 0;
        struct component_iterator *current_iter;
        current_iter = list_entry(l, struct component_iterator, same_kv_list);
        BUG_ON(!CVT_LEAF_VAL(current_iter->cached_entry.cvt));

        if(current_iter->cached_entry.cvt.user_timestamp > most_recent_object.user_timestamp)
            more_recent_entry_found = 1; /* deprecation by timestamp */
        else if((current_iter->cached_entry.cvt.user_timestamp == most_recent_object.user_timestamp) &&
                current_iter < most_recent_iter)
            more_recent_entry_found = 1; /* same timestamp; deprecation by iter order */

        if( more_recent_entry_found )
        {
            most_recent_iter   = current_iter;
            most_recent_object = current_iter->cached_entry.cvt;
        }

        list_del(l);
    }

    BUG_ON(!CVT_LEAF_VAL(most_recent_object));
    return most_recent_object;
}

static void castle_ct_merged_iter_next(c_merged_iter_t *iter,
                                       void **key_p,
                                       c_ver_t *version_p,
                                       c_val_tup_t *cvt_p)
{
    struct component_iterator *comp_iter;
    c_val_tup_t cvt;

    BUG_ON(!iter);
    BUG_ON(!iter->da);

    debug_iter("%s:%p\n", __FUNCTION__, iter);
    debug("Merged iterator next.\n");

    /* Iterator shouldn't be running(waiting for prep_next to complete) now. */
    BUG_ON(iter->iter_running);

    /* Get the smallest kv pair from RB tree. */
    comp_iter = castle_ct_merge_iter_rbtree_min_del(iter);
    BUG_ON(!comp_iter);
    debug("Smallest entry is from iterator: %p.\n", comp_iter);

    /* Consume (clear cached flags) from the component iterators. */
    castle_ct_merged_iter_consume(iter, comp_iter, 0 /* don't skip. */, NULL);

    /* Work out the counter value (handle the case where the iterator contains a counter.
       NOTE: this destroys same_kv list. Don't use it after this point. */
    if(CVT_ANY_COUNTER(comp_iter->cached_entry.cvt))
        cvt = castle_ct_merged_iter_counter_reduce(comp_iter);
    else if (castle_da_user_timestamping_check(iter->da)) /* it's not a counter, and we are timestamping */
        cvt = castle_ct_merged_iter_timestamp_select(comp_iter);
    else /* this DA not timestamped */
        cvt = comp_iter->cached_entry.cvt;

    /* Return the smallest entry */
    if(key_p)     *key_p     = comp_iter->cached_entry.k;
    if(version_p) *version_p = comp_iter->cached_entry.v;
    if(cvt_p)     *cvt_p     = cvt;
}

static void castle_ct_merged_iter_skip(c_merged_iter_t *iter,
                                       void *key)
{
    struct component_iterator *comp_iter;
    int i;

    debug_iter("%s:%p\n", __FUNCTION__, iter);

    /* Iterator shouldn't be running(waiting for prep_next to complete) now. */
    BUG_ON(iter->iter_running);

    /* If we are skipping in the merged iterator, we are not able to inform the client
       about all duplicate entries. Check that the client isn't asking for it. */
    BUG_ON(iter->each_skip);

    /* Call skip on lower level iterators, if the iterator is not cached. */
    for(i=0; i<iter->nr_iters; i++)
    {
        comp_iter = iter->iterators + i;

        BUG_ON(!comp_iter->iterator_type->skip);
        if (!comp_iter->completed && !comp_iter->cached)
            comp_iter->iterator_type->skip(comp_iter->iterator, key);
    }

    /* Go through the rbtree, and extract all the keys smaller than the key we
       are skipping to. */
    while((comp_iter = castle_ct_merged_iter_rbtree_min_get(iter)) &&
          (iter->btree->key_compare(comp_iter->cached_entry.k, key) < 0))
    {
        /* Since the iterator is in the rb_tree, it must be cached. */
        BUG_ON(!comp_iter->cached);
        /* Delete from the rbtree. */
        castle_ct_merged_iter_rbtree_del(iter, comp_iter);
        /* Consume (clear cached flags & skip) from all component iterators
           on the same_kv list. */
        castle_ct_merged_iter_consume(iter, comp_iter, 1 /* skip. */, key);
    }
}

static void castle_ct_merged_iter_cancel(c_merged_iter_t *iter)
{
    /* FIXME: Handle gracefully. It is possible for range queries to cancel iterator, when it
     * is running. But, usually prep_next completes before expire time. Still possible not to
     * complete.We need to wait for iterator to complete with prep_next. But, make sure
     * it is not racing. */
    /* Iterator shouldn't be running(waiting for prep_next to complete) now. */
    BUG_ON(iter->iter_running);

    castle_check_free(iter->iterators);
}

struct castle_iterator_type castle_ct_merged_iter = {
    .register_cb = (castle_iterator_register_cb_t)castle_ct_merged_iter_register_cb,
    .prep_next   = (castle_iterator_prep_next_t)  castle_ct_merged_iter_prep_next,
    .has_next    = (castle_iterator_has_next_t)   castle_ct_merged_iter_has_next,
    .next        = (castle_iterator_next_t)       castle_ct_merged_iter_next,
    .skip        = (castle_iterator_skip_t)       castle_ct_merged_iter_skip,
    .cancel      = (castle_iterator_cancel_t)     castle_ct_merged_iter_cancel,
};

/**
 * Initialise a meta iterator from a number of component iterators.
 *
 * Once initialised the iterator will return the smallest entry from any of the
 * component trees when castle_ct_merged_iter_next() is called.
 *
 * This iterator is used for merges and range queries (non-exhaustive list).
 */
static void castle_ct_merged_iter_init(c_merged_iter_t *iter,
                                       void **iterators,
                                       struct castle_iterator_type **iterator_types,
                                       castle_merged_iterator_each_skip each_skip,
                                       struct castle_double_array *da)
{
    int i;

    debug("Initing merged iterator for %d component iterators.\n", iter->nr_iters);
    BUG_ON(!iter->btree);
    iter->err                  = 0;
    iter->src_items_completed  = 0;
    iter->async_iter.end_io    = NULL;
    iter->async_iter.iter_type = &castle_ct_merged_iter;
    iter->iter_running         = 0;
    iter->rb_root              = RB_ROOT;
    iter->iterators            = castle_alloc(iter->nr_iters * sizeof(struct component_iterator));
    if (iter->nr_iters && !iter->iterators)
    {
        castle_printk(LOG_WARN, "Failed to allocate memory for merged iterator.\n");
        iter->err = -ENOMEM;
        return;
    }
    iter->each_skip = each_skip;
    iter->da        = da;
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


#ifdef DEBUG
c_modlist_iter_t test_iter1;
c_modlist_iter_t test_iter2;
c_merged_iter_t  test_miter;
static USED void castle_ct_sort(struct castle_component_tree *ct1,
                                struct castle_component_tree *ct2)
{
    c_ver_t version;
    void *key;
    c_val_tup_t cvt;
    int i=0;
    void *iters[2];
    struct castle_iterator_type *iter_types[2];

    debug("Number of items in the ct1: %lld, ct2=%lld\n",
            atomic64_read(&ct1->item_count),
            atomic64_read(&ct2->item_count));

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

    BUG_ON(ct1->da != ct2->da);
    castle_ct_merged_iter_init(&test_miter,
                               iters,
                               iter_types,
                               NULL,
                               ct1->da);
    debug("=============== SORTED ================\n");
    while(castle_iterator_has_next_sync(&castle_ct_merged_iter, &test_miter))
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
    iter->async_iter.end_io  = cb;
    iter->async_iter.private = data;
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
    c_da_rq_iter_t *iter = ((c_merged_iter_t *)merged_iter)->async_iter.private;

    if (castle_da_rq_iter_prep_next(iter))
    {
        iter->async_iter.end_io(iter, 0);
        return;
    }
    else
        BUG();
}

static void castle_da_rq_iter_next(c_da_rq_iter_t *iter,
                                   void **key_p,
                                   c_ver_t *version_p,
                                   c_val_tup_t *cvt_p)
{
    castle_ct_merged_iter_next(&iter->merged_iter, key_p, version_p, cvt_p);
}

static void castle_da_rq_iter_skip(c_da_rq_iter_t *iter, void *key)
{
    castle_ct_merged_iter_skip(&iter->merged_iter, key);
}

/**
 * Deinitialise Range Query iterator.
 *
 * Drops references and frees structures.
 */
void castle_da_rq_iter_cancel(c_da_rq_iter_t *iter)
{
    int i;

    /* Only cancel the iterator if it was actually initialized properly. */
    if (iter->err != 0)
        return;

    /* Cancel merged iterator. */
    castle_ct_merged_iter_cancel(&iter->merged_iter);

    /* Cancel CT iterators. */
    for (i = 0; i < iter->nr_iters; i++)
    {
        c_rq_iter_t *ct_iter = &iter->ct_iters[i];

        castle_rq_iter_cancel(ct_iter);
    }

    /* Free CT iterators structures. */
    castle_free(iter->ct_iters);

    /* Put DA CTs proxy structure. */
    castle_da_cts_proxy_put(iter->cts_proxy);
}

/**
 * Complete range query iterator initialisation.
 *
 * @param   iter    Range query iterator to initialise
 *
 * Called from castle_da_rq_iter_relevant_cts_get() or one of the asynchronous
 * check callbacks once iter->relevant_cts[] has been finalised.  Finalise
 * iterator initialisation and asynchronously inform the caller that it has
 * been done.
 *
 * @also castle_da_rq_iter_init()
 * @also castle_da_rq_iter_relevant_cts_get()
 */
static void _castle_da_rq_iter_init(c_da_rq_iter_t *iter)
{
    struct castle_iterator_type **iters_types = NULL;
    struct castle_btree_type *btree;
    void **iters = NULL;
    int nr_iters, i;

    /* Work out the btree type used by this DA. */
    btree = castle_btree_type_get(iter->da->btree_type);

    /* Count how many relevant CTs there are.  It's possible here that there
     * are no relevant CTs - in that case, we will initialise an empty merged
     * iterator and let that handle things for us. */
    for (i = 0, nr_iters = 0; i < iter->cts_proxy->nr_cts; i++)
        if (iter->relevant_cts[i].relevant)
            nr_iters++;

    /* Initialise iterator structure. */
    iter->nr_iters = nr_iters;
    iter->ct_iters = castle_zalloc(nr_iters * sizeof(c_rq_iter_t));
    iters          = castle_alloc(nr_iters * sizeof(void *));
    iters_types    = castle_alloc(nr_iters * sizeof(struct castle_iterator_type *));
    if (!iter->ct_iters || !iters || !iters_types)
        goto alloc_fail;

    /* Initialise CT iterators. */
    for (i = 0, nr_iters = 0; i < iter->cts_proxy->nr_cts; i++)
    {
        struct castle_da_cts_proxy_ct *proxy_ct;
        void *ct_start_key, *ct_end_key;
        c_rq_iter_t *ct_iter;

        /* Don't initialise irrelevant CTs. */
        if (!iter->relevant_cts[i].relevant)
            continue;

        proxy_ct = &iter->cts_proxy->cts[i];
        ct_iter  = &iter->ct_iters[nr_iters];

        switch (proxy_ct->state)
        {
            case NO_REDIR:
                /* No redirection, use requested start and end keys. */
                ct_start_key    = iter->start_key;
                ct_end_key      = iter->end_key;
                break;
            case REDIR_INTREE:
                /* Input tree, start at key_next(partition key), or at start_key
                 * whichever greater.
                 * Prior keys (if queried for) are handled by the output tree. */
                if(btree->key_compare(iter->start_key, proxy_ct->pk_next) >= 0)
                    ct_start_key = iter->start_key;
                else
                    ct_start_key = proxy_ct->pk_next;
                ct_end_key       = iter->end_key;
                break;
            case REDIR_OUTTREE:
                /* Output tree, end at partition key or at end key, whichever
                 * smaller.
                 * Later keys are handled by the input trees. */
                ct_start_key    = iter->start_key;
                if(btree->key_compare(iter->end_key, proxy_ct->pk) >= 0)
                    ct_end_key  = proxy_ct->pk;
                else
                    ct_end_key  = iter->end_key;
                break;
            default:
                BUG();
        }

        /* Initialise CT iterator. */
        castle_rq_iter_init(ct_iter, iter->version, proxy_ct->ct, ct_start_key, ct_end_key);
        BUG_ON(ct_iter->err); /* doesn't fail */

        /* Add initialised iterator to merged iterators lists. */
        iters[nr_iters]       = ct_iter;
        iters_types[nr_iters] = &castle_rq_iter;

        /* We've added one more iterator. */
        nr_iters++;
    }
    BUG_ON(nr_iters != iter->nr_iters);

    /* Initialise merged iterator. */
    iter->merged_iter.nr_iters = iter->nr_iters;
    iter->merged_iter.btree    = btree;
    castle_ct_merged_iter_init(&iter->merged_iter, iters, iters_types, NULL, iter->da);
    castle_ct_merged_iter_register_cb(&iter->merged_iter, castle_da_rq_iter_end_io, iter);

    /* Free structures used to initialise merged iterator. */
    castle_check_free(iter->start_stripped);
    castle_check_free(iter->end_stripped);
    castle_free(iter->relevant_cts);
    castle_free(iters_types);
    castle_free(iters);

    /* Fire asynchronous initialisation callback. */
    iter->init_cb(iter->private);

    return;

alloc_fail:
    if (iter->cts_proxy)
    {
        castle_da_cts_proxy_put(iter->cts_proxy);
        iter->cts_proxy = NULL;
    }
    else
        BUG();

    BUG_ON(iter->relevant_cts == NULL);
    castle_check_free(iter->relevant_cts);

    castle_check_free(iter->start_stripped);
    castle_check_free(iter->end_stripped);
    castle_check_free(iters_types);
    castle_check_free(iters);
    castle_check_free(iter->ct_iters);

    iter->err = -ENOMEM;
    iter->init_cb(iter->private);
}

/**
 * Callback handler when castle_bloom_key_exists() returns a result.
 *
 * @param   private     relevant_ct pointer
 * @param   key_exists  Whether relevant_ct->iter->stripped_start exists
 *
 * NOTE: Called only from castle_bloom_key_exists() if it needed to go
 *       asynchronous to issue read I/O.  It does requeue, so we are not
 *       called in interrupt context.
 *
 * @also castle_da_rq_iter_relevant_cts_get()
 */
inline void castle_da_rq_iter_relevant_ct_cb(void *private, int key_exists)
{
    c_da_rq_iter_ct_relevant_t *relevant_ct = private;

    BUG_ON(key_exists < 0);

    relevant_ct->relevant = key_exists;

    if (atomic_dec_return(&relevant_ct->rq_iter->pending_lookups) == 0)
        /* All CT relevance checks complete, finish initialising iterator. */
        _castle_da_rq_iter_init(relevant_ct->rq_iter);
}

/**
 * Is proxy_ct->ct relevant for range query between start_key, end_key?
 *
 * @return  0   CT is not relevant for this range query
 * @return  1   CT is relevant for this range query, needs to be searched
 * @return  2   CT may be relevant for this range query, verify in bloom filter
 */
static inline int castle_da_rq_iter_ct_relevant(struct castle_da_cts_proxy_ct *proxy_ct,
                                                struct castle_btree_type *btree,
                                                void *start_key,
                                                void *end_key,
                                                void **start_stripped,
                                                void **end_stripped)
{
    if (proxy_ct->state == REDIR_INTREE
            && btree->key_compare(proxy_ct->pk_next, end_key) > 0)
        /* Skip this input tree if the next(partition key) is greater than
         * the end key - it can't have any relevant results. */
        return 0;

    if (proxy_ct->state == REDIR_OUTTREE
            && btree->key_compare(start_key, proxy_ct->pk) > 0)
        /* Skip this output tree if the start key is greater than the
         * partition key - it can't have any relevant results. */
        return 0;

    if (!proxy_ct->ct->bloom_exists)
        /* Query all trees that do not have bloom filters. */
        return 1;

    else if (btree->nr_dims(start_key) <= HASH_STRIPPED_DIMS)
        /* Bloom filters cannot be used if the keys are too short. */
        return 1;

    else
    {
        /* Tree has a bloom filter. */
        if (!*start_stripped)
        {
            /* Start and end keys have not yet been stripped, do it now. */
            *start_stripped = btree->key_strip(start_key, NULL, 0, HASH_STRIPPED_DIMS);
            *end_stripped   = btree->key_strip(end_key,   NULL, 0, HASH_STRIPPED_DIMS);
            BUG_ON(!*start_stripped || !*end_stripped);
        }

        if (btree->key_compare(*start_stripped, *end_stripped) != 0)
            /* Significant stripped dimensions are different.  Query this
             * tree as we can not currently use bloom filters here. */
            return 1;
        else
            /* Significant stripped dimensions are the same.  Query the
             * bloom filter to see if the significant stripped dimensions
             * exist within the filter. */
            return 2;
    }

    BUG(); /* not reached */
}

/**
 * Determine which trees are relevant for a range query of start_key to end_key.
 *
 * @param   iter        Range query iterator to check CTs for
 * @param   start_key   Range query start key
 * @param   end_key     Range query end key
 *
 * Allocates an array of relevant CTs structures (c_da_rq_iter_ct_relevant_t[])
 * and sets the 'relevant' field accordingly.
 *
 * Caller assumes that the iterator completes asynchronously.  This is necessary
 * as we may need to query bloom filters which may go asynchronous.
 *
 * Asynchronous relevance checks are tracked via the iter->pending_lookups.
 * Whoever takes this count down to 0 calls into _castle_da_rq_iter_init() to
 * complete initialisation of the iterator.  In certain circumstances, this may
 * be us at the bottom of this function, otherwise via the bloom filter lookup
 * callback, castle_da_rq_iter_relevant_ct_cb().
 *
 * @return  0       Successfully allocated relevant_cts structure
 * @return -ENOMEM  Failed to allocate relevant_cts structure
 *
 * @also _castle_da_rq_iter_init()
 * @also castle_bloom_key_exists()
 * @also castle_da_rq_iter_ct_relevant()
 * @also castle_da_rq_iter_relevant_ct_cb()
 */
int castle_da_rq_iter_relevant_cts_get(c_da_rq_iter_t *iter,
                                       void *start_key,
                                       void *end_key)
{
    struct castle_btree_type *btree = castle_btree_type_get(iter->da->btree_type);
    struct castle_da_cts_proxy *cts_proxy = iter->cts_proxy;
    int key_exists, i;

    /* Allocate CT relevance structure. */
    iter->relevant_cts   = castle_alloc(cts_proxy->nr_cts * sizeof(c_da_rq_iter_ct_relevant_t));
    if (!iter->relevant_cts)
        return -ENOMEM;

    iter->start_stripped = NULL;
    iter->end_stripped   = NULL;
    atomic_set(&iter->pending_lookups, 1);

    for (i = 0; i < cts_proxy->nr_cts; i++)
    {
        switch (castle_da_rq_iter_ct_relevant(&cts_proxy->cts[i],
                                              btree,
                                              start_key,
                                              end_key,
                                              &iter->start_stripped,
                                              &iter->end_stripped))
        {
            case 0:
                /* CT is not relevant to range query. */
                iter->relevant_cts[i].relevant = 0;
                break;

            case 1:
                /* CT is relevant to range query. */
                iter->relevant_cts[i].relevant = 1;
                break;

            case 2:
                /* CT may be relevant to range query, check bloom filter. */
                atomic_inc(&iter->pending_lookups);
                iter->relevant_cts[i].rq_iter = iter;
                key_exists = castle_bloom_key_exists(&iter->relevant_cts[i].bloom_lookup,
                                                     &cts_proxy->cts[i].ct->bloom,
                                                     iter->start_stripped,
                                                     HASH_STRIPPED_KEYS,
                                                     castle_da_rq_iter_relevant_ct_cb,
                                                     &iter->relevant_cts[i]);
                if (key_exists >= 0)
                {
                    iter->relevant_cts[i].relevant = key_exists;
                    BUG_ON(atomic_dec_return(&iter->pending_lookups) == 0);
                }
                break;

            default:
                BUG();
        }
    }

    if (atomic_dec_return(&iter->pending_lookups) == 0)
        /* All CT relevance checks complete, finish initialising iterator. */
        _castle_da_rq_iter_init(iter);

    return 0;
}

/**
 * Initialise range query iterator.
 *
 * @param   iter        Range query iterator to initialise
 * @param   version     Version to query
 * @param   da_id       DA to iterate
 * @param   start_key   Range query start key
 * @param   end_key     Range query end key
 * @param   init_cb     Callback to fire when initialisation is complete
 * @param   private     Caller-provided data to be passed to init_cb()
 *
 * Iterator initialisation is likely to go asynchronous due to bloom filter
 * lookups.  As a result we inform the caller of initialisation success/failure
 * asynchronously via the init_cb() callback.
 *
 * The real heavy lifting is done in _castle_da_rq_iter_init().
 *
 * @also _castle_da_rq_iter_init()
 * @also castle_da_rq_iter_prep_next()
 * @also castle_da_rq_iter_relevant_cts_get()
 */
void castle_da_rq_iter_init(c_da_rq_iter_t *iter,
                            c_ver_t version,
                            c_da_t da_id,
                            void *start_key,
                            void *end_key,
                            castle_da_rq_iter_init_cb_t init_cb,
                            void *private)
{
    struct castle_double_array *da;

    BUG_ON(!init_cb);

    /* Get DA structure from hash. */
    da = castle_da_hash_get(da_id);
    BUG_ON(!da);
    BUG_ON(!castle_version_is_ancestor(da->root_version, version));

    /* Get CTs proxy structure. */
    iter->cts_proxy = castle_da_cts_proxy_get(da);
    if (!iter->cts_proxy)
        goto alloc_fail;

    /* Initialise the iterator. */
    iter->async_iter.end_io = NULL;
    iter->err               = 0;
    iter->version           = version;

    /* Initialise async init stuff. */
    iter->da                = da;
    iter->init_cb           = init_cb;
    iter->private           = private;
    /* It's safe to reference the passed start and end keys as the caller will
     * not go away at least until we asynchronously wake them up. */
    iter->start_key         = start_key;
    iter->end_key           = end_key;

    /* Determine CTs relevant to range query. */
    if (castle_da_rq_iter_relevant_cts_get(iter, start_key, end_key) != 0)
        goto alloc_fail2;

    /* The remainder of the iterator initialisation is done asynchronously.
     * See _castle_da_rq_iter_init() for more details. */

    return;

alloc_fail2:
    if (iter->cts_proxy)
    {
        castle_da_cts_proxy_put(iter->cts_proxy);
        iter->cts_proxy = NULL;
    }
alloc_fail:
    iter->err = -ENOMEM;
    init_cb(private);
}

struct castle_iterator_type castle_da_rq_iter = {
    .register_cb= (castle_iterator_register_cb_t)castle_da_rq_iter_register_cb,
    .prep_next  = (castle_iterator_prep_next_t)  castle_da_rq_iter_prep_next,
    .has_next   = (castle_iterator_has_next_t)   castle_da_rq_iter_has_next,
    .next       = (castle_iterator_next_t)       castle_da_rq_iter_next,
    .skip       = (castle_iterator_skip_t)       castle_da_rq_iter_skip,
    .cancel     = (castle_iterator_cancel_t)     castle_da_rq_iter_cancel,
};

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
        /* For static trees, we are using immut iterator. */
        /* @TODO: do we need to do better resource release here? */
        castle_ct_immut_iter_cancel(iter);
        castle_free(iter);
    }
}

/**
 * Allocate/initialise correct iterator type for level of merge.
 *
 * - Allocate a castle_ct_modlist_iter for T1 merges
 * - Allocate a castle_ct_immut_iter for all higher level merges
 */
static void castle_da_iterator_create(struct castle_da_merge *merge,
                                      struct castle_component_tree *tree,
                                      void **iter_p,
                                      c_ext_pos_t *resume_merge_node_cep,
                                      int already_completed)
{
    if (tree->dynamic)
    {
        c_modlist_iter_t *iter = castle_alloc(sizeof(c_modlist_iter_t));
        BUG_ON(merge->serdes.des); /* we should only serialise merges
                                                                     with immut in_trees */
        if (!iter)
            return;
        iter->tree = tree;
        iter->merge = merge;
        if (tree->level == 1)
            castle_trace_da_merge(TRACE_START, TRACE_DA_MERGE_MODLIST_ITER_INIT_ID,
                    merge->da->id, tree->level, 0, 0);
        castle_ct_modlist_iter_init(iter);
        if (tree->level == 1)
            castle_trace_da_merge(TRACE_END, TRACE_DA_MERGE_MODLIST_ITER_INIT_ID,
                    merge->da->id, tree->level, 0, 0);
        if (iter->err)
        {
            castle_free(iter);
            return;
        }
        /* Success */
        *iter_p = iter;
    }
    else
    {
        c_immut_iter_t *iter = castle_alloc(sizeof(c_immut_iter_t));
        if (!iter)
            return;
        iter->tree = tree;
        iter->merge = merge;
        castle_ct_immut_iter_init(iter, NULL, NULL, resume_merge_node_cep, already_completed);
        /* @TODO: after init errors? */
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

/**
 * each_skip() callback for merge merged iterator.
 *
 * Called whenever a duplicate entry gets skipped during merges.
 *
 * Store any stat changes in merged iterator stats structure.  These are to
 * be handled via the merge process (castle_da_merge_unit_do()).
 */
static void castle_da_each_skip(c_merged_iter_t *iter,
                                c_ver_t version,
                                c_val_tup_t dup_cvt,
                                c_val_tup_t new_cvt)
{
    struct castle_da_merge *merge = iter->merge;

    /* If this is a medium object that is marked not to drain, then change the stats. */
    if (CVT_MEDIUM_OBJECT(dup_cvt))
    {
        castle_data_extent_update(dup_cvt.cep.ext_id, NR_BLOCKS(dup_cvt.length) * C_BLK_SIZE, 0);
        merge->nr_bytes += NR_BLOCKS(dup_cvt.length) * C_BLK_SIZE;
    }

    /* Update per-version statistics, only if not level 1 merge (entries in level 1 merge
       aren't yet known to the version stats). */
    if(merge->level != 1)
        castle_version_stats_entry_replace(version,
                                           dup_cvt,
                                           new_cvt,
                                           &merge->version_states);
}

/**
 * Extracts two oldest component trees from the DA, and waits for all the write references
 * to disappear. If either of the trees turns out to be empty is deallocated and an error
 * is returned.
 *
 * @return  -EAGAIN     A tree was deallocated, restart the merge.
 * @return   0          Trees were found, and stored in cts array.
 */
static int castle_da_l1_merge_cts_get(struct castle_double_array *da,
                                      struct castle_component_tree **cts,
                                      int nr_trees)
{
    struct castle_component_tree *ct;
    struct list_head *l;
    int i;

    /* Zero out the CTs array. */
    for (i=0; i<nr_trees; i++)
        cts[i] = NULL;

    /* Take read lock on DA, to make sure neither CTs nor DA would go away while looking at the
     * list. */
    read_lock(&da->lock);

    i=nr_trees;
    /* Find two oldest trees walking the list backwards. */
    list_for_each_prev(l, &da->levels[1].trees)
    {
        struct castle_component_tree *ct =
                            list_entry(l, struct castle_component_tree, da_list);

        BUG_ON(test_bit(CASTLE_CT_MERGE_OUTPUT_BIT, &ct->flags));

        cts[--i] = ct;
        if (i == 0)
            break;
    }
    read_unlock(&da->lock);

    if (i)
        return -EAGAIN;

    /* Wait for RW refs to disappear. Free the CT if it is empty after that. */
    for(i = 0; i < nr_trees; i++)
    {
        ct = cts[i];

        /* Wait until write ref count reaches zero. */
        BUG_ON(!ct->dynamic && (atomic_read(&ct->write_ref_count) != 0));
        while(atomic_read(&ct->write_ref_count))
        {
            debug("Found non-zero write ref count on ct=%d scheduled for merge cnt=%d\n",
                ct->seq, atomic_read(&ct->write_ref_count));
            msleep_interruptible(10);
        }

        /* Check that the tree has non-zero elements. */
        if(atomic64_read(&ct->item_count) == 0)
        {
            castle_printk(LOG_DEBUG, "Found empty CT=0x%llx, freeing it up.\n", ct->seq);
            /* No items in this CT, deallocate it by removing it from the DA,
               and dropping the ref. */
            CASTLE_TRANSACTION_BEGIN;

            castle_sysfs_ct_del(ct);

            write_lock(&da->lock);
            castle_component_tree_del(da, ct);
            write_unlock(&da->lock);
            CASTLE_TRANSACTION_END;
            castle_ct_put(ct, READ /*rw*/, NULL);

            return -EAGAIN;
        }
    }

    return 0;
}

/**
 * Creates iterators for each of the input trees. And merged iterator used to
 * construct the output tree.
 *
 * Doesn't cleanup half-created state on failure. It is done by castle_da_merge_dealloc()
 * which would be called from castle_da_merge_init().
 *
 * @param merge [in] merge to be created
 *
 * @return non-zero if failed to create iterators
 *
 * @see castle_da_merge_init
 * @see castle_da_merge_dealloc
 */
static int castle_da_iterators_create(struct castle_da_merge *merge)
{
    struct castle_btree_type *btree;
    int ret;
    struct castle_iterator_type **iter_types;
    int i;

    debug("Creating iterators for the merge.\n");
    FOR_EACH_MERGE_TREE(i, merge)
        BUG_ON(!merge->in_trees[i]);

    btree = castle_btree_type_get(merge->in_trees[0]->btree_type);

    /* The wait for write ref count to reach zero should have already be done. */
    FOR_EACH_MERGE_TREE(i, merge)
        BUG_ON(atomic_read(&merge->in_trees[i]->write_ref_count) != 0);

    /* Allocate space for iter_types. */
    ret = -ENOMEM;
    iter_types = castle_alloc(merge->nr_trees * sizeof(struct castle_iterator_type *));
    if (!iter_types)
        goto err_out;

    /* Allocate space for iterators. */
    merge->iters = castle_zalloc(sizeof(void *) * merge->nr_trees);
    if (!merge->iters)
        goto err_out2;

    /* Create appropriate iterators for all of the trees. */
    ret = -EINVAL;
    FOR_EACH_MERGE_TREE(i, merge)
    {
        c_ext_pos_t *resume_merge_node_cep;
        int          already_complete;

        resume_merge_node_cep = NULL;
        already_complete      = 0;

        /* Fast-forward node c2bs */
        if(merge->serdes.des)
        {
            struct castle_in_tree_merge_state_entry *in_tree_merge_mstore_arr =
                merge->serdes.live.in_tree_state_arr;
            if(!EXT_POS_INVAL(in_tree_merge_mstore_arr[i].iter.immut_curr_c2b_cep))
            {
                resume_merge_node_cep = &in_tree_merge_mstore_arr[i].iter.immut_curr_c2b_cep;
                castle_printk(LOG_DEBUG, "%s::[da %d level %d] des first cep "cep_fmt_str"\n",
                        __FUNCTION__, merge->da->id, merge->level, cep2str(*resume_merge_node_cep));
            }
            else
            {
                /* if we don't have a valid curr_c2b_cep, the iterator must have completed */
                BUG_ON(!in_tree_merge_mstore_arr[i].iter.component_completed);
                already_complete = 1;
                castle_printk(LOG_DEBUG, "%s::[da %d level %d] des iter complete \n",
                        __FUNCTION__, merge->da->id, merge->level);
            }
        }

        castle_da_iterator_create(merge,
                                  merge->in_trees[i],
                                 &merge->iters[i],
                                  resume_merge_node_cep,
                                  already_complete);

        /* Check if the iterators got created properly. */
        if (!merge->iters[i])
            goto err_out2;
    }
    debug("Tree iterators created.\n");

    /* Init the merged iterator */
    ret = -ENOMEM;
    merge->merged_iter = castle_alloc(sizeof(c_merged_iter_t));
    if(!merge->merged_iter)
        goto err_out2;
    debug("Merged iterator allocated.\n");

    merge->merged_iter->merge    = merge;
    merge->merged_iter->nr_iters = merge->nr_trees;
    merge->merged_iter->btree    = btree;
    FOR_EACH_MERGE_TREE(i, merge)
        iter_types[i] = castle_da_iter_type_get(merge->in_trees[i]);
    castle_ct_merged_iter_init(merge->merged_iter,
                               merge->iters,
                               iter_types,
                               castle_da_each_skip,
                               merge->da);
    ret = merge->merged_iter->err;
    debug("Merged iterator inited with ret=%d.\n", ret);
    if(ret)
        goto err_out2;

    /* Fast-forward merge iterator and immutable iterators states */
    if(merge->serdes.des)
    {
        int i;
        struct component_iterator *curr_comp;
        c_immut_iter_t *curr_immut;
        struct castle_dmserlist_entry *merge_mstore =
                                        merge->serdes.live.merge_state;
        struct castle_in_tree_merge_state_entry    *in_tree_merge_mstore_arr =
                                        merge->serdes.live.in_tree_state_arr;

        debug("%s::Fast-forward iterators on merge %p (da %d level %d)\n",
                      __FUNCTION__, merge, merge->da->id, merge->level);

        /* merged iter state */
        merge->merged_iter->err                 = merge_mstore->iter_err;
        merge->merged_iter->non_empty_cnt       = merge_mstore->iter_non_empty_cnt;
        merge->merged_iter->src_items_completed = merge_mstore->iter_src_items_completed;

        /* immut iters states */
        curr_comp = merge->merged_iter->iterators;
        for(i=0; i<merge->nr_trees; i++)
        {
            BUG_ON(!curr_comp);
            curr_immut=(c_immut_iter_t *)curr_comp->iterator;
            BUG_ON(!curr_immut);

            curr_comp->completed   = curr_immut->completed = in_tree_merge_mstore_arr[i].iter.component_completed;
            curr_comp->cached      = in_tree_merge_mstore_arr[i].iter.component_cached;

            curr_immut->curr_idx   = in_tree_merge_mstore_arr[i].iter.immut_curr_idx;
            curr_immut->cached_idx = in_tree_merge_mstore_arr[i].iter.immut_cached_idx;
            curr_immut->next_idx   = in_tree_merge_mstore_arr[i].iter.immut_next_idx;

            /* Sanity check curr_c2b, and restore cache */
            if(!EXT_POS_INVAL(in_tree_merge_mstore_arr[i].iter.immut_curr_c2b_cep))
            {
                c_ext_pos_t cep = in_tree_merge_mstore_arr[i].iter.immut_curr_c2b_cep;
                BUG_ON(!curr_immut->curr_c2b);

                BUG_ON(curr_immut->curr_c2b->cep.ext_id != cep.ext_id);
                BUG_ON(curr_immut->curr_c2b->cep.offset != cep.offset);

                /* Restore current btree node */
                curr_immut->curr_node = c2b_bnode(curr_immut->curr_c2b);
                BUG_ON(!curr_immut->curr_node);
                BUG_ON(curr_immut->curr_node->magic != BTREE_NODE_MAGIC);

                if(curr_comp->cached)
                {
                    /* Restore the cache */
                    curr_immut->btree->entry_get(curr_immut->curr_node, curr_immut->cached_idx,
                            &(curr_comp->cached_entry.k),
                            &(curr_comp->cached_entry.v),
                            &(curr_comp->cached_entry.cvt));
                    /* Restore the rbtree */
                    /* Assume we should never serialise on a deleted kv pair */
                    castle_ct_merged_iter_rbtree_insert(merge->merged_iter, curr_comp);
                } /* replenished cache */
            } /* restored curr_c2b */
            else
                BUG_ON(!curr_immut->completed);

            /* Sanity check next_c2b */
            if(!EXT_POS_INVAL(in_tree_merge_mstore_arr[i].iter.immut_next_c2b_cep))
            {
                struct castle_btree_node *node;

                c_ext_pos_t cep = in_tree_merge_mstore_arr[i].iter.immut_next_c2b_cep;
                BUG_ON(!curr_immut->next_c2b);

                BUG_ON(curr_immut->next_c2b->cep.ext_id != cep.ext_id);
                BUG_ON(curr_immut->next_c2b->cep.offset != cep.offset);

                /* Sanity check the node */
                node = c2b_bnode(curr_immut->next_c2b);
                BUG_ON(!node);
                BUG_ON(node->magic != BTREE_NODE_MAGIC);
            } /* restored next_c2b */
            curr_comp++;
        } /* restored c_immut_iters */
    } /* merged iterator fast-forwarded to serialised state */

    castle_free(iter_types);

    /* Success */
    return 0;

err_out2:
    castle_free(iter_types);
err_out:
    /* castle_da_merge_dealloc() frees merge-> allocations. */
    debug("Failed to create iterators. Ret=%d\n", ret);

    BUG_ON(!ret);
    return ret;
}

/**
 * Check if any of the components of DA are blocked on Low Free-Space.
 *
 * @param [in] da - Double array to be checked.
 *
 * @return 1 - DA is already suffering due to LFS
 *         0 - So far no component suffered due to LFS
 */
static int castle_da_no_disk_space(struct castle_double_array *da)
{
    if (atomic_read(&da->lfs_victim_count))
        return 1;

    return 0;
}

/**
 * Increment victim count for DA, purging queued IOs if we are first to set.
 */
static void castle_da_lfs_victim_count_inc(struct castle_double_array *da)
{
    if (atomic_inc_return(&da->lfs_victim_count) == 1)
        castle_da_queues_kick(da);

    castle_da_get(da);
}

/**
 * Set structure for Low Free Space (LFS) handler. This functions sets the size of each
 * extent that got to be created by the LFS handler when more space is available. LFS handler
 * would allocate space and fill the extent ids in the same structure.
 *
 * @param [inout] LFS Structure.
 * @param [in] Size of Internal tree extent size (in chunks).
 * @param [in] Size of B-Tree extent size (in chunks).
 * @param [in] Size of Medium Object extent size (in chunks).
 *
 * @also castle_da_lfs_ct_init
 * @also castle_da_lfs_ct_reset
 * @also castle_da_lfs_ct_space_alloc
 * @also castle_da_lfs_ct_init_tree
 */
static void castle_da_lfs_ct_init(struct castle_da_lfs_ct_t *lfs,
                                  c_chk_cnt_t internal_tree_size,
                                  c_chk_cnt_t tree_size,
                                  c_chk_cnt_t data_size,
                                  int rwct)
{
    /* Setting up the structure, there shouldn't be any reserved space. */
    BUG_ON(lfs->space_reserved);

    /* Save whether we are allocating RWCT. */
    lfs->rwct = rwct;

    /* Shouldn't see any valid ext_ids. */
    BUG_ON(!EXT_ID_INVAL(lfs->internal_ext.ext_id) ||
           !EXT_ID_INVAL(lfs->tree_ext.ext_id) ||
           !EXT_ID_INVAL(lfs->data_ext.ext_id));
    BUG_ON(lfs->internal_ext.size || lfs->tree_ext.size || lfs->data_ext.size);

    /* Set-up LFS structure, assuming space allocation will fail. */
    lfs->tree_ext.size = tree_size;
    lfs->data_ext.size = data_size;
    lfs->internal_ext.size = internal_tree_size;
    lfs->leafs_on_ssds = lfs->internals_on_ssds = 0;
}

/**
 * Reset the LFS structure.
 *
 * @param [inout] LFS Structure.
 *
 * @also castle_da_lfs_ct_init
 * @also castle_da_lfs_ct_space_alloc
 * @also castle_da_lfs_ct_init_tree
 */
static void castle_da_lfs_ct_reset(struct castle_da_lfs_ct_t *lfs)
{
    lfs->internal_ext.ext_id = lfs->tree_ext.ext_id = lfs->data_ext.ext_id = INVAL_EXT_ID;
    lfs->internal_ext.size = lfs->tree_ext.size = lfs->data_ext.size = 0;
    lfs->space_reserved = 0;
    lfs->leafs_on_ssds = lfs->internals_on_ssds = 0;

    /* Make sure all writes are completed, before next thread tries to do some checks
     * during lfs_init. */
    wmb();
}

/**
 * Use the space allocated by LFS handler in CT. Make sure LFS structure has extents of same
 * size required by CT and set up CT.
 *
 * @param [out] Component Tree to be set.
 * @param [in] LFS structure with reserved space (allocated extents).
 * @param [in] Size of Internal tree extent size (in chunks).
 * @param [in] Size of B-Tree extent size (in chunks).
 * @param [in] Size of Medium Object extent size (in chunks).
 *
 * @also castle_da_lfs_ct_init
 * @also castle_da_lfs_ct_reset
 * @also castle_da_lfs_ct_space_alloc
 */
static int castle_da_lfs_ct_init_tree(struct castle_component_tree *ct,
                                       struct castle_da_lfs_ct_t *lfs,
                                       c_chk_cnt_t internal_tree_size,
                                       c_chk_cnt_t tree_size,
                                       c_chk_cnt_t data_size)
{
    /* We shouldn't be here, if the space is not already reserved. */
    BUG_ON(!lfs->space_reserved);

    /* Space is already reserved, we should have had valid extents already. */
    BUG_ON(EXT_ID_INVAL(lfs->internal_ext.ext_id));
    BUG_ON(EXT_ID_INVAL(lfs->tree_ext.ext_id));

    /* Sizes of extents should match. */
    if (tree_size > lfs->tree_ext.size ||
        data_size > lfs->data_ext.size ||
        internal_tree_size > lfs->internal_ext.size)
    {
        /* Reserved space is not enough. Free this space. And try to allocate again.
         * Note: This can be made better by freeing only unmatched extents. */
        castle_extent_free(lfs->internal_ext.ext_id);
        castle_extent_free(lfs->tree_ext.ext_id);
        castle_extent_free(lfs->data_ext.ext_id);

        castle_da_lfs_ct_reset(lfs);

        return -1;
    }

    /* Setup extent IDs. */
    ct->internal_ext_free.ext_id = lfs->internal_ext.ext_id;
    ct->tree_ext_free.ext_id     = lfs->tree_ext.ext_id;
    ct->data_ext_free.ext_id     = lfs->data_ext.ext_id;

    /* Setup extent freespaces. */
    castle_ext_freespace_init(&ct->internal_ext_free,
                               ct->internal_ext_free.ext_id);
    castle_ext_freespace_init(&ct->tree_ext_free,
                               ct->tree_ext_free.ext_id);

    /* Add the new data extent to list of medium objects. */
    if (!EXT_ID_INVAL(ct->data_ext_free.ext_id))
    {
        castle_ext_freespace_init(&ct->data_ext_free, ct->data_ext_free.ext_id);
        castle_data_ext_add(ct->data_ext_free.ext_id, 0, 0, 0);
        castle_ct_data_ext_link(ct->data_ext_free.ext_id, ct);
    }

    return 0;
}

/**
 * Low Freespace handler for Component Tree extents. Gets called by extents code, when more
 * space is available.
 *
 * @param [inout] lfs           - Low Free Space structure.
 * @param [in]    is_realloc    - Is re-allocation (previous allocation failed due to
 *                                low free space).
 * @param [in]    lfs_callback  - Callback to be used in case of low freespace.
 * @param [in]    lfs_data      - Data pointer to be used by callback.
 * @param [in]    use_ssd       - Use SSD for Internal nodes.
 * @param [in]    growable      - Growable tree extent and data extent.
 *
 * @also castle_da_lfs_ct_init
 * @also castle_da_lfs_ct_reset
 * @also castle_da_lfs_ct_space_alloc
 * @also castle_da_lfs_ct_init_tree
 */
static int castle_da_lfs_ct_space_alloc(struct castle_da_lfs_ct_t *lfs,
                                        int                        is_realloc,
                                        c_ext_event_callback_t     lfs_callback,
                                        void                      *lfs_data,
                                        int                        growable)
{
    struct castle_double_array *da = lfs->da;
    c_ext_id_t internal_ext_id, tree_ext_id, data_ext_id;

    /* If the DA is dead already, no need to handle the event anymore. */
    BUG_ON(da == NULL);

    if (castle_da_deleted(da) && is_realloc)
    {
        castle_printk(LOG_DEBUG, "Skipping LFS for da: %u\n", da->id);

        if (atomic_dec_and_test(&da->lfs_victim_count))
            castle_da_merge_restart(da, NULL);

        castle_da_put(da);

        return 0;
    }

    /* Function shouldn't have been called, if space is already reserved. */
    BUG_ON(lfs->space_reserved);

    debug("Allocating space for a ct for da: %u, and extents of size - %u, %u, %u\n",
          lfs->da_id,
          lfs->internal_ext.size,
          lfs->tree_ext.size,
          lfs->data_ext.size);

    /* Size of extents to be created should have been set. */
    BUG_ON(!lfs->internal_ext.size || !lfs->tree_ext.size);
    BUG_ON(!EXT_ID_INVAL(lfs->internal_ext.ext_id) || !EXT_ID_INVAL(lfs->tree_ext.ext_id) ||
           !EXT_ID_INVAL(lfs->data_ext.ext_id));

    internal_ext_id = tree_ext_id = data_ext_id = INVAL_EXT_ID;

    /* Start an extent transaction, to make sure all the extent operations are atomic. */
    castle_extent_transaction_start();

    /* Attempt to allocate an SSD extent for internal nodes. */
    lfs->internals_on_ssds = 1;
    lfs->internal_ext.ext_id = castle_extent_alloc(castle_get_ssd_rda_lvl(),
                                                   da->id,
                                                   lfs->rwct ?
                                                        EXT_T_T0_INTERNAL_NODES :
                                                        EXT_T_INTERNAL_NODES,
                                                   lfs->internal_ext.size, 1,
                                                   NULL, NULL);

    if (EXT_ID_INVAL(lfs->internal_ext.ext_id))
    {
        /* FAILED to allocate internal node SSD extent.
         * ATTEMPT to allocate internal node HDD extent. */
        lfs->internals_on_ssds = 0;
        lfs->internal_ext.ext_id = castle_extent_alloc(castle_get_rda_lvl(),
                                                       da->id,
                                                       lfs->rwct ?
                                                            EXT_T_T0_INTERNAL_NODES :
                                                            EXT_T_INTERNAL_NODES,
                                                       lfs->internal_ext.size, 1,
                                                       lfs_data, lfs_callback);
        if (EXT_ID_INVAL(lfs->internal_ext.ext_id))
        {
            /* FAILED to allocate internal node HDD extent. */
            castle_printk(LOG_WARN, "Merge failed due to space constraint for internal node tree.\n");
            goto no_space;
        }
    }
    else
    {
        /* SUCCEEDED allocating internal node SSD extent.
         * ATTEMPT to allocate leaf node SSD extent. */
        if(castle_use_ssd_leaf_nodes)
        {
            if(growable)
            {
                lfs->tree_ext.ext_id = castle_extent_alloc_sparse(castle_get_ssd_rda_lvl(),
                                                                  da->id,
                                                                  lfs->rwct ?
                                                                       EXT_T_T0_LEAF_NODES :
                                                                       EXT_T_LEAF_NODES,
                                                                  lfs->tree_ext.size,
                                                                  0,
                                                                  1,
                                                                  NULL, NULL);
                castle_printk(LOG_DEBUG, "%s::growable ssd extent %d\n", __FUNCTION__,
                        lfs->tree_ext.ext_id);
            }
            else
                lfs->tree_ext.ext_id = castle_extent_alloc(castle_get_rda_lvl(),
                                                           da->id,
                                                           lfs->rwct ?
                                                                EXT_T_T0_LEAF_NODES :
                                                                EXT_T_LEAF_NODES,
                                                           lfs->tree_ext.size,
                                                           1,
                                                           NULL, NULL);
        }
    }

    lfs->leafs_on_ssds = 1;
    if (EXT_ID_INVAL(lfs->tree_ext.ext_id))
    {
        /* FAILED to allocate leaf node SSD extent.
         * ATTEMPT to allocate leaf node HDD extent. */
        lfs->leafs_on_ssds = 0;
        if(growable)
        {
            lfs->tree_ext.ext_id = castle_extent_alloc_sparse(castle_get_rda_lvl(),
                                                              da->id,
                                                              lfs->rwct ?
                                                                   EXT_T_T0_LEAF_NODES :
                                                                   EXT_T_LEAF_NODES,
                                                              lfs->tree_ext.size,
                                                              0, /*ext_size*/
                                                              1, /*in_tran*/
                                                              lfs_data,
                                                              lfs_callback);
            castle_printk(LOG_DEBUG, "%s::growable tree extent %d\n", __FUNCTION__,
                    lfs->tree_ext.ext_id);
        }
        else
            lfs->tree_ext.ext_id = castle_extent_alloc(castle_get_rda_lvl(),
                                                       da->id,
                                                       lfs->rwct ?
                                                            EXT_T_T0_LEAF_NODES :
                                                            EXT_T_LEAF_NODES,
                                                       lfs->tree_ext.size,
                                                       1, /*in_tran*/
                                                       lfs_data,
                                                       lfs_callback);
    }

    if (EXT_ID_INVAL(lfs->tree_ext.ext_id))
    {
        /* FAILED to allocate leaf node HDD extent. */
        castle_printk(LOG_WARN, "Extents allocation failed due to space constraint for "
                                "leaf node tree.\n");
        goto no_space;
    }

    if (lfs->data_ext.size == 0)
        goto skip_data_ext;

    /* Allocate an extent for medium objects of merged tree for the size equal to
     * sum of both the trees. */
    if(growable)
    {
        lfs->data_ext.ext_id = castle_extent_alloc_sparse(castle_get_rda_lvl(),
                                                          da->id,
                                                          lfs->rwct ?
                                                               EXT_T_T0_MEDIUM_OBJECTS :
                                                               EXT_T_MEDIUM_OBJECTS,
                                                          lfs->data_ext.size,
                                                          0,
                                                          1,
                                                          lfs_data, lfs_callback);
        castle_printk(LOG_DEBUG, "%s::growable data extent %d\n", __FUNCTION__,
                lfs->data_ext.ext_id);
    }
    else
        lfs->data_ext.ext_id = castle_extent_alloc(castle_get_rda_lvl(),
                                                   da->id,
                                                   lfs->rwct ?
                                                        EXT_T_T0_MEDIUM_OBJECTS :
                                                        EXT_T_MEDIUM_OBJECTS,
                                                   lfs->data_ext.size, 1,
                                                   lfs_data, lfs_callback);

    if (EXT_ID_INVAL(lfs->data_ext.ext_id))
    {
        castle_printk(LOG_WARN, "Merge failed due to space constraint for data\n");
        goto no_space;
    }

skip_data_ext:
    /* Mark it as space reserved. */
    lfs->space_reserved = 1;

    /* Make sure all writes are completed, before decrementing victim count. */
    wmb();

    /* If it's a reallocation (last allocation failed due to low free space), reduce the count of lfs
     * victims in DA; If there are no more victims left for DA, then restart merges. */
    if (is_realloc && atomic_dec_and_test(&da->lfs_victim_count))
        castle_da_merge_restart(da, NULL);

    /* End extent transaction. */
    castle_extent_transaction_end();

    /* Note: After this point don't access da pointer. It is possible da_destroy_complete()
     * is racing. */
    if (is_realloc)
        castle_da_put(da);

    return 0;

no_space:
    /* If the allocation is not a reallocation, update victim count. */
    if (lfs_callback && !is_realloc)
        castle_da_lfs_victim_count_inc(da);

    /* Take a copy of ext IDs. */
    internal_ext_id = lfs->internal_ext.ext_id;
    tree_ext_id = lfs->tree_ext.ext_id;
    BUG_ON(!EXT_ID_INVAL(lfs->data_ext.ext_id));

    /* If there is no callback, no need to kep sizes in this LFS structure. */
    if (!lfs_callback)
    {
        castle_da_lfs_ct_reset(lfs);
    }
    else
    {
        /* Reset ext ids. */
        lfs->internal_ext.ext_id = lfs->tree_ext.ext_id = lfs->data_ext.ext_id = INVAL_EXT_ID;
        lfs->leafs_on_ssds = lfs->internals_on_ssds = 0;
    }

    /* End extent transaction. */
    castle_extent_transaction_end();

    /* In case of failure release free space. It is safe to call castle_extent_free as it doesnt
     * try to get global extent lock again. */
    if (!EXT_ID_INVAL(internal_ext_id))
        castle_extent_free(internal_ext_id);
    if (!EXT_ID_INVAL(tree_ext_id))
        castle_extent_free(tree_ext_id);

    debug("Failed to allocate from realloc\n");

    return -ENOSPC;
}

/*
 * Low freespace handling for T0 allocation: T0s could be created from different places. All of
 * === ========= ======== === == ==========  them take castle_da_growing bit lock. So, at any
 * point of time, only one gets executed. It's hard to have one common LFS policy for all of them.
 * Instead, check the freespace condition of DA after taking bit-lock.
 */

static void castle_da_lfs_ct_cleanup(struct castle_da_lfs_ct_t *lfs)
{
    if (!lfs->space_reserved)
        return;

    castle_extent_free(lfs->internal_ext.ext_id);
    castle_extent_free(lfs->tree_ext.ext_id);
    castle_extent_free(lfs->data_ext.ext_id);

    castle_da_lfs_ct_reset(lfs);
}

/**
 * Low freespace event handler for creation of all T0 RWCTs.
 *
 * Called as a result of a T0 creation failure during castle_da_all_rwcts_create().
 *
 * @param   data    castle_double_array pointer
 *
 * @also castle_da_all_rwcts_create()
 */
static void castle_da_lfs_all_rwcts_callback(void *data)
{
    struct castle_double_array *da = data;

    /* Reset LFS structure now as it will be reused in all_rwcts_create(). */
    if (!castle_da_deleted(da))
        castle_da_all_rwcts_create(da,
                                   0 /*in_tran*/,
                                   LFS_VCT_T_T0_GRP);


    /* Decrement lfs_victim_count - if all_rwcts_create() failed it will have
     * been incremented, if it succeeded, we may be re-enabling inserts on
     * this doubling-array.  Ensure we do it after all_rwcts_create() to
     * prevent races. */
    atomic_dec(&da->lfs_victim_count);

    castle_da_put(da);
}

/**
 * Low freespace event handler for creation of T0 extents.
 *
 * @param   data    castle_double_array pointer
 *
 * Called as a result of a T0 creation failure during
 * castle_da_lfs_ct_space_alloc().  Gets called asynchronously when more
 * freespace is available.
 *
 * This callback does not create a new T0 - we wait for a subsequent write
 * request to do this via castle_da_rwct_acquire().
 *
 * @also castle_da_lfs_ct_space_alloc
 */
static void castle_da_lfs_rwct_callback(void *data)
{
    struct castle_double_array *da = data;

    castle_printk(LOG_WARN, "T0 extent low freespace callback invoked.\n");
    if (atomic_dec_and_test(&da->lfs_victim_count))
        castle_da_merge_restart(da, NULL);

    castle_da_put(da);
}

/**
 * Low Freespace event handler function for merge extents. Will be called by extent code
 * when more space is available.
 *
 * @param [inout] data - void * for lfs structure
 *
 * @also castle_da_lfs_ct_space_alloc
 */
static void castle_da_lfs_merge_ct_callback(void *data)
{
    castle_da_lfs_ct_space_alloc(data,
                                 1,     /* Reallocation. */
                                 castle_da_lfs_merge_ct_callback,
                                 data,
                                 0);    /* Extents not growable. */
}
static void castle_da_lfs_merge_ct_growable_callback(void *data)
{
    castle_da_lfs_ct_space_alloc(data,
                                 1,     /* Reallocation. */
                                 castle_da_lfs_merge_ct_growable_callback,
                                 data,
                                 1);    /* Extents growable. */
}

/**
 * Allocate all required extents for a T0 RWCT.
 *
 * @param   da          Doubling array
 * @param   ct          Component tree to create T0s for
 * @param   lfs_type    LFS type we are allocating for
 *
 * @return  0       All extents allocated successfully
 * @return -ENOSPC  Failed to allocate all extents, LFS callback may have been
 *                  registered depending on lfs_type
 *
 * @also castle_new_ext_freespace_init()
 */
static int castle_da_t0_extents_alloc(struct castle_double_array    *da,
                                      struct castle_component_tree  *ct,
                                      c_lfs_vct_type_t               lfs_type)
{
    int ret;
    void *data = da;
    c_ext_event_callback_t lfs_callback;

    /* Set callback based on LFS_VCT_T_ type. */
    switch (lfs_type)
    {
        case LFS_VCT_T_T0_GRP:
            lfs_callback = castle_da_lfs_all_rwcts_callback;
            break;
        case LFS_VCT_T_T0:
            lfs_callback = castle_da_lfs_rwct_callback;
            break;
        case LFS_VCT_T_INVALID:
            lfs_callback = NULL;
            data         = NULL;
            break;
        default:
            BUG();
    }

    /* Start an extent transaction, to make sure all the extent operations are atomic. */
    castle_extent_transaction_start();

    /* Allocate T0 internal nodes extent. */
    ret = castle_new_ext_freespace_init(&ct->internal_ext_free,
                                         da->id,
                                         EXT_T_T0_INTERNAL_NODES,
                                         MAX_DYNAMIC_INTERNAL_SIZE * C_CHK_SIZE,
                                         1 /* in tran */,
                                         data, lfs_callback);
    if (ret)
    {
        /* FAILED to allocate internal node HDD extent. */
        castle_printk(LOG_WARN,
                      "New T0[DA%u] failed due to space constraint for internal node tree.\n",
                      da->id);
        goto no_space;
    }

    /* Allocate T0 leaf nodes extent. */
    ret = castle_new_ext_freespace_init(&ct->tree_ext_free,
                                         da->id,
                                         EXT_T_T0_LEAF_NODES,
                                         MAX_DYNAMIC_TREE_SIZE * C_CHK_SIZE,
                                         1 /* in tran */,
                                         data, lfs_callback);
    if (ret)
    {
        /* FAILED to allocate leaf node HDD extent. */
        castle_printk(LOG_WARN,
                      "New T0[DA%u] failed due to space constraint for leaf node tree.\n",
                      da->id);
        goto no_space;
    }

    /* Allocate T0 data extent. */
    ret = castle_new_ext_freespace_init(&ct->data_ext_free,
                                         da->id,
                                         EXT_T_T0_MEDIUM_OBJECTS,
                                         MAX_DYNAMIC_TREE_SIZE * C_CHK_SIZE,
                                         1 /* in tran */,
                                         data, lfs_callback);
    if (ret)
    {
        /* FAILED to allocate value extent. */
        castle_printk(LOG_WARN,
                      "New T0[DA%u] failed due to space constraint for value extent.\n",
                      da->id);
        goto no_space;
    }

    /* All T0 extents successfully allocated.
     *
     * Link the data extent. */
    castle_data_ext_add(ct->data_ext_free.ext_id, 0, 0, 0);
    castle_ct_data_ext_link(ct->data_ext_free.ext_id, ct);

    castle_extent_transaction_end();

    return 0;

no_space:
    /* Mark DA as LFS victim. */
    if (lfs_callback)
        castle_da_lfs_victim_count_inc(da);

    castle_extent_transaction_end();

    /* Unlink and reset extents that were allocated. */
    castle_ext_freespace_fini(&ct->internal_ext_free);
    castle_ext_freespace_fini(&ct->tree_ext_free);
    castle_ext_freespace_fini(&ct->data_ext_free);

    return -ENOSPC;
}

static void castle_da_merge_res_pool_attach(struct castle_da_merge *merge)
{
    int i;

    /* Attach extents to reservation pools. */
    /* Attach all in-tree tree extents to reservation pool, adds space to pool. */
    for (i=0; i<merge->nr_trees; i++)
        castle_res_pool_extent_attach(merge->pool_id, merge->in_trees[i]->tree_ext_free.ext_id);

    /* Attach all data extents that are going to drain to reservation pool, adds space to pool. */
    for (i=0; i<merge->nr_drain_exts; i++)
        castle_res_pool_extent_attach(merge->pool_id, merge->drain_exts[i]);

    /* Attach output tree's tree extent and data extent to reservation pool, consumes space. */
    castle_res_pool_extent_attach(merge->pool_id, merge->out_tree->tree_ext_free.ext_id);
    if (!EXT_ID_INVAL(merge->out_tree->data_ext_free.ext_id))
        castle_res_pool_extent_attach(merge->pool_id, merge->out_tree->data_ext_free.ext_id);
}

static void castle_da_merge_res_pool_detach(struct castle_da_merge *merge, int err)
{
    int i;

    /* Detach extents from reservation pools and destroy reservation pool. */
    if (RES_POOL_INVAL(merge->pool_id))
        return;

    /* Detach all in-tree tree extents from reservation pool. */
    for (i=0; i<merge->nr_trees; i++)
        castle_res_pool_extent_detach(merge->in_trees[i]->tree_ext_free.ext_id);

    /* Detach all data extents that are drained from reservation pool. */
    for (i=0; i<merge->nr_drain_exts; i++)
        castle_res_pool_extent_detach(merge->drain_exts[i]);

    /* Detach output tree's tree extent and data extent from reservation pool. */
    castle_res_pool_extent_detach(merge->out_tree->tree_ext_free.ext_id);
    if (!EXT_ID_INVAL(merge->out_tree->data_ext_free.ext_id))
        castle_res_pool_extent_detach(merge->out_tree->data_ext_free.ext_id);

    /* Destroy reservation pool, if this end of merge. */
    if (err != -ESHUTDOWN)
    {
        castle_res_pool_destroy(merge->pool_id);

        /* Already detached all extents from it. Shouldn't be alive any more. */
        BUG_ON(castle_res_pool_is_alive(merge->pool_id));
    }
}

/**
 * Allocates extents for the output tree, medium objects and Bloom filetrs. Tree may be split
 * between two extents (internal nodes in an SSD-backed extent, leaf nodes on HDDs).
 *
 * @param merge     Merge state structure.
 */
static int castle_da_merge_extents_alloc(struct castle_da_merge *merge)
{
    c_byte_off_t internal_tree_size, tree_size, data_size, bloom_size;
    struct castle_da_lfs_ct_t _lfs, *lfs;
    c_ext_event_callback_t lfs_callback;
    void *lfs_data;
    int i, ret;
    const int growable = MERGE_CHECKPOINTABLE(merge);

    /* Handle Low Freespace gracefully, for L1 merges - fail the merge and also register
     * for notification when more space available. */
    if (merge->level == 1)
    {
        lfs             = &merge->da->l1_merge_lfs;
        lfs_callback    = castle_da_lfs_merge_ct_callback;
        lfs_data        = lfs;
    }
    /* For other merges just fail the merge. */
    else
    {
        lfs             = &_lfs;
        lfs_callback    = NULL;
        lfs_data        = NULL;
        lfs->da         = merge->da;
        castle_da_lfs_ct_reset(lfs);
    }

    /* Allocate an extent for merged tree for the size equal to sum of all the
     * trees being merged (could be a total merge).
     */
    internal_tree_size = tree_size = data_size = bloom_size = 0;
    FOR_EACH_MERGE_TREE(i, merge)
    {
        struct castle_component_tree *ct = merge->in_trees[i];
        int j;

        BUG_ON(!castle_ext_freespace_consistent(&ct->tree_ext_free));
        tree_size += atomic64_read(&ct->tree_ext_free.used);

        for (j=0; j<ct->nr_data_exts; j++)
            if (castle_data_ext_should_drain(ct->data_exts[j], merge) >= 0)
                data_size += atomic64_read(&castle_data_exts_hash_get(ct->data_exts[j])->nr_bytes);

        bloom_size += atomic64_read(&merge->in_trees[i]->item_count);
    }

    if (CHUNK_OFFSET(data_size))
        data_size = MASK_CHK_OFFSET(data_size + C_CHK_SIZE);

    /* In case of multiple version test-case, in worst case tree could grow upto
     * double the size. Ex: For every alternative k_n in o/p stream of merged
     * iterator, k_n has only one version and k_(n+1) has (p-1) versions, where p
     * is maximum number of versions that can fit in a node. */
    tree_size = 2 * (MASK_CHK_OFFSET(tree_size) + C_CHK_SIZE);
    /* Calculate total size of internal nodes, assuming that leafs are stored on HDDs ... */
    internal_tree_size = tree_size;
    /* ... number of leaf nodes ... */
    internal_tree_size /= (HDD_RO_TREE_NODE_SIZE * C_BLK_SIZE);
    /* ... number of level 1 nodes ... */
    internal_tree_size /= merge->out_btree->max_entries(SSD_RO_TREE_NODE_SIZE);
    internal_tree_size ++;
    /* ... size of level 1 ... */
    internal_tree_size *= (SSD_RO_TREE_NODE_SIZE * C_BLK_SIZE);
    /* ... chunk rounding ... */
    internal_tree_size  = MASK_CHK_OFFSET(internal_tree_size + C_CHK_SIZE);
    /* ... factor of 2 explosion, just as before ... */
    internal_tree_size *= 2;
    /* NOTE: Internal nodes on HDDs will always require less space than internal nodes
       on SSDs, because the overheads are smaller (node headers amortised between greater
       number of entries in the node). */

    BUG_ON(!EXT_ID_INVAL(merge->out_tree->internal_ext_free.ext_id) ||
           !EXT_ID_INVAL(merge->out_tree->tree_ext_free.ext_id));

    /* Create a reservation pool and reserve some space. For now, allocate fixed amount of space
     * for all merges. We could change this based on merge type, later. */
    if (growable)
    {
        merge->pool_id = castle_res_pool_create(castle_get_ssd_rda_lvl(), 100);
        if (RES_POOL_INVAL(merge->pool_id))
        {
            debug_res_pools("Failed to reserve space for merge on SSD\n");
            merge->pool_id = castle_res_pool_create(castle_get_rda_lvl(), 100);
            if (RES_POOL_INVAL(merge->pool_id))
            {
                castle_printk(LOG_USERINFO, "Failed to reserve space for merge\n");
                return -ENOSPC;
            }
        }
        debug_res_pools("Created reservation pool %u for the merge at level %u\n",
                         merge->pool_id, merge->level);
    }

__again:
    /* If the space is not already reserved for the merge, allocate it from freespace. */
    if (!lfs->space_reserved)
    {
        /* Initialize the lfs structure with required extent sizes. */
        /* Note: Also, add a growth safety margin */
        castle_da_lfs_ct_init(lfs,
                              CHUNK(internal_tree_size),
                              CHUNK(tree_size) + (growable? (MERGE_OUTPUT_TREE_GROWTH_RATE) : 0),
                              (!data_size)? 0:
                              CHUNK(data_size) + (growable ? (MERGE_OUTPUT_DATA_GROWTH_RATE) : 0),
                              0 /* Not a T0. */);

        /* Allocate space from freespace. */
        ret = castle_da_lfs_ct_space_alloc(lfs,
                                           0,                   /* First allocation. */
                                           lfs_callback,
                                           lfs_data,
                                           growable);           /* Extents growable */

        /* If failed to allocate space, return error. lfs structure is already set.
         * Low freespace handler would allocate space, when more freespace is available. */
        if (ret)
        {
            /* Destroy reservation pool and reset ID in merge structure, merge_dealloc() can't
             * handle partial done work from extents_alloc(). */
            if (growable)
            {
                castle_res_pool_destroy(merge->pool_id);
                BUG_ON(castle_res_pool_is_alive(merge->pool_id));
                merge->pool_id = INVAL_RES_POOL;
            }

            return ret;
        }
    }

    /* Successfully allocated space. Initialize the component tree with alloced extents.
     * castle_da_lfs_ct_init_tree() would fail if the space reserved by lfs handler is not
     * enough for CT. */
    if (castle_da_lfs_ct_init_tree(merge->out_tree,
                                   lfs,
                                   CHUNK(internal_tree_size),
                                   CHUNK(tree_size),
                                   CHUNK(data_size)))
        goto __again;

    merge->internals_on_ssds = lfs->internals_on_ssds;
    merge->leafs_on_ssds = lfs->leafs_on_ssds;

    /* Done with lfs structure; reset it. */
    castle_da_lfs_ct_reset(lfs);

    /* Allocate Bloom filters. */
    if ((ret = castle_bloom_create(&merge->out_tree->bloom,
                                   merge->da->id,
                                   merge->da->btree_type,
                                   bloom_size)))
        merge->out_tree->bloom_exists = 0;
    else
        merge->out_tree->bloom_exists = 1;

    if (growable)
        castle_da_merge_res_pool_attach(merge);

    return 0;
}

#define exit_cond (castle_da_exiting || castle_da_deleted(da))

/**
 * Check if extent has enough space to accommodate the asked bytes. If not, grow the extent.
 * This function wouldn't increase the count of used bytes. If grow fails, just respond back
 * as failure. Doesn't block on low freespace.
 */
static int castle_da_merge_extent_grow(c_ext_free_t     *ext_free,
                                       uint64_t          space_needed_bytes,
                                       int               growth_rate_chunks)
{
    debug("%s:: ext %llu, bytes currently allocated: %llu, bytes used: %llu; bytes needed %llu\n",
            __FUNCTION__,
            ext_free->ext_id,
            ext_free->ext_size,
            atomic64_read(ext_free->used),
            space_needed_bytes);

    while (castle_ext_freespace_available(ext_free) < space_needed_bytes)
    {
        int ret;
        uint64_t old_avail_bytes = ext_free->ext_size;

        if ((ret = castle_extent_grow(ext_free->ext_id, growth_rate_chunks)))
            return ret;

        castle_ext_freespace_size_update(ext_free, 1 /* Do checks. */);

        BUG_ON(ext_free->ext_size < old_avail_bytes); /* overflow? */
    }

    return 0;
}

static c_val_tup_t castle_da_medium_obj_copy(struct castle_da_merge *merge,
                                             c_val_tup_t old_cvt)
{
    c_ext_pos_t old_cep, new_cep;
    c_val_tup_t new_cvt;
    int total_blocks, blocks, i;
    c2_block_t *s_c2b, *c_c2b;
    c_byte_off_t ext_space_needed;

    old_cep = old_cvt.cep;
    /* Old cvt needs to be a medium object. */
    BUG_ON(!CVT_MEDIUM_OBJECT(old_cvt));
    /* It needs to be of the right size. */
    BUG_ON(!is_medium(old_cvt.length));
    /* It must belong to one of the in_trees data extent. */
    FOR_EACH_MERGE_TREE(i, merge)
    {
        struct castle_component_tree *ct = merge->in_trees[i];
        int j;

        for (j=0; j<ct->nr_data_exts; j++)
            if (old_cvt.cep.ext_id == ct->data_exts[j])
                break;

        if (j != ct->nr_data_exts)
            break;
    }
    BUG_ON(i == merge->nr_trees);
    /* We assume objects are page aligned. */
    BUG_ON(BLOCK_OFFSET(old_cep.offset) != 0);

    /* Don't copy if data extent is marked not to merge. */
    if (castle_data_ext_should_drain(old_cvt.cep.ext_id, merge) == -1)
        return old_cvt;

    /* Should have a valid data extent. */
    BUG_ON(EXT_ID_INVAL(merge->out_tree->data_ext_free.ext_id));

    /* Allocate space for the new copy. */
    total_blocks = (old_cvt.length - 1) / C_BLK_SIZE + 1;
    ext_space_needed = total_blocks * C_BLK_SIZE;
    debug("%s::[da %d level %d] new object consuming %d blocks (%llu bytes)\n",
        __FUNCTION__, merge->da->id, merge->level, total_blocks, ext_space_needed);

    BUG_ON(castle_ext_freespace_get(&merge->out_tree->data_ext_free,
                                     ext_space_needed,
                                     0,
                                    &new_cep) < 0);
    BUG_ON(BLOCK_OFFSET(new_cep.offset) != 0);
    /* Save the cep to return later. */
    new_cvt = old_cvt;
    new_cvt.cep = new_cep;

    /* Do the actual copy. */
    debug("Copying "cep_fmt_str" to "cep_fmt_str_nl,
            cep2str(old_cep), cep2str(new_cep));

    while (total_blocks > 0)
    {
        int chk_off, pgs_to_end;

        /* Chunk-align blocks if total_blocks is large enough to make it worthwhile. */
        chk_off = CHUNK_OFFSET(old_cep.offset);
        if (chk_off)
            pgs_to_end = (C_CHK_SIZE - chk_off) >> PAGE_SHIFT;

        /* Be careful about subtraction, if it goes negative, and is compared to
           BLKS_PER_CHK the test is likely not to work correctly. */
        if (chk_off && (total_blocks >= 2*BLKS_PER_CHK + pgs_to_end))
            /* Align for a minimum of 2 full blocks (1 can be inefficient) */
            blocks = pgs_to_end;
        else if (total_blocks > BLKS_PER_CHK)
            blocks = BLKS_PER_CHK;
        else
            blocks = total_blocks;
        total_blocks -= blocks;

        s_c2b = castle_cache_block_get(old_cep, blocks, MERGE_IN);
        c_c2b = castle_cache_block_get(new_cep, blocks, MERGE_OUT);
        castle_cache_advise(s_c2b->cep, C2_ADV_PREFETCH|C2_ADV_SOFTPIN, MERGE_IN, 0);
        BUG_ON(castle_cache_block_sync_read(s_c2b));
        read_lock_c2b(s_c2b);
        write_lock_c2b(c_c2b);
        update_c2b(c_c2b);
        memcpy(c2b_buffer(c_c2b), c2b_buffer(s_c2b), blocks * PAGE_SIZE);
        dirty_c2b(c_c2b);
        write_unlock_c2b(c_c2b);
        read_unlock_c2b(s_c2b);
        put_c2b(c_c2b);
        put_c2b_and_demote(s_c2b);
        old_cep.offset += blocks * PAGE_SIZE;
        new_cep.offset += blocks * PAGE_SIZE;
    }

    /* Update stats for Data extent stats. */
    castle_data_extent_update(new_cvt.cep.ext_id, NR_BLOCKS(new_cvt.length) * C_BLK_SIZE, 1);
    castle_data_extent_update(old_cvt.cep.ext_id, NR_BLOCKS(old_cvt.length) * C_BLK_SIZE, 0);
    merge->nr_bytes += NR_BLOCKS(old_cvt.length) * C_BLK_SIZE;

    debug("Finished copy, i=%d\n", i);

    return new_cvt;
}

/**
 * Works out what node size should be used for given level in the btree in a given merge.
 *
 * @param merge     Merge state structure.
 * @param level     Level counted from leaves.
 * @return          The size of the node.
 */
uint16_t castle_da_merge_node_size_get(struct castle_da_merge *merge, uint8_t level)
{
    if (level > 0)
    {
        if (merge->internals_on_ssds)
            return SSD_RO_TREE_NODE_SIZE;
        else
            return HDD_RO_TREE_NODE_SIZE;
    }
    else
    {
        if (merge->leafs_on_ssds)
            return SSD_RO_TREE_NODE_SIZE;
        else
            return HDD_RO_TREE_NODE_SIZE;
    }
}

/**
 * Works out which extent, and what node size should be used for given level in the btree
 * in a given merge.
 *
 * @param merge     Merge state structure.
 * @param level     Level counted from leaves.
 * @param node_size Return argument: size of the node.
 * @param ext_free  Return argument: extent freespace structure.
 */
static inline void castle_da_merge_node_info_get(struct castle_da_merge *merge,
                                                 uint8_t level,
                                                 uint16_t *node_size,
                                                 c_ext_free_t **ext_free)
{
    struct castle_component_tree *out_tree = merge->out_tree;

    *node_size = castle_da_merge_node_size_get(merge, level);
    /* If level is zero, we are allocating from tree_ext. Size depends on whether the
       extent is on SSDs or HDDs. */
    if (level > 0)
    {
        /* Internal nodes extent should always exist. */
        BUG_ON(EXT_ID_INVAL(out_tree->internal_ext_free.ext_id));
        *ext_free = &out_tree->internal_ext_free;
    }
    else
    {
        /* Leaf nodes extent should always exist. */
        BUG_ON(EXT_ID_INVAL(out_tree->tree_ext_free.ext_id));
        *ext_free = &out_tree->tree_ext_free;
    }
}

/**
 * Add an entry to the nodes that are being constructed in merge.
 *
 * @param merge [in, out] Doubling array merge structure
 * @param depth [in] B-tree depth at which entry should be added. 0 being leaf nodes.
 * @param key [in] key of the entry to be added
 * @param version [in]  version of the entry to be added
 * @param cvt [in] value tuple of the entry to be added
 * @param is_re_add [in] are we trying to re-add the entry to output tree?
 *                       (possible when we are trying to move entries from one node to
 *                       another node while completing the former node.)
 * @return c_val_tup_t*  If a new node is created, return a cvt specifying how to link this node
                         to a higher level node.
 * Note: if is_re_add flag is set, then the data wont be processed again, just
 * the key gets added.  Used when entry is being moved from one node to another
 * node.
 */
static c_val_tup_t _castle_da_entry_add(struct castle_da_merge *merge,
                                         int depth,
                                         void *key,
                                         c_ver_t version,
                                         c_val_tup_t cvt,
                                         int is_re_add)
{
    struct castle_immut_tree_level *level = merge->levels + depth;
    struct castle_btree_type *btree = merge->out_btree;
    struct castle_component_tree *out_tree = merge->out_tree;
    struct castle_double_array *da = merge->da;
    struct castle_btree_node *node;
    int key_cmp;
    c_val_tup_t  preadoption_cvt = INVAL_VAL_TUP;
    uint8_t      new_root_node   = 0;
    uint16_t     new_node_size   = 0;
    c_ext_pos_t  new_cep         = INVAL_EXT_POS;

    debug("%s::[%p] Adding an entry at depth: %u for tree id %u (out tree depth: %d)\n",
            __FUNCTION__, out_tree, depth, out_tree->seq, atomic_read(&out_tree->tree_depth));
    BUG_ON(depth >= MAX_BTREE_DEPTH);

    /* Alloc a new block if we need one */
    if(!level->node_c2b)
    {
        c_ext_free_t *ext_free;

        castle_da_merge_node_info_get(merge, depth, &new_node_size, &ext_free);
        if ( atomic_read(&out_tree->tree_depth) < (depth+1) )
        {
            debug("%s::Creating a new root level: %d\n", __FUNCTION__, depth);
            out_tree->node_sizes[depth] = new_node_size;
            new_root_node = 1; /* actual new root node linking has to be deferred till the entry is
                                  added; use this flag */
        }

        BUG_ON(level->next_idx      != 0);
        BUG_ON(level->valid_end_idx >= 0);

        debug("Allocating a new node at depth: %d\n", depth);

        BUG_ON(castle_ext_freespace_get(ext_free,
                                        new_node_size * C_BLK_SIZE,
                                        0,
                                        &new_cep) < 0);
        debug("Got "cep_fmt_str_nl, cep2str(new_cep));
        level->node_c2b = castle_cache_block_get(new_cep, new_node_size, MERGE_OUT);
        debug("Locking the c2b, and setting it up to date.\n");
        write_lock_c2b(level->node_c2b);
        update_c2b(level->node_c2b);
        /* Init the node properly */
        node = c2b_bnode(level->node_c2b);
        castle_btree_node_init(out_tree, node, 0, new_node_size, depth);
        if (depth > 0)
            node->flags &= ~BTREE_NODE_IS_LEAF_FLAG;
        debug("%s::Allocating a new node at depth: %d for tree %p (da %d)\n",
            __FUNCTION__, depth, out_tree, da->id);

        /* if a parent node exists, return preadoption cvt for caller to perform preadoption */
        if ( atomic_read(&out_tree->tree_depth) > (depth+1) )
        {
            BUG_ON(new_root_node);
            CVT_NODE_INIT(preadoption_cvt,
                          level->node_c2b->nr_pages * C_BLK_SIZE,
                          level->node_c2b->cep);
        }
    }
    else if (depth > 0)
        write_lock_c2b(level->node_c2b);

    node = c2b_bnode(level->node_c2b);
    debug("Adding at idx=%d depth=%d into node %p for immut tree on da %d\n",
        level->next_idx, depth, node, da->id);
    debug("Adding an idx=%d, key=%p, *key=%d, version=%d\n",
            level->next_idx, key, *((uint32_t *)key), version);

    /*
     * Compare the current key to the last key. Should never be smaller.
     *
     * key_compare() is a costly function. Trying to avoid duplicates. We already
     * did comparision between last key added to the out_tree and current key in
     * snapshot_delete algorithm (in castle_da_entry_skip()). Reuse the result
     * of it here again.
     *
     * Note: In case of re-adds is_new_key doesn't represent comparision between key being
     * added and last key added to the node. But, it repesents the comparision between last
     * 2 keys added to the tree. Still, it is okay as in case of re-adds both the comparisions
     * yield same value.
     *
     * Note: In rare circumstances entry_add() executed below can cause the node
     * to get compacted. This invalidates the last_key ptr, and could cause bugs (if the
     * space pointed to by last_key gets reused). We last_key reset unconditionally in order
     * to avoid any such issues.
     */
    key_cmp = (level->next_idx != 0) ?
               ((depth == 0)? merge->is_new_key: btree->key_compare(key, level->last_key)) :
               0;

    debug("Key cmp=%d\n", key_cmp);
    BUG_ON(key_cmp < 0);

    /* Add the entry to the node (this may get dropped later, but leave it here for now */
    btree->entry_add(node, level->next_idx, key, version, cvt);

    /* Unsafe to access last_key here, since the node may have got compacted. Reset it.
       Save this last key as the last merge key as well if level is the leaf level. */
    btree->entry_get(node, level->next_idx, &level->last_key, NULL, NULL);
    if (depth == 0)
        merge->last_key = level->last_key;

    /* Dirty the node, and unlock if non-leaf node. */
    dirty_c2b(level->node_c2b);
    if (depth > 0)
        write_unlock_c2b(level->node_c2b);

    if(new_root_node)
    {
        /* only have contention on output tree if tree queriable */
        write_lock(&da->lock);
        out_tree->root_node = new_cep;
        /* tree_depth is weird; it goes from -1 to 1, no 0 */
        if (unlikely(atomic_read(&out_tree->tree_depth) == -1))
            atomic_add(2, &out_tree->tree_depth);
        else
            atomic_inc(&out_tree->tree_depth);
        write_unlock(&da->lock);
    }

    /* Work out if the current/previous entry could be a valid node end.
       Case 1: We've just started a new node (node_idx == 0) => current must be a valid node entry */
    if(level->next_idx == 0)
    {
        debug("Node valid_end_idx=%d, Case1.\n", level->next_idx);
        BUG_ON(level->valid_end_idx >= 0);
        /* Save version as a valid_version, and init valid_end_idx. */
        level->valid_end_idx = 0;
        level->valid_version = version;
    } else
    /* Case 2: We've moved on to a new key. Previous entry is a valid node end. */
    if(key_cmp > 0)
    {
        debug("Node valid_end_idx=%d, Case2.\n", level->next_idx);
        BUG_ON(level->next_idx <= 0);
        level->valid_end_idx = level->next_idx - 1;
        level->valid_version = 0;
    }
#if 0
    /* This is disabled now, because we don't want keys crossing the node boundaries.
       Otherwise counter accumulation may not work correctly on gets/rqs. */
    else
    /* Case 3: Version is STRONGLY ancestral to valid_version. */
    if(castle_version_is_ancestor(version, level->valid_version))
    {
        debug("Node valid_end_idx=%d, Case3.\n", level->next_idx);
        BUG_ON(version == level->valid_version);
        level->valid_end_idx = level->next_idx;
        level->valid_version = version;
    }
#endif

    /* Node may be (over-)complete now, if it is full. Set next_idx to -1 (invalid) */
    if(btree->need_split(node, 0))
    {
        debug("Node now complete.\n");
        level->next_idx = -1;
    }
    else
        /* Go to the next node_idx */
        level->next_idx++;

    return preadoption_cvt;
}

/* wrapper around the real castle_da_entry_add; this performs orphan node preadoption iteratively */
static int castle_da_entry_add(struct castle_da_merge *merge,
                               int depth,
                               void *key,
                               c_ver_t version,
                               c_val_tup_t cvt,
                               int is_re_add,
                               int node_complete)
{
    c_val_tup_t preadoption_cvt;

    if (depth==0)
        BUG_ON(!CVT_LEAF_VAL(cvt) && !CVT_LOCAL_COUNTER(cvt));

    do {
        preadoption_cvt = _castle_da_entry_add(merge, depth, key, version, cvt, is_re_add);

        if(CVT_INVALID(preadoption_cvt))
            break; /* no new node was created, nothing new to adopt, so return now. */

        /* prepare for next loop iteration, to preadopt newly created node */
        cvt = preadoption_cvt;
        key = merge->out_btree->max_key;
        is_re_add = 0;
        depth++;

        debug("%s:: preadopting new orphan node for out_tree %p.\n",
                __FUNCTION__, merge->out_tree);
    } while(true); /* we rely on the ret from _castle_da_entry_add to break out of the loop */

    /* Try to complete node. */
    if (node_complete)
        return castle_da_nodes_complete(merge);

    return 0;
}

static void castle_da_node_complete(struct castle_da_merge *merge, int depth, int completing)
{
    struct castle_immut_tree_level *level = merge->levels + depth;
    struct castle_btree_type *btree = merge->out_btree;
    struct castle_component_tree *ct = merge->out_tree;
    struct castle_btree_node *node;
    int node_idx;
    void *key;
    void *last_key;
    c_ver_t version;
    c_val_tup_t cvt, node_cvt;
    c2_block_t *node_c2b;
    int valid_end_idx;

    /* Make sure we are not in recursion. */
#ifdef CASTLE_DEBUG
    BUG_ON(merge->is_recursion);
    merge->is_recursion = 1;
#endif

    debug("%s::Completing node at depth=%d for da %d\n",
        __FUNCTION__, depth, merge->da->id);
    BUG_ON(depth >= MAX_BTREE_DEPTH);

    node      = c2b_bnode(level->node_c2b);
    BUG_ON(!node);
    /* Version of the node should be the last valid_version */
    debug("Node version=%d\n", level->valid_version);
    node->version = level->valid_version;

    if (depth > 0)
        BUG_ON(BTREE_NODE_IS_LEAF(node));

    /* Note: This code calls castle_da_entry_add(), which would change all
     * parameters in level. Taking a copy of required members. */
    node_c2b        = level->node_c2b;
    last_key        = level->last_key;
    valid_end_idx   = level->valid_end_idx;

    btree->entry_get(node, valid_end_idx, &key, &version, &cvt);
    debug("Inserting into parent key=%p, *key=%d, version=%d\n",
            key, *((uint32_t*)key), node->version);

    /* Btree walk takes locks 2 at a time as it moves downwards. Node adoption attempts to do the
       reverse, i.e. move upwards while holding locks. To avoid deadlock, we need to temporarily
       give up the lock on the current node; this should be fine since we are the only writer. */
    if(depth == 0)
    {
        dirty_c2b(node_c2b);
        write_unlock_c2b(node_c2b);
    }

    /* Insert correct pointer in the parent, unless we've just completed the
       root node at the end of the merge. */
    if(!(unlikely(completing) && (atomic_read(&ct->tree_depth) == (depth+1) )))
    {
        CVT_NODE_INIT(node_cvt, (node_c2b->nr_pages * C_BLK_SIZE), node_c2b->cep);
        if ( likely( atomic_read(&ct->tree_depth) > (depth+1) ) )
        {
            /* this is not the top level, so there must be a higher level which contains a
               preadoption link that must be replaced with a "real" link. */
            struct castle_immut_tree_level *parent_level = merge->levels + depth + 1;
            c2_block_t *parent_node_c2b                = parent_level->node_c2b;
            struct castle_btree_node *parent_node      = c2b_bnode(parent_node_c2b);

            write_lock_c2b(parent_node_c2b);
            parent_node      = c2b_bnode(parent_node_c2b);

            debug("%s::replacing preadoption link with real link.("cep_fmt_str"->"cep_fmt_str")\n",
                    __FUNCTION__, cep2str(level->node_c2b->cep), cep2str(parent_node_c2b->cep));
            //btree->key_print(LOG_DEBUG, key);

            btree->entry_replace(parent_node, parent_node->used - 1, key, node->version, node_cvt);
            dirty_c2b(parent_node_c2b);
            write_unlock_c2b(parent_node_c2b);
        }
        else
        {
            /* add a "real" link; this will make a new top-level node */
            debug("%s::linking completed node to parent.\n", __FUNCTION__);
            castle_da_entry_add(merge,
                                depth+1,
                                key,
                                node->version,
                                node_cvt,
                                0,  /* Not a re-add. */
                                0); /* Don't complete nodes. */
        }
    }

    /* Reset the variables to the correct state for castle_da_entry_add(). */
    level->node_c2b      = NULL;
    level->last_key      = NULL;
    level->next_idx      = 0;
    level->valid_end_idx = -1;
    level->valid_version = INVAL_VERSION;

    /* When a node is complete, we need to copy the entries after valid_end_idx to
       the corresponding buffer */
    node_idx = valid_end_idx + 1;
    BUG_ON(node_idx <= 0 || node_idx > node->used);
    debug("%s::[%p] Entries to be copied to the buffer are in range [%d, %d)\n",
            __FUNCTION__, ct, node_idx, node->used);
    while(node_idx < node->used)
    {
        /* If tree is completing, there shouldn't be any splits any more. */
        BUG_ON(completing);
        btree->entry_get(node, node_idx,  &key, &version, &cvt);
        debug("%s::[%p] splitting node at depth %d, cep "cep_fmt_str_nl,
                __FUNCTION__, ct, depth, cep2str(node_c2b->cep));
        castle_da_entry_add(merge,
                            depth,
                            key,
                            version,
                            cvt,
                            1,  /* Re-add. */
                            0); /* Don't complete nodes. */
        node_idx++;
        BUG_ON(level->node_c2b == NULL);
        /* Check if the node completed, it should never do */
        BUG_ON(level->next_idx < 0);
    }

    debug("Dropping entries [%d, %d] from the original node\n",
            valid_end_idx + 1, node->used - 1);
    /* Now that entries are safely in the new node, drop them from the node */
    if((valid_end_idx + 1) <= (node->used - 1))
    {
        write_lock_c2b(node_c2b);
        btree->entries_drop(node, valid_end_idx + 1, node->used - 1);
        dirty_c2b(node_c2b);
        write_unlock_c2b(node_c2b);
    }

    BUG_ON(node->used != valid_end_idx + 1);
    if(completing && (atomic_read(&ct->tree_depth) == depth + 1))
    {
        /* Node c2b was set to NULL earlier in this function. When we are completing the tree
           we should never have to create new nodes at the same level (i.e. there shouldn't be
           any castle_da_entry_adds above). */
        BUG_ON(level->node_c2b);
        debug("Just completed the root node (depth=%d), at the end of the tree.\n",
                depth);
    }
    debug("Releasing c2b for cep=" cep_fmt_str_nl, cep2str(node_c2b->cep));
    debug("Completing a node with %d entries at depth %d\n", node->used, depth);

    merge->node_complete(merge, node_c2b, depth, completing);

    put_c2b(node_c2b);

#ifdef CASTLE_DEBUG
    merge->is_recursion = 0;
#endif
}

static void castle_da_merge_node_complete_cb(struct castle_da_merge             *merge,
                                             c2_block_t                         *node_c2b,
                                             int                                 depth,
                                             int                                 completing)
{
    struct castle_btree_node *node = c2b_bnode(node_c2b);
    void *key;

    /* Hold on to last leaf node for the sake of last_key. No need of lock, this
     * is a immutable node. */
    if (depth == 0)
    {
        c2_block_t *last_leaf_c2b = merge->last_leaf_node_c2b;

        /* Release the reference to the previous last node. */
        if (last_leaf_c2b)
        {
            /* The last_key pointer mustn't be pointing to the node any more. */
            BUG_ON(ptr_in_range(merge->last_key,
                                c2b_buffer(last_leaf_c2b),
                                last_leaf_c2b->nr_pages * PAGE_SIZE));
            put_c2b(last_leaf_c2b);
        }

        merge->last_leaf_node_c2b = node_c2b;
        get_c2b(merge->last_leaf_node_c2b);
    }

    /* Update partial merge partition redirection key */

    if (!MERGE_CHECKPOINTABLE(merge))
        return;

    if (depth != PARTIAL_MERGES_QUERY_REDIRECTION_BTREE_NODE_LEVEL)
        return;

    if (completing)
        return;

    /* Read the last key commited to node.
     *
     * Note: This might not be the last key written. As we might have moved the last
     * key to next node. */
    merge->out_btree->entry_get(node, node->used - 1, &key, NULL, NULL);

    castle_da_merge_new_partition_update(merge, node_c2b, key);
}

static int castle_da_nodes_complete(struct castle_da_merge *merge)
{
    struct castle_immut_tree_level *level;
    int i;

    debug("Checking if we need to complete nodes.");
    /* Check if the level i node has been completed, which may trigger a cascade of
       completes up the tree. */
    for(i=0; i<MAX_BTREE_DEPTH-1; i++)
    {
        level = merge->levels + i;
        /* Complete if next_idx < 0 */
        if(level->next_idx < 0)
        {
            debug("%s:: tree %d completing level %d\n",
                    __FUNCTION__, merge->out_tree->seq, i);
            castle_da_node_complete(merge, i, 0 /* Not yet completing tree.  */);
            debug("%s:: tree %d completed level %d\n",
                    __FUNCTION__, merge->out_tree->seq, i);
        }
        else
            /* As soon as we see an incomplete node, we need to break out: */
            goto out;
    }
    /* If we reached the top of the tree, we must fail the merge */
    if(i == MAX_BTREE_DEPTH - 1)
        return -EINVAL;

out:
    debug("We got as far as depth=%d\n", i);

    return 0;
}

static void castle_da_merge_package(struct castle_da_merge *merge, c_ext_pos_t root_cep)
{
    struct castle_component_tree *out_tree = merge->out_tree;

    BUG_ON(!CASTLE_IN_TRANSACTION);

    debug("Using component tree id=%d to package the merge.\n", out_tree->seq);

    castle_printk(LOG_INFO, "Depth of ct=%d (%p) is: %d\n",
            out_tree->seq, out_tree, atomic_read(&out_tree->tree_depth) );
    castle_printk(LOG_INFO, "Max key version set size of ct=%d (%p) is: %d\n",
            out_tree->seq, out_tree, out_tree->max_versions_per_key );
    BUG_ON(out_tree->root_node.ext_id != root_cep.ext_id);
    BUG_ON(out_tree->root_node.offset != root_cep.offset);

    debug("Root for that tree is: " cep_fmt_str_nl, cep2str(out_tree->root_node));
    BUG_ON(atomic_read(&out_tree->write_ref_count) != 0);

    /* truncate remaining blank chunks in output tree... */
    if(MERGE_CHECKPOINTABLE(merge))
    {
        /* ... if there is at least one unused chunk */
        if (castle_ext_freespace_available(&out_tree->tree_ext_free) > C_CHK_SIZE)
        {
            castle_printk(LOG_DEBUG, "%s::[da %d] truncating tree ext %u beyond chunk %u,"
                    " after %llu bytes used and %llu bytes allocated (grown)\n",
                    __FUNCTION__,
                    merge->da->id,
                    out_tree->tree_ext_free.ext_id,
                    USED_CHUNK(atomic64_read(&out_tree->tree_ext_free.used)),
                    atomic64_read(&out_tree->tree_ext_free.used),
                    out_tree->tree_ext_free.ext_size);
            castle_extent_truncate(out_tree->tree_ext_free.ext_id,
                                   USED_CHUNK(atomic64_read(&out_tree->tree_ext_free.used)));
        }

        if (castle_ext_freespace_available(&out_tree->data_ext_free) > C_CHK_SIZE)
        {
            castle_printk(LOG_DEBUG, "%s::[da %d] truncating data ext %u beyond chunk %u,"
                    " after %llu bytes used and %llu bytes allocated (grown)\n",
                    __FUNCTION__,
                    merge->da->id,
                    out_tree->data_ext_free.ext_id,
                    USED_CHUNK(atomic64_read(&out_tree->data_ext_free.used)),
                    atomic64_read(&out_tree->data_ext_free.used),
                    out_tree->data_ext_free.ext_size);
            castle_extent_truncate(out_tree->data_ext_free.ext_id,
                                   USED_CHUNK(atomic64_read(&out_tree->data_ext_free.used)));
        }
    }

    BUG_ON(merge->da != out_tree->da);

    FAULT(MERGE_FAULT);
}

static void castle_da_max_path_complete(struct castle_da_merge *merge, c_ext_pos_t root_cep)
{
    struct castle_btree_type *btree = merge->out_btree;
    struct castle_btree_node *node;
    c2_block_t *node_c2b, *next_node_c2b;
    struct castle_component_tree *out_tree = merge->out_tree;
    uint8_t level;
    uint16_t node_size;

    BUG_ON(atomic_read(&out_tree->tree_depth) < 1);

    /* Start with the root node. */
    node_size = out_tree->node_sizes[atomic_read(&out_tree->tree_depth) - 1];
    node_c2b = castle_cache_block_get(root_cep, node_size, MERGE_OUT);
    BUG_ON(castle_cache_block_sync_read(node_c2b));
    write_lock_c2b(node_c2b);
    node = c2b_bnode(node_c2b);
    debug("Maxifying the right most path, starting with root_cep="cep_fmt_str_nl,
            cep2str(node_c2b->cep));
    /* Init other temp vars. */
    level = 2;
    while (!BTREE_NODE_IS_LEAF(node))
    {
        void *k;
        c_ver_t v;
        c_val_tup_t cvt;

        /* Replace right-most entry with (k=max_key, v=0) */
        btree->entry_get(node, node->used-1, &k, &v, &cvt);
        BUG_ON(!CVT_NODE(cvt));
        debug("The node is non-leaf, replacing the right most entry with (max_key, 0).\n");
        btree->entry_replace(node, node->used-1, btree->max_key, 0, cvt);
        /* Change the version of the node to 0 */
        node->version = 0;
        /* Dirty the c2b */
        dirty_c2b(node_c2b);
        /* Go to the next btree node */
        debug("Locking next node cep=" cep_fmt_str_nl,
              cep2str(cvt.cep));
        node_size = out_tree->node_sizes[atomic_read(&out_tree->tree_depth) - level];
        next_node_c2b = castle_cache_block_get(cvt.cep, node_size, MERGE_OUT);
        /* unlikely to do IO as these nodes have just been in the cache. */
        BUG_ON(castle_cache_block_sync_read(next_node_c2b));
        write_lock_c2b(next_node_c2b);
        /* Release the old node. */
        debug("Unlocking prev node cep=" cep_fmt_str_nl,
               cep2str(node_c2b->cep));
        write_unlock_c2b(node_c2b);
        put_c2b(node_c2b);

        node_c2b = next_node_c2b;
        node = c2b_bnode(node_c2b);
        level++;
    }
    /* Release the leaf node. */
    debug("Unlocking prev node cep="cep_fmt_str_nl,
           cep2str(node_c2b->cep));
    write_unlock_c2b(node_c2b);
    put_c2b(node_c2b);
}

/**
 * Complete merge process.
 *
 * Each level can have at most one uncompleted node. Complete each node with the
 * entries we got now, and link the node to its parent. During this process, each
 * non-leaf node can get one extra entry in worst case. Mark valid_end_idx in each
 * level to used-1. And call castle_da_node_complete on every level, which would
 * complete the node and might add one entry in next higher level.
 *
 * @param merge [in, out] merge structure to be completed.
 *
 * @return ct Complete out tree
 *
 * @see castle_da_node_complete
 */
static void castle_da_merge_complete(struct castle_da_merge *merge)
{
    struct castle_component_tree *out_tree = merge->out_tree;
    struct castle_immut_tree_level *level;
    struct castle_btree_node *node;
    c_ext_pos_t root_cep = INVAL_EXT_POS;
    int next_idx, i;

    BUG_ON(!CASTLE_IN_TRANSACTION);

    debug("Completed immut tree construction of depth: %d\n", atomic_read(&out_tree->tree_depth));
    /* Force the nodes to complete by setting next_idx negative. Valid node idx
       can be set to the last entry in the node safely, because it happens in
       conjunction with setting the version to 0. This guarantees that all
       versions in the node are descendant of the node version. */
    for(i=0; i<MAX_BTREE_DEPTH; i++)
    {
        debug("Flushing at depth: %d\n", i);
        level = merge->levels + i;
        /* Node index == 0 indicates that there is no node at this level,
           therefore we don't have to complete anything. */
        next_idx = level->next_idx;
        /* Record the root cep for later use. */
        if(i+1 == atomic_read(&out_tree->tree_depth))
        {
            /* Root node must always exist, and have > 0 entries.
               -1 is also allowed, if the node overflowed once the node for
               previous (out_tree->tree_depth-1) got completed. */
            BUG_ON(next_idx == 0 || next_idx < -1);
            root_cep = level->node_c2b->cep;
        }
        if(next_idx != 0)
        {
            debug("Artificially completing the node at depth: %d\n", i);

            /* Complete the node by marking last entry as valid end. Also, mark
             * the version of this node to 0, as the node might contain multiple
             * entries. */
            node = c2b_bnode(level->node_c2b);
            /* Point the valid_end_idx past the last entry ... */
            level->valid_end_idx = next_idx < 0 ? node->used : level->next_idx;
            /* ... and now point it at the last entry. */
            level->valid_end_idx--;
            level->valid_version = 0;
            level->next_idx = -1;
            castle_da_node_complete(merge, i, 1 /* completing tree. */);
        }
    }
    /* Write out the max keys along the max path. */
    if ( atomic64_read(&out_tree->item_count) > 0 )
        castle_da_max_path_complete(merge, root_cep);

    /* Complete Bloom filters. */
    if (out_tree->bloom_exists)
        castle_bloom_complete(&out_tree->bloom);

    /* Package the merge result. */
    castle_da_merge_package(merge, root_cep);
}

static void castle_ct_large_objs_remove(struct list_head *);

/**
 * Deallocate a serdes state of merge state from merge->da.
 *
 * @param merge [in] in-flight merge.
 *
 * @also castle_da_merge_dealloc
 */
static void castle_da_merge_serdes_dealloc(struct castle_da_merge *merge)
{
    int level;

    BUG_ON(!merge);

    level = merge->level;
    BUG_ON( (level < MIN_DA_SERDES_LEVEL) );

    debug("%s::[%p] deallocating merge SERDES state for merge %u\n",
            __FUNCTION__, merge, merge->id);

    castle_da_merge_mstore_package_check_free(&merge->serdes.live);
    castle_da_merge_mstore_package_check_free(&merge->serdes.checkpointable);
}

static void castle_da_merge_sysfs_cleanup(struct castle_da_merge *merge, int err)
{
    int i;

    /* Merges are exposed to user, in case, GN is enabled. */
    if (merge->level != 1)
        castle_sysfs_merge_del(merge);

    /* If merge succeeded, delete all input trees from sysfs. */
    if (!err)
    {
        for (i=0; i<merge->nr_trees; i++)
            castle_sysfs_ct_del(merge->in_trees[i]);
    }

    /* Delete output tree, if the merge has failed or number of entries are 0. */
    if (merge->out_tree && (err || (atomic64_read(&merge->out_tree->item_count) == 0)))
        castle_sysfs_ct_del(merge->out_tree);
}

void castle_ct_dealloc(struct castle_component_tree *ct)
{
    struct list_head *lh, *t;

    /* Ref count should be 1 by now. */
    BUG_ON(atomic_read(&ct->ref_count) != 1);

    /* Free large object structures. */
    list_for_each_safe(lh, t, &ct->large_objs)
    {
        struct castle_large_obj_entry *lo = list_entry(lh, struct castle_large_obj_entry, list);

        list_del(lh);
        castle_free(lo);
    }

    list_del(&ct->hash_list);
    castle_check_free(ct->data_exts);
    castle_free(ct);
}

static void castle_da_merge_cts_release(struct castle_da_merge *merge, int err)
{
    int i;
    struct castle_component_tree *out_tree = merge->out_tree;

    /* Now, it is safe to release the last reference on unusable trees. */
    /* Merge Succeeded. */
    if (!err)
    {
        /* Release all input trees. */
        for (i=0; i<merge->nr_trees; i++)
            castle_ct_put(merge->in_trees[i], READ /*rw*/, NULL);

        /* Get-rid of empty out_tree. */
        if (out_tree && (atomic64_read(&merge->out_tree->item_count) == 0))
            castle_ct_put(out_tree, READ /*rw*/, NULL);
    }
    /* Merge Failed and out_tree is valid. */
    else if (out_tree)
    {
        /* Abort (i.e. free) incomplete bloom filter */
        if (out_tree->bloom_exists)
            castle_bloom_abort(&out_tree->bloom);

        /* If we are aborting a merge, cleanup output tree in memory. */
        if (err == -ESHUTDOWN)
            castle_ct_dealloc(out_tree);
        else
            castle_ct_put(out_tree, READ /*rw*/, NULL);
    }

    merge->out_tree = NULL;
}

static void castle_da_inserts_enable(unsigned long data);
static void castle_da_merge_trees_cleanup(struct castle_da_merge *merge, int err)
{
    struct castle_component_tree *out_tree = merge->out_tree;
    int i;

    /* Any operations on DA tree lists should be a transaction. */
    BUG_ON(!CASTLE_IN_TRANSACTION);

    /* On error, there shouldn't be any parallel reads on it. */
    if (out_tree && err)
    {
        BUG_ON(atomic_read(&out_tree->ref_count) != 1);
        BUG_ON(atomic_read(&out_tree->write_ref_count) != 0);
    }

    /* If the merge is aborting release extra reference on LO. This has no side effects, just
     * for the sake of more sanity checks at extents_fini(). */
    if (err == -ESHUTDOWN && out_tree)
    {
        struct list_head *lh;

        list_for_each(lh, &out_tree->large_objs)
        {
            struct castle_large_obj_entry *lo = list_entry(lh, struct castle_large_obj_entry, list);

            castle_extent_unlink(lo->ext_id);
        }
    }

    /* Delete the old trees from DA list.
       Note 1: Old trees may still be used by IOs and will only be destroyed on the last ct_put.
               But we want to remove it from the DA straight away. The out_tree now takes over
               their functionality.
       Note 2: DA structure modifications don't race with checkpointing because transaction lock
               is taken.
     */

    /* Get the lock and make modifications to DA.  We release last reference on trees, outside
     * lock*/
    write_lock(&merge->da->lock);

    /* Delete input trees, if merge succeeded. */
    if (!err)
    {
        for (i=0; i<merge->nr_trees; i++)
            castle_component_tree_del(merge->da, merge->in_trees[i]);

        /* Commit output tree stats. */
        castle_ct_stats_commit(out_tree);
    }

    /* Handle output tree. */
    if (out_tree)
    {
        BUG_ON(out_tree->level != 2);

        /* Get-rid of partition key. */
        if (test_bit(CASTLE_CT_PARTIAL_TREE_BIT, &out_tree->flags))
        {
            BUG_ON(!merge->redirection_partition.node_c2b);
            BUG_ON(!merge->redirection_partition.key);
            castle_key_ptr_destroy(&merge->redirection_partition);
        }

        /* If merge failed or out_tree is empty, delete it from DA. */
        if (err || (atomic64_read(&merge->out_tree->item_count) == 0))
            castle_component_tree_del(merge->da, out_tree);

        /* Reset all merge related bits on output tree. */
        out_tree->merge     = NULL;
        out_tree->merge_id  = INVAL_MERGE_ID;
        clear_bit(CASTLE_CT_MERGE_OUTPUT_BIT, &out_tree->flags);
        clear_bit(CASTLE_CT_PARTIAL_TREE_BIT, &out_tree->flags);
        merge->da->levels[out_tree->level].nr_output_trees--;
    }

    /* Reset all merge related bits on input trees. */
    for (i=0; i<merge->nr_trees; i++)
    {
        merge->in_trees[i]->merge       = NULL;
        merge->in_trees[i]->merge_id    = INVAL_MERGE_ID;
        clear_bit(CASTLE_CT_MERGE_INPUT_BIT, &merge->in_trees[i]->flags);
        clear_bit(CASTLE_CT_PARTIAL_TREE_BIT, &merge->in_trees[i]->flags);
    }

    /* Release the lock. */
    write_unlock(&merge->da->lock);

    if (out_tree && (atomic64_read(&out_tree->item_count)>0) && merge->level == 1)
        castle_events_new_tree_added(out_tree->seq, out_tree->da->id);

    /* FIXME: This again looks hacky. Need to fix rate control in clean way - BM. */
    /* If this is a level 1 merge, check if this is time to restart inserts. */
    if ((merge->level == 1) &&
        (castle_da_exiting || (merge->da->levels[1].nr_trees < 4 * castle_double_array_request_cpus())) &&
        test_bit(CASTLE_DA_INSERTS_BLOCKED_ON_MERGE, &merge->da->flags))
    {
        clear_bit(CASTLE_DA_INSERTS_BLOCKED_ON_MERGE, &merge->da->flags);
        castle_da_inserts_enable((unsigned long)merge->da);
    }

    castle_da_merge_restart(merge->da, NULL);

    castle_da_merge_cts_release(merge, err);

    castle_printk(LOG_INFO, "Completed merge at level: %d and deleted %u entries\n",
                            merge->level, merge->skipped_count);
}

static void castle_da_merge_partial_merge_cleanup(struct castle_da_merge *merge)
{
    BUG_ON(!MERGE_CHECKPOINTABLE(merge));

    castle_da_merge_serdes_dealloc(merge);

    castle_check_free(merge->shrinkable_extent_boundaries.tree);
    castle_check_free(merge->latest_mo_cep);
    castle_check_free(merge->shrinkable_extent_boundaries.data);
    castle_check_free(merge->in_tree_shrinkable_cep);
    castle_check_free(merge->serdes.shrinkable_cep);

}

/**
 * End-of-merge cleanup
 *
 * @param merge     [in]    merge structure
 * @param err       [in]    error code indicating how merge completed (e.g. success, fail, abort)
 *
 * @note Things inited in castle_da_merge_init should have matching fini here
 *
 * @also castle_da_merge_init
 */
static void castle_da_merge_dealloc(struct castle_da_merge *merge, int err, int locked)
{
    int i;

    if (!locked)
        CASTLE_TRANSACTION_BEGIN;

    BUG_ON(!merge);

    if (merge->level != 1)
    {
        castle_printk(LOG_WARN, "Completing merge with err: %d\n", err);
        for (i=0; i<merge->nr_trees; i++)
            castle_printk(LOG_WARN, "\t0x%llx\n", merge->in_trees[i]->seq);
    }

    /* Remove entries from sysfs first. This has to happen before any another clean-up. */
    castle_da_merge_sysfs_cleanup(merge, err);

    /* Remove merge from hash table. */
    castle_merges_hash_remove(merge);

    /* Release all outstanding locks on merge c2bs. */
    for (i=0; i<MAX_BTREE_DEPTH; i++)
        check_and_put_c2b(merge->levels[i].node_c2b);

    /* Release the last leaf node c2b. */
    check_and_put_c2b(merge->last_leaf_node_c2b);

    /* Destroy all iterators. */
    if (merge->iters)
    {
        FOR_EACH_MERGE_TREE(i, merge)
            castle_da_iterator_destroy(merge->in_trees[i], merge->iters[i]);
        castle_free(merge->iters);
    }

    if (merge->merged_iter)
        castle_ct_merged_iter_cancel(merge->merged_iter);

    /* Cleanup everything realted partial merges and merge checkpointing. This function depends
     * on merge trees, so this gets executed before tree_cleanup(). But, this doesn't cleanup
     * redirection key. That should happen in-sync tree_cleanup() and it left for it. */
    if (MERGE_CHECKPOINTABLE(merge))
        castle_da_merge_partial_merge_cleanup(merge);

    /* Detach and destroy reservation pool. */
    castle_da_merge_res_pool_detach(merge, err);

    /* Delete input trees from DA. Don't do partial merge cleanup, until we are done with this.
     * There could be parallel reads going on. */
    castle_da_merge_trees_cleanup(merge, err);

    /* Always free the list of new large_objs; we don't want to write them out because they
       won't correspond to serialised state. */
    castle_ct_large_objs_remove(&merge->new_large_objs);

    /* Free up structures that are used by the dfs resolver. This will handle cleanup regardless of
       what state the structure is in; i.e. if allocation failed (in which case merge_init would
       have called merge_dealloc directly), or allocation succeeded and the structure was used. */
    if (merge->tv_resolver)
    {
        castle_dfs_resolver_destroy(merge->tv_resolver);
        castle_check_free(merge->tv_resolver);
    }

    if (castle_version_states_free(&merge->version_states) != EXIT_SUCCESS)
    {
        castle_printk(LOG_ERROR, "%s::[da %d level %d] version_states not fully"
                " allocated.\n", __FUNCTION__, merge->da->id, merge->level);
        BUG();
    }

    /* Free the merged iterator, if one was allocated. */
    castle_check_free(merge->merged_iter);

    /* Free all the buffers */
    castle_check_free(merge->snapshot_delete.occupied);
    castle_check_free(merge->snapshot_delete.need_parent);
    castle_check_free(merge->drain_exts);
    castle_check_free(merge->in_trees);
    castle_free(merge);

    if (!locked)
        CASTLE_TRANSACTION_END;
}

/**
 * Is entry from a version marked for deletion that has no descendant keys.
 *
 * @param merge [in]    merge stream that entry comes from
 * @param key [in]      key of the entry
 * @param version [in]  version of the entry
 *
 * @return 1            Entry can be skipped
 *
 * @also castle_version_is_deletable
 */
static int castle_da_entry_skip(struct castle_da_merge *merge,
                                void *key,
                                c_ver_t version)
{
    struct castle_btree_type *btree = merge->out_btree;
    struct castle_version_delete_state *state = &merge->snapshot_delete;
    void *last_key = merge->last_key;

    merge->is_new_key = (last_key)? btree->key_compare(key, last_key): 1;

    /* Compare the keys. If looking at new key then reset data
     * structures. */
    if (merge->is_new_key)
    {
        int nr_bytes = state->last_version/8 + 1;

        memset(state->occupied, 0, nr_bytes);
        memset(state->need_parent, 0, nr_bytes);
        state->next_deleted = NULL;
    }

    return castle_version_is_deletable(state, version, merge->is_new_key);
}

/**
 * Deals with deletable counter, by 'pushing' its value to all direct children (so
 * grand-children etc won't be modified) of the counter version.
 *
 * 'Push' is performed according to the usual counter reduction semantics (i.e.
 * it'll only have an effect if the child is a counter add).
 *
 * Its assumed that all the children will exist in a single (current) leaf btree node.
 */
static void castle_da_counter_delete(struct castle_da_merge *merge,
                                     void *key,
                                     c_ver_t version,
                                     c_val_tup_t cvt)
{
    c_val_tup_t entry_cvt, accumulator_cvt;
    c_ver_t child_version, entry_version;
    struct castle_immut_tree_level *level;
    struct castle_btree_type *btree;
    struct castle_btree_node *node;
    void *entry_key;
    int idx, ret;

    castle_printk(LOG_DEBUG, "Deleting a counter, merge %p\n", merge);
    /* Init vars. */
    level = &merge->levels[0];
    btree = merge->out_btree;

    /* non counters are treated as implicit SET 0s */
    if(!CVT_ANY_COUNTER(cvt))
    {
        CVT_COUNTER_LOCAL_SET_INIT(cvt, 0);
        cvt.user_timestamp = 0;
    }

    /* If the node doesn't exist, it means there are no descendants to worry about. */
    if(!level->node_c2b)
        return;

    castle_printk(LOG_DEBUG, "Starting from idx=%d\n", level->next_idx-1);
    node = c2b_bnode(level->node_c2b);
    child_version = INVAL_VERSION;
    /* Go through entries in the node, accumulate the relevant ones. */
    for(idx=level->next_idx-1; idx>=0; idx--)
    {
        btree->entry_get(node, idx, &entry_key, &entry_version, &entry_cvt);
        castle_printk(LOG_DEBUG, "Idx=%d, entry_version=%d, cvt.type=%d\n",
            idx, entry_version, entry_cvt.type);

        /* If we reached another (smaller) key, we can terminate. */
        ret = btree->key_compare(entry_key, key);
        castle_printk(LOG_DEBUG, "Key compare=%d\n", ret);
        BUG_ON(ret > 0);
        if(ret < 0)
            return;

        castle_printk(LOG_DEBUG, "Deleted version=%d, entry version=%d, child_version=%d\n",
            version, entry_version, child_version);
        /* If we reached a version which isn't a descendant of the deleted version
           we must have dealt with entire subtree of the deleted version. Exit. */
        if(!castle_version_is_ancestor(version, entry_version))
            return;

        castle_printk(LOG_DEBUG, "Entry version is descendant of the deleted version.\n");
        /* Go to the next entry if current entry is a descendant of the current
           'child' version, which already accumulated the deleted entry. */
        if(!VERSION_INVAL(child_version) &&
            castle_version_is_ancestor(child_version, entry_version))
            continue;

        castle_printk(LOG_DEBUG, "Entry version is a direct child.\n");
        /* We reached a direct child (in this array) of the deleted version,
           do the accumulation, and update vars.
           If the entry isn't a counter add, accumulation is a no-op.
         */
        child_version = entry_version;
        if(!CVT_ADD_COUNTER(entry_cvt))
            continue;

        castle_printk(LOG_DEBUG, "Entry cvt is an add.\n");
        /* Accumulation is necessary. Accumulate entry_cvt first. */
        CVT_COUNTER_LOCAL_ADD_INIT(accumulator_cvt, 0);
        /* we don't support timestamped counters but let's explicitly set the timestamp field anyway */
        accumulator_cvt.user_timestamp = 0;

        ret = castle_counter_simple_reduce(&accumulator_cvt, entry_cvt);
        /* We know that entry_cvt is an add, therefore accumulation mustn't terminate. */
        BUG_ON(ret);
        /* Accumulate deleted cvt next. */
        castle_counter_simple_reduce(&accumulator_cvt, cvt);
        castle_printk(LOG_DEBUG, "Accumulated to 0x%llx.\n", accumulator_cvt.counter);
        /* Write out the updated entry. */
        btree->entry_replace(node, idx, key, entry_version, accumulator_cvt);
    }
}

/*
    The partial merges partition pipeline...

    The overall pipeline is distributed as follows:

    1) castle_ct_immut_iter_next: update the latest_mo_cep, potentially updated
       on every insert! This is tricky to avoid if we want to shrink the MO extent
       as much as possible.
    2) castle_ct_immut_iter_next_node: set valid extent boundaries for the input tree,
       i.e. the node boundary and the current latest_mo_cep. Updated on every new node
       in the iter.
    3) castle_da_merge_new_partition_update: create a partition key, and collect all
       valid extent boundaries into a single array of ceps. At this point we cannot drop
       the input tree extents because crash consistency is not yet guaranteed - for that
       we have to wait for...
    4) castle_da_merge_serialise: when setting the merge state as checkpointable, propagate
       the extent boundary array into the serdes structure so that checkpoint can find them
       and call extent_shrink.
    5) merge_writeback: call extent_shrink.
*/
static void castle_da_merge_new_partition_update(struct castle_da_merge *merge,
                                                 c2_block_t *node_c2b,
                                                 void *key)
{
    int i;
    uint16_t expected_node_size;
    struct castle_btree_node *node;
    unsigned int cep_arr_index = 0;
    unsigned int max_cep_arr_index = merge->nr_trees + merge->nr_drain_exts;

    BUG_ON(!MERGE_CHECKPOINTABLE(merge));
    BUG_ON(!merge);
    BUG_ON(!node_c2b);
    BUG_ON(!key);
    node = c2b_bnode(node_c2b);
    BUG_ON(node->magic != BTREE_NODE_MAGIC);

    BUG_ON(merge->out_tree->btree_type != merge->da->btree_type);

    /* == update redirection partition key == */

    write_lock(&merge->da->lock);
    if(!test_bit(CASTLE_CT_PARTIAL_TREE_BIT, &merge->out_tree->flags))
    {
        /* Tree not yet queriable, and this is the first time setting a redirection partition */
        BUG_ON(merge->redirection_partition.node_c2b);
        BUG_ON(merge->redirection_partition.key);

        /* Mark all input/outtrees as partial trees. */
        BUG_ON(test_and_set_bit(CASTLE_CT_PARTIAL_TREE_BIT, &merge->out_tree->flags));
        for (i=0; i<merge->nr_trees; i++)
            BUG_ON(test_and_set_bit(CASTLE_CT_PARTIAL_TREE_BIT, &merge->in_trees[i]->flags));

        castle_printk(LOG_DEBUG, "%s::[da %d level %d] making output tree %p queriable;",
                                 __FUNCTION__, merge->da->id, merge->level,
                                 merge->out_tree);
    }
    else
    {
        struct castle_btree_type *btree = merge->out_btree;
        BUG_ON(!merge->redirection_partition.node_c2b);
        BUG_ON(!merge->redirection_partition.key);
        /* The new redirection partition key must be > than the existing
           redirection partition key. */
        BUG_ON(btree->key_compare(key, merge->redirection_partition.key) <= 0 );

        /* Destroy current partition key */
        castle_key_ptr_destroy(&merge->redirection_partition);
    }
    /* Make new partition key */
    expected_node_size =
        castle_da_merge_node_size_get(merge, PARTIAL_MERGES_QUERY_REDIRECTION_BTREE_NODE_LEVEL);
    BUG_ON(node->size != expected_node_size);
    merge->redirection_partition.node_size = node->size;
    merge->redirection_partition.node_c2b  = node_c2b;
    merge->redirection_partition.key       = key;
    get_c2b(merge->redirection_partition.node_c2b);
    write_unlock(&merge->da->lock);

    atomic64_inc(&merge->da->stats.partial_merges.partition_updates);

    /* == update extents shrink boundaries == */
    BUG_ON(!merge->in_tree_shrinkable_cep);
    BUG_ON(!merge->merged_iter);
    BUG_ON(!merge->merged_iter->iterators);

    /* pack all shrinkable extent boundaries into a single list */
    /* first the tree extents... */
    for(i = 0; i < merge->nr_trees; i++)
    {
        c_ext_pos_t *cep_source_arr = merge->shrinkable_extent_boundaries.tree;
        BUG_ON(!cep_source_arr);
        if ( !EXT_POS_INVAL(cep_source_arr[i]) )
        {
            merge->in_tree_shrinkable_cep[cep_arr_index++] =
                cep_source_arr[i];
            cep_source_arr[i] = INVAL_EXT_POS;
            BUG_ON(cep_arr_index > max_cep_arr_index);
        }
    }
    /* then the data extents... */
    for(i = 0; i < merge->nr_drain_exts; i++)
    {
        c_ext_pos_t *cep_source_arr = merge->shrinkable_extent_boundaries.data;
        BUG_ON(!cep_source_arr);
        if ( !EXT_POS_INVAL(cep_source_arr[i]) )
        {
            merge->in_tree_shrinkable_cep[cep_arr_index++] =
                cep_source_arr[i];
            cep_source_arr[i] = INVAL_EXT_POS;
            BUG_ON(cep_arr_index > max_cep_arr_index);
        }
    }
    /* and explicitly set the remaining spots to INVAL, so we will not attempt to call
       extent_shrink on garbage. */
    for(i=cep_arr_index; i<max_cep_arr_index; i++)
        merge->in_tree_shrinkable_cep[i] = INVAL_EXT_POS;
}

static int castle_da_merge_space_reserve(struct castle_da_merge *merge, c_val_tup_t cvt)
{
    c_byte_off_t space_needed;
    int ret = 0;

    /* If the tree can't be checkpointable, it can't be partially merged. */
    if (!MERGE_CHECKPOINTABLE(merge))
        return 0;

    /* Always make sure we have enough space available in the extent for next leaf node. */
    /* Need space for one leaf node. */
    space_needed = castle_da_merge_node_size_get(merge, 0) * C_BLK_SIZE;

    /* This functions checks whether we got enough space, if not grows the extent. */
    ret = castle_da_merge_extent_grow(&merge->out_tree->tree_ext_free,
                                      space_needed,
                                      MERGE_OUTPUT_TREE_GROWTH_RATE);
    if (ret)
    {
        castle_printk(LOG_USERINFO, "Failed to grow the tree extent %llu for merge: %u\n",
                                     merge->out_tree->tree_ext_free.ext_id, merge->id);
        return ret;
    }

    /* If not a medium object or if this extent nor marked to drain, nothing else to be
     * done, just return. */
    if ( !CVT_MEDIUM_OBJECT(cvt) || (castle_data_ext_should_drain(cvt.cep.ext_id, merge) == -1) )
        return 0;

    /* Calculate space needed for the medium object. 4K aligned. */
    space_needed = ((cvt.length - 1) / C_BLK_SIZE + 1) * C_BLK_SIZE;

    /* Grow data extent. */
    ret = castle_da_merge_extent_grow(&merge->out_tree->data_ext_free,
                                      space_needed,
                                      MERGE_OUTPUT_DATA_GROWTH_RATE);
    if (ret)
    {
        castle_printk(LOG_USERINFO, "Failed to grow data extent %llu for merge: %u\n",
                                     merge->out_tree->data_ext_free.ext_id, merge->id);
        return ret;
    }

    return 0;
}

/* Give up locks before the merge goes to "sleep" so it doesn't block anything else,
   like checkpoint thread. */
static void castle_merge_sleep_prepare(struct castle_da_merge *merge)
{
    if (merge->levels[0].node_c2b)
    {
        castle_printk(LOG_DEBUG, "%s::[%p] merge id %u, unlocking leaf node c2b "cep_fmt_str_nl,
                __FUNCTION__, merge, merge->id, cep2str(merge->levels[0].node_c2b->cep));
        dirty_c2b(merge->levels[0].node_c2b);
        write_unlock_c2b(merge->levels[0].node_c2b);
    }
}
/* Retake locks after returning from a "sleep", so merge finds things as it expects to. */
static void castle_merge_sleep_return(struct castle_da_merge *merge)
{
    if (merge->levels[0].node_c2b)
    {
        castle_printk(LOG_DEBUG, "%s::[%p] merge id %u, relocking leaf node c2b "cep_fmt_str_nl,
                __FUNCTION__, merge, merge->id, cep2str(merge->levels[0].node_c2b->cep));
        write_lock_c2b(merge->levels[0].node_c2b);
    }
}

static int castle_da_entry_do(struct castle_da_merge *merge,
                              void *key,
                              c_val_tup_t cvt,
                              c_ver_t version,
                              uint64_t max_nr_bytes)
{
    int ret;
    struct castle_component_tree *out_tree = merge->out_tree;

    /* Skip entry if version marked for deletion and no descendant keys. */
    if (castle_da_entry_skip(merge, key, version))
    {
        /* If a counter is being deleted, it needs to be pushed to its
           descendants, otherwise we would loose its contribution. But
           we have to test every value, not just counters, because our
           counters semantics require that non-counters are implicit
           SET 0s, and we should not lose their contribution. */
        castle_da_counter_delete(merge, key, version, cvt);

        /* Update per-version and merge statistics.
         *
         * We do not need to decrement keys/tombstones for level 1 merges
         * as these keys have not yet been accounted for; skip them. */
        merge->skipped_count++;
        if(merge->level != 1)
            castle_version_stats_entry_discard(version,
                                               cvt,
                                               CVS_VERSION_DISCARD,
                                               &merge->version_states);

        /*
         * The skipped key gets freed along with the input extent.
         */
        return EXIT_SUCCESS;
    }

    /* No tv_resolver; rely on merge->is_new_key for serialisation control. */
    if(MERGE_CHECKPOINTABLE(merge) && !merge->tv_resolver)
        castle_da_merge_serialise(merge, 0 /* not using tvr */, 69 /* whatever... */);

    /* Make sure we got enough space for the entry_add() current cvt to be success. */
    while (castle_da_merge_space_reserve(merge, cvt))
    {
        /* On exit, just return error code -ESHUTDOWN. */
        if (castle_da_exiting)
            return -ESHUTDOWN;

        castle_printk(LOG_WARN, "******* Sleeping on LFS *****\n");
        castle_merge_sleep_prepare(merge);
        castle_merge_debug_locks(merge);
        msleep(1000);
        castle_merge_sleep_return(merge);
    }

    /* Deal with medium and large objects first. For medium objects, we need to copy them
       into our new medium object extent. For large objects, we need to save the aggregate
       size. plus take refs to extents? */
    /* It is possible to do castle_da_entry_add() on the same entry multiple
     * times. Don't process data again. */
    if (CVT_MEDIUM_OBJECT(cvt))
        cvt = castle_da_medium_obj_copy(merge, cvt);
    else if (CVT_LARGE_OBJECT(cvt))
    {
        atomic64_add(castle_extent_size_get(cvt.cep.ext_id), &out_tree->large_ext_chk_cnt);
        /* No need to add Large Objects under lock as merge is done in sequence. No concurrency
         * issues on the tree. With merge serialisation, checkpoint thread uses the list on
         * the output tree, which is only spliced in da_merge_marshall (under serdes lock) and
         * da_merge_package (which explicitly takes serdes lock).*/
        /* Adding LO to a temp list, wait for merge_serialise to splice when appropriate, or
           da_merge_package to do final splice. */
        castle_ct_large_obj_add(cvt.cep.ext_id, cvt.length, &merge->new_large_objs, NULL);
        BUG_ON(castle_extent_link(cvt.cep.ext_id) < 0);
        debug("%s::large object ("cep_fmt_str") for da %d level %d.\n",
            __FUNCTION__, cep2str(cvt.cep), da->id, merge->level);
    }

    /* Keep track of the max stream length of versions for any given key. */
    if (merge->is_new_key)
        merge->current_key_stream_v_count = 1;
    else
        merge->current_key_stream_v_count++;

    out_tree->max_versions_per_key =
            max(out_tree->max_versions_per_key, merge->current_key_stream_v_count);

    /* Add entry to the output btree.
     *
     * - Add to level 0 node (and recurse up the tree)
     * - Update the bloom filter */
    ret = castle_da_entry_add(merge,
                              0,
                              key,
                              version,
                              cvt,
                              0,    /* Not a re-add. */
                              1);   /* Complete nodes. */
    BUG_ON(ret == -ESHUTDOWN);

    if (castle_da_user_timestamping_check(merge->da))
    {
        castle_atomic64_max(cvt.user_timestamp,
                            &out_tree->max_user_timestamp);
        castle_atomic64_min(cvt.user_timestamp,
                            &out_tree->min_user_timestamp);
    }

    if (out_tree->bloom_exists && merge->is_new_key)
        castle_bloom_add(&out_tree->bloom, merge->out_btree, key);

    /* Update per-version and merge statistics.
     * We are starting with merged iterator stats (from above). */
    atomic64_inc(&out_tree->item_count);
    /* Level 1 merge introduces keys/tombstones into the version stats. */
    if (merge->level == 1)
        castle_version_stats_entry_add(version,
                                       cvt,
                                       &merge->version_states);

    /* Update component tree size stats. */
    castle_tree_size_stats_update(key, &cvt, out_tree, 1 /* Add. */);

    return ret;
}

static int castle_da_merge_tv_resolver_flush(struct castle_da_merge *merge,
                                             uint64_t max_nr_bytes)
{
    int ret = 0;

    uint32_t expected_pop_count;
    uint32_t actual_pop_count = 0;

    void                    *tvr_key     = NULL;
    c_ver_t                  tvr_version = INVAL_VERSION;
    c_val_tup_t              tvr_cvt;
    CVT_INVALID_INIT(tvr_cvt);

    BUG_ON(!merge);
    BUG_ON(!merge->tv_resolver);

    expected_pop_count = castle_dfs_resolver_process(merge->tv_resolver);
    while(castle_dfs_resolver_entry_pop(merge->tv_resolver,
                                        &tvr_key,
                                        &tvr_cvt,
                                        &tvr_version))
    {
        BUG_ON(!tvr_key);
        BUG_ON(actual_pop_count == expected_pop_count);
        BUG_ON(!CVT_LEAF_VAL(tvr_cvt) && !CVT_LOCAL_COUNTER(tvr_cvt));
        actual_pop_count++;

        ret = castle_da_entry_do(merge,
                                 tvr_key,
                                 tvr_cvt,
                                 tvr_version,
                                 max_nr_bytes);
        if(ret != EXIT_SUCCESS)
            return ret;
    }
    BUG_ON(actual_pop_count != expected_pop_count);
    return ret;
}

/**
 * Performs specified amount of merge work, adding entries directly to the output tree.
 * It assumes that the leaf btree node is locked (if one exists).
 * This doesn't deal with merge serialisation directly. Instead it relies on
 * @see castle_da_entry_do() subcall to do that (after version deletion has been handled).
 *
 * @param merge         Merge which needs to be performed
 * @param max_nr_bytes  How much merge work needs to be done in bytes (approx)
 * @return EAGAIN       If the unit got done successfully but the merge isn't finished yet.
 * @return EXIT_SUCCESS If the unit got done successfully and the merge is finished.
 * @return -ESHUTDOWN   If an exit condition was detected (FS shutdown/DA deletion)
 * @return -errno       On merge errors.
 */
static int castle_da_merge_unit_without_resolver_do(struct castle_da_merge *merge,
                                                    uint64_t max_nr_bytes)
{
    void *key;
    c_ver_t version;
    c_val_tup_t cvt;
    int ret = 0;

    /* max_nr_bytes should point to total number of bytes this merge could be done upto. */
    max_nr_bytes += merge->nr_bytes;

    while (castle_iterator_has_next_sync(&castle_ct_merged_iter, merge->merged_iter))
    {
        /* Let merge release the CPU if its been running too long. */
        might_resched();

        /* Get the next entry and account stats. */
        castle_ct_merged_iter_next(merge->merged_iter, &key, &version, &cvt);

        /* We should always get a valid cvt. */
        BUG_ON(CVT_INVALID(cvt));

        /* No resolver, add entries to the output directly. */
        ret = castle_da_entry_do(merge, key, cvt, version, max_nr_bytes);
        if(ret != EXIT_SUCCESS)
            return ret;

        /* Abort if we completed the work asked to do. */
        if (merge->nr_bytes > max_nr_bytes)
            return EAGAIN;

        FAULT(MERGE_FAULT);
    }

    /* Return success, if we are finished with the merge. */
    return EXIT_SUCCESS;
}

/**
 * Performs specified amount of merge work, going through the tombstone/timestamp resolution first.
 * The resolver buffers up one key worth of entries before it can perform the resolution.
 * Consequently serialisation needs to be handled here (extra buffering makes the process difficult
 * to handle elsewhere).
 * It assumes that the leaf btree node is locked (if one exists).
 *
 * @param merge         Merge which needs to be performed
 * @param max_nr_bytes  How much merge work needs to be done in bytes (approx)
 * @return EAGAIN       If the unit got done successfully but the merge isn't finished yet.
 * @return EXIT_SUCCESS If the unit got done successfully and the merge is finished.
 * @return -ESHUTDOWN   If an exit condition was detected (FS shutdown/DA deletion)
 * @return -errno       On merge errors.
 */
static int castle_da_merge_unit_with_resolver_do(struct castle_da_merge *merge,
                                                 uint64_t max_nr_bytes)
{
    void *key;
    c_ver_t version;
    c_val_tup_t cvt;
    int ret = 0;

    /* max_nr_bytes should point to total number of bytes this merge could be done upto. */
    max_nr_bytes += merge->nr_bytes;

    while (castle_iterator_has_next_sync(&castle_ct_merged_iter, merge->merged_iter))
    {
        /* Let merge release the CPU if its been running too long. */
        might_resched();

        /* Get the next entry and account stats. */
        castle_ct_merged_iter_next(merge->merged_iter, &key, &version, &cvt);

        /* We should always get a valid cvt. */
        BUG_ON(CVT_INVALID(cvt));

        /* Flush the resolver on new key boundary. Then serialise. */
        if(castle_dfs_resolver_is_new_key_check(merge->tv_resolver, key))
        {
            int ret;
            ret = castle_da_merge_tv_resolver_flush(merge, max_nr_bytes);
            if (MERGE_CHECKPOINTABLE(merge))
                castle_da_merge_serialise(merge, 1 /* using tvr */, 1 /* is a new key */);
            if (ret != EXIT_SUCCESS)
                return ret;
        }

        /* Record the iterator state if necessary. */
        if (MERGE_CHECKPOINTABLE(merge))
            castle_da_merge_serialise(merge, 1 /* using tvr */, 0 /* not a new key */);

        /* Add the entry to the resolver. */
        castle_dfs_resolver_entry_add(merge->tv_resolver, key, cvt, version);

        /* Abort if we completed the work asked to do. */
        if (merge->nr_bytes > max_nr_bytes)
            return EAGAIN;

        FAULT(MERGE_FAULT);
    }

    /* If the merge is finished, the resolver has to be flushed the final time. */
    ret = castle_da_merge_tv_resolver_flush(merge, max_nr_bytes);
    if (ret != EXIT_SUCCESS)
        return ret;

    /* Return success, if we are finished with the merge. */
    return EXIT_SUCCESS;
}

/**
 * Performs specified amount of merge work.
 * Pins T0s in memory if level 1 merge is being performed.
 *
 * @param merge         Merge which needs to be performed
 * @param max_nr_bytes  How much merge work needs to be done in bytes (approx)
 * @param hardpin       Whether to prefetch and hardpin data in memory first
 * @return EAGAIN       If the unit got done successfully but the merge isn't finished yet.
 * @return EXIT_SUCCESS If the unit got done successfully and the merge is finished.
 * @return -ESHUTDOWN   If an exit condition was detected (FS shutdown/DA deletion)
 * @return -errno       On merge errors.
 */
static int castle_da_merge_unit_do(struct castle_da_merge *merge,
                                   uint64_t max_nr_bytes,
                                   int hardpin)
{
    int i, ret;

    if(hardpin)
    {
        /* Hard-pin T1s in the cache. */
        for (i=0; i<merge->nr_trees; i++)
            castle_cache_advise((c_ext_pos_t){merge->in_trees[i]->data_ext_free.ext_id, 0},
                    C2_ADV_EXTENT|C2_ADV_HARDPIN,
                    MERGE_IN,
                    0);
    }

    ret = merge->tv_resolver ?
           castle_da_merge_unit_with_resolver_do(merge, max_nr_bytes) :
           castle_da_merge_unit_without_resolver_do(merge, max_nr_bytes);

    if(hardpin)
    {
        /* Unhard-pin T1s in the cache. Do this before we deallocate the merge and extents. */
        for (i=0; i<merge->nr_trees; i++)
            castle_cache_advise_clear((c_ext_pos_t){merge->in_trees[i]->data_ext_free.ext_id, 0},
                    C2_ADV_EXTENT|C2_ADV_HARDPIN,
                    0);
    }

    return ret;
}

int check_dext_list(c_ext_id_t ext_id, c_ext_id_t *list, uint32_t size)
{
    int i;

    for (i=0; i<size; i++)
        if (list[i] == ext_id)
            return 1;

    return 0;
}

/**
 * Check if the merge involves the oldest tree in the DA.
 *
 * @param merge The merge to check
 * @return 1    If the merge IS top-level
 * @return 0    If the merge IS NOT top-level
 * @note        The implementation of this is based on the da trees list, so any changes there
 *              could break. Refer inline comments to see how this works.
 * @note        Takes da->lock
 */
static unsigned int castle_da_merge_top_level_check(struct castle_da_merge *merge)
{
    int top_occupied_level;
    struct castle_component_tree * merge_oldest_tree = merge->in_trees[merge->nr_trees - 1];
    struct castle_component_tree * da_oldest_tree = NULL;
    int i;

    /* Assert that we really have the merge's oldest tree, according to data_age */
    FOR_EACH_MERGE_TREE(i, merge)
    {
        castle_printk(LOG_DEBUG, "%s::[%p] intree %d data_age %d, oldest tree data_age %d\n",
                __FUNCTION__, merge, i, merge->in_trees[i]->data_age, merge_oldest_tree->data_age);
        BUG_ON( (i!=merge->nr_trees-1) &&
                (merge->in_trees[i]->data_age <= merge_oldest_tree->data_age) );
    }

    read_lock(&merge->da->lock);
    for(top_occupied_level = MAX_DA_LEVEL-1; top_occupied_level > 1; top_occupied_level--)
        if (merge->da->levels[top_occupied_level].nr_trees > 0) break;

    /* Below level 2 the concept of tree age is a bit wonky, so let's just give up. */
    if (top_occupied_level < 2)
    {
        read_unlock(&merge->da->lock);
        castle_printk(LOG_DEBUG, "%s::[%p] top occupied level %d\n",
                __FUNCTION__, merge, top_occupied_level);
        return 0;
    }
    /* top_occupied_level must be >=2, and there must be a tree on this level */
    BUG_ON(list_empty(&merge->da->levels[top_occupied_level].trees));

    /* If the merge's oldest CT is on the end of the da list for the top occupied level, then it is
       the oldest tree in the DA, and this is the top-level merge. */

    /* The oldest tree on a given level in a DA is the last tree on the circularly linked list */
    da_oldest_tree = list_entry(merge->da->levels[top_occupied_level].trees.prev,
            struct castle_component_tree,
            da_list);

    read_unlock(&merge->da->lock);
    return (da_oldest_tree == merge_oldest_tree);
}

/**
 * Initialize merge process for multiple component trees.
 *
 * @param merge  [in]    merge to be initialised.
 *
 * @also castle_da_merge_dealloc
 */
static int castle_da_merge_init(struct castle_da_merge *merge, void *unused)
{
    btree_t btree_type;
    struct castle_double_array *da = merge->da;
    int level = merge->level;
    int nr_trees = merge->nr_trees;
    struct castle_component_tree **in_trees = merge->in_trees;
    int i, j, ret;
    uint32_t nr_non_drain_exts;
    tree_seq_t out_tree_data_age;
    c_thread_id_t thread_id;
    uint64_t nr_rwcts;
    c_dfs_resolver_functions_t dfs_resolver_functions = DFS_RESOLVE_NOTHING;

    BUG_ON(!CASTLE_IN_TRANSACTION);

    debug("Merging Trees:\n");
    for (i=0; i<nr_trees; i++)
        debug("\tct=0x%x, dynamic=%d, size=%lu\n", in_trees[i]->seq, in_trees[i]->dynamic,
                                                   atomic64_read(&in_trees[i]->nr_bytes));

    /* Sanity checks. Now, we do allow merge on single tree for the sake of
     * snapshot delete and data extents compaction. */
    BUG_ON(nr_trees < 1);

    /* Deserialising merge should always be at level 2. */
    BUG_ON(merge->serdes.des && (merge->level != 2));

    /* Work out what type of trees are we going to be merging. Bug if in_trees don't match. */
    nr_rwcts = 0;
    btree_type = in_trees[0]->btree_type;
    for (i=0; i<nr_trees; i++)
    {
        /* Btree types may, and often will be different during big merges. */
        BUG_ON(btree_type != in_trees[i]->btree_type);
        BUG_ON(in_trees[i]->level != level);
        nr_rwcts += in_trees[i]->nr_rwcts;
    }

    /* Malloc everything ... */
    ret = -ENOMEM;

    /* Deserialise ongoing merge state */
    /* only reason a lock might be needed here would be if we were racing with double_array_read,
       which should never happen */
    if (merge->serdes.des)
    {
        BUG_ON(merge->out_tree == NULL);

        castle_printk(LOG_DEBUG, "%s::found serialised merge in da %d level %d, attempting des\n",
                                 __FUNCTION__, da->id, level);
        castle_da_merge_deser_check(merge, da, level, nr_trees, in_trees);
        castle_da_merge_struct_deser(merge, da, level);

        debug_res_pools("Found merge %u with pool: %u\n", merge->id, merge->pool_id);

        /* Attach extents to reservation pools. */
        castle_da_merge_res_pool_attach(merge);

        castle_printk(LOG_INFO, "Found merge with %llu entries\n", atomic64_read(&merge->out_tree->item_count));

        goto deser_done;
    }

    /* Calculate number of extents that are not draining and should be added to output tree. */
    for (i=0, nr_non_drain_exts=0; i<merge->nr_trees; i++)
        for (j=0; j<merge->in_trees[i]->nr_data_exts; j++)
            if (!check_dext_list(merge->in_trees[i]->data_exts[j],
                                 merge->drain_exts, merge->nr_drain_exts))
                nr_non_drain_exts++;

    /* Data extents in output tree - Number of data extents that are not being
     * merged and one more for the extents that are being merged.  */
    merge->out_tree = castle_ct_alloc(da,
                                      2,
                                      INVAL_TREE,
                                      nr_non_drain_exts + 1,
                                      nr_rwcts);
    if(!merge->out_tree)
        goto error_out;

    ret = castle_da_merge_extents_alloc(merge);
    if(ret)
    {
        castle_ct_put(merge->out_tree, READ /*rw*/, NULL);
        merge->out_tree = NULL;

        goto error_out;
    }

    /* Link data extents that are not being drained to out_tree. */
    for (i=0; i<merge->nr_trees; i++)
    {
        struct castle_component_tree *ct = merge->in_trees[i];

        for (j=0; j<ct->nr_data_exts; j++)
        {
            uint64_t nr_bytes, nr_entries, nr_drain_bytes;

            castle_data_ext_size_get(ct->data_exts[j], &nr_bytes, &nr_drain_bytes,
                                     &nr_entries);

            if (nr_entries == 0)
            {
                BUG_ON(nr_bytes - nr_drain_bytes);
                continue;
            }

            if (!check_dext_list(ct->data_exts[j], merge->drain_exts, merge->nr_drain_exts))
                castle_ct_data_ext_link(ct->data_exts[j], merge->out_tree);
        }
    }

    BUG_ON(merge->out_tree->nr_data_exts > nr_non_drain_exts + 1);

deser_done:

    /* Iterators */
    ret = castle_da_iterators_create(merge); /* built-in handling of deserialisation, triggered by
                                                merge->serdes.des flag. */
    if(ret)
        goto error_out;

    /* If the merge is getting de-serialised, create a thread for it. */
    if (merge->serdes.des)
    {
        castle_merge_thread_create(&thread_id, da);
        if (THREAD_ID_INVAL(thread_id))
        {
            castle_printk(LOG_USERINFO, "Failed to create thread for the merge: %u\n", merge->id);
            goto error_out;
        }

        BUG_ON(castle_merge_thread_attach(merge->id, thread_id));

        /* Get a reference on DA, if this deserialisation of the merge from previous run.
         * For other cases, we must have already gotten the reference. Reference would be
         * released by merge thread. */
        castle_da_get(da);
    }

    /* We need a DFS resolver if this is a level 2+ merge, AND we are timestamping, OR if this is
       the top-level merge and we need to discard non-queriable tombstones. */
    if (merge->level >1)
    {
        if (castle_da_user_timestamping_check(merge->da))
            dfs_resolver_functions |= DFS_RESOLVE_TIMESTAMPS;
        if (castle_da_merge_top_level_check(merge))
            dfs_resolver_functions |= DFS_RESOLVE_TOMBSTONES;
    }
    if(dfs_resolver_functions != DFS_RESOLVE_NOTHING)
    {
        merge->tv_resolver = castle_zalloc(sizeof(c_dfs_resolver));
        if(!merge->tv_resolver)
            goto error_out;
        if(castle_dfs_resolver_preconstruct(merge->tv_resolver, merge, dfs_resolver_functions))
            goto error_out;
        BUG_ON(!merge->tv_resolver);
    }
    else
        merge->tv_resolver = NULL;

    /********** Important Note. *********/
    /**
     * Any failure before this point assumes that nothing is added to sysfs and error handling
     * is done accordingly. If it is important to fail after this, use some other label, but not
     * error_out.
     */

    /* This is very important to be write locked, as the requests need to see consistent view
     * mergable state of DA. */
    write_lock(&da->lock);

    out_tree_data_age = in_trees[0]->data_age;
    /* Attach all input trees to this merge.  */
    FOR_EACH_MERGE_TREE(i, merge)
    {
        if (in_trees[i]->data_age < out_tree_data_age)
            out_tree_data_age = in_trees[i]->data_age;

        /* If this merge trying to finish the left-over, it should have already set proper bits. */
        BUG_ON(test_and_set_bit(CASTLE_CT_MERGE_INPUT_BIT, &in_trees[i]->flags));

        if (test_bit(CASTLE_CT_PARTIAL_TREE_BIT, &merge->out_tree->flags))
            BUG_ON(test_and_set_bit(CASTLE_CT_PARTIAL_TREE_BIT, &in_trees[i]->flags));

        in_trees[i]->merge = merge;
        in_trees[i]->merge_id = merge->id;
    }

    /* Attach the output tree to the merge and mark as output tree. */
    merge->out_tree->merge      = merge;
    merge->out_tree->merge_id   = merge->id;
    merge->out_tree->data_age   = out_tree_data_age;

    /* Add the output tree to the DA list. */
    set_bit(CASTLE_CT_MERGE_OUTPUT_BIT, &merge->out_tree->flags);

    castle_component_tree_add(merge->da, merge->out_tree, NULL);
    da->levels[merge->out_tree->level].nr_output_trees++;

    write_unlock(&da->lock);

    /* Update merge stats. */
    /* Add all input B-Trees size. */
    merge->total_nr_bytes = merge->nr_bytes = 0;
    for (i=0; i<merge->nr_trees; i++)
    {
        merge->total_nr_bytes   += atomic64_read(&merge->in_trees[i]->nr_bytes);
        merge->nr_bytes         += merge->in_trees[i]->nr_drained_bytes;
    }

    /* Add all data extents that are being drained to the merge progress. */
    for (i=0; i<merge->nr_drain_exts; i++)
    {
        uint64_t nr_bytes, nr_drain_bytes, nr_entries;

        castle_data_ext_size_get(merge->drain_exts[i], &nr_bytes, &nr_drain_bytes, &nr_entries);
        merge->total_nr_bytes   += nr_bytes;
        merge->nr_bytes         += nr_drain_bytes;
    }

    BUG_ON(merge->nr_bytes > merge->total_nr_bytes);

    castle_sysfs_ct_add(merge->out_tree);
    if (merge->level != 1)
        BUG_ON(castle_sysfs_merge_add(merge));

    if (!merge->serdes.des && merge->level == 2)
        castle_events_new_tree_added(merge->out_tree->seq, merge->out_tree->da->id);

    merge->serdes.des=0;

    if (merge->tv_resolver)
        castle_dfs_resolver_construct_complete(merge->tv_resolver);

    if (merge->level != 1)
    {
        castle_printk(LOG_INFO, "Doing merge on trees:\n");
        for (i=0; i<nr_trees; i++)
            castle_printk(LOG_INFO, "\t0x%llx\n", merge->in_trees[i]->seq);
    }

    merge->current_key_stream_v_count = 0;

    return 0;

error_out:
    BUG_ON(!ret);
    if (merge->out_tree)
    {
        castle_da_merge_res_pool_detach(merge, ret);
        if (merge->out_tree->bloom_exists)
            castle_bloom_abort(&merge->out_tree->bloom);
        castle_ct_put(merge->out_tree, READ /*rw*/, NULL);
        merge->out_tree = NULL;
    }
    castle_printk(LOG_ERROR, "%s::Failed a merge with ret=%d\n", __FUNCTION__, ret);
    castle_da_merge_dealloc(merge, ret, 1 /* In transaction. */);
    debug_merges("Failed a merge with ret=%d\n", ret);

    return ret;
}

static struct castle_da_merge* castle_da_merge_alloc(int                            nr_trees,
                                                     int                            level,
                                                     struct castle_double_array    *da,
                                                     c_merge_id_t                   merge_id,
                                                     struct castle_component_tree **in_trees,
                                                     int                            nr_drain_exts,
                                                     c_ext_id_t                    *drain_exts)
{
    struct castle_da_merge *merge = NULL;
    int i, ret;

    /* Sanity checks. */
    //BUG_ON(level > 2);
    BUG_ON(nr_trees < 1);

    /* Malloc everything. Use zalloc to make sure everything is set to 0. */
    ret = -ENOMEM;
    merge = castle_zalloc(sizeof(struct castle_da_merge));
    if (!merge)
        return NULL;

    merge->id                   = INVAL_MERGE_ID;
    merge->thread_id            = INVAL_THREAD_ID;
    merge->pool_id              = INVAL_RES_POOL;
    merge->da                   = da;
    merge->out_btree            = castle_btree_type_get(da->btree_type);
    merge->level                = level;
    merge->nr_trees             = nr_trees;
    if ((merge->in_trees = castle_zalloc(sizeof(void *) * nr_trees)) == NULL)
    {
        castle_free(merge);
        return NULL;
    }
    if (in_trees)
        memcpy(merge->in_trees, in_trees, sizeof(void *) * nr_trees);
    merge->drain_exts           = drain_exts;
    merge->nr_drain_exts        = nr_drain_exts;
    merge->out_tree             = NULL;
    merge->iters                = NULL;
    merge->merged_iter          = NULL;
    merge->last_leaf_node_c2b   = NULL;
    merge->last_key             = NULL;
    merge->total_nr_bytes       = 0;
    merge->nr_bytes             = 0;
    merge->is_new_key           = 1;

    for (i = 0; i < MAX_BTREE_DEPTH; i++)
    {
        merge->levels[i].node_c2b      = NULL;
        merge->levels[i].last_key      = NULL;
        merge->levels[i].next_idx      = 0;
        merge->levels[i].valid_end_idx = -1;
        merge->levels[i].valid_version = INVAL_VERSION;
    }
    merge->node_complete        = castle_da_merge_node_complete_cb;

    INIT_LIST_HEAD(&merge->new_large_objs);

    if (castle_version_states_alloc(&merge->version_states,
                castle_versions_count_get(da->id, CVH_TOTAL)) != EXIT_SUCCESS)
        goto error_out;

    /* Bit-arrays for snapshot delete algorithm. */
    merge->snapshot_delete.last_version = castle_version_max_get();
    merge->snapshot_delete.occupied     = castle_alloc(merge->snapshot_delete.last_version / 8 + 1);
    if (!merge->snapshot_delete.occupied)
        goto error_out;
    merge->snapshot_delete.need_parent  = castle_alloc(merge->snapshot_delete.last_version / 8 + 1);
    if (!merge->snapshot_delete.need_parent)
        goto error_out;
    merge->snapshot_delete.next_deleted = NULL;

#ifdef CASTLE_DEBUG
    merge->is_recursion                 = 0;
#endif

    merge->skipped_count                = 0;

    merge->redirection_partition.node_c2b     = NULL;
    merge->redirection_partition.key          = NULL;

    merge->shrinkable_extent_boundaries.tree  = NULL;
    merge->latest_mo_cep                      = NULL;
    merge->shrinkable_extent_boundaries.data  = NULL;
    merge->in_tree_shrinkable_cep             = NULL;
    merge->serdes.shrinkable_cep              = NULL;

    if(MERGE_CHECKPOINTABLE(merge))
    {
        /* When an iterator moves to a leaf node new node boundary, a new s.e.b is set. */
        BUG_ON(nr_trees <= 0);
        merge->shrinkable_extent_boundaries.tree =
            castle_alloc(sizeof(c_ext_pos_t) * (nr_trees));
        if(!merge->shrinkable_extent_boundaries.tree)
            goto error_out;
        for(i=0; i<nr_trees; i++)
            merge->shrinkable_extent_boundaries.tree[i] = INVAL_EXT_POS;

        if (nr_drain_exts > 0)
        {
            /* When an iterator sees a new medium object, the latest_mo_cep is updated */
            merge->latest_mo_cep =
                castle_alloc(sizeof(c_ext_pos_t) * (nr_drain_exts));
            if(!merge->latest_mo_cep)
                goto error_out;
            for(i=0; i<nr_drain_exts; i++)
                merge->latest_mo_cep[i] = INVAL_EXT_POS;

            /* When an iterator sets a new s.e.b, the latest_mo_cep array is copied, thus ticking the
               state pipeline. */
            merge->shrinkable_extent_boundaries.data =
                castle_alloc(sizeof(c_ext_pos_t) * (nr_drain_exts));
            if(!merge->shrinkable_extent_boundaries.data)
                goto error_out;
            for(i=0; i<nr_drain_exts; i++)
                merge->shrinkable_extent_boundaries.data[i] = INVAL_EXT_POS;
        }

        /* We allocate space for 1 leaf node extent per tree, plus all the medium object
           extents we can eat. */
        merge->in_tree_shrinkable_cep =
            castle_alloc(sizeof(c_ext_pos_t) * (nr_drain_exts + nr_trees));
        if(!merge->in_tree_shrinkable_cep)
            goto error_out;

        merge->serdes.shrinkable_cep =
            castle_alloc(sizeof(c_ext_pos_t) * (nr_drain_exts + nr_trees));
        if(!merge->serdes.shrinkable_cep)
            goto error_out;

        for(i=0; i<(nr_drain_exts + nr_trees); i++)
            merge->in_tree_shrinkable_cep[i] = merge->serdes.shrinkable_cep[i] = INVAL_EXT_POS;

        /* merge serdes structs */
        if (castle_da_merge_mstore_package_alloc(&merge->serdes.live, nr_trees))
            goto error_out;
        if (castle_da_merge_mstore_package_alloc(&merge->serdes.checkpointable, nr_trees))
            goto error_out;
    }

    merge->serdes.des                          = 0;

    atomic_set(&merge->serdes.live.state, NULL_DAM_SERDES);
    atomic_set(&merge->serdes.checkpointable.state, NULL_DAM_SERDES);

    if (MERGE_ID_INVAL(merge_id))
        merge->id = atomic_inc_return(&castle_da_max_merge_id);
    else
        merge->id = merge_id;

    /* Poison kobject, so we don't try to free the kobject that is not yet initialised. */
    kobject_poison(&merge->kobj);

    castle_merges_hash_add(merge);

    return merge;

error_out:
    BUG_ON(!ret);

    castle_da_merge_mstore_package_check_free(&merge->serdes.live);
    castle_da_merge_mstore_package_check_free(&merge->serdes.checkpointable);
    castle_check_free(merge->shrinkable_extent_boundaries.tree);
    castle_check_free(merge->latest_mo_cep);
    castle_check_free(merge->shrinkable_extent_boundaries.data);
    castle_check_free(merge->serdes.shrinkable_cep);
    castle_check_free(merge->in_tree_shrinkable_cep);

    castle_check_free(merge->snapshot_delete.need_parent);
    castle_check_free(merge->snapshot_delete.occupied);
    castle_version_states_free(&merge->version_states);
    castle_check_free(merge->in_trees);
    castle_free(merge);

    debug_merges("Failed a merge with ret=%d\n", ret);

    return NULL;
}
#ifdef CASTLE_PERF_DEBUG
static void castle_da_merge_cache_efficiency_stats_flush_reset(struct castle_double_array *da,
                                                               struct castle_da_merge *merge,
                                                               uint32_t units_cnt,
                                                           struct castle_component_tree *in_trees[])
{
    int i, percentage;
    int pref_chunks_not_up2date, pref_chunks_up2date;

    /* Btree (internal + leaf) cache efficiency. */
    percentage = 0;
    pref_chunks_not_up2date = 0;
    pref_chunks_up2date = 0;
    FOR_EACH_MERGE_TREE(i, merge)
    {
        c_ext_id_t ext_id;

        ext_id = in_trees[i]->internal_ext_free.ext_id;

        pref_chunks_not_up2date += castle_extent_not_up2date_get_reset(ext_id);
        pref_chunks_up2date += castle_extent_up2date_get_reset(ext_id);

        ext_id = in_trees[i]->tree_ext_free.ext_id;
        pref_chunks_not_up2date += castle_extent_not_up2date_get_reset(ext_id);
        pref_chunks_up2date += castle_extent_up2date_get_reset(ext_id);
    }
    if (pref_chunks_up2date)
        percentage = (100 * pref_chunks_up2date) / (pref_chunks_not_up2date + pref_chunks_up2date);

    if (pref_chunks_up2date || pref_chunks_not_up2date)
        castle_trace_da_merge_unit(TRACE_VALUE,
                                   TRACE_DA_MERGE_UNIT_CACHE_BTREE_EFFICIENCY_ID,
                                   da->id,
                                   merge->level,
                                   units_cnt,
                                   percentage);

    /* Medium object cache efficiency. */
    percentage = 0;
    pref_chunks_not_up2date = 0;
    pref_chunks_up2date = 0;
    FOR_EACH_MERGE_TREE(i, merge)
    {
        c_ext_id_t ext_id;

        ext_id = in_trees[i]->data_ext_free.ext_id;
        if (EXT_ID_INVAL(ext_id))
            continue;

        pref_chunks_not_up2date += castle_extent_not_up2date_get_reset(ext_id);
        pref_chunks_up2date += castle_extent_up2date_get_reset(ext_id);
    }
    if (pref_chunks_up2date)
        percentage = (100 * pref_chunks_up2date) / (pref_chunks_not_up2date + pref_chunks_up2date);

    if (pref_chunks_up2date || pref_chunks_not_up2date)
        castle_trace_da_merge_unit(TRACE_VALUE,
                                   TRACE_DA_MERGE_UNIT_CACHE_DATA_EFFICIENCY_ID,
                                   da->id,
                                   merge->level,
                                   units_cnt,
                                   percentage);
}
#endif /* CASTLE_PERF_DEBUG */

/* A merge_mstore_package structure collects structures (mstore + state) required to
   checkpoint a single merge; the following are manipulator methods for this structure:
   1) ...package_deep_copy:          does memcpy
   2) ...package_live_to_chkpnt_cp:  a convenience method for deserialisation, calls _deep_cp,
                                     called through merge_hash_iterate.
   3) ...package_check_free:         dealloc
   4) ...package_alloc:              alloc (needs number of merge input trees as a param)
*/
void castle_da_merge_mstore_package_deep_copy(struct castle_da_merge_mstore_package *dest,
                                              struct castle_da_merge_mstore_package *source)
{
    int nr_of_in_trees = -1;

    BUG_ON(!dest->merge_state);
    BUG_ON(!dest->in_tree_state_arr);
    BUG_ON(!source->merge_state);
    BUG_ON(!source->in_tree_state_arr);

    nr_of_in_trees = source->merge_state->nr_trees;
    BUG_ON(nr_of_in_trees < 1);
    memcpy(dest->merge_state, source->merge_state, sizeof(struct castle_dmserlist_entry));
    memcpy(dest->in_tree_state_arr, source->in_tree_state_arr,
            (nr_of_in_trees * sizeof(struct castle_in_tree_merge_state_entry)));
    atomic_set(&dest->state, atomic_read(&source->state));
}

static int castle_da_merge_serdes_live_to_chkpnt_cp(struct castle_da_merge *merge, void *null)
{
    BUG_ON(!CASTLE_IN_TRANSACTION);
    BUG_ON(null);
    castle_da_merge_mstore_package_deep_copy(&merge->serdes.checkpointable, &merge->serdes.live);
    return 0;
}

void castle_da_merge_mstore_package_check_free(struct castle_da_merge_mstore_package *m)
{
    castle_check_free(m->merge_state);
    castle_check_free(m->in_tree_state_arr)
    atomic_set(&m->state, NULL_DAM_SERDES);
}

int castle_da_merge_mstore_package_alloc(struct castle_da_merge_mstore_package *m,
                                         unsigned int nr_in_trees)
{
    m->merge_state = castle_zalloc(sizeof(struct castle_dmserlist_entry));
    if (!m->merge_state)
        goto error_out;
    m->in_tree_state_arr = castle_zalloc(nr_in_trees * sizeof(struct castle_in_tree_merge_state_entry));
    if (!m->in_tree_state_arr)
        goto error_out;
    atomic_set(&m->state, NULL_DAM_SERDES);
    return 0;
error_out:
    castle_da_merge_mstore_package_check_free(m);
    castle_printk(LOG_WARN, "%s::failed to malloc\n", __FUNCTION__);
    return -ENOMEM;
}

/* For those times when we expect the states to be in synch... return non-zero if non-identical. */
static unsigned int castle_da_merge_mstore_package_cmp(struct castle_da_merge_mstore_package *m1,
                                                       struct castle_da_merge_mstore_package *m2)
{
    int nr_of_in_trees = -1;
    if(atomic_read(&m1->state) != atomic_read(&m2->state))
        return 1;
    if(memcmp(m1->merge_state, m2->merge_state, sizeof(struct castle_dmserlist_entry)))
        return 1;
    nr_of_in_trees = m1->merge_state->nr_trees;
    BUG_ON(nr_of_in_trees < 1);
    if(memcmp(m1->in_tree_state_arr, m2->in_tree_state_arr,
            nr_of_in_trees * sizeof(struct castle_in_tree_merge_state_entry)  ))
        return 1;
    return 0;
}

/**
 * Produce a serialisable "snapshot" of merge state. Saves state in merge->da.
 *
 * @param merge [in] in-flight merge.
 * @param using_tvr [in] indicates the use of a buffering timestamp-version resolver, which means
 *                       we cannot trust the merge->is_new_key flag.
 * @param tvr_update_outct_now [in] with the use of a tv_resolver, this flag indicates when to
 *                                  update the state of the output tree.
 *
 * @also castle_da_merge_unit_do
 * @note positioning of the call is crucial: it MUST be after iter state is updated,
 *       and before the output tree is updated.
 */
static void castle_da_merge_serialise(struct castle_da_merge *merge, int using_tvr, int tvr_new_key)
{
    int i;
    struct castle_double_array *da;
    int level;
    c_merge_serdes_state_t live_state;
    c_merge_serdes_state_t checkpointable_state;

    BUG_ON(!merge);
    BUG_ON(!merge->da);

    da=merge->da;
    level=merge->level;
    BUG_ON(level > MAX_DA_LEVEL);
    /* assert that we are not serialising merges on lower levels */
    BUG_ON((level < MIN_DA_SERDES_LEVEL));
    BUG_ON(!merge->out_tree);

    /* DO NOT reorder the following 2 initializations! See comment in block T4 below to find out why...*/
    checkpointable_state = atomic_read(&merge->serdes.checkpointable.state);
    barrier();
    live_state = atomic_read(&merge->serdes.live.state);

    /*
    Possible state transitions: (MT = this thread, CT = checkpoint thread)
                                (left hand is live state, right hand if checkpointable state)

        NULL/NULL               -> INVAL/NULL              [MT]
        INVAL/NULL              -> VALID_FRESH/VALID_FRESH [MT]
        VALID_FRESH/VALID_FRESH -> VALID_FRESH/VALID_STALE [CT]
        VALID_FRESH/VALID_STALE -> VALID_FRESH/VALID_STALE [CT]
        VALID_FRESH/VALID_STALE -> INVAL/VALID_STALE       [MT]
        INVAL/VALID_STALE       -> INVAL/VALID_STALE       [CT]
        INVAL/VALID_STALE       -> VALID_FRESH/VALID_FRESH [MT]

    Assertable observations:
        1) live state never valid_and_stale
        2) checkpointable state never invalid

    Note: CT writes merge state (and LOs) to mstore when state is VALID_AND_STALE or
          VALID_AND_FRESH, but if it is VALID_AND_STALE then it does not do extent_shrink
          or flush c2bs.
    */

    BUG_ON(live_state >= MAX_DAM_SERDES);
    BUG_ON(checkpointable_state >= MAX_DAM_SERDES);
    BUG_ON(live_state == VALID_AND_STALE_DAM_SERDES);
    BUG_ON(checkpointable_state == INVALID_DAM_SERDES);

    if( unlikely(live_state == NULL_DAM_SERDES ) ) /* -- T1 -- */
    {
        /* Don't bother serialising a merge that hasn't gone far enough to produce an output tree
           with > 1 level yet (meaning >=2 for ct->tree_depth). */
        if (atomic_read(&merge->out_tree->tree_depth) < 2)
            return;

        castle_printk(LOG_DEBUG, "%s::[%p] init SERDES merge: %u\n", __FUNCTION__, merge, merge->id);

        /* first write - initialise */
        debug("%s::initialising mstore entry for merge %p in "
                "da %d, level %d\n", __FUNCTION__, merge, da->id, level);

        /* marshall_all will touch large_objs list, which in principal we might race with against
           checkpoint thread... won't happen in this specific case, but for simplicity of assertion,
           we take the lock anyway (this only happens once per merge at most) */
        CASTLE_TRANSACTION_BEGIN;
        castle_da_merge_marshall(merge, DAM_MARSHALL_ALL);
        CASTLE_TRANSACTION_END;

        atomic_set(&merge->serdes.live.state, INVALID_DAM_SERDES);

        return;
    }
    else if( unlikely(live_state == INVALID_DAM_SERDES) ) /* -- T2 -- */
    {
        int is_new_key = 0;

        if( using_tvr )
            is_new_key = tvr_new_key;
        else
            is_new_key = merge->is_new_key;

        if( is_new_key ) /* -- T2a -- */
        {
            /* Here we need transaction lock because we want to guarantee synchronization btwn
            merge serdes state, version stats, ct stats etc, and also to protect the merge
            mstore package checkpointable structure. */

            CASTLE_TRANSACTION_BEGIN;

            /* update output tree state */
            castle_da_merge_marshall(merge, DAM_MARSHALL_OUTTREE);

            debug("%s::found new_key boundary; existing serialisation for "
                    "da %d, level %d is now checkpointable, so stop updating it.\n",
                    __FUNCTION__, da->id, level);

            /* Commit and zero private stats to global crash-consistent tree. */
            castle_version_states_commit(&merge->version_states);

            /* Commit output tree stats. */
            castle_ct_stats_commit(merge->out_tree);

            /* Commit input tree stats. */
            for (i=0; i<merge->nr_trees; i++)
                castle_ct_stats_commit(merge->in_trees[i]);

            for(i=0; i < (merge->nr_trees + merge->nr_drain_exts); i++)
                debug("%s::[da %d level %d] scheduling shrink of "cep_fmt_str"\n",
                        __FUNCTION__, merge->da->id, merge->level,
                        cep2str(merge->in_tree_shrinkable_cep[i]));

            /* Commit cep shrink list */
            memcpy(merge->serdes.shrinkable_cep,
                   merge->in_tree_shrinkable_cep,
                   sizeof(c_ext_pos_t) * (merge->nr_trees +merge->nr_drain_exts));

            for(i=0; i < (merge->nr_trees + merge->nr_drain_exts); i++)
            {
                if(EXT_POS_INVAL(merge->serdes.shrinkable_cep[i]))
                    continue;
                castle_printk(LOG_DEBUG, "%s::[merge %p id %d] scheduling shrink of "cep_fmt_str"\n",
                        __FUNCTION__, merge, merge->id, cep2str(merge->serdes.shrinkable_cep[i]));
            }

            /* mark serialisation as checkpointable, and no longer updatable */
            atomic_set(&merge->serdes.live.state, VALID_AND_FRESH_DAM_SERDES);

            /* Set up a new package for checkpoint */
            castle_da_merge_mstore_package_deep_copy(&merge->serdes.checkpointable, &merge->serdes.live);

            CASTLE_TRANSACTION_END;
            return;
        }
        else /* !is_new_key */ /* -- T2b -- */
        {
            /* update iterator state */
            castle_da_merge_marshall(merge, DAM_MARSHALL_ITERS);

            return;
        }
    }
    else if( unlikely(checkpointable_state == VALID_AND_STALE_DAM_SERDES) ) /* -- T3 -- */
    {
        /* we just got back from checkpoint - so FORCE an update */

        /* merge_serialise should have been firing noops until checkpoint processed the
           serdes.checkpointable package, so the following assertion must hold */
        BUG_ON(live_state != VALID_AND_FRESH_DAM_SERDES);

        debug("%s::updating mstore entry for merge in "
                "da %d, level %d\n", __FUNCTION__, da->id, level);
        castle_da_merge_marshall(merge, DAM_MARSHALL_ITERS);

        atomic_set(&merge->serdes.live.state, INVALID_DAM_SERDES);
        return; /* state now 1,1 */
    }
    else if( likely(live_state == VALID_AND_FRESH_DAM_SERDES) ) /* -- T4 -- */
    {
        /* state 2,1 -- this is usually the most common case, and is basically a noop; waiting
           for checkpoint to write checkpointable state before making a new state snapshot. */

        /* Is this assertion safe?
           checkpointable_state is updated in 2 places:
                (1) it is set to VALID_AND_FRESH here by merge thread
                (2) it is set to VALID_AND_STALE by checkpoint
           State (1) occurs when live state is set to VALID_AND_FRESH - see T2a. This puts live
           state into a noop loop (i.e. in this block here, T4). In the meantime, checkpoint could
           come along and induce State (2). At the start of this function, we update the local copy
           of checkpointable_state before the local copy of live_state; therefore if checkpoint
           state was STALE as per (2), we would have entered T3 instead of coming into T4 here. By
           this point it doesn't matter what checkpoint does, we already have our local copy of
           checkpointable state, so the following assertion should work.
        */
        BUG_ON(checkpointable_state != VALID_AND_FRESH_DAM_SERDES);
        return;
    }
    else
        BUG();

    /* all states should have been covered above */
    castle_printk(LOG_ERROR, "%s::should not have gotten here, with merge %p\n", __FUNCTION__, merge);
    BUG();
}

/**
 * Marshalls merge structure into disk-writable mstore structure (write to 'live' state instead of
 * 'checkpointable' state.
 *
 * @param merge [in] merge state
 * @param partial_marshall [in] flag to indicate how much stuff to marshall;
 *        0 = everything, 1 = iterators, 2 = output tree
 *
 * @note assumes merge is in serialisable state (e.g. new_key boundary)
 */
static void castle_da_merge_marshall(struct castle_da_merge *merge,
                                     c_da_merge_marshall_set_t partial_marshall)
{
    unsigned int i;
    struct component_iterator *curr_comp;
    c_immut_iter_t *curr_immut;
    int lo_count=0;
    struct castle_dmserlist_entry *merge_mstore = merge->serdes.live.merge_state;
    struct castle_in_tree_merge_state_entry *in_tree_merge_mstore =
                                                            merge->serdes.live.in_tree_state_arr;

    BUG_ON(!merge_mstore);
    BUG_ON(!merge->merged_iter->iterators);

    if( (partial_marshall == DAM_MARSHALL_ITERS) || (partial_marshall == DAM_MARSHALL_ALL) )
    {
        /* iterators */
        /* iterator marshalling happens often... make it as cheap as possible! */

        debug("%s::merge %p (da %d, level %d) iterator marshall\n", __FUNCTION__,
                merge, merge->da->id, merge->level);

        merge_mstore->iter_err                    = merge->merged_iter->err;
        merge_mstore->iter_non_empty_cnt          = merge->merged_iter->non_empty_cnt;
        merge_mstore->iter_src_items_completed    = merge->merged_iter->src_items_completed;

        curr_comp = merge->merged_iter->iterators;
        for(i=0; i<merge->nr_trees; i++)
        {
            BUG_ON(!curr_comp);
            curr_immut=curr_comp->iterator;
            BUG_ON(!curr_immut);

            if(partial_marshall==DAM_MARSHALL_ALL)
            {
                /* this stuff should never change; per-tree once-per-merge marshalling done here */
                in_tree_merge_mstore[i].pos_in_merge_struct = i;
                in_tree_merge_mstore[i].seq                 = merge->in_trees[i]->seq;
                in_tree_merge_mstore[i].da_id               = merge->da->id;
                in_tree_merge_mstore[i].merge_id            = merge->id;

                /* make sure we haven't mismatched trees and iterators */
                BUG_ON(curr_immut->tree->seq != in_tree_merge_mstore[i].seq);
            }
            else
                BUG_ON(in_tree_merge_mstore[i].pos_in_merge_struct != i);

            /* There are 'completed' flags for each immut iterator within c_immut_iter_t and also
               c_merged_iter_t. This seems like a duplicate so we serialise only 1 and restore the other
               on deserialisation. If the following BUGs, then the completed flags can have different
               states at serialisation boundary, which means we have to handle both seperately. */
            BUG_ON(curr_immut->completed != curr_comp->completed);
            in_tree_merge_mstore[i].iter.component_completed         = curr_comp->completed;
            in_tree_merge_mstore[i].iter.component_cached            = curr_comp->cached;
            in_tree_merge_mstore[i].iter.immut_curr_idx              = curr_immut->curr_idx;
            in_tree_merge_mstore[i].iter.immut_cached_idx            = curr_immut->cached_idx;
            in_tree_merge_mstore[i].iter.immut_next_idx              = curr_immut->next_idx;

            if(curr_immut->curr_c2b)
                in_tree_merge_mstore[i].iter.immut_curr_c2b_cep = curr_immut->curr_c2b->cep;
            else
            {
                /* the only known valid situation in which an immutable iterator may not have curr_c2b
                   is when it is completed. */
                BUG_ON(!curr_comp->completed);
                in_tree_merge_mstore[i].iter.immut_curr_c2b_cep = INVAL_EXT_POS;
            }

            if(curr_immut->next_c2b)
                in_tree_merge_mstore[i].iter.immut_next_c2b_cep = curr_immut->next_c2b->cep;
            else
                in_tree_merge_mstore[i].iter.immut_next_c2b_cep = INVAL_EXT_POS;

            curr_comp++; /* go to next component iterator */
        }
    }

    if( (partial_marshall == DAM_MARSHALL_OUTTREE) || (partial_marshall == DAM_MARSHALL_ALL) )
    {
        struct list_head *lh, *tmp;
        /* output tree */
        /* output tree marshalling is expensive... make it rare (i.e. once per checkpoint) */

        debug("%s::merge %p (da %d, level %d) output tree marshall with "
                "%d new LOs.\n", __FUNCTION__, merge, merge->da->id, merge->level, lo_count);

        list_for_each_safe(lh, tmp, &merge->new_large_objs)
        {
            struct castle_large_obj_entry *lo =
                list_entry(lh, struct castle_large_obj_entry, list);
            int lo_ref_cnt = castle_extent_link_count_get(lo->ext_id);
            /* we expect the input cct and output cct to both have reference to the LO ext */
            BUG_ON(lo_ref_cnt < 2);
            lo_count++;
        }

        /* update list of large objects */
        /* no need to take out_tree lo_mutex because we are here with transaction lock, which will
           block checkpoint thread, which is the only race candidate */
        BUG_ON(!CASTLE_IN_TRANSACTION);
        list_splice_init(&merge->new_large_objs, &merge->out_tree->large_objs);

        BUG_ON(!merge->out_tree);
        BUG_ON(EXT_POS_INVAL(merge->out_tree->internal_ext_free));
        BUG_ON(EXT_POS_INVAL(merge->out_tree->tree_ext_free));

        castle_da_ct_marshall(&merge_mstore->out_tree, merge->out_tree);
        merge_mstore->is_new_key         = merge->is_new_key;
        merge_mstore->skipped_count      = merge->skipped_count;
        merge_mstore->last_leaf_node_cep = INVAL_EXT_POS;

        if(merge->last_leaf_node_c2b)
            merge_mstore->last_leaf_node_cep = merge->last_leaf_node_c2b->cep;

        merge_mstore->redirection_partition_node_cep   = INVAL_EXT_POS;
        merge_mstore->redirection_partition_node_size = 0;
        if(merge->redirection_partition.node_c2b)
        {
            merge_mstore->redirection_partition_node_size = merge->redirection_partition.node_size;
            merge_mstore->redirection_partition_node_cep  = merge->redirection_partition.node_c2b->cep;

            if(merge_mstore->redirection_partition_node_size == 0 ||
                    merge_mstore->redirection_partition_node_size > 256)
            {
                castle_printk(LOG_ERROR, "%s::redir_partition_node_cep="cep_fmt_str", node size=%u\n",
                        __FUNCTION__,
                        cep2str(merge_mstore->redirection_partition_node_cep),
                        merge_mstore->redirection_partition_node_size);
                BUG();
            }
        }

        for(i=0; i<MAX_BTREE_DEPTH; i++)
        {
            BUG_ON(merge->levels[i].next_idx <= merge->levels[i].valid_end_idx);
            /* if the above ever BUGs, then an assumption about how to deserialise - specifically what
               entries should be dropped - is broken! */

            merge_mstore->levels[i].next_idx            = merge->levels[i].next_idx;
            merge_mstore->levels[i].valid_end_idx       = merge->levels[i].valid_end_idx;
            merge_mstore->levels[i].valid_version       = merge->levels[i].valid_version;

            merge_mstore->levels[i].node_c2b_cep        = INVAL_EXT_POS;
            merge_mstore->levels[i].node_used           = 0;

            if(merge->levels[i].node_c2b)
            {
                struct castle_btree_node *node;

                BUG_ON(EXT_POS_INVAL(merge->levels[i].node_c2b->cep));
                merge_mstore->levels[i].node_c2b_cep = merge->levels[i].node_c2b->cep;

                node=c2b_bnode(merge->levels[i].node_c2b);
                debug("%s::merge %p (da %d, level %d) sanity check node_c2b[%d] ("
                        cep_fmt_str")\n", __FUNCTION__, merge, merge->da->id, merge->level, i,
                        cep2str(merge_mstore->levels[i].node_c2b_cep));
                BUG_ON(!node);
                BUG_ON(node->magic != BTREE_NODE_MAGIC);
                merge_mstore->levels[i].node_used = node->used; /* to know which entries to drop at DES time */

                debug("%s::level[%d] for merge %p (da %d level %d) node size %d, node flags %d\n",
                        __FUNCTION__, i, merge, merge->da->id, merge->level, node->size, node->flags);

                /* dirty the incomplete node so it will be flushed at next checkpoint */
                if(i > 0)
                {
                    /* Potential for deadlock here! To avoid it, we have to temporarily unlock the
                       current leaf node before we try to lock an internal node. */
                    if(merge->levels[0].node_c2b)
                    {
                        dirty_c2b(merge->levels[0].node_c2b);
                        write_unlock_c2b(merge->levels[0].node_c2b);
                    }
                    write_lock_c2b(merge->levels[i].node_c2b);
                }
                dirty_c2b(merge->levels[i].node_c2b);
                if(i > 0)
                {
                    write_unlock_c2b(merge->levels[i].node_c2b);
                    if(merge->levels[0].node_c2b)
                        write_lock_c2b(merge->levels[0].node_c2b);
                }
            }//fi
        }//rof

        /* bloom build parameters, so we can resume building the output CT's bloom filter */
        merge_mstore->have_bbp = 0;
        if(merge->out_tree->bloom_exists)
        {
            struct castle_bloom_build_params *bf_bp = merge->out_tree->bloom.private;
            BUG_ON(!bf_bp);

            debug("%s::merge %p (da %d, level %d) bloom_build_param marshall.\n",
                    __FUNCTION__, merge, merge->da->id, merge->level);
            castle_bloom_build_param_marshall(&merge_mstore->out_tree_bbp, bf_bp);
            merge_mstore->have_bbp = 1;
        }
    }

    if( partial_marshall == DAM_MARSHALL_ALL )
    {
        /* the rest of the merge state */
        /* this stuff should never change; once-per-merge marshalling done here */

        debug("%s::merge %p (da %d, level %d) total marshall\n", __FUNCTION__,
                merge, merge->da->id, merge->level);

        merge_mstore->merge_id          = merge->id;
        merge_mstore->da_id             = merge->da->id;
        merge_mstore->level             = merge->level;
        merge_mstore->nr_trees          = merge->nr_trees;
        merge_mstore->btree_type        = merge->out_btree->magic;
        merge_mstore->leafs_on_ssds     = merge->leafs_on_ssds;
        merge_mstore->internals_on_ssds = merge->internals_on_ssds;
        merge_mstore->nr_drain_exts     = merge->nr_drain_exts;
        merge_mstore->pool_id           = merge->pool_id;
    }

    return;
}

/* During merge deserialisation, recover c2bs on a serialised output tree. Get the c2b, update it
   (i.e. READ), then return the c2b pointer in writelocked for condition. */
static c2_block_t* castle_da_merge_des_out_tree_c2b_write_fetch(struct castle_da_merge *merge,
                                                                c_ext_pos_t cep,
                                                                int depth)
{
    c2_block_t *c2b;
    uint16_t node_size;

    BUG_ON(!merge);
    BUG_ON(EXT_POS_INVAL(cep));

    node_size = castle_da_merge_node_size_get(merge, depth);
    BUG_ON(node_size == 0);

    c2b = castle_cache_block_get(cep, node_size, MERGE_OUT);
    BUG_ON(castle_cache_block_sync_read(c2b));

    return c2b;
}

/**
 * Deserialise merge structure
 *
 * @param merge [out] structure into which state is unpacked, and if error set 'deserialising'
 *        flag to 0
 * @param da [in] doubling array containing in-flight merge state
 * @param level [in] merge level in doubling array containing in-flight merge state
 */
static void castle_da_merge_struct_deser(struct castle_da_merge *merge,
                                         struct castle_double_array *da,
                                         int level)
{
    struct castle_dmserlist_entry *merge_mstore;
    struct castle_btree_node *node;
    struct list_head *lh, *tmp;
    struct castle_component_tree *des_tree = merge->out_tree;
    int i;

    merge_mstore=merge->serdes.live.merge_state;
    /* recover bloom_build_params. */
    if(merge->serdes.live.merge_state->have_bbp)
        castle_da_ct_bloom_build_param_deserialise(des_tree,
                                                  &merge->serdes.live.merge_state->out_tree_bbp);

    /* out_btree (type) can be assigned directly because we passed the BUG_ON() btree_type->magic
       in da_merge_deser_check. */
    merge->out_btree         = castle_btree_type_get(da->btree_type);
    merge->is_new_key        = merge_mstore->is_new_key;
    merge->skipped_count     = merge_mstore->skipped_count;
    merge->leafs_on_ssds     = merge_mstore->leafs_on_ssds;
    merge->internals_on_ssds = merge_mstore->internals_on_ssds;

    /* get reference to all LOs so the extents don't get dropped when the input cct is put */
    mutex_lock(&des_tree->lo_mutex);
    list_for_each_safe(lh, tmp, &des_tree->large_objs)
    {
        struct castle_large_obj_entry *lo =
            list_entry(lh, struct castle_large_obj_entry, list);
        BUG_ON(castle_extent_link(lo->ext_id) < 0);
    }
    mutex_unlock(&des_tree->lo_mutex);

    node=NULL;
    merge->last_key=NULL;
    for(i=0; i<MAX_BTREE_DEPTH; i++)
    {
        BUG_ON(merge->levels[i].node_c2b); /* Initialising merge - this should always be NULL */
        merge->levels[i].node_c2b      = NULL;
        merge->levels[i].last_key      = NULL;

        merge->levels[i].next_idx      = merge_mstore->levels[i].next_idx;
        merge->levels[i].valid_end_idx = merge_mstore->levels[i].valid_end_idx;
        merge->levels[i].valid_version = merge_mstore->levels[i].valid_version;

        /* Recover each btree level's node_c2b and last_key */
        if(!EXT_POS_INVAL(merge_mstore->levels[i].node_c2b_cep))
        {
            int idx;
            void        *dummy_k;
            void        *dummy_k_unpack;
            c_ver_t      dummy_v;
            c_val_tup_t  dummy_cvt;

            castle_printk(LOG_DEBUG, "%s::sanity check for merge %p (da %d level %d) node_c2b[%d] ("cep_fmt_str")\n",
                    __FUNCTION__, merge, da->id, level,
                    i, cep2str(merge_mstore->levels[i].node_c2b_cep) );

            merge->levels[i].node_c2b =
                castle_da_merge_des_out_tree_c2b_write_fetch(merge, merge_mstore->levels[i].node_c2b_cep, i);
            BUG_ON(!merge->levels[i].node_c2b);
            /* sanity check on btree node */
            node = c2b_bnode(merge->levels[i].node_c2b);
            debug("%s::recovered level %d node at %p with magic %lx for merge %p (da %d level %d) from "
                    cep_fmt_str" \n",
                    __FUNCTION__, i, node, node->magic, merge, da->id, level, cep2str(merge_mstore->levels[i].node_c2b_cep) );
            BUG_ON(!node);
            BUG_ON(node->magic != BTREE_NODE_MAGIC);

            BUG_ON(merge_mstore->levels[i].node_used > (node->used) );
            if(merge_mstore->levels[i].next_idx < (node->used))
            {
                int drop_start=0;
                int drop_end=0;
                debug("%s::for merge %p (da %d level %d) entries_drop on node_c2b[%d] "
                        "ser used = %d, current used = %d, valid_end_idx = %d, next_idx = %d, node size = %d\n",
                        __FUNCTION__, merge, da->id, level, i,
                        merge_mstore->levels[i].node_used,
                        node->used,
                        merge_mstore->levels[i].valid_end_idx,
                        merge_mstore->levels[i].next_idx,
                        node->size);

                /* if the following BUGs, then it seems possible that some node entries were dropped
                   after the serialisation point */
                BUG_ON(node->used < merge_mstore->levels[i].node_used);
                if(node->used != merge_mstore->levels[i].node_used)
                {
                    drop_start = merge_mstore->levels[i].node_used;
                    drop_end   = node->used - 1;
                    merge->out_btree->entries_drop(node, drop_start, drop_end);
                }
            }
            /* recover last key */
            if(node->used)
            {
                merge->out_btree->entry_get(node, node->used - 1,
                        &merge->levels[i].last_key, NULL, NULL);
                if(i==0)
                    merge->last_key = merge->levels[i].last_key;
            }
            /* test that each key is sane, by forcing it through the entry_get code path */
            for(idx=0; idx<node->used; idx++)
            {
                merge->out_btree->entry_get(node, idx, &dummy_k, &dummy_v, &dummy_cvt);
                dummy_k_unpack = merge->out_btree->key_unpack(dummy_k, NULL, NULL);
                castle_free(dummy_k_unpack);
            }
        }
    }

    merge->last_leaf_node_c2b = NULL;
    if(!EXT_POS_INVAL(merge_mstore->last_leaf_node_cep))
    {
        debug("%s::last_leaf_node_c2b for merge %p (da %d level %d)\n",
                __FUNCTION__, merge, da->id, level);
        merge->last_leaf_node_c2b =
            castle_da_merge_des_out_tree_c2b_write_fetch(merge, merge_mstore->last_leaf_node_cep,
                    0 /* leaf */);

        read_lock_c2b(merge->last_leaf_node_c2b);

        BUG_ON(!merge->last_leaf_node_c2b);
        node = c2b_bnode(merge->last_leaf_node_c2b);
        BUG_ON(!node);
        BUG_ON(node->magic != BTREE_NODE_MAGIC);

        /* if we don't already have the last_key, then it is on the already completed node. */
        if( (!merge->last_key) && (node->used) )
            merge->out_btree->entry_get(node, node->used - 1, &merge->last_key, NULL, NULL);

        read_unlock_c2b(merge->last_leaf_node_c2b);

        castle_printk(LOG_DEBUG, "%s::recovered last leaf node for merge %p (da %d level %d) from "
                cep_fmt_str" \n",
                __FUNCTION__, merge, da->id, level, cep2str(merge_mstore->last_leaf_node_cep) );
    }

    return;
}

/**
 * Sanity checks on deserialising merge state.
 *
 * @param da [in] doubling array containing in-flight merge state
 * @param level [in] merge level in doubling array containing in-flight merge state
 * @param nr_trees [in] number of trees to be merged
 * @param in_trees [in] component trees to be merged
 *
 * @also castle_double_array_read()
 * @also castle_da_merge_init()
 * @also struct castle_da_merge
 */
static void castle_da_merge_deser_check(struct castle_da_merge *merge,
                                        struct castle_double_array *da,
                                        int level,
                                        int nr_trees,
                                        struct castle_component_tree **in_trees)
{
    struct castle_dmserlist_entry *merge_mstore;
    struct castle_in_tree_merge_state_entry    *in_tree_merge_mstore_arr;
    int i;

    BUG_ON(!da);
    BUG_ON(!merge);
    BUG_ON((level < MIN_DA_SERDES_LEVEL));

    merge_mstore             = merge->serdes.live.merge_state;
    in_tree_merge_mstore_arr = merge->serdes.live.in_tree_state_arr;

    /* if BUG here, there is a problem with the mstore read (probably double_array_read) */
    BUG_ON(!merge_mstore);
    BUG_ON(!in_tree_merge_mstore_arr);
    /* if BUG on the following two, it is likely there is a problem with serialisation -
       the wrong state information was written, or it was written to the wrong place */
    BUG_ON(merge_mstore->da_id          != da->id);
    BUG_ON(merge_mstore->level          != level);
    BUG_ON(merge_mstore->out_tree.level != 2);
    BUG_ON(merge_mstore->btree_type     != da->btree_type);

    /* if seq numbers match up, everything else would be fine as well */
    for(i=0; i<nr_trees; i++)
        BUG_ON(in_tree_merge_mstore_arr[i].seq != in_trees[i]->seq);

    /* Sane. Proceed. */
    debug("Interrupted merge da %d level %d passed initial SERDES logic sanity checks.\n",
            da->id, level);

    return;
}

/**
 * Performs specified amount of merge work on a merge that's already initialised.
 * Wraps @see castle_da_merge_unit_do(), and also deals with:
 * a) detecting exit conditions (due to FS shutdown or DA deletion)
 * b) retaking/releasing locks, in order to put the merge in the expected state/release
 *    locks for the period of (possibly extended) inactivity
 * c) finishing merge off when terminating successfully or on errors
 *
 * @param merge     [in]    Do some work on this merge.
 * @param nr_bytes  [in]    Approx amount of merge work in bytes, 0 for everything
 *
 * @return EXIT_SUCCESS if the unit of work god done successfully and the merge terminated.
 * @return EAGAIN       if the unit of work got done successfully and the merge continues
 * @return -ESHUTDOWN   if a termination condition was detected
 *                      (the merge won't be cleaned up here in such case)
 * @return -errno       if the merge terminated with a failure. Merge is cleaned up here.
 */
static int castle_da_merge_do(struct castle_da_merge *merge, uint64_t nr_bytes)
{
    struct castle_double_array *da = merge->da;
    int level = merge->level;
    int ret;

    /* Check for FS stop and merge abort due to DA deletion. */
    if (castle_merges_abortable && exit_cond)
    {
        /* If FS exiting, delay merge_dealloc until DA finish for the sake of last checkpoint.
           In case of DA destroy, merge thread itself will dealloc the merge. */
        castle_printk(LOG_INFO, "Merge for DA=%d, level=%d, aborted.\n", da->id, level);

        return -ESHUTDOWN;
    }

    /* If the work size is 0, complete everything in one shot. RWCT merges are expected
       to happen in one shot (we pin/unpin all the data, would be waste to have to be
       doing it multiple times). */
    BUG_ON((merge->level == 1) && (nr_bytes != 0));
    if (nr_bytes == 0)
        nr_bytes = merge->total_nr_bytes;

    /* Retake locks, so the rest of merge code finds things as it expects to. */
    castle_merge_sleep_return(merge);

    /* Perform the merge work. Specify hardpin if merging RWCTs. */
    ret = castle_da_merge_unit_do(merge, nr_bytes, (merge->level == 1) /*hardpin*/);

#ifdef CASTLE_PERF_DEBUG
    /* Output & reset cache efficiency stats. */
    castle_da_merge_cache_efficiency_stats_flush_reset(da, merge, 0, merge->in_trees);
#endif

    /* Release the locks and return straight away if the unit of work completed
       successfully (common path), or got failed due to an exit condition. */
    if ((ret == EAGAIN) || (ret == -ESHUTDOWN))
    {
        castle_merge_sleep_prepare(merge);
        return ret;
    }

    /* If merge is terminating due to successful completion, or an error
       do the remaining work under transaction lock in order not to race with checkpoint. */
    CASTLE_TRANSACTION_BEGIN;

    /* On errors don't perform finalisation work. Don't commit the stats either.
       This isn't really expected to happen (only a corner case when the out tree
       grew to beyond 10 levels). */
    if (ret == EXIT_SUCCESS)
    {
        /* Finish packaging the output tree. */
        castle_da_merge_complete(merge);

        /* update list of large objects */
        /* in transaction, so won't race against checkpoint - safe to proceed without locks */
        list_splice_init(&merge->new_large_objs, &merge->out_tree->large_objs);

        /* Commit and zero private stats to global crash-consistent tree. */
        castle_version_states_commit(&merge->version_states);
    }
    /* Release the locks. */
    castle_merge_sleep_prepare(merge);
    /* Get rid of the merge structure. */
    castle_da_merge_dealloc(merge, ret, 1/* In transaction. */);

    CASTLE_TRANSACTION_END;
    return 0;

}

/**
 * Determines whether to do merge or not.
 *
 * Do not do merge if one of following is true:
 *  - DA has few outstanding low free space victims
 *  - DA is marked for compaction
 *  - There is a ongoing merge unit at a level above
 *
 * IMPORTANT: this function has side effect of incrementing ongoing merges counter,
 *            this happens iff the wait is supposed to terminate (non-zero return from
 *            this function).
 *
 * @param da [in] doubling array to check for
 * @param level [out] merge level
 *
 * @return whether to start merge or not.
 */
static int castle_da_l1_merge_trigger(struct castle_double_array *da, int nr_trees)
{
    int ret = 1;

    /* Don't start merge, if there is no disk space. */
    if (castle_da_no_disk_space(da))
        return 0;

    read_lock(&da->lock);

    if ((da->levels[1].nr_trees - da->levels[1].nr_output_trees) < nr_trees)
        ret = 0;

    read_unlock(&da->lock);

    return ret;
}

/**
 * Merge doubling array trees at level-1.
 *
 * @param da_p [in] Doubling array to do merge on.
 */
static int castle_da_l1_merge_run(void *da_p)
{
    int i, j, k, ignore, ret, nr_trees = 1, level = 1;
    struct castle_double_array *da = (struct castle_double_array *)da_p;
    struct castle_component_tree *in_trees[nr_trees];
    struct castle_da_merge *merge = NULL;
    uint32_t nr_data_exts;
    c_ext_id_t *data_exts;

    castle_printk(LOG_DEBUG, "Starting merge thread.\n");
    do {
        /* Wait for nr_trees to appear at this level.
           NOTE: we moved exit condition from */
        __wait_event_interruptible(da->merge_waitq,
                                   (ret = exit_cond) ||
                                        castle_da_l1_merge_trigger(da, nr_trees),
                                   ignore);

        /* If ret is set, exit_cond should return true as well. */
        BUG_ON(ret && !(exit_cond));

        /* Exit without doing a merge, if we are stopping execution, or da has been deleted.
           NOTE: this is the only case for which we haven't bumped up the ongoing merges counter.
         */
        if(ret)
            break;

        /* Extract the two oldest component trees. */
        ret = castle_da_l1_merge_cts_get(da, in_trees, nr_trees);
        BUG_ON(ret && (ret != -EAGAIN));
        if(ret == -EAGAIN)
            continue;

        nr_data_exts = 0;
        for (i=0; i<nr_trees; i++)
        {
            BUG_ON(!MERGE_ID_INVAL(in_trees[i]->merge_id));
            nr_data_exts += in_trees[i]->nr_data_exts;
        }

        data_exts = castle_zalloc(nr_data_exts * sizeof(c_ext_id_t));
        BUG_ON(!data_exts);

        k = 0;
        for (i = 0; i < nr_trees; i++)
        {
            /* Truncate extents so during merge we don't over-prefetch. */
            castle_printk(LOG_DEBUG, "%s: Truncating T0 seq_id=%lu extents to %d %d %d\n",
                    __FUNCTION__,
                    in_trees[i]->seq,
                    USED_CHUNK(atomic64_read(&in_trees[i]->internal_ext_free.used)),
                    USED_CHUNK(atomic64_read(&in_trees[i]->tree_ext_free.used)),
                    USED_CHUNK(atomic64_read(&in_trees[i]->data_ext_free.used)));
            castle_extent_truncate(in_trees[i]->internal_ext_free.ext_id,
                                   USED_CHUNK(atomic64_read(&in_trees[i]->internal_ext_free.used)));
            castle_extent_truncate(in_trees[i]->tree_ext_free.ext_id,
                                   USED_CHUNK(atomic64_read(&in_trees[i]->tree_ext_free.used)));
            castle_extent_truncate(in_trees[i]->data_ext_free.ext_id,
                                   USED_CHUNK(atomic64_read(&in_trees[i]->data_ext_free.used)));

            for (j = 0; j < in_trees[i]->nr_data_exts; j++)
                data_exts[k++] = in_trees[i]->data_exts[j];
        }
        BUG_ON(k != nr_data_exts);

        merge = castle_da_merge_alloc(nr_trees, level, da, INVAL_MERGE_ID, in_trees,
                                      nr_data_exts, data_exts);
        if (merge == NULL)
        {
            /* Merge failed, wait 10s to retry. */
            msleep_interruptible(10000);
            continue;
        }

        castle_trace_da_merge(TRACE_START,
                              TRACE_DA_MERGE_ID,
                              da->id,
                              level,
                              in_trees[0]->seq,
                              in_trees[0]->seq);

        /* Initialise the merge, including merged iterator and component iterators.
         * Level 1 merges have modlist component btrees that need sorting - this is
         * currently done using a malloc'd buffer.  Serialise function entry across
         * all DAs to prevent races decrementing the modlist mem budget. */
        mutex_lock(&castle_da_level1_merge_init);

        /* Run merge_init() in transaction lock, component_tree_add() needs it. */
        /* Note: Only component_tree_add needs the lock, no other operation in merge_init() require
         * transaction lock. Holding it more than required time. */
        CASTLE_TRANSACTION_BEGIN;
        ret = castle_da_merge_init(merge, NULL);
        CASTLE_TRANSACTION_END;

        mutex_unlock(&castle_da_level1_merge_init);

        /* On failure merge_init() cleansup the merge structure. */
        if(ret)
        {
            castle_printk(LOG_WARN, "Could not start a L1 merge for DA=%d.\n", da->id);
            continue;
        }

        /* Do the merge.  If it fails, retry after 10s (unless it's a merge abort). */
        /* This is L1 merge, complete in one shot. */
        ret = castle_da_merge_do(merge, 0);

        /* Merge has been aborted. */
        if (ret == -ESHUTDOWN)
        {
            /* If DA is destroyed, get-rid of merge. */
            if (castle_da_deleted(da))
                castle_da_merge_dealloc(merge, -ESTALE, 0 /* Not in transaction. */);

            break;
        }
        else if (ret)
        {
            castle_printk(LOG_WARN, "Failed to do merge with err=%d.\n", ret);

            BUG_ON(ret == EAGAIN);
            /* Merge failed, wait 10s to retry. */
            msleep_interruptible(10000);
            continue;
        }

        castle_trace_da_merge(TRACE_END, TRACE_DA_MERGE_ID, da->id, level, 0, 0);

    } while(1);

    debug_merges("Merge thread exiting.\n");

    write_lock(&da->lock);
    /* Remove ourselves from the da merge threads array to indicate that we are finished. */
    da->l1_merge_thread = NULL;
    write_unlock(&da->lock);

    /* castle_da_alloc() took a reference for us, we have to drop it now. */
    castle_da_put(da);

    return 0;
}

static int __castle_da_threads_priority_set(struct castle_double_array *da, void *_value);

static int castle_da_merge_start(struct castle_double_array *da, void *unused)
{
    /* Wake up all of the merge threads. */
    if (da->l1_merge_thread)
        castle_wake_up_task(da->l1_merge_thread, 1 /*inhibit_cs*/);

    __castle_da_threads_priority_set(da, &castle_nice_value);

    return 0;
}

static int castle_da_merge_stop(struct castle_double_array *da, void *unused)
{
    /* castle_da_exiting should have been set by now. */
    BUG_ON(!exit_cond);
    wake_up(&da->merge_waitq);

    while (da->l1_merge_thread)
        msleep(10);

    castle_printk(LOG_INIT, "Stopped merge thread for DA=%d, level=1\n", da->id);

    return 0;
}

/**
 * Enable/disable inserts on DA and wake-up merge threads and kick write queues.
 *
 * @param   da  Doubling array to throttle and merge
 */
static int castle_da_merge_restart(struct castle_double_array *da, void *unused)
{
    debug("Restarting merge for DA=%d\n", da->id);

    wake_up(&da->merge_waitq);

    return 0;
}

#if 0
static void castle_da_merges_print(struct castle_double_array *da)
{
    struct castle_merge_token *token;
    struct list_head *l;
    int level, print;
    struct timeval time;

    print = 0;
    do_gettimeofday(&time);
    read_lock(&da->lock);
    castle_printk(LOG_INFO, "\nPrinting merging stats for DA=%d, t=(%ld,%ld)\n",
            da->id, time.tv_sec, time.tv_usec/1000);
    for(level=MAX_DA_LEVEL-2; level>0; level--)
    {
        if(!print && (da->levels[level].nr_trees == 0))
            continue;
        print = 1;
        castle_printk(LOG_INFO, " level[%.2d]: nr_trees=%d, units_committed=%.3d,"
              " active_token_dl=%.2d, driver_token_dl=%.2d\n",
              level,
              da->levels[level].nr_trees,
              da->levels[level].merge.units_committed,
              da->levels[level].merge.active_token ?
                da->levels[level].merge.active_token->driver_level : 0,
              da->levels[level].merge.driver_token ?
                da->levels[level].merge.driver_token->driver_level : 0);
        list_for_each(l, &da->levels[level].merge.merge_tokens)
        {
            token = list_entry(l, struct castle_merge_token, list);
            castle_printk(LOG_INFO, "  merge_token_dl=%d\n", token->driver_level);
        }
    }
    castle_printk(LOG_INFO, "\n");
    read_unlock(&da->lock);
}
#endif

/**********************************************************************************************/
/* Generic DA code */

/**
 * Calculate hash of castle key length key_len and modulo for cpu_index.
 *
 * @return  Offset into request_cpus.cpus[]
 */
int castle_double_array_key_cpu_index(c_vl_bkey_t *key)
{
    uint32_t seed = 0;

    seed = murmur_hash_32(key, castle_object_btree_key_length(key), 0);

    return seed % castle_double_array_request_cpus();
}

/**
 * Get cpu id for specified cpu_index.
 *
 * @return  CPU id
 */
int castle_double_array_request_cpu(int cpu_index)
{
    return request_cpus.cpus[cpu_index];
}

/**
 * Get number of cpus handling requests.
 *
 * @return  Number of cpus handling requests.
 */
int castle_double_array_request_cpus(void)
{
    return request_cpus.cnt;
}

/**
 * Allocate write IO wait queues for specified DA.
 *
 * @return  EXIT_SUCCESS    Successfully allocated wait queues
 * @return  1               Failed to allocate wait queues
 *
 * @also castle_da_all_rwcts_create()
 */
static int castle_da_wait_queue_create(struct castle_double_array *da, void *unused)
{
    int i;

    da->ios_waiting = castle_alloc(castle_double_array_request_cpus()
                            * sizeof(struct castle_da_io_wait_queue));
    if (!da->ios_waiting)
        return 1;

    for (i = 0; i < castle_double_array_request_cpus(); i++)
    {
        spin_lock_init(&da->ios_waiting[i].lock);
        INIT_LIST_HEAD(&da->ios_waiting[i].list);
        CASTLE_INIT_WORK(&da->ios_waiting[i].work, castle_da_queue_kick);
        atomic_set(&da->ios_waiting[i].cnt, 0);
        da->ios_waiting[i].da = da;
    }

    return 0;
}

/* sanity check serialised state of DA merge output tree */
static void castle_da_merge_serdes_out_tree_check(struct castle_dmserlist_entry *merge_mstore,
                                                  struct castle_double_array *da,
                                                  int level)
{
    int i=0; /* btree level */

    BUG_ON(!merge_mstore);
    BUG_ON(!da);
    BUG_ON(merge_mstore->da_id          != da->id);
    BUG_ON(merge_mstore->level          != level);
    BUG_ON(merge_mstore->out_tree.level != 2);
    BUG_ON(merge_mstore->btree_type     != da->btree_type);

    debug("%s::sanity checking merge SERDES on da %d level %d.\n",
            __FUNCTION__, da->id, level);

    for(i=0; i<MAX_BTREE_DEPTH; i++)
    {
        if(!EXT_POS_INVAL(merge_mstore->levels[i].node_c2b_cep))
        {
            int node_size = 0;
            c2_block_t *node_c2b = NULL;
            struct castle_btree_node *node = NULL;

            if (i == 0) /* leaf node */
                node_size = merge_mstore->leafs_on_ssds ?
                    SSD_RO_TREE_NODE_SIZE : HDD_RO_TREE_NODE_SIZE;
            else /* internal node */
                node_size = merge_mstore->internals_on_ssds ?
                    SSD_RO_TREE_NODE_SIZE : HDD_RO_TREE_NODE_SIZE;

            node_c2b = castle_cache_block_get(merge_mstore->levels[i].node_c2b_cep,
                                              node_size,
                                              MERGE_OUT);
            BUG_ON(castle_cache_block_sync_read(node_c2b));

            node = c2b_bnode(node_c2b);
            BUG_ON(!node);
            debug("%s::recovered node at %p with magic %lx for merge on "
                    "da %d level %d from"cep_fmt_str", btree level %d.\n",
                    __FUNCTION__, node, node->magic, da->id, level,
                    cep2str(merge_mstore->levels[i].node_c2b_cep), i);
            if(node->magic != BTREE_NODE_MAGIC)
            {
                castle_printk(LOG_ERROR, "%s::failed to recover node at "cep_fmt_str
                        "; found weird magic=%lx.\n",
                        __FUNCTION__, cep2str(merge_mstore->levels[i].node_c2b_cep), node->magic);
                BUG();
            }

            put_c2b(node_c2b);
        }//fi
    }//rof
    debug("%s::sanity check passed merge SERDES on da %d level %d.\n",
            __FUNCTION__, da->id, level);
}

int castle_da_read_rate_set(c_da_t da_id, uint32_t read_rate)
{
    struct castle_double_array *da = castle_da_hash_get(da_id);

    if (!da)
    {
        castle_printk(LOG_USERINFO, "Couldn't set read rate for unknown version tree: %u\n",
                                    da_id);
        return C_ERR_INVAL_DA;
    }

    /* User passes it in MB/s, but kernel stores it in Bytes/secs. */
    da->read_rate = read_rate * 1024 * 1024;

    return 0;
}

/**
 * Check if data rate is faster than set rate. If so, then calculate the time that the
 * requests have to be throttled.
 *
 * @param   [in]    set_rate        rate set - bytes/second
 */
static inline uint64_t castle_da_throttle_time_get(uint64_t data_bytes, uint64_t time_us,
                                                   uint64_t set_rate)
{
    uint64_t nr_usecs;

    /* We shouldn't come till here, if the set_rate is 0. */
    BUG_ON(set_rate == 0);

    /* Number of micro seconds that should have been taken. */
    nr_usecs = (data_bytes / set_rate) * 1000000L;

    if (nr_usecs > time_us)
        return nr_usecs - time_us;

    return 0;
}

/**
 * Enable inserts, unconditionally. This runs in interrupt context and it doesn't hold any
 * lock. It's not safe to do any checks here.
 */
static void castle_da_inserts_enable(unsigned long data)
{
    struct castle_double_array *da = (struct castle_double_array *)data;

    /* Enable inserts. */
    clear_bit(CASTLE_DA_INSERTS_DISABLED, &da->flags);

    /* Schedule drain of pending write IOs now inserts are enabled. */
    castle_da_queues_kick(da);

    wake_up(&da->merge_waitq);
}

static int _castle_da_inserts_enable(struct castle_double_array *da, void *unused)
{
    castle_da_insert_rate_set(da->id, 500);

    return 0;
}

void castle_double_array_inserts_enable(void)
{
    __castle_da_hash_iterate(_castle_da_inserts_enable, NULL);
}

/**
 * Checks the current write rate and throttles them if the writes are going faster than
 * set rate.
 */
void castle_da_write_rate_check(struct castle_double_array *da, uint32_t nr_bytes)
{
    struct timeval cur_time;
    uint64_t delta_time, throttle_time;
    extern int castle_no_ctrl_prog_insert_rate;

    if (castle_fs_exiting)
        return;

    spin_lock(&da->rate_ctrl_lock);

    da->sample_data_bytes += nr_bytes;

    if (!castle_ctrl_prog_present())
        da->write_rate = castle_no_ctrl_prog_insert_rate * 1024L * 1024L;

    /* If this is not yet time for sampling, just return. */
    else if (da->sample_data_bytes < da->sample_rate)
        goto out;

    /* If inserts are already disabled, return from here. */
    if (test_bit(CASTLE_DA_INSERTS_DISABLED, &da->flags))
        goto out;

    /* If write rate is 0 - disable inserts. */
    if (da->write_rate == 0)
    {
        /* Don't set timer, but disable inserts. Inserts would be enabled by insert_rate_set(). */
        throttle_time = 0;
        goto throttle_ios;
    }

    /* If the number of trees in level 1 are more than 4 - disable inserts. */
    if (da->levels[1].nr_trees >= 4 * castle_double_array_request_cpus())
    {
        set_bit(CASTLE_DA_INSERTS_BLOCKED_ON_MERGE, &da->flags);
        /* Note: This could be starving ios, unnecessary long time. Fix it. */
        throttle_time = 0; /* in micro seconds. */
        goto throttle_ios;
    }

    /* Get current time. */
    do_gettimeofday(&cur_time);

    /* Time since last recorded sample in micro seconds. */
    delta_time    = (timeval_to_ns(&cur_time) - timeval_to_ns(&da->prev_time)) / 1000;

    /* Find the time to throttle writes. */
    throttle_time = castle_da_throttle_time_get(da->sample_data_bytes, delta_time, da->write_rate);

    /* Reset sample counters. */
    da->sample_data_bytes = 0;
    da->prev_time         = cur_time;

    /* If data rate is under the limit, just return. */
    if (!throttle_time)
        goto out;

throttle_ios:

    /* Disable inserts. */
    set_bit(CASTLE_DA_INSERTS_DISABLED, &da->flags);

    /* If write rate is 0, don't even set timer. */
    if (!throttle_time)
        goto out;

    /* Reschedule ourselves. */
    /* Throttle_time is in micro seconds, convert it into jiffies. */
    mod_timer(&da->write_throttle_timer,
               jiffies + (HZ * throttle_time) / (1000L * 1000L) + 1);

out:
    spin_unlock(&da->rate_ctrl_lock);
}

int castle_da_insert_rate_set(c_da_t da_id, uint32_t insert_rate)
{
    struct castle_double_array *da = castle_da_hash_get(da_id);
    int enable_inserts = 0;

    if (!da)
    {
        castle_printk(LOG_USERINFO, "Couldn't set insert rate for unknown version tree: %u\n",
                                    da_id);
        return C_ERR_INVAL_DA;
    }

    /* We don't want to change the rate, while check is going on. */
    spin_lock(&da->rate_ctrl_lock);

    if (da->write_rate == 0 && insert_rate)
        enable_inserts = 1;

    /* User passes it in MB/s, but kernel stores it in Bytes/secs. */
    da->write_rate = insert_rate * 1024L * 1024L;

    /* Note: In rare circumstances, this could be racing with castle_da_inserts_enable(),
     * due to timer expire. But, that is okay - castle_da_inserts_enable() is thread safe
     * against itself. */
    if (enable_inserts)
        castle_da_inserts_enable((unsigned long)da);

    spin_unlock(&da->rate_ctrl_lock);

    return 0;
}

/**
 * Deallocate doubling array and all associated data.
 *
 * @param da    Doubling array for deallocate
 *
 * - Merge threads
 * - IO wait queues
 */
static void castle_da_dealloc(struct castle_double_array *da)
{
    BUG_ON(!da);

    if (da->l1_merge_thread != NULL)
        kthread_stop(da->l1_merge_thread);

    /* Delete rate control timer. */
    del_timer_sync(&da->write_throttle_timer);

    castle_check_free(da->ios_waiting);

    /* Poison and free (may be repoisoned on debug kernel builds). */
    memset(da, 0xa7, sizeof(struct castle_double_array));
    castle_free(da);
}

static struct castle_double_array* castle_da_alloc(c_da_t da_id, c_da_opts_t opts)
{
    struct castle_double_array *da;
    int i = 0;

    da = castle_zalloc(sizeof(struct castle_double_array));
    if(!da)
        return NULL;

    castle_printk(LOG_INFO, "Allocating DA=%d\n", da_id);
    da->id              = da_id;
    da->root_version    = INVAL_VERSION;
    rwlock_init(&da->lock);
    da->flags           = 0;
    da->nr_trees        = 0;
    atomic_set(&da->ref_cnt, 1);
    atomic_set(&da->attachment_cnt, 0);
    atomic_set(&da->ios_waiting_cnt, 0);
    if (castle_da_wait_queue_create(da, NULL) != EXIT_SUCCESS)
        goto err_out;
    da->top_level       = 0;
    /* For existing double arrays driver merge has to be reset after loading it. */
    da->cts_proxy       = NULL;
    atomic_set(&da->lfs_victim_count, 0);

    /* Init LFS structure for Level-1 merge. */
    da->l1_merge_lfs.da  = da;
    castle_da_lfs_ct_reset(&da->l1_merge_lfs);

    init_waitqueue_head(&da->merge_waitq);

    for(i=0; i<MAX_DA_LEVEL-1; i++)
    {
        /* Initialise merge serdes */
        INIT_LIST_HEAD(&da->levels[i].trees);
        da->levels[i].nr_trees             = 0;
        da->levels[i].nr_output_trees      = 0;
    }

    /* Create merge threads, and take da ref for all levels >= 1. */
    castle_da_get(da);
    da->l1_merge_thread = kthread_create(castle_da_l1_merge_run,
                                         da, "castle-m-%d-L1", da_id);
    if(IS_ERR(da->l1_merge_thread) || !da->l1_merge_thread)
    {
        castle_printk(LOG_WARN, "Failed to allocate memory for L1 merge thread.\n");
        da->l1_merge_thread = NULL;
        goto err_out;
    }

    /* allocate top-level */
    INIT_LIST_HEAD(&da->levels[MAX_DA_LEVEL-1].trees);
    da->levels[MAX_DA_LEVEL-1].nr_trees = 0;

    /* Init rate control parameters. */
    atomic64_set(&da->write_key_bytes, 0);
    atomic64_set(&da->write_data_bytes, 0);
    atomic64_set(&da->read_key_bytes, 0);
    atomic64_set(&da->read_data_bytes, 0);
    //da->write_rate                  = 50 * 1024 * 1024;
    da->write_rate                  = UINT_MAX * 1024 * 1024;
    da->read_rate                   = 0;
    da->sample_rate                 = 1 * 1024 * 1024;
    da->sample_data_bytes           = 0;
    do_gettimeofday(&da->prev_time);
    spin_lock_init(&da->rate_ctrl_lock);

    /* Setup rate control timer. */
    setup_timer(&da->write_throttle_timer, castle_da_inserts_enable, (unsigned long)da);

    /* set up creation-time DA options */
    da->creation_opts = opts;

    /* Set default tombstone discard realtime threshold */
    atomic64_set(&da->tombstone_discard_threshold_time_s,
            CASTLE_TOMBSTONE_DISCARD_TD_DEFAULT);

    atomic64_set(&da->stats.partial_merges.partition_updates, 0);
    atomic64_set(&da->stats.partial_merges.extent_shrinks, 0);
    atomic64_set(&da->stats.tombstone_discard.tombstone_inserts, 0);
    atomic64_set(&da->stats.tombstone_discard.tombstone_discards, 0);
    atomic64_set(&da->stats.user_timestamps.t0_discards, 0);
    atomic64_set(&da->stats.user_timestamps.merge_discards, 0);
    atomic64_set(&da->stats.user_timestamps.ct_max_uts_negatives, 0);
    atomic64_set(&da->stats.user_timestamps.ct_max_uts_false_positives, 0);

    castle_printk(LOG_USERINFO, "Allocated DA=%d successfully with creation opts 0x%llx.\n",
            da_id, opts);

    return da;

err_out:
    castle_da_dealloc(da);

    return NULL;
}

void castle_da_marshall(struct castle_dlist_entry *dam,
                        struct castle_double_array *da)
{
    dam->id                = da->id;
    dam->root_version      = da->root_version;
    dam->btree_type        = da->btree_type;
    dam->creation_opts     = da->creation_opts;

    dam->tombstone_discard_threshold_time_s =
            atomic64_read(&da->tombstone_discard_threshold_time_s);
}

static void castle_da_unmarshall(struct castle_double_array *da,
                                 struct castle_dlist_entry *dam)
{
    BUILD_BUG_ON(sizeof(struct castle_dlist_entry) != 256);
    da->id                = dam->id;
    da->root_version      = dam->root_version;
    da->btree_type        = dam->btree_type;
    da->creation_opts     = dam->creation_opts;

    atomic64_set(&da->tombstone_discard_threshold_time_s,
            dam->tombstone_discard_threshold_time_s);

    castle_sysfs_da_add(da);
}

struct castle_component_tree* castle_component_tree_get(tree_seq_t seq)
{
    return castle_ct_hash_get(seq);
}

/**
 * Insert ct into da->levels[ct->level].trees list at index.
 *
 * @param   da      To insert onto
 * @param   ct      To be inserted
 * @param   head    List head to add ct after (or NULL)
 * @param   in_init Set if we are adding a just demarshalled CT from disk
 *
 * WARNING: Caller must hold da->lock
 */
static void castle_component_tree_add(struct castle_double_array *da,
                                      struct castle_component_tree *ct,
                                      struct list_head *head)
{
    struct castle_component_tree *cmp_ct;

    BUG_ON(da != ct->da);
    BUG_ON(ct->level >= MAX_DA_LEVEL);
    BUG_ON(read_can_lock(&da->lock));
    BUG_ON(!CASTLE_IN_TRANSACTION);

    /* CTs are sorted by decreasing seq number (newer trees towards the front
     * of the list) to guarantee newest values are returned during gets.
     *
     * Levels 0,1 are a special case as their seq numbers are 'prefixed' with
     * the cpu_index.  This means an older CT would appear before a newer CT if
     * it had a greater cpu_index prefixed.
     *
     * At level 0 this is valid because inserts are disjoint (they go to a
     * specific CT based on the key->cpu_index hash).
     * At level 1 this is valid because CTs from a given cpu_index are still in
     * order, and for the same reasons it is valid at level 0.
     *
     * Skip ordering checks during init (we sort the tree afterwards). */
    if (!head)
    {
        struct list_head *l;

        list_for_each(l, &da->levels[ct->level].trees)
        {
            cmp_ct = list_entry(l, struct castle_component_tree, da_list);
            if (castle_da_ct_compare(ct, cmp_ct) > 0)
                break; /* list_for_each() */
            head = l;
        }

        if (!head)  head = &da->levels[ct->level].trees;
    }

    /* CT seq should be < head->next seq (skip if head is the last elephant) */
    if (!list_is_last(head, &da->levels[ct->level].trees))
    {
        cmp_ct = list_entry(head->next, struct castle_component_tree, da_list);
        BUG_ON(castle_da_ct_compare(ct, cmp_ct) <= 0);
    }

    list_add(&ct->da_list, head);
    da->levels[ct->level].nr_trees++;
    da->nr_trees++;

    if (ct->level > da->top_level)
    {
        da->top_level = ct->level;
        castle_printk(LOG_INFO, "DA: %d growing one level to %d\n", da->id, ct->level);
    }
}

/**
 * Unlink ct from da->level[ct->level].trees list.
 */
static void castle_component_tree_del(struct castle_double_array *da,
                                      struct castle_component_tree *ct)
{
    BUG_ON(da != ct->da);
    BUG_ON(read_can_lock(&da->lock));
    BUG_ON(!CASTLE_IN_TRANSACTION);

    list_del(&ct->da_list);
    ct->da_list.next = NULL;
    ct->da_list.prev = NULL;
    da->levels[ct->level].nr_trees--;
    da->nr_trees--;
}

/**
 * Promote ct to next level.
 *
 * @param   da      Doubling array to promote ct in
 * @param   level   CT to promote
 * @param   in_init Set if we are adding a just demarshalled CT from disk
 */
static void castle_component_tree_promote(struct castle_double_array *da,
                                          struct castle_component_tree *ct)
{
    castle_component_tree_del(da, ct);
    ct->level++;

    BUG_ON(ct->level != 1);
    ct->data_age = atomic64_inc_return(&castle_next_tree_data_age);

    castle_ct_stats_commit(ct);

    castle_component_tree_add(da, ct, NULL /* append */);
}

static void castle_ct_large_obj_writeback(struct castle_large_obj_entry *lo,
                                          struct castle_component_tree *ct,
                                          struct castle_mstore *store)
{
    struct castle_lolist_entry mstore_entry;

    mstore_entry.ext_id = lo->ext_id;
    mstore_entry.length = lo->length;
    mstore_entry.ct_seq = ct->seq;

    castle_mstore_entry_insert(store,
                               &mstore_entry,
                               sizeof(struct castle_lolist_entry));
}

static void __castle_ct_large_obj_remove(struct list_head *lh)
{
    struct castle_large_obj_entry *lo = list_entry(lh, struct castle_large_obj_entry, list);

    /* Remove LO from list. */
    list_del(&lo->list);

    /* Unlink LO extent from this CT. If it from merge, the output CT could hold a link to it. */
    castle_extent_unlink(lo->ext_id);

    /* Free memory. */
    castle_free(lo);
}

/* Remove a large object from list attached to the CT. This gets called only from T0 replaces.
 * This call could be inefficient due to linear search for LO through the complete list. But,
 * this gets called for only LO replaces.
 * Also this remove blocks new LO insertions as it is holding the mutex. Instead it might be a
 * good idea to not maintain LO list for T0. (that would make T0 persistence hard) */
int castle_ct_large_obj_remove(c_ext_id_t           ext_id,
                               struct list_head    *lo_list_head,
                               struct mutex        *mutex)
{
    struct list_head *lh, *tmp;
    int ret = -1;

    /* Get mutex on LO list. */
    if (mutex) mutex_lock(mutex);

    /* Search for LO we are trying to remove in the list. */
    list_for_each_safe(lh, tmp, lo_list_head)
    {
        struct castle_large_obj_entry *lo = list_entry(lh, struct castle_large_obj_entry, list);

        if (lo->ext_id == ext_id)
        {
            /* Remove LO from list. */
            __castle_ct_large_obj_remove(lh);
            ret = 0;
            break;
        }
    }
    if (mutex) mutex_unlock(mutex);

    return ret;
}

static void castle_ct_large_objs_remove(struct list_head *lo_list_head)
{
    struct list_head *lh, *tmp;

    /* no need of lock. Called from castle_ct_put. There shouldn't be any parallel operations. */
    list_for_each_safe(lh, tmp, lo_list_head)
        __castle_ct_large_obj_remove(lh);
}

int castle_ct_large_obj_add(c_ext_id_t              ext_id,
                            uint64_t                length,
                            struct list_head       *head,
                            struct mutex           *mutex)
{
    struct castle_large_obj_entry *lo;

    if (EXT_ID_INVAL(ext_id))
        return -EINVAL;

    lo = castle_alloc(sizeof(struct castle_large_obj_entry));
    if (!lo)
        return -ENOMEM;

    lo->ext_id = ext_id;
    lo->length = length;

    if (mutex) mutex_lock(mutex);
    list_add(&lo->list, head);
    if (mutex) mutex_unlock(mutex);

    return 0;
}

void castle_data_extent_update(c_ext_id_t ext_id, uint64_t length, int op)
{
    struct castle_data_extent *data_ext = castle_data_exts_hash_get(ext_id);

    BUG_ON(data_ext == NULL);
    BUG_ON(atomic64_read(&data_ext->nr_entries) < 0);

    switch (op)
    {
        case  1:     /* Add.    */
            atomic64_add(length, &data_ext->nr_bytes);
            atomic64_inc(&data_ext->nr_entries);
            break;
        case -1:    /* Deduct.  */
            atomic64_sub(length, &data_ext->nr_bytes);
            atomic64_dec(&data_ext->nr_entries);
            break;
        case  0:     /* Drain.   */
            /* Stats could be out-of-sync in case of merge aborts. Make sure we don't overflow
             * stats. Don't worry about synchronization, draining is serialized. */
            if ((length + atomic64_read(&data_ext->nr_drain_bytes) <=
                                                    atomic64_read(&data_ext->nr_bytes)) &&
                atomic64_read(&data_ext->nr_entries))
            {
                atomic64_add(length, &data_ext->nr_drain_bytes);
                atomic64_dec(&data_ext->nr_entries);
            }
            break;
        default:
            BUG();
    }
}

struct castle_data_extent * castle_data_extent_get(c_ext_id_t ext_id)
{
    return castle_data_exts_hash_get(ext_id);
}

static void castle_data_extent_stats_commit(struct castle_component_tree *ct)
{
    int i;

    for (i=0; i<ct->nr_data_exts; i++)
    {
        struct castle_data_extent *data_ext = castle_data_exts_hash_get(ct->data_exts[i]);

        BUG_ON(data_ext == NULL);

        data_ext->chkpt_nr_bytes        = atomic64_read(&data_ext->nr_bytes);
        data_ext->chkpt_nr_drain_bytes  = atomic64_read(&data_ext->nr_drain_bytes);
        data_ext->chkpt_nr_entries      = atomic64_read(&data_ext->nr_entries);
    }
}

static void castle_ct_stats_commit(struct castle_component_tree *ct)
{
    ct->chkpt_nr_bytes              =   atomic64_read(&ct->nr_bytes);
    ct->chkpt_nr_drained_bytes      =   ct->nr_drained_bytes;

    castle_data_extent_stats_commit(ct);
}

/**
 * Create data extent object and add to the sysfs. This could be called for either during
 * creation or unmarshall.
 *
 * @param   [in]    ext_id      Data extent ID.
 * @param   [in]    nr_entries  Number of entries in this extent.
 * @param   [in]    nr_bytes    Number of bytes in this extent.
 *
 * @return  0   SUCCESS
 *         <0   ERROR CODE
 */
int castle_data_ext_add(c_ext_id_t                    ext_id,
                        uint64_t                      nr_entries,
                        uint64_t                      nr_bytes,
                        uint64_t                      nr_drain_bytes)
{
    struct castle_data_extent *data_ext =
                    castle_alloc(sizeof(struct castle_data_extent));

    if (!data_ext)
        return -ENOMEM;

    debug_dexts("Creating data extent: %llu\n", ext_id);

    /* Shouldn't be already in the hash. */
    BUG_ON(castle_data_exts_hash_get(ext_id));

    data_ext->ext_id                = ext_id;
    data_ext->chkpt_nr_entries      = nr_entries;
    data_ext->chkpt_nr_bytes        = nr_bytes;
    data_ext->chkpt_nr_drain_bytes  = nr_drain_bytes;
    atomic64_set(&data_ext->nr_entries, nr_entries);
    atomic64_set(&data_ext->nr_bytes, nr_bytes);
    atomic64_set(&data_ext->nr_drain_bytes, nr_drain_bytes);

    /* Set initial reference. */
    atomic_set(&data_ext->ref_cnt, 0);

    /* Add to sysfs and hash table. */
    castle_sysfs_data_extent_add(data_ext);
    castle_data_exts_hash_add(data_ext);

    return 0;
}

/**
 * Destroy data extent object. This function doesn't remove the extent. This cleansup hash
 * table, sysfs and memory. Could be called during data extent free or FS fini.
 */
static int castle_data_ext_remove(struct castle_data_extent *data_ext, void *unused)
{
    debug_dexts("Removing data extent: %llu of size: %lu\n", data_ext->ext_id,
                                                             atomic64_read(&data_ext->nr_bytes));

    castle_sysfs_data_extent_del(data_ext);
    castle_data_exts_hash_remove(data_ext);

    castle_free(data_ext);

    return 0;
}

static void castle_data_ext_size_get(c_ext_id_t ext_id, uint64_t *nr_bytes,
                                     uint64_t *nr_drain_bytes, uint64_t *nr_entries)
{
    struct castle_data_extent *data_ext = castle_data_exts_hash_get(ext_id);

    BUG_ON(data_ext == NULL);

    *nr_bytes           = atomic64_read(&data_ext->nr_bytes);
    *nr_drain_bytes     = atomic64_read(&data_ext->nr_drain_bytes);
    *nr_entries         = atomic64_read(&data_ext->nr_entries);
}

void castle_ct_data_ext_link(c_ext_id_t ext_id, struct castle_component_tree *ct)
{
    struct castle_data_extent *data_ext = castle_data_exts_hash_get(ext_id);

    debug_dexts("Linking data extent %llu to ct %u\n", ext_id, ct->seq);

    /* Take a reference and Sanity check. */
    BUG_ON(atomic_inc_return(&data_ext->ref_cnt) <= 0);

    BUG_ON(ct->nr_data_exts >= ct->data_exts_count);
    ct->data_exts[ct->nr_data_exts++] = ext_id;
}

static void castle_data_ext_unlink(c_ext_id_t ext_id)
{
    struct castle_data_extent *data_ext = castle_data_exts_hash_get(ext_id);

    BUG_ON(atomic_read(&data_ext->ref_cnt) == 0);

    /* Release the reference. If this is the last reference delete the extent. */
    if (atomic_dec_return(&data_ext->ref_cnt) == 0)
    {
        BUG_ON(castle_extent_unlink(ext_id));
        castle_data_ext_remove(data_ext, NULL);
    }
}

static void castle_ct_data_exts_unlink(struct castle_component_tree *ct)
{
    int i;

    for (i=0; i<ct->nr_data_exts; i++)
    {
        debug_dexts("Unlinking data extent %llu to ct %u\n", ct->data_exts[i], ct->seq);
        castle_data_ext_unlink(ct->data_exts[i]);
    }

    castle_check_free(ct->data_exts);
    ct->nr_data_exts = 0;
}

static int castle_data_ext_check_orphan(struct castle_data_extent *data_ext, void *unused)
{
    /* If the reference count is 0, get-rid of the data extent. */
    if (atomic_read(&data_ext->ref_cnt) == 0)
    {
        castle_printk(LOG_WARN, "Cleaning orphaned data extent: %llu\n", data_ext->ext_id);
        /* No need to free-up the extent, orphan extents gets freed by extent layer. And
         * also extent layer can't handle extent_free() until fs_init() is completed.
         * All the freed extents would still hang to extents hash and check_alive would
         * try to free it again. */
        castle_data_ext_remove(data_ext, NULL);
    }

    return 0;
}

static void castle_data_ext_check_orphans(void)
{
    __castle_data_exts_hash_iterate(castle_data_ext_check_orphan, NULL);
}

static int castle_merge_data_exts_writeback(struct castle_da_merge *merge,
                                            struct castle_mstore *store)
{
    int i;

    for (i=0; i<merge->nr_drain_exts; i++)
    {
        struct castle_dext_map_list_entry mentry;
        c_ext_id_t ext_id = merge->drain_exts[i];

        /* Data extent should be alive. */
        BUG_ON(castle_data_exts_hash_get(ext_id) == NULL);

        mentry.ext_id       = ext_id;
        mentry.merge_id     = merge->id;
        mentry.is_merge     = 1;

        castle_mstore_entry_insert(store, &mentry, sizeof(struct castle_dext_map_list_entry));
    }

    return 0;
}

static int castle_ct_data_exts_writeback(struct castle_component_tree *ct,
                                         struct castle_mstore *store)
{
    int i;

    for (i=0; i<ct->nr_data_exts; i++)
    {
        struct castle_dext_map_list_entry mentry;
        c_ext_id_t ext_id = ct->data_exts[i];

        /* Data extent should be alive. */
        BUG_ON(castle_data_exts_hash_get(ext_id) == NULL);

        mentry.ext_id   = ext_id;
        mentry.ct_seq   = ct->seq;
        mentry.is_merge = 0;

        castle_mstore_entry_insert(store, &mentry, sizeof(struct castle_dext_map_list_entry));

        /* Mark the extent for flush. We want flush only the data extents that are linked to
         * checkpointable trees. It is fine to mark same data extent multiple times. */
        castle_cache_extent_flush_schedule(ext_id, 0, 0);
    }

    return 0;
}

static int castle_data_exts_maps_read(void)
{
    struct castle_mstore_iter *iterator = castle_mstore_iterate(MSTORE_CT_DATA_EXTENTS);

    if (!iterator)
        return -EINVAL;

    while(castle_mstore_iterator_has_next(iterator))
    {
        struct castle_component_tree *ct;
        struct castle_da_merge *merge;
        struct castle_dext_map_list_entry mentry;
        size_t mentry_size;

        castle_mstore_iterator_next(iterator, &mentry, &mentry_size);
        BUG_ON(mentry_size != sizeof(struct castle_dext_map_list_entry));

        if (!mentry.is_merge)
        {
            ct = castle_ct_hash_get(mentry.ct_seq);

            castle_ct_data_ext_link(mentry.ext_id, ct);

            /* CT could be NULL, if just recovering from crash. Data extent could belong to
             * a T0. */
            castle_extent_mark_live(mentry.ext_id, (ct->da)? ct->da->id: INVAL_DA);
        }
        else
        {
            merge = castle_merges_hash_get(mentry.merge_id);
            merge->drain_exts[merge->nr_drain_exts++] = mentry.ext_id;
        }
    }

    castle_mstore_iterator_destroy(iterator);

    /* Linked all CTs to corresponding data extents. Free any orphan data extents. */
    castle_data_ext_check_orphans();

    return 0;
}

static int castle_data_ext_writeback(struct castle_data_extent *data_ext,
                                     void *_store)
{
    struct castle_mstore *store = _store;
    struct castle_dext_list_entry mentry;

    mentry.ext_id           = data_ext->ext_id;
    mentry.nr_entries       = data_ext->chkpt_nr_entries;
    mentry.nr_bytes         = data_ext->chkpt_nr_bytes;
    mentry.nr_drain_bytes   = data_ext->chkpt_nr_drain_bytes;

    castle_mstore_entry_insert(store, &mentry, sizeof(struct castle_dext_list_entry));

    return 0;
}

static int castle_data_exts_read(void)
{
    struct castle_mstore_iter *iterator = castle_mstore_iterate(MSTORE_DATA_EXTENTS);

    if (!iterator)
        return -EINVAL;

    while(castle_mstore_iterator_has_next(iterator))
    {
        struct castle_dext_list_entry mentry;
        size_t mentry_size;

        castle_mstore_iterator_next(iterator, &mentry, &mentry_size);
        BUG_ON(mentry_size != sizeof(struct castle_dext_list_entry));

        castle_data_ext_add(mentry.ext_id, mentry.nr_entries, mentry.nr_bytes,
                            mentry.nr_drain_bytes);

        castle_printk(LOG_INFO, "Reading data extent of %llu bytes and %llu entries\n",
                                 mentry.nr_bytes, mentry.nr_entries);
    }

    castle_mstore_iterator_destroy(iterator);

    return 0;
}

/**
 * Get a reference to the CT.
 *
 * @param   ct      Component Tree to get bump reference count on
 * @param   write   1 => Get a write reference
 *                  0 => Get a read reference
 * @param   refs    *    => Pre-allocated array of extent references.
 *                  NULL => Don't take extent references.
 *
 * NOTE: Extent references must be taken on all CTs which might be involved in
 *       partial merges, i.e. those that are the result of a merge.
 *
 * @also castle_ct_put()
 */
void castle_ct_get(struct castle_component_tree *ct, int rw, c_ct_ext_ref_t *refs)
{
    int i, nr_refs = 0;

    /* NOTE: Caller should hold castle_da_lock. */
    BUG_ON(write_can_lock(&ct->da->lock));

    /* Take read reference. */
    atomic_inc(&ct->ref_count);
    if (rw == WRITE)
        /* Take write reference. */
        atomic_inc(&ct->write_ref_count);

    if (refs == NULL)
    {
        BUG_ON(ct->level >= MIN_DA_SERDES_LEVEL); /* allow RWCTs only */

        return;
    }

    refs->nr_refs = CASTLE_CT_EXTENTS(ct);

    /* Take references on all extents associated with CT. */
    refs->refs[nr_refs++] = castle_extent_get(ct->internal_ext_free.ext_id);
    refs->refs[nr_refs++] = castle_extent_get(ct->tree_ext_free.ext_id);
    if (ct->bloom_exists)
        refs->refs[nr_refs++] = castle_extent_get(ct->bloom.ext_id);
    for (i = 0; i < ct->nr_data_exts; i++)
        refs->refs[nr_refs++] = castle_extent_get(ct->data_exts[i]);

    /* Verify we got references on all extents. */
    BUG_ON(nr_refs != refs->nr_refs);
    for (i = 0; i < nr_refs; i++)
        BUG_ON(refs->refs[i] == INVAL_MASK_ID);
}

/**
 * Drop CT and extent references.
 *
 * @param   ct      Component Tree to drop references on
 * @param   rw      READ  => Get a read reference
 *                  WRITE => Get a write reference
 * @param   refs    *     => Pointer to extent references to drop
 *                  NULL  => Don't drop extent references (not taken during get)
 *
 * @also castle_ct_get()
 */
void castle_ct_put(struct castle_component_tree *ct, int rw, c_ct_ext_ref_t *refs)
{
    int i;

    BUG_ON(in_atomic());

    if (rw == WRITE)
        /* Drop write reference. */
        atomic_dec(&ct->write_ref_count);

    /* Drop CT extent references. */
    if (refs)
        for (i = 0; i < refs->nr_refs; i++)
            castle_extent_put(refs->refs[i]);

    if(likely(!atomic_dec_and_test(&ct->ref_count)))
        return;

    BUG_ON(atomic_read(&ct->write_ref_count) != 0);

    debug("Ref count for ct id=%d went to 0, releasing.\n", ct->seq);
    /* If the ct still on the da list, this must be an error. */
    if(ct->da_list.next != NULL)
    {
        castle_printk(LOG_ERROR, "CT=%d, still on DA list, but trying to remove.\n", ct->seq);
        BUG();
    }
    /* Destroy the component tree */
    BUG_ON(TREE_GLOBAL(ct->seq) || TREE_INVAL(ct->seq));
    castle_ct_hash_remove(ct);

    debug("Releasing freespace occupied by ct=%d\n", ct->seq);
    /* Freeing all large objects. */
    castle_ct_large_objs_remove(&ct->large_objs);

    /* Unlink all the data extents from this ct. */
    castle_ct_data_exts_unlink(ct);

    /* Free the extents. */
    castle_ext_freespace_fini(&ct->internal_ext_free);
    castle_ext_freespace_fini(&ct->tree_ext_free);

    if (ct->bloom_exists)
        castle_bloom_destroy(&ct->bloom);

    /* Poison ct (note this will be repoisoned by kfree on kernel debug build. */
    memset(ct, 0xde, sizeof(struct castle_component_tree));
    castle_free(ct);
}

/**
 * Promote level 0 RWCTs without any checks, without (re-)creating new RWCTs.
 *
 * @param   da  Doubling array to promote for
 */
static int castle_da_level0_force_promote(struct castle_double_array *da, void *unused)
{
    struct castle_component_tree *ct;
    struct list_head *l, *tmp;

    write_lock(&da->lock);
    castle_printk(LOG_INFO, "Promoting RWCTs at level 0 to level 1 for DA=%d.\n", da->id);

    list_for_each_safe(l, tmp, &da->levels[0].trees)
    {
        ct = list_entry(l, struct castle_component_tree, da_list);
        castle_component_tree_promote(da, ct);
    }
    write_unlock(&da->lock);

    return 0;
}

/**
 * Promote modified level 0 RWCTs so the checkpoint thread writes them out.
 *
 * @param   work    Work structure (embedded in DA structure)
 *
 * @also castle_da_level0_modified_promote()
 */
static void __castle_da_level0_modified_promote(struct work_struct *work)
{
    struct castle_double_array *da;
    struct castle_component_tree *ct;
    int cpu_index;
    int create_failed;

    da = container_of(work, struct castle_double_array, work);

    /* Wait until *we* set the growing bit. */
    while (castle_da_growing_rw_test_and_set(da) != EXIT_SUCCESS)
        msleep_interruptible(1);

    /* Don't do promotion if we are in LFS. */
    if (castle_da_no_disk_space(da))
        goto out;
    BUG_ON(da->levels[0].nr_trees != castle_double_array_request_cpus());

    create_failed = 0;
    for (cpu_index = 0; cpu_index < castle_double_array_request_cpus(); cpu_index++)
    {
        ct = castle_da_rwct_get(da, cpu_index);

        /* Promote non-empty level 0 CTs.  Don't register an LFS callback if we
         * fail to allocate space - we'll try again in the future, perhaps when
         * more space is available.
         *
         * One at level 1 CTs will be written to disk by checkpoint. */
        if (atomic64_read(&ct->item_count) != 0)
        {
            castle_printk(LOG_INFO, "Promote for DA 0x%x level 0 RWCT seq %u (has %ld items)\n",
                    da->id, ct->seq, atomic64_read(&ct->item_count));
            create_failed = _castle_da_rwct_create(da,
                                                   cpu_index,
                                                   0 /*in_tran*/,
                                                   LFS_VCT_T_INVALID);
        }
        castle_ct_put(ct, WRITE /*rw*/, NULL);
        if (create_failed)
            goto out;
    }

out:
    castle_da_growing_rw_clear(da);

    /* Drop DA reference, adjust promoting DAs counter and signal caller. */
    atomic_dec((atomic_t *)da->private);
    castle_da_put(da);
    wake_up(&castle_da_promote_wq);
}

/**
 * Promote modified level 0 RWCTs so the checkpoint thread writes them out.
 *
 * @param   da      DA to search for modified level 0 RWCTs in
 * @param   counter To count outstanding DA promotes
 *
 * Schedule each DA promote on a workqueue as castle_da_rwct_create() might
 * sleep which is not safe while holding the da hash spinlock.
 *
 * @return  0       So hash iterator continues
 *
 * @also __castle_da_level0_modified_promote()
 * @also castle_double_arrays_writeback()
 */
static int castle_da_level0_modified_promote(struct castle_double_array *da, void *counter)
{
    atomic_inc((atomic_t *)counter);

    if (castle_da_deleted(da))
        return 0;

    /* Get DA reference and place on workqueue. */
    castle_da_get(da);
    da->private = counter;
    CASTLE_INIT_WORK(&da->work, __castle_da_level0_modified_promote);
    schedule_work(&da->work);

    return 0;
}

void castle_da_ct_marshall(struct castle_clist_entry *ctm,
                           struct castle_component_tree *ct)
{
    int i;

    ctm->da_id                = (ct->da)?ct->da->id:INVAL_DA;
    ctm->item_count           = atomic64_read(&ct->item_count);
    ctm->nr_bytes             = ct->chkpt_nr_bytes;
    ctm->nr_drained_bytes     = ct->chkpt_nr_drained_bytes;
    ctm->btree_type           = ct->btree_type;
    ctm->dynamic              = ct->dynamic;
    ctm->seq                  = ct->seq;
    ctm->data_age             = ct->data_age;
    ctm->level                = ct->level;
    ctm->tree_depth           = atomic_read(&ct->tree_depth);
    ctm->root_node            = ct->root_node;
    ctm->large_ext_chk_cnt    = atomic64_read(&ct->large_ext_chk_cnt);
    ctm->nr_data_exts         = ct->nr_data_exts;
    ctm->nr_rwcts             = ct->nr_rwcts;
    for(i=0; i<MAX_BTREE_DEPTH; i++)
        ctm->node_sizes[i] = ct->node_sizes[i];
    ctm->max_versions_per_key = ct->max_versions_per_key;

    castle_ext_freespace_marshall(&ct->internal_ext_free, &ctm->internal_ext_free_bs);
    castle_ext_freespace_marshall(&ct->tree_ext_free, &ctm->tree_ext_free_bs);
    castle_ext_freespace_marshall(&ct->data_ext_free, &ctm->data_ext_free_bs);

    ctm->bloom_exists = ct->bloom_exists;
    if (ct->bloom_exists)
        castle_bloom_marshall(&ct->bloom, ctm);

    /* if someone changed the typedef of castle_user_timestamp_t, make sure a corresponding
       change has been made in the clist_entry and the atomic in the cct struct.            */
    BUILD_BUG_ON(sizeof(castle_user_timestamp_t) != sizeof(uint64_t));
    ctm->max_user_timestamp = atomic64_read(&ct->max_user_timestamp);
    ctm->min_user_timestamp = atomic64_read(&ct->min_user_timestamp);
}

/**
 * Read an existing component tree from disk.
 *
 * - Prefetches btree extent for T0s.
 */
static struct castle_component_tree * castle_da_ct_unmarshall(struct castle_clist_entry *ctm)
{
    int i;
    struct castle_double_array *da = castle_da_hash_get(ctm->da_id);
    struct castle_component_tree *ct;

    castle_printk(LOG_DEBUG, "%s::seq %d\n", __FUNCTION__, ctm->seq);

    ct = castle_ct_init(da, ctm->nr_data_exts);
    if (!ct)
        return NULL;

    ct->seq                  = ctm->seq;
    ct->data_age             = ctm->data_age;
    atomic64_set(&ct->item_count, ctm->item_count);
    atomic64_set(&ct->nr_bytes, ctm->nr_bytes);
    ct->nr_drained_bytes     = ctm->nr_drained_bytes;
    ct->chkpt_nr_bytes       = ctm->nr_bytes;
    ct->chkpt_nr_drained_bytes = ctm->nr_drained_bytes;
    ct->btree_type           = ctm->btree_type;
    ct->dynamic              = ctm->dynamic;
    ct->da                   = da;           BUG_ON(!ct->da && !TREE_GLOBAL(ct->seq));
    ct->level                = ctm->level;
    ct->nr_rwcts             = ctm->nr_rwcts;
    atomic_set(&ct->tree_depth, ctm->tree_depth);
    ct->root_node            = ctm->root_node;
    atomic64_set(&ct->large_ext_chk_cnt, ctm->large_ext_chk_cnt);
    for(i=0; i<MAX_BTREE_DEPTH; i++)
        ct->node_sizes[i] = ctm->node_sizes[i];
    ct->max_versions_per_key = ctm->max_versions_per_key;

    castle_ext_freespace_unmarshall(&ct->internal_ext_free, &ctm->internal_ext_free_bs);
    castle_ext_freespace_unmarshall(&ct->tree_ext_free, &ctm->tree_ext_free_bs);
    castle_ext_freespace_unmarshall(&ct->data_ext_free, &ctm->data_ext_free_bs);
    castle_extent_mark_live(ct->internal_ext_free.ext_id, ctm->da_id);
    castle_extent_mark_live(ct->tree_ext_free.ext_id, ctm->da_id);
    castle_extent_mark_live(ct->data_ext_free.ext_id, ctm->da_id);
    ct->bloom_exists = ctm->bloom_exists;
    if (ctm->bloom_exists)
        castle_bloom_unmarshall(&ct->bloom, ctm);
    /* Pre-warm cache for T0 btree extents. */
    if (ct->level == 0)
    {
        /* CHUNK() will give us the offset of the last btree node (from chunk 0)
         * so bump it by 1 to get the number of chunks to prefetch. */
        uint64_t nr_bytes = atomic64_read(&ct->tree_ext_free.used);
        int chunks = (nr_bytes)? (CHUNK(nr_bytes - 1) + 1): 0;

        castle_cache_advise((c_ext_pos_t){ct->tree_ext_free.ext_id, 0},
                C2_ADV_EXTENT|C2_ADV_PREFETCH, USER, chunks);
    }

    atomic64_set(&ct->max_user_timestamp, ctm->max_user_timestamp);
    atomic64_set(&ct->min_user_timestamp, ctm->min_user_timestamp);

    castle_ct_hash_add(ct);

    return ct;
}

/**
 * Run fn() on each CT in the doubling array.
 *
 * @param da    Doubling array's CTs to enumerate
 * @param fn    Function to pass each of the da's CTs too
 */
static void __castle_da_foreach_tree(struct castle_double_array *da,
                                     int (*fn)(struct castle_double_array *da,
                                               struct castle_component_tree *ct,
                                               int level_cnt,
                                               void *private),
                                     void *private)
{
    struct castle_component_tree *ct;
    struct list_head *lh, *t;
    int i, j;

    for(i=0; i<MAX_DA_LEVEL; i++)
    {
        j = 0;
        list_for_each_safe(lh, t, &da->levels[i].trees)
        {
            ct = list_entry(lh, struct castle_component_tree, da_list);
            if(fn(da, ct, j, private))
                return;
            j++;
        }
    }
}

static USED void castle_da_foreach_tree(struct castle_double_array *da,
                                        int (*fn)(struct castle_double_array *da,
                                                  struct castle_component_tree *ct,
                                                  int level_cnt,
                                                  void *private),
                                        void *private)
{
    write_lock(&da->lock);
    __castle_da_foreach_tree(da, fn, private);
    write_unlock(&da->lock);
}

static int castle_da_ct_dealloc(struct castle_double_array *da,
                                struct castle_component_tree *ct,
                                int level_cnt,
                                void *_unused)
{
    /* We should have already gone through castle_merge_hash_destroy(), which should have
     * deleted all merges and all output trees. */
    BUG_ON(test_bit(CASTLE_CT_MERGE_OUTPUT_BIT, &ct->flags));
    BUG_ON(test_bit(CASTLE_CT_MERGE_INPUT_BIT, &ct->flags));
    BUG_ON(test_bit(CASTLE_CT_PARTIAL_TREE_BIT, &ct->flags));
    BUG_ON(ct->merge || !MERGE_ID_INVAL(ct->merge_id));

    castle_sysfs_ct_del(ct);
    list_del(&ct->da_list);

    castle_ct_dealloc(ct);

    return 0;
}

static int _castle_da_merge_dealloc(struct castle_da_merge *merge, void *unused)
{
    castle_da_merge_dealloc(merge, -ESHUTDOWN, 0/* Not in transaction. */);

    return 0;
}

static void castle_merge_hash_destroy(void)
{
    __castle_merges_hash_iterate(_castle_da_merge_dealloc, NULL);
    castle_check_free(castle_merges_hash);
    castle_check_free(castle_merge_threads_hash);
}

static int castle_da_hash_dealloc(struct castle_double_array *da, void *unused)
{
    BUG_ON(!da);
    castle_sysfs_da_del(da);

    __castle_da_foreach_tree(da, castle_da_ct_dealloc, NULL);

    list_del(&da->hash_list);

    castle_sysfs_da_del_check(da);
    castle_da_dealloc(da);

    return 0;
}

static void castle_da_hash_destroy(void)
{
    /* No need for the lock, end-of-day stuff. */
   __castle_da_hash_iterate(castle_da_hash_dealloc, NULL);
   castle_free(castle_da_hash);
}

static void castle_ct_hash_destroy(void)
{
    /* At this there shouldn't be any more CTs left in hash table. Check it by passing NULL
     * as iterator. */
    castle_ct_hash_iterate(NULL, NULL);
    castle_free(castle_ct_hash);
}

static void castle_data_exts_hash_destroy(void)
{
    __castle_data_exts_hash_iterate(castle_data_ext_remove, NULL);
    castle_free(castle_data_exts_hash);
}

struct castle_da_writeback_mstores {
    struct castle_mstore *da_store;
    struct castle_mstore *tree_store;
    struct castle_mstore *lo_store;
    struct castle_mstore *data_exts_store;
    struct castle_mstore *data_exts_maps_store;
    struct castle_mstore *dmser_store;
    struct castle_mstore *dmser_in_tree_store;
};

/**
 * Flush CT's extents to disk and marshall CT structure.
 *
 * @note any changes here will require a review of the handling of incomplete cct checkpointing
 *       which is necessary for merge checkpointing.
 * @also castle_da_writeback
 */
static int castle_da_tree_writeback(struct castle_double_array *da,
                                    struct castle_component_tree *ct,
                                    int level_cnt,
                                    void *mstores_p)
{
    struct castle_da_writeback_mstores *mstores;
    struct castle_clist_entry mstore_entry;
    struct list_head *lh, *tmp;
    int being_written;

    mstores = (struct castle_da_writeback_mstores *)mstores_p;

    /* Partial merge output tree is being checkpointed using merge serialisation. */
    /* FIXME: Move that to here. */
    if (test_bit(CASTLE_CT_MERGE_OUTPUT_BIT, &ct->flags))
        return 0;

    /* Always writeback Global tree structure but, don't writeback. */
    /* Note: Global Tree is not Crash-Consistent. */
    if (TREE_GLOBAL(ct->seq))
        goto mstore_writeback;

    /* Don't write back T0, unless the FS is exiting. */
    if ((ct->level == 0) && !castle_da_exiting)
        return 0;

    being_written = atomic_read(&ct->write_ref_count) > 0;
    /* There should be no ongoing writes when exiting. */
    BUG_ON(castle_da_exiting && being_written);
    /* Don't write back trees with outstanding writes. */
    if (being_written)
        return 0;

    /* Commit stats for T0s. There are no more writes at this stage. */
    if (ct->level <= 1)
        castle_ct_stats_commit(ct);

    /* Schedule flush of the CT onto disk. */
    if(!EXT_ID_INVAL(ct->internal_ext_free.ext_id))
        castle_cache_extent_flush_schedule(ct->internal_ext_free.ext_id, 0,
                                       atomic64_read(&ct->internal_ext_free.used));
    castle_cache_extent_flush_schedule(ct->tree_ext_free.ext_id, 0,
                                       atomic64_read(&ct->tree_ext_free.used));
    if (!EXT_ID_INVAL(ct->data_ext_free.ext_id))
        castle_cache_extent_flush_schedule(ct->data_ext_free.ext_id, 0,
                                           atomic64_read(&ct->data_ext_free.used));
    if(ct->bloom_exists)
        castle_cache_extent_flush_schedule(ct->bloom.ext_id, 0, 0);

mstore_writeback:
    /* Never writeback T0 in periodic checkpoints. */
    BUG_ON((ct->level == 0) && !castle_da_exiting);

    mutex_lock(&ct->lo_mutex);
    list_for_each_safe(lh, tmp, &ct->large_objs)
    {
        struct castle_large_obj_entry *lo =
                            list_entry(lh, struct castle_large_obj_entry, list);

        castle_ct_large_obj_writeback(lo, ct, mstores->lo_store);
    }
    mutex_unlock(&ct->lo_mutex);

    /* Writeback data extents. */
    castle_ct_data_exts_writeback(ct, mstores->data_exts_maps_store);

    castle_da_ct_marshall(&mstore_entry, ct);
    castle_mstore_entry_insert(mstores->tree_store,
                               &mstore_entry,
                               sizeof(struct castle_clist_entry));

    return 0;
}

uint32_t castle_da_count(void)
{
    return castle_da_nr_entries;
}

static void __castle_da_merge_writeback(struct castle_da_merge *merge,
                                        struct castle_da_writeback_mstores *mstores)
{
    struct castle_double_array *da = merge->da;
    unsigned int level = merge->level;
    struct castle_dmserlist_entry *merge_mstore;
    struct castle_in_tree_merge_state_entry *in_tree_merge_mstore_arr;
    struct castle_component_tree *ct;
    c_merge_serdes_state_t current_state;
    unsigned int i;

    BUG_ON(!da);
    BUG_ON(level > MAX_DA_LEVEL);
    BUG_ON((level < MIN_DA_SERDES_LEVEL));

    ct = merge->out_tree;
    BUG_ON(!ct);

    merge_mstore = merge->serdes.checkpointable.merge_state;
    BUG_ON(!merge_mstore);

    /* sanity check that there isn't a mismatch between the serdes state
       and where it's located in the da structure */
    BUG_ON(da->id != merge_mstore->da_id);
    BUG_ON(level  != merge_mstore->level);

    in_tree_merge_mstore_arr = merge->serdes.checkpointable.in_tree_state_arr;
    BUG_ON(!in_tree_merge_mstore_arr);

    /* sanity check each input tree state structure */
    for(i=0; i<merge_mstore->nr_trees; i++)
    {
        BUG_ON(da->id != in_tree_merge_mstore_arr[i].da_id);
        BUG_ON(merge_mstore->merge_id  != in_tree_merge_mstore_arr[i].merge_id);
        BUG_ON(i      != in_tree_merge_mstore_arr[i].pos_in_merge_struct);
    }

    current_state = atomic_read(&merge->serdes.checkpointable.state);

    castle_printk(LOG_INFO, "%s::[%p] checkpointing merge %u\n",
            __FUNCTION__, merge, merge->id);

    /* writeback LOs */
    {
        struct list_head *lh, *tmp;
        mutex_lock(&ct->lo_mutex);
        list_for_each_safe(lh, tmp, &ct->large_objs)
        {
            struct castle_large_obj_entry *lo =
                list_entry(lh, struct castle_large_obj_entry, list);
            int lo_ref_cnt = castle_extent_link_count_get(lo->ext_id);
            /* input ct and/or output ct will have ref */
            BUG_ON(lo_ref_cnt < 1);
            debug("%s::writeback lo at ext %d\n", __FUNCTION__,
                    lo->ext_id);
            castle_ct_large_obj_writeback(lo, ct, mstores->lo_store);
        }
        mutex_unlock(&ct->lo_mutex);
    }

    /* Writeback list of data extents not to be merged. */
    castle_merge_data_exts_writeback(merge, mstores->data_exts_maps_store);
    /* insert merge state into mstore */
    castle_mstore_entry_insert(mstores->dmser_store,
                               merge_mstore,
                               sizeof(struct castle_dmserlist_entry));
    for(i=0; i<merge_mstore->nr_trees; i++)
        castle_mstore_entry_insert(mstores->dmser_in_tree_store,
                                   &in_tree_merge_mstore_arr[i],
                                   sizeof(struct castle_in_tree_merge_state_entry));

    /* Writeback data extents. */
    castle_ct_data_exts_writeback(ct, mstores->data_exts_maps_store);

    /* flush and shrink extents if necessary */
    if(current_state == VALID_AND_FRESH_DAM_SERDES)
    {
        c_merge_serdes_state_t new_state;
        struct castle_clist_entry *cl    = &merge_mstore->out_tree;

        BUG_ON(castle_da_merge_mstore_package_cmp(&merge->serdes.checkpointable, &merge->serdes.live));

        /* == shrink extents == */
        if(merge->serdes.shrinkable_cep)
        {
            for(i=0; i < (merge_mstore->nr_trees + merge_mstore->nr_drain_exts); i++)
            {
                /* If this extent is a data extent and marked not to merge, or there is no
                   shrink needed, don't shrink it. */
                if(!EXT_POS_INVAL(merge->serdes.shrinkable_cep[i]) &&
                   (merge->serdes.shrinkable_cep[i].offset/C_CHK_SIZE) != 0)
                {
                    castle_printk(LOG_DEBUG, "%s::calling shrink on cep "cep_fmt_str_nl,
                            __FUNCTION__, cep2str(merge->serdes.shrinkable_cep[i]));
                    castle_extent_shrink(merge->serdes.shrinkable_cep[i].ext_id,
                                         merge->serdes.shrinkable_cep[i].offset/C_CHK_SIZE);
                    atomic64_inc(&merge->da->stats.partial_merges.extent_shrinks);
                }
            }
        }

        /* == we have fresh serialisation state, so flush output tree extents == */
        /* make sure extents are valid */
        BUG_ON(EXT_ID_INVAL(cl->internal_ext_free_bs.ext_id));
        BUG_ON(EXT_ID_INVAL(cl->tree_ext_free_bs.ext_id));

        /* make sure serialised extents match live extents */
        BUG_ON(ct->internal_ext_free.ext_id != cl->internal_ext_free_bs.ext_id);
        BUG_ON(ct->tree_ext_free.ext_id     != cl->tree_ext_free_bs.ext_id);
        BUG_ON(ct->data_ext_free.ext_id     != cl->data_ext_free_bs.ext_id);

        /* make sure we haven't somehow moved backwards on each extent */
        BUG_ON(atomic64_read(&ct->internal_ext_free.used) <
                cl->internal_ext_free_bs.used);
        BUG_ON(atomic64_read(&ct->tree_ext_free.used)     <
                cl->tree_ext_free_bs.used);
        BUG_ON(atomic64_read(&ct->data_ext_free.used)     <
                cl->data_ext_free_bs.used);

        castle_printk(LOG_DEBUG, "%s::flushing out_tree extents for ongoing merge on "
                "da %d, level %d:\n", __FUNCTION__, da->id, level);

        debug("%s::    internal_ext_free_bs ext_id = %lld.\n",
                __FUNCTION__, cl->internal_ext_free_bs.ext_id);
        castle_cache_extent_flush_schedule(
                cl->internal_ext_free_bs.ext_id, 0, cl->internal_ext_free_bs.used);

        debug("%s::    tree_ext_free_bs ext_id = %lld.\n",
                __FUNCTION__, cl->tree_ext_free_bs.ext_id);
        castle_cache_extent_flush_schedule(
                cl->tree_ext_free_bs.ext_id, 0, cl->tree_ext_free_bs.used);

        debug("%s::    data_ext_free_bs ext_id = %lld.\n",
                __FUNCTION__, cl->data_ext_free_bs.ext_id);
        if (!EXT_ID_INVAL(cl->data_ext_free_bs.ext_id))
            castle_cache_extent_flush_schedule(cl->data_ext_free_bs.ext_id, 0,
                                               cl->data_ext_free_bs.used);

        if(cl->bloom_exists)
        {
            BUG_ON(EXT_ID_INVAL(cl->bloom_ext_id));
            BUG_ON(ct->bloom.ext_id != cl->bloom_ext_id);
            debug("%s::    bloom ext_id = %lld.\n",
                    __FUNCTION__, cl->bloom_ext_id);
            castle_cache_extent_flush_schedule(cl->bloom_ext_id, 0, 0);
        }
        new_state = VALID_AND_STALE_DAM_SERDES;
        atomic_set(&merge->serdes.checkpointable.state, (int)new_state);
    }
}

/**
 * Checkpoint function for DAs (including merges); calls mstore_insert.
 *
 * @param da [in] doubling array
 *
 * @note called through castle_da_hash_iterate from castle_double_arrays_writeback
 */
static int castle_da_writeback(struct castle_double_array *da, void *mstores_p)
{
    struct castle_da_writeback_mstores *mstores;
    struct castle_dlist_entry mstore_dentry;

    BUG_ON(!CASTLE_IN_TRANSACTION);
    mstores = (struct castle_da_writeback_mstores *)mstores_p;

    castle_da_marshall(&mstore_dentry, da);

    /* Writeback is happening under CASTLE_TRANSACTION LOCK, which guarantees no
     * addition/deletions to component tree list, no need of DA lock here. */
    __castle_da_foreach_tree(da, castle_da_tree_writeback, mstores);

    debug("Inserting a DA id=%d\n", da->id);
    castle_mstore_entry_insert(mstores->da_store,
                               &mstore_dentry,
                               sizeof(struct castle_dlist_entry));

    return 0;
}

static int castle_da_merge_writeback(struct castle_da_merge *merge, void *mstores_p)
{
    struct castle_da_writeback_mstores *mstores;
    c_merge_serdes_state_t current_state;

    BUG_ON(!CASTLE_IN_TRANSACTION);

    /* Don't serialise merges that belong to dead DA. This is running in a transaction, same
     * as castle_double_array_destroy(), protected against races. */
    if (castle_da_deleted(merge->da))
        return 0;

    mstores = (struct castle_da_writeback_mstores *)mstores_p;

    current_state = atomic_read(&merge->serdes.checkpointable.state);
    if( (current_state == VALID_AND_FRESH_DAM_SERDES) ||
            (current_state == VALID_AND_STALE_DAM_SERDES) )
        __castle_da_merge_writeback(merge, mstores);

    return 0;
}

/**
 * Write double array structures to mstores.
 *
 * NOTE: Called within CASTLE_TRANSACTION.
 *
 * @also castle_double_arrays_pre_writeback()
 */
void castle_double_arrays_writeback(void)
{
    struct castle_da_writeback_mstores mstores;

    memset(&mstores, 0, sizeof(struct castle_da_writeback_mstores));
    mstores.da_store             = castle_mstore_init(MSTORE_DOUBLE_ARRAYS);
    mstores.tree_store           = castle_mstore_init(MSTORE_COMPONENT_TREES);
    mstores.lo_store             = castle_mstore_init(MSTORE_LARGE_OBJECTS);
    mstores.data_exts_store      = castle_mstore_init(MSTORE_DATA_EXTENTS);
    mstores.data_exts_maps_store = castle_mstore_init(MSTORE_CT_DATA_EXTENTS);
    mstores.dmser_store          = castle_mstore_init(MSTORE_DA_MERGE);
    mstores.dmser_in_tree_store  = castle_mstore_init(MSTORE_DA_MERGE_IN_TREE);

    if(!mstores.da_store ||
       !mstores.tree_store ||
       !mstores.lo_store ||
       !mstores.data_exts_store ||
       !mstores.data_exts_maps_store ||
       !mstores.dmser_store ||
       !mstores.dmser_in_tree_store)
    {
        castle_printk(LOG_USERINFO,
                      "FS Checkpoint failed: mstore open failed in %s\n",
                      __FUNCTION__);
        goto out;
    }

    __castle_da_hash_iterate(castle_da_writeback, &mstores);

    /* Writeback all the merges. */
    __castle_merges_hash_iterate(castle_da_merge_writeback, &mstores);

    castle_da_tree_writeback(NULL, castle_global_tree, -1, &mstores);

    /* Writeback all data extent structures. */
    __castle_data_exts_hash_iterate(castle_data_ext_writeback, mstores.data_exts_store);

out:
    if (mstores.dmser_in_tree_store)  castle_mstore_fini(mstores.dmser_in_tree_store);
    if (mstores.dmser_store)          castle_mstore_fini(mstores.dmser_store);
    if (mstores.lo_store)             castle_mstore_fini(mstores.lo_store);
    if (mstores.data_exts_store)      castle_mstore_fini(mstores.data_exts_store);
    if (mstores.data_exts_maps_store) castle_mstore_fini(mstores.data_exts_maps_store);
    if (mstores.tree_store)           castle_mstore_fini(mstores.tree_store);
    if (mstores.da_store)             castle_mstore_fini(mstores.da_store);
}

/**
 * Perform any work prior to castle_double_arrays_writeback() outside of transaction lock.
 *
 * NOTE: Called outside of CASTLE_TRANSACTION.
 *
 * @also castle_double_arrays_writeback()
 */
void castle_double_arrays_pre_writeback(void)
{
    static int rwct_checkpoints = 0;
    atomic_t in_flight = ATOMIC(0);

    if (!castle_da_exiting && ++rwct_checkpoints >= castle_rwct_checkpoint_frequency)
    {
        /* Promote non-empty CTs in all DAs. */
        castle_da_hash_iterate(castle_da_level0_modified_promote, &in_flight);
        /* Wait for all promotes to complete. */
        wait_event(castle_da_promote_wq, atomic_read(&in_flight) == 0);

        rwct_checkpoints = 0;
    }
}

/**
 * Create one RWCT per strand for specified DA if they do not already exist.
 *
 * - Allocate one CT per CPU handling requests
 *
 * When any of these CTs subsequently get exhausted a new CT is allocated and
 * the old CT promoted in an atomic fashion (da->lock held).  This means we are
 * guaranteed to have none or all of the CTs at level 0.
 *
 * @param   da          Doubling array to create T0 CTs for
 * @param   in_tran     Whether CASTLE_TRANSACTION_LOCK is held
 * @param   lfs_check   Whether to perform LFS checks before attempting allocations
 * @param   lfs_type    Type of LFS allocation (determines LFS CB)
 *
 * @also castle_double_array_start()
 * @also castle_da_rwct_create()
 * @also castle_da_lfs_all_rwcts_callback()
 */
static int castle_da_all_rwcts_create(struct castle_double_array *da,
                                      int in_tran,
                                      c_lfs_vct_type_t lfs_type)
{
    struct list_head *l, *p;
    LIST_HEAD(list);
    int cpu_index, had_to_wait = 0;

    /* Wait until *we* set the growing bit. */
    while (castle_da_growing_rw_test_and_set(da) != EXIT_SUCCESS)
    {
        had_to_wait = 1;
        /* Cannot sleep in interruptible, because this function is called from an IOCTL,
           and therefore in a user process context. This could be interrupted, and go into
           busy loop. This would cause a softlockup. */
        msleep(1);
    }

    /* We can return immediately if:
     * - the RWCTs already exist (yay!)
     * - we had to wait to get the growing lock (another thread just tried to
     *   create the RWCTs and failed; most likely we will also fail) */
    read_lock(&da->lock);
    if (!list_empty(&da->levels[0].trees))
    {
        BUG_ON(da->levels[0].nr_trees != castle_double_array_request_cpus());
        read_unlock(&da->lock);
        goto out;
    }
    else if (had_to_wait)
    {
        read_unlock(&da->lock);
        goto err_out;
    }
    else
        BUG_ON(da->levels[0].nr_trees != 0);
    read_unlock(&da->lock);

    /* Note: We don't have any Low Freespace check here. Always, try to create T0s, irrespective
     * of the Low Freespace state. */

    /* No RWCTs at level 0 in this DA.  Create on per request-handling CPU. */
    for (cpu_index = 0; cpu_index < castle_double_array_request_cpus(); cpu_index++)
    {
        if (_castle_da_rwct_create(da,
                                   cpu_index,
                                   in_tran,
                                   lfs_type) != EXIT_SUCCESS)
        {
            castle_printk(LOG_WARN, "Failed to create T0 %d for DA %u\n", cpu_index, da->id);
            goto err_out;
        }
    }

    /* Clear the growing bit and return success. */
    castle_printk(LOG_INFO, "Created %d CTs for DA %u T0\n", cpu_index, da->id);
out:
    castle_da_growing_rw_clear(da);
    return 0;

err_out:
    /* We were unable to allocate all of the T0s we need.  Free the ones we did
     * manage to allocate.  Splice them into a private list first. */
    write_lock(&da->lock);
    list_splice_init(&da->levels[0].trees, &list);
    da->levels[0].nr_trees = 0;
    write_unlock(&da->lock);

    list_for_each_safe(l, p, &list)
    {
        struct castle_component_tree *ct;
        list_del(l);
        l->next = NULL; /* for castle_ct_put() */
        l->prev = NULL; /* for castle_ct_put() */
        ct = list_entry(l, struct castle_component_tree, da_list);
        castle_ct_put(ct, READ /*rw*/, NULL);
    }

    /* Clear the growing bit and return failure. */
    castle_da_growing_rw_clear(da);
    return -ENOSPC;
}

/**
 * Wrapper for castle_da_all_rwcts_create() to be called from castle_double_array_start().
 *
 * - Ignores errors
 * - Always returns 0 (to force iterator to continue)
 */
static int castle_da_rwct_init(struct castle_double_array *da, void *unused)
{
    castle_da_all_rwcts_create(da,
                               1 /*in_tran*/,
                               LFS_VCT_T_T0_GRP);

    return 0;
}

/**
 * Start existing doubling arrays.
 *
 * - Called during module initialisation only
 *
 * @also castle_fs_init()
 * @also castle_double_array_read()
 */
int castle_double_array_start(void)
{
    /* Create T0 RWCTs for all DAs that don't have them (acquires lock).
     * castle_da_rwct_init() wraps castle_da_rwcts_create() for hash_iter. */
    __castle_da_hash_iterate(castle_da_rwct_init, NULL);

    /* Check all DAs to see whether any merges need to be done. */
    castle_da_hash_iterate(castle_da_merge_start, NULL);
    castle_da_hash_iterate(castle_da_merge_restart, NULL);

    return 0;
}

static int castle_da_ct_bloom_build_param_deserialise(struct castle_component_tree *ct,
                                                      struct castle_bbp_entry *bbpm)
{
    /* memory allocation and some sanity checking: */
    if(!ct->bloom_exists)
    {
        castle_printk(LOG_ERROR, "%s::no bloom filter attached to CT %d, "
                "yet we have build_params. Weird.\n", __FUNCTION__, ct->seq);
        BUG(); /* relax this if we might ever end up in this situation */
        return -ENXIO;
    }

    BUG_ON(ct->bloom.btree->magic != ct->btree_type);
    ct->bloom.private = castle_zalloc(sizeof(struct castle_bloom_build_params));
    if(!ct->bloom.private)
    {
        castle_printk(LOG_ERROR, "%s::failed to deserialise bloom build parameters for CT %d; "
                "discarding bloom filter on this CT.", __FUNCTION__, ct->seq);
        castle_bloom_abort(&ct->bloom);
        castle_bloom_destroy(&ct->bloom);
        ct->bloom_exists=0;
        BUG(); /* Out of memory at init time? relax this if it's a possible valid situation */
        return -ENOMEM;
    }

    /* actual deserialisation work happens here: */
    castle_bloom_build_param_unmarshall(&ct->bloom, bbpm);
    return 0;
}

static int _castle_sysfs_ct_add(struct castle_component_tree *ct, void *_unused)
{
    /* No need to add global tree to sysfs. */
    if (TREE_GLOBAL(ct->seq))
        return 0;

    /* Don't add output trees to sysfs yet. */
    if (test_bit(CASTLE_CT_MERGE_OUTPUT_BIT, &ct->flags))
        return 0;

    /* Don't add T0s to sysfs. This is definitely not possible when DA is being created. As, the
     * parent doesn't exist yet. */
    if (ct->level < 2)
        return 0;

    if (castle_sysfs_ct_add(ct))
    {
        castle_printk(LOG_USERINFO, "Failed to add CT: 0x%x to sysfs\n", ct->seq);
        return -1;
    }

    return 0;
}

/**
 * First phase of merge deserialisation. Recover output tree and merge serdes state into a newly
 * created merge struct. Specific actions are (in sequence):
 *
 * 1) merge = merge_alloc()
 * 2) copy mstore entry so the merge is immediately re-checkpointable
 * 3) unmarshall output tree into merge->out_tree
 * 4) recover redirection partition key (if one exists)
 *
 */
static int castle_da_merge_deser_mstore_outtree_recover(void)
{
    struct castle_mstore_iter *iterator = NULL;
    int ret = 0;

    iterator = castle_mstore_iterate(MSTORE_DA_MERGE);
    if (!iterator)
    {
        ret = -ENOSYS;
        goto out;
    }

    while (castle_mstore_iterator_has_next(iterator))
    {
        int da_id;
        int level;
        struct castle_double_array *des_da = NULL;
        struct castle_dmserlist_entry *entry = NULL;
        struct castle_da_merge *merge = NULL;
        c_ext_id_t *drain_exts = NULL;
        size_t entry_size;

        /* alloc temp storage for mstore entry; will be used until we have a struct alloc'd by
           castle_da_merge_alloc(). */
        entry = castle_zalloc(sizeof(struct castle_dmserlist_entry));
        if(!entry)
        {
            castle_printk(LOG_ERROR, "%s:: castle_alloc fail\n", __FUNCTION__);
            BUG();
        }

        castle_mstore_iterator_next(iterator, entry, &entry_size);
        BUG_ON(entry_size != sizeof(struct castle_dmserlist_entry));
        da_id = entry->da_id;
        level = entry->level;
        BUG_ON((level < MIN_DA_SERDES_LEVEL));

        des_da = castle_da_hash_get(da_id);
        if(!des_da)
        {
            castle_printk(LOG_ERROR, "%s::could not find da %d\n", __FUNCTION__, da_id);
            ret = -ENOENT;
            goto out;
        }

        if (entry->merge_id > atomic_read(&castle_da_max_merge_id))
            atomic_set(&castle_da_max_merge_id, entry->merge_id);

        if (entry->nr_drain_exts > 0)
        {
            drain_exts = castle_zalloc(sizeof(c_ext_id_t) * entry->nr_drain_exts);
            BUG_ON(!drain_exts);
        }

        merge = castle_da_merge_alloc(entry->nr_trees, level, des_da,
                                      entry->merge_id, NULL,
                                      entry->nr_drain_exts, drain_exts);
        /* if we failed to malloc at init, something must be horribly wrong */
        BUG_ON(!merge);
        castle_printk(LOG_DEBUG, "%s::made merge structure at %p.\n", __FUNCTION__, merge);

        /* Change the count to 0 for now, while serialising data_ext maps we add them. */
        merge->nr_drain_exts = 0;

        /* Check and update reservation pool_id. */
        merge->pool_id = entry->pool_id;
        BUG_ON(!castle_res_pool_is_alive(merge->pool_id));

        /* Copy mstore entry into merge struct so the merge is immediately re-checkpointable */
        memcpy(merge->serdes.live.merge_state, entry, sizeof(struct castle_dmserlist_entry));
        castle_free(entry);
        entry = NULL;
        /* set merge state as immediately re-checkpointable */
        /* Why _FRESH instead of _STALE? Surely there's nothing to flush now???...
           Because in practice, the live serdes state is never actually 'stale', only checkpointable
           state may be 'stale'. Therefore, to simplify the assertion logic let's just mark this as
           fresh - nothing will be flushed anyway because no pages are dirty. */
        atomic_set(&merge->serdes.live.state, VALID_AND_FRESH_DAM_SERDES);
        /* Don't forget to deep copy the live state to checkpointable state! But we can't do that
           now because the input trees array is not ready yet. */

        /* Recover partially complete output CT */
        merge->out_tree = castle_da_ct_unmarshall(&merge->serdes.live.merge_state->out_tree);
        BUG_ON(!merge->out_tree);
        BUG_ON(da_id != merge->out_tree->da->id);
        castle_printk(LOG_DEBUG, "%s::deserialising merge on da %d level %d with partially-"
                                 "complete ct, seq %d\n",
                                 __FUNCTION__, da_id, level, merge->out_tree->seq);
        set_bit(CASTLE_CT_MERGE_OUTPUT_BIT, &merge->out_tree->flags);
        /* the difference between unmarshalling a partially complete in-merge ct and a "normal" ct is
           unlike a normal ct, a partially complete in-merge ct does not get added to a DA through
           cct_add(da, ct, NULL, 1). */

        /* bloom_build_param recovery is left to merge_init() (see castle_da_merge_struct_deser()) */

        /* sanity check merge output tree state */
        castle_da_merge_serdes_out_tree_check(merge->serdes.live.merge_state, des_da, level);

        /* inc ct seq number if necessary */
        if (merge->out_tree->seq >= atomic64_read(&castle_next_tree_seq))
            atomic64_set(&castle_next_tree_seq, merge->out_tree->seq+1);

        /* enable query redirection if necessary */
        if(!EXT_POS_INVAL(merge->serdes.live.merge_state->redirection_partition_node_cep))
        {
            int node_size = -1;
            struct castle_btree_node *node;
            struct castle_btree_type *out_btree =
                castle_btree_type_get(merge->serdes.live.merge_state->out_tree.btree_type);

            /* output tree pointer */
            set_bit(CASTLE_CT_PARTIAL_TREE_BIT, &merge->out_tree->flags);

            /* recover c2b containing partition key */
            node_size = merge->serdes.live.merge_state->redirection_partition_node_size;
            if(node_size == 0 || node_size > 256)
            {
                castle_printk(LOG_ERROR, "%s::redir_partition_node_cep="cep_fmt_str", node size=%u\n",
                    __FUNCTION__,
                    cep2str(merge->serdes.live.merge_state->redirection_partition_node_cep),
                    node_size);
                BUG();
            }
            merge->redirection_partition.node_c2b =
                castle_cache_block_get(
                    merge->serdes.live.merge_state->redirection_partition_node_cep,
                    node_size,
                    MERGE_OUT);
            merge->redirection_partition.node_size = node_size;
            BUG_ON(castle_cache_block_sync_read(merge->redirection_partition.node_c2b));

            /* recover partition key */
            node = c2b_bnode(merge->redirection_partition.node_c2b);
            BUG_ON(!node);
            BUG_ON(node->magic != BTREE_NODE_MAGIC);
            BUG_ON(!node->used); /* must have been a completed node! */
            out_btree->entry_get(node, node->used - 1,
                    &merge->redirection_partition.key, NULL, NULL);
        }
        /* notify rest of merge deserialisation process that this is a deserialising merge */
        merge->serdes.des = 1;
    }

    BUG_ON(ret);
out:
    if (ret)
        castle_printk(LOG_ERROR, "%s::failed with err %u.\n", __FUNCTION__, ret);

    if (iterator)
        castle_mstore_iterator_destroy(iterator);

    return ret;
}

/**
 * Reattach input trees to their corresponding merge structure
 */
static int castle_da_merge_deser_intrees_attach(void)
{
    struct castle_mstore_iter *iterator;
    int ret = 0;

    iterator = castle_mstore_iterate(MSTORE_DA_MERGE_IN_TREE);
    if (!iterator)
    {
        ret = -ENOSYS;
        goto out;
    }

    while (castle_mstore_iterator_has_next(iterator))
    {
        int da_id;
        int level;
        int pos;
        int seq;
        struct castle_double_array *da;
        struct castle_in_tree_merge_state_entry *entry;
        size_t entry_size;
        struct castle_component_tree *ct;
        struct castle_da_merge *merge = NULL;

        entry = castle_zalloc(sizeof(struct castle_in_tree_merge_state_entry));
        if(!entry)
        {
            castle_printk(LOG_ERROR, "%s:: castle_alloc fail\n", __FUNCTION__);
            BUG();
        }

        castle_mstore_iterator_next(iterator, entry, &entry_size);
        BUG_ON(entry_size != sizeof(struct castle_in_tree_merge_state_entry));

        da_id = entry->da_id;
        merge = castle_merges_hash_get(entry->merge_id);
        pos   = entry->pos_in_merge_struct;
        seq   = entry->seq;
        BUG_ON(TREE_GLOBAL(seq));
        BUG_ON(TREE_INVAL(seq));
        BUG_ON(!merge);
        level = merge->level;

        BUG_ON(da_id==0);
        BUG_ON((level < MIN_DA_SERDES_LEVEL));
        BUG_ON(level > MAX_DA_LEVEL);

        da = castle_da_hash_get(da_id);
        BUG_ON(!da);

        /* there must already be a corresponding mstore_entry */
        BUG_ON(!merge->serdes.live.merge_state);
        /* the array should already have been allocated */
        BUG_ON(!merge->serdes.live.in_tree_state_arr);
        /* if BUG on following, then there may be a mismatch between the merge state and input
           tree merge state, with the former expecting fewer trees and therefore Stage 1 having
           not allocated enough space. */
        BUG_ON(pos > merge->serdes.live.merge_state->nr_trees);
        /* if BUG on the following, then we are trying to insert more than one in_tree_merge_state entry
           into the same slot. */
        BUG_ON(merge->serdes.live.in_tree_state_arr[pos].da_id != 0);

        ct = castle_ct_hash_get(entry->seq);
        BUG_ON(!ct);
        BUG_ON(ct->da->id    != da_id);
        castle_printk(LOG_DEBUG, "%s::ct level = %d, level = %d\n", __FUNCTION__, ct->level, level);
        BUG_ON(ct->level != level);

        /* Set component tree in the merge in_trees array. */
        merge->in_trees[pos] = ct;
        memcpy(&merge->serdes.live.in_tree_state_arr[pos],
                entry, sizeof(struct castle_in_tree_merge_state_entry));
        castle_check_free(entry);

        castle_printk(LOG_DEBUG, "%s::recovered input tree (seq=%d) merge state for da %d merge_id %u pos %d.\n",
                __FUNCTION__,
                merge->serdes.live.in_tree_state_arr[pos].seq,
                merge->serdes.live.in_tree_state_arr[pos].da_id,
                merge->serdes.live.in_tree_state_arr[pos].merge_id,
                merge->serdes.live.in_tree_state_arr[pos].pos_in_merge_struct);
    }

    BUG_ON(ret);
out:
    if (ret)
        castle_printk(LOG_ERROR, "%s::failed with err %u.\n", __FUNCTION__, ret);

    if (iterator)
        castle_mstore_iterator_destroy(iterator);

    return ret;
}

static int castle_da_ct_read(void)
{
    struct castle_mstore_iter *iterator = NULL;
    int ret = 0;

    iterator = castle_mstore_iterate(MSTORE_COMPONENT_TREES);
    if (!iterator)
    {
        ret = -1;
        goto out;
    }

    while(castle_mstore_iterator_has_next(iterator))
    {
        uint64_t ct_seq;
        struct castle_component_tree *ct;
        struct castle_double_array *da;
        struct castle_clist_entry entry;
        size_t entry_size;

        castle_mstore_iterator_next(iterator, &entry, &entry_size);
        BUG_ON(entry_size != sizeof(struct castle_clist_entry));
        /* Special case for castle_global_tree, it doesn't have a da associated with it. */
        ct = castle_da_ct_unmarshall(&entry);
        da = ct->da;
        if(TREE_GLOBAL(ct->seq))
        {
            BUG_ON(ct->da != NULL);
            castle_global_tree = ct;
            continue;
        }
        BUG_ON(!da);

        debug("Read CT seq=%d\n", ct->seq);
        write_lock(&da->lock);
        castle_component_tree_add(da, ct, NULL /*head*/);
        write_unlock(&da->lock);

        /* Calculate maximum CT sequence number. Be wary of T0 sequence numbers, they prefix
         * CPU indexes. */
        ct_seq = ct->seq & ((1ULL << TREE_SEQ_SHIFT) - 1);
        if (ct_seq >= atomic64_read(&castle_next_tree_seq))
            atomic64_set(&castle_next_tree_seq, ct_seq+1);

        /* Calculate current data age. */
        if (ct->data_age >= atomic64_read(&castle_next_tree_data_age))
            atomic64_set(&castle_next_tree_data_age, ct->data_age+1);
    }

    BUG_ON(ret);
out:
    if (iterator)
        castle_mstore_iterator_destroy(iterator);

    return ret;
}

/**
 * Read doubling arrays and serialised component trees in from disk.
 *
 * - Called during module initialisation only
 *
 * @also castle_fs_init()
 */
int castle_double_array_read(void)
{
    struct castle_dlist_entry mstore_dentry;
    struct castle_lolist_entry mstore_loentry;
    struct castle_mstore_iter *iterator = NULL;
    struct castle_double_array *da;
    size_t mstore_dentry_size, mstore_loentry_size;
    int ret = 0;
    debug("%s::start.\n", __FUNCTION__);

    BUG_ON(!CASTLE_IN_TRANSACTION);

    /* Read doubling arrays */
    iterator = castle_mstore_iterate(MSTORE_DOUBLE_ARRAYS);
    if(!iterator)
        goto error_out;

    while(castle_mstore_iterator_has_next(iterator))
    {
        castle_mstore_iterator_next(iterator, &mstore_dentry, &mstore_dentry_size);
        BUG_ON(mstore_dentry_size != sizeof(struct castle_dlist_entry));
        da = castle_da_alloc(mstore_dentry.id, mstore_dentry.creation_opts);
        if(!da)
            goto error_out;
        castle_da_unmarshall(da, &mstore_dentry);
        castle_da_hash_add(da);
        debug("Read DA id=%d\n", da->id);
        castle_next_da_id = (da->id >= castle_next_da_id) ? da->id + 1 : castle_next_da_id;
    }
    castle_mstore_iterator_destroy(iterator);

    /***********************************************************************************************
    Merge deserialisation is a multistage process. To grok it, plot the following with dot:

    digraph{
        castle_da_merge_deser_mstore_outtree_recover -> castle_da_merge_deser_intrees_attach [label="alloc'd merge structure"]
        castle_da_merge_deser_mstore_outtree_recover -> castle_da_merge_init
        castle_da_ct_read -> castle_da_merge_deser_intrees_attach
        castle_data_exts_read -> castle_data_exts_maps_read
        castle_da_merge_deser_intrees_attach -> castle_da_merge_init
        castle_data_exts_maps_read -> castle_da_merge_init [label="growth_control recovery does extent_mask_read"]
        castle_mstore_iterate_MSTORE_LARGE_OBJECTS_ -> castle_da_merge_init [label="extent linking"]
    }

    The above illustrates the dependencies between the various stages required for merge
    deserialisation. Where the rationale for specific dependencies is not immediately obvious,
    the arc corresponding to the dependency is labeled with a brief explanation.

    Disclaimer: While these dependencies are necessary, the illustration may not be complete;
    there may exist other stages that are not illustrated here, and there may be dependencies
    that are not illustrated here.
    ***********************************************************************************************/
    /* Stage 1 merge DES */
    BUG_ON(castle_da_merge_deser_mstore_outtree_recover());

    /* Read component trees, but not output trees. They are read by merge deser. */
    castle_da_ct_read();

    BUG_ON(castle_da_merge_deser_intrees_attach());

    /* intree and outtree data should now be ready in the live serdes package, so the package
       may be made checkpointable. */
    __castle_merges_hash_iterate(castle_da_merge_serdes_live_to_chkpnt_cp, NULL);

    /* Read all data extents. Also, output tree data extents. */
    castle_data_exts_read();

    /* Read data extent to CT mappings. Expects data extents and CTs in hash table. */
    castle_data_exts_maps_read();

    debug("castle_next_da_id = %d, castle_next_tree_id=%lld\n",
            castle_next_da_id,
            atomic64_read(&castle_next_tree_seq));

    /* Read all Large Objects lists. */
    iterator = castle_mstore_iterate(MSTORE_LARGE_OBJECTS);
    if(!iterator)
        goto error_out;

    while(castle_mstore_iterator_has_next(iterator))
    {
        struct castle_component_tree *ct;


        castle_mstore_iterator_next(iterator, &mstore_loentry, &mstore_loentry_size);
        BUG_ON(mstore_loentry_size != sizeof(struct castle_lolist_entry));
        ct = castle_component_tree_get(mstore_loentry.ct_seq);
        if (!ct)
        {
            castle_printk(LOG_ERROR, "Found zombie Large Object(%llu, %u)\n",
                    mstore_loentry.ext_id, mstore_loentry.ct_seq);
            BUG();
        }
        if (castle_ct_large_obj_add(mstore_loentry.ext_id,
                                    mstore_loentry.length,
                                    &ct->large_objs, NULL))
        {
            castle_printk(LOG_WARN, "Failed to add Large Object %llu to CT: %u\n",
                    mstore_loentry.ext_id,
                    mstore_loentry.ct_seq);
            goto error_out;
        }
        castle_extent_mark_live(mstore_loentry.ext_id, ct->da->id);
        debug("%s::Acquired Large Object %llu on CT: %u.\n",
                    __FUNCTION__, mstore_loentry.ext_id, mstore_loentry.ct_seq);
    }
    castle_mstore_iterator_destroy(iterator);
    iterator = NULL;

    /* Finalize merge deserialization. */
    __castle_merges_hash_iterate(castle_da_merge_init, NULL);

    /* Add CTs to sysfs. */
    __castle_ct_hash_iterate(_castle_sysfs_ct_add, NULL);

    /* Promote level 0 RWCTs. This guarantees crash consistency of RWCTs (if an RWCT is
       updated in place, and then FS crashes, it'd become corrupt). This also deals with
       # of CPUs changing between FS runs (# of RWCTs must equal # of CPUs). */
    castle_da_hash_iterate(castle_da_level0_force_promote, NULL);

    goto out;

error_out:
    /* The doubling arrays we've created so far should be destroyed by the module fini code. */
    ret = -EINVAL;
out:
    if (iterator)
        castle_mstore_iterator_destroy(iterator);

    debug("%s::end.\n", __FUNCTION__);
    return ret;
}

tree_seq_t castle_da_next_ct_seq(void)
{
    return atomic64_inc_return(&castle_next_tree_seq);
}

static struct castle_component_tree * castle_ct_init(struct castle_double_array *da,
                                                     uint32_t nr_data_exts)
{
    int i;
    struct castle_component_tree *ct;

    ct = castle_zalloc(sizeof(struct castle_component_tree));

    if (!ct)
        return NULL;

    ct->seq                      = INVAL_TREE;
    ct->data_age                 = 0;
    ct->flags                    = 0;
    ct->nr_drained_bytes         = 0;
    ct->chkpt_nr_bytes           = 0;
    ct->chkpt_nr_drained_bytes   = 0;
    ct->btree_type               = da? da->btree_type: MTREE_TYPE;
    ct->dynamic                  = 0;
    ct->da                       = da;
    ct->level                    = -1;
    ct->root_node                = INVAL_EXT_POS;
    ct->internal_ext_free.ext_id = INVAL_EXT_ID;
    ct->tree_ext_free.ext_id     = INVAL_EXT_ID;
    ct->data_ext_free.ext_id     = INVAL_EXT_ID;
    ct->data_exts                = castle_zalloc(sizeof(c_ext_id_t) * nr_data_exts);
    ct->data_exts_count          = nr_data_exts;
    ct->nr_data_exts             = 0;
    ct->bloom_exists             = 0;
    ct->merge                    = NULL;
    ct->merge_id                 = INVAL_MERGE_ID;
    ct->max_versions_per_key     = 0;

    atomic_set(&ct->tree_depth, -1);

    if (!ct->data_exts)
        goto err_out;

    atomic_set(&ct->ref_count, 1);
    atomic_set(&ct->write_ref_count, 0);
    atomic64_set(&ct->item_count, 0);
    atomic64_set(&ct->nr_bytes, 0);

    for (i = 0; i < MAX_BTREE_DEPTH; ++i)
        ct->node_sizes[i] = castle_btree_node_size_get(ct->btree_type);

    init_rwsem(&ct->lock);

    ct->da_list.next = NULL;
    ct->da_list.prev = NULL;
    INIT_LIST_HEAD(&ct->hash_list);
    INIT_LIST_HEAD(&ct->large_objs);

    atomic64_set(&ct->large_ext_chk_cnt, 0);
    mutex_init(&ct->lo_mutex);

    atomic64_set(&ct->max_user_timestamp, 0);
    atomic64_set(&ct->min_user_timestamp, ULLONG_MAX);

    /* Poison kobject, so we don't try to free the kobject that is not yet initialised. */
    kobject_poison(&ct->kobj);

    return ct;

err_out:
    castle_check_free(ct->data_exts);
    castle_check_free(ct);

    return NULL;
}

/**
 * Allocate and initialise a CT.
 *
 * - Does not allocate extents
 *
 * @return NULL (CT could not be allocated) or pointer to new CT
 */
struct castle_component_tree* castle_ct_alloc(struct castle_double_array *da,
                                              int level,
                                              tree_seq_t seq,
                                              uint32_t nr_data_exts,
                                              uint64_t nr_rwcts)
{
    struct castle_component_tree *ct;

    ct = castle_ct_init(da, nr_data_exts);
    if(!ct)
        return NULL;

    /* Allocate an id for the tree, init the ct. */
    ct->seq = (TREE_INVAL(seq)? castle_da_next_ct_seq(): seq);

    if(ct->seq >= (1ULL<<TREE_SEQ_SHIFT))
    {
        castle_printk(LOG_ERROR, "Could not allocate a CT because of sequence # overflow.\n");
        castle_free(ct->data_exts);
        castle_free(ct);
        return NULL;
    }

    ct->dynamic         = (level == 0);
    ct->level           = level;
    ct->nr_rwcts        = nr_rwcts;

    castle_ct_hash_add(ct);

    return ct;
}

/**
 * Allocate and initialise a T0 component tree.
 *
 * @param   See castle_da_rwct_create()
 * @param   lfs_type    Type of LFS callback to register
 *
 * NOTE: Caller must have set the DA growing bit.
 *
 * NOTE: Caller must have checked LFS condition or be sure what they're doing.
 *
 * - Allocates a new CT structure
 * - Allocates all necessary T0 extents
 * - Initialise root btree node
 * - Place new CT onto DA's level 0 CT list
 * - Invalidate CTs proxy
 * - Restart merges
 *
 * @return  0       RWCT created successfully
 * @return -ENOMEM  Unable to allocate CT structure
 * @return -ENOSPC  Failed to allocate extents
 *
 * @also castle_da_rwct_create()
 * @also castle_ct_alloc()
 * @also castle_ext_fs_init()
 */
static int _castle_da_rwct_create(struct castle_double_array *da,
                                  int cpu_index,
                                  int in_tran,
                                  c_lfs_vct_type_t lfs_type)
{
    struct castle_component_tree *ct, *old_ct;
    struct list_head *l = NULL;
    c2_block_t *c2b;
#ifdef DEBUG
    static int t0_count = 0;
#endif

    /* Caller must have set the DA's growing bit. */
    BUG_ON(!castle_da_growing_rw_test(da));

    ct = castle_ct_alloc(da, 0 /* level */, INVAL_TREE, 1, 1);
    if (!ct)
        return -ENOMEM;

    /* RWCTs are present only at levels 0,1 in the DA.
     * Prefix these CTs with cpu_index to preserve operation ordering when
     * inserting into the DA trees list at RWCT levels. */
    BUILD_BUG_ON(sizeof(ct->seq) != 8);
    ct->seq = ((tree_seq_t)cpu_index << TREE_SEQ_SHIFT) + ct->seq;

    /* Allocate extents for this T0. */
    if (castle_da_t0_extents_alloc(da, ct, lfs_type))
        goto no_space;

    /* Create a root node for this tree, and update the root version */
    atomic_set(&ct->tree_depth, 0);
    c2b = castle_btree_node_create(ct,
                                   0 /* version */,
                                   0 /* level */,
                                   0 /* wasn't preallocated */);
    ct->root_node = c2b->cep;
    atomic_set(&ct->tree_depth, 1);
    write_unlock_c2b(c2b);
    put_c2b(c2b);

    if (!in_tran) CASTLE_TRANSACTION_BEGIN;
    write_lock(&da->lock);

    /* Find cpu_index^th element from back and promote to level 1. */
    if (cpu_index < da->levels[0].nr_trees)
    {
        int index = 0;
        list_for_each_prev(l, &da->levels[0].trees)
        {
            if (index++ == cpu_index)
            {
                /* Found cpu_index^th element. */
                old_ct = list_entry(l, struct castle_component_tree, da_list);
                l = old_ct->da_list.prev; /* Position to insert new CT. */
                castle_component_tree_promote(da, old_ct);
                break;
            }
        }
    }
    /* Insert new CT onto list.  l will be the previous element (from delete above) or NULL. */
    castle_component_tree_add(da, ct, l);

    debug("Added component tree seq=%d, root_node="cep_fmt_str
          ", it's threaded onto da=%p, level=%d\n",
            ct->seq, cep2str(c2b->cep), da, ct->level);

    FAULT(MERGE_FAULT);

    if (!in_tran) CASTLE_TRANSACTION_END;

    debug("Created T0: %d\n", ++t0_count);
    /* DA is attached, therefore we must be holding a ref, therefore it is safe to schedule
       the merge check. */
    write_unlock(&da->lock);

    /* Invalidate any existing DA CTs proxy structure. */
    castle_da_cts_proxy_invalidate(da);

    castle_da_merge_restart(da, NULL);

    return 0;

no_space:
    if (ct)
        castle_ct_put(ct, READ /*rw*/, NULL);
    return -ENOSPC;
}

/**
 * Allocate and initialise a T0 component tree.
 *
 * - Set the DA growing bit (if already set, wait for other caller to
 *   complete then return)
 * - Perform an LFS check
 * - Call _castle_da_rwct_create() to create the RWCT
 *
 * Note: No need to check Low Freespace condition. Already checked by callers.
 *
 * @param da        Doubling array to create a T0 for
 * @param cpu_index Which CPU's T0 to create
 * @param in_tran   Is CASTLE_TRANSACTION lock held?
 *
 * @also _castle_da_rwct_create()
 */
static int castle_da_rwct_create(struct castle_double_array *da,
                                 int cpu_index,
                                 int in_tran)
{
    int ret;

    /* Serialise per-DA RWCT creation using the growing bit.
     * If it was already set then wait for whomever is already creating a new T0
     * RWCT to complete and return with EAGAIN.  Otherwise create a new T0. */
    if (castle_da_growing_rw_test_and_set(da))
    {
        debug("Racing RWCT make on da=%d\n", da->id);
        /* This look cannot use msleep_interruptible. Read comments in
           castle_da_all_rwcts_create() for more info. */
        while (castle_da_growing_rw_test(da))
            msleep(1); /* @TODO use out_of_line_wait_on_bit(_lock)() here instead */
        return -EAGAIN;
    }

    /* Try and create the RWCT now, registering a callback if we fail. */
    ret = _castle_da_rwct_create(da, cpu_index, in_tran, LFS_VCT_T_T0);

    castle_da_growing_rw_clear(da);

    return ret;
}

/**
 * Allocate a new doubling array.
 *
 * - Called when userland creates a new doubling array
 *
 * @param da_id         id of doubling array (unique)
 * @param root_version  Root version
 *
 * @also castle_control_create()
 * @also castle_da_all_rwcts_create()
 */
int castle_double_array_make(c_da_t da_id, c_ver_t root_version, c_da_opts_t opts)
{
    struct castle_double_array *da;
    int ret;

    debug("Creating doubling array for da_id=%d, version=%d\n", da_id, root_version);
    da = castle_da_alloc(da_id, opts);
    if(!da)
        return -ENOMEM;
    /* Write out the id, root version and tree type. */
    da->id = da_id;
    da->root_version = root_version;
    da->btree_type = SLIM_TREE_TYPE;

    /* Allocate all T0 RWCTs - use the invalid LFS type to prevent
     * LFS callbacks from being generated. */
    ret = castle_da_all_rwcts_create(da,
                                     1 /*in_tran*/,
                                     LFS_VCT_T_INVALID);
    if (ret != EXIT_SUCCESS)
    {
        castle_printk(LOG_WARN, "Exiting from failed ct create.\n");
        castle_da_dealloc(da);
        return ret;
    }

    /* Insert empty DA into hash. */
    castle_da_hash_add(da);
    castle_sysfs_da_add(da);

    /* Successfully created a DA. Send event. */
    castle_events_version_tree_created(da->id);

    debug("Successfully made a new doubling array, id=%d, for version=%d\n",
           da_id, root_version);
    /* DA make succeeded, start merge threads. */
    castle_da_merge_start(da, NULL);

    return 0;
}

/**
 * Return cpu_index^th T0 CT for da.
 *
 * - Does not take a reference
 *
 * NOTE: Caller must hold da read-lock.
 *
 * @return  cpu_index^th element from back of da->levels[0].trees list
 */
static struct castle_component_tree* __castle_da_rwct_get(struct castle_double_array *da,
                                                          int cpu_index)
{
    struct list_head *l;

    BUG_ON(cpu_index >= da->levels[0].nr_trees);
    BUG_ON(da->levels[0].nr_trees > num_online_cpus());
    list_for_each_prev(l, &da->levels[0].trees)
    {
        if (cpu_index == 0)
            /* Found cpu_index^th element. */
            return list_entry(l, struct castle_component_tree, da_list);
        else
            cpu_index--;
    }
    BUG_ON(cpu_index < 0);

    return NULL;
}

/**
 * Return cpu_index^th T0 CT for da with a reference held.
 *
 * NOTE: Always returns a valid CT pointer.
 *
 * @also __castle_da_rwct_get()
 */
static struct castle_component_tree* castle_da_rwct_get(struct castle_double_array *da,
                                                        int cpu_index)
{
    struct castle_component_tree *ct = NULL;

    read_lock(&da->lock);
    ct = __castle_da_rwct_get(da, cpu_index);
    BUG_ON(!ct);
    castle_ct_get(ct, WRITE /*rw*/, NULL);
    read_unlock(&da->lock);

    return ct;
}

/**
 * Acquires the write reference to a T0 (appropriate for the cpu_index provided), it dosen't
 * pre-allocate any freespace, but checks that at least 2 nodes worth of space is available.
 * If not, it'll try to allocate new T0.
 *
 * It should only be used if CT hasn't already been acquired through castle_da_reserve().
 * ATM all inserts do go through castle_da_reserve() therefore this function is effectively
 * unused
 */
static struct castle_component_tree* castle_da_rwct_acquire(struct castle_double_array *da,
                                                            int cpu_index)
{
    struct castle_component_tree *ct;
    int ret;

again:
    if (castle_da_no_disk_space(da))
        return NULL;

    ct = castle_da_rwct_get(da, cpu_index);
    BUG_ON(!ct);

    /* Use this tree, but only if there is still some space left in it (otherwise
       we could get stuck in a loop where write fails, but we still use the same CT
       and try again). */
    if(castle_ext_freespace_can_alloc(&ct->tree_ext_free,
                                      2 * ct->node_sizes[0] * C_BLK_SIZE))
        return ct;

    debug("Number of items in component tree %d, # items %ld. Trying to add a new rwct.\n",
            ct->seq, atomic64_read(&ct->item_count));
    /* Drop reference for old CT. */
    castle_ct_put(ct, WRITE /*rw*/, NULL);

    /* Try creating a new CT. */
    ret = castle_da_rwct_create(da, cpu_index, 0 /* in_tran */);

    if((ret == 0) || (ret == -EAGAIN))
        goto again;

    castle_printk(LOG_INFO, "Warning: failed to create RWCT with errno=%d\n", ret);

    return NULL;
}

/**
 * Queue a write IO for later submission.
 *
 * @param da        Doubling array to queue IO for
 * @param c_bvec    IO to queue
 *
 * WARNING: Caller must hold c_bvec's wait queue lock.
 */
static void castle_da_bvec_queue(struct castle_double_array *da, c_bvec_t *c_bvec)
{
    struct castle_da_io_wait_queue *wq = &da->ios_waiting[c_bvec->cpu_index];

    BUG_ON(!spin_is_locked(&wq->lock));

    /* Queue the bvec. */
    list_add_tail(&c_bvec->io_list, &wq->list);

    /* Increment IO waiting counters. */
    atomic_inc(&wq->cnt);
    atomic_inc(&da->ios_waiting_cnt);
}

/**
 * Submit write IOs queued on wait queue to btree.
 *
 * @param   work    Embedded in struct castle_da_io_wait_queue
 *
 * - Submit pending IOs from wait queue while inserts_enabled
 * - Place pending IOs on a new list of IOs to be submitted to the appropriate
 *   btree
 * - We use an intermediate list to minimise the amount of time we hold the
 *   wait queue lock (although subsequent IOs should be hitting the same CPU)
 *
 * @also struct castle_da_io_wait_queue
 * @also castle_da_write_bvec_start()
 */
static void castle_da_queue_kick(struct work_struct *work)
{
    struct castle_da_io_wait_queue *wq = container_of(work, struct castle_da_io_wait_queue, work);
    struct list_head *l, *t;
    LIST_HEAD(submit_list);
    c_bvec_t *c_bvec;

    /* Get as many c_bvecs as we can and place them on the submit list.
       Take them all on module exit. */
    spin_lock(&wq->lock);
    while ((!test_bit(CASTLE_DA_INSERTS_DISABLED, &wq->da->flags)
                    || castle_fs_exiting
                    || castle_da_no_disk_space(wq->da))
                && !list_empty(&wq->list))
    {
        /* Wait queue is FIFO so pull from the front for correct ordering. */
        c_bvec = list_first_entry(&wq->list, c_bvec_t, io_list);
        list_del(&c_bvec->io_list);
        list_add(&c_bvec->io_list, &submit_list);

        /* Decrement IO waiting counters. */
        BUG_ON(atomic_dec_return(&wq->cnt) < 0);
        BUG_ON(atomic_dec_return(&wq->da->ios_waiting_cnt) < 0);
    }
    spin_unlock(&wq->lock);

    /* Submit c_bvecs to the btree. */
    list_for_each_safe(l, t, &submit_list)
    {
        c_bvec = list_entry(l, c_bvec_t, io_list);
        list_del(&c_bvec->io_list);
        castle_da_reserve(wq->da, c_bvec);
    }
}

/**
 * Flush all write IOs queued for this DA.
 *
 * - Each T0 has a castle_da_io_wait_queue, flush them all with
 *   castle_da_queue_kick().
 *
 * NOTE: May run in interrupt context.
 *
 * @also castle_da_queue_kick()
 */
static void castle_da_queues_kick(struct castle_double_array *da)
{
    int i;

    for (i = 0; i < castle_double_array_request_cpus(); i++)
    {
        struct castle_da_io_wait_queue *wq;

        wq = &da->ios_waiting[i];

        if (atomic_read(&wq->cnt))
            queue_work_on(request_cpus.cpus[i], castle_wqs[0], &wq->work);
    }
}

/**
 * Return number of Bytes required to duplicate all merge partition keys in DA.
 *
 * @param   da  Locked DA (read/write)
 *
 * @return  Bytes required to duplicate all partition keys.
 */
static size_t castle_da_cts_proxy_keys_size(struct castle_double_array *da)
{
    struct castle_da_merge *last_merge;
    int i;
    size_t size;

    /* DA must be locked.  If it's read-locked, we don't allow writers, if it's
     * write-locked, we don't allow another writer. */
    BUG_ON(write_can_lock(&da->lock));

    /* Evaluate all mergeable CTs in the DA (not level 0). */
    for (i = 1, size = 0, last_merge = NULL; i < MAX_DA_LEVEL; i++)
    {
        struct list_head *l;

        list_for_each(l, &da->levels[i].trees)
        {
            struct castle_component_tree *ct;

            ct = list_entry(l, struct castle_component_tree, da_list);

            if (test_bit(CASTLE_CT_PARTIAL_TREE_BIT, &ct->flags))
            {
                /* CT is involved in a merge. */
                BUG_ON(!ct->merge);
                if (ct->merge != last_merge)
                {
                    /* CT is involved in a merge we've not seen before. */
                    struct castle_btree_type *btree;

                    btree = castle_btree_type_get(ct->btree_type);
                    size += btree->key_size(ct->merge->redirection_partition.key);

                    /* Update last_merge pointer. */
                    last_merge = ct->merge;
                }
            }
        }
    }

    return size;
}

/**
 * Return total number of extents associated with CTs in DA.
 *
 * @param   da  Locked DA
 *
 * @return  Number of extents in DA.
 */
static inline int castle_da_cts_proxy_extents(struct castle_double_array *da)
{
    int i, extents = 0;

    for (i = 0; i < MAX_DA_LEVEL; i++)
    {
        struct list_head *l;

        list_for_each(l, &da->levels[i].trees)
            extents += CASTLE_CT_EXTENTS(list_entry(l,
                                        struct castle_component_tree, da_list));
    }

    return extents;
}

/**
 * Create a DA CTs proxy and make it active in the DA.
 *
 * @return  *       Pointer to CTs proxy (with 2 references taken)
 * @return  NULL    Failed to allocate CTs proxy
 */
static struct castle_da_cts_proxy* castle_da_cts_proxy_create(struct castle_double_array *da)
{
#define VERIFY_PROXY_CT(_ct, _da) BUG_ON((_ct)->btree_type != (_da)->btree_type)
#define OVERALLOCATE_FACTOR 2

    struct castle_da_cts_proxy *proxy;
    struct castle_da_merge *last_merge;
    int nr_exts, nr_cts, ct, level;
    void *keys, *pk, *pk_next;
    size_t keys_rem;
    void *ext_refs;

    proxy = castle_alloc(sizeof(struct castle_da_cts_proxy));
    if (!proxy)
        return NULL;

reallocate:
    read_lock(&da->lock);
    /* Determine Bytes required to duplicate all partition keys.  A normalized
     * key's key_next() occupies the same amount of space so double the result
     * to handle both key and key_next(key).  Overallocate in case between
     * switching from read to write lock the required size has increased. */
    keys_rem = OVERALLOCATE_FACTOR * 2 * castle_da_cts_proxy_keys_size(da);
    /* Determine total number of extents in DA.  Overestimate in case the
     * number of extents changes after we allocate buffers. */
    nr_exts  = OVERALLOCATE_FACTOR * castle_da_cts_proxy_extents(da);
    read_unlock(&da->lock);

    nr_cts      = da->nr_trees;
    if (nr_cts <= 0)
        goto err;
    proxy->cts  = castle_alloc(nr_cts * sizeof(struct castle_da_cts_proxy_ct));
    if (!proxy->cts)
        goto err;
    proxy->keys = castle_alloc(keys_rem);
    if (!proxy->keys)
        goto err2;
    proxy->ext_refs = castle_alloc(nr_cts  * sizeof(c_ct_ext_ref_t)
                                 + nr_exts * sizeof(c_ext_mask_id_t));
    if (!proxy->ext_refs)
        goto err3;
    ext_refs = proxy->ext_refs;

    /* Verify nr_cts still matches under DA lock.  Write because we're going
     * to make this proxy structure active once it is generated. */
    /* Take lock on DA, to make sure neither CTs nor DA would go away
     * while looking at the list. */
    write_lock(&da->lock);

    if (nr_cts != da->nr_trees
            || nr_exts < castle_da_cts_proxy_extents(da)
            || keys_rem < 2 * castle_da_cts_proxy_keys_size(da))
    {
        /* nr_cts has changed or the memory we pre-allocated to store partition
         * keys and extent references is no longer sufficient.  We need to
         * re-allocate these structures to ensure they're large enough. */
        write_unlock(&da->lock);

        castle_free(proxy->ext_refs);
        castle_free(proxy->keys);
        castle_free(proxy->cts);

        goto reallocate;
    }

    /* Under the DA lock store pointers to referenced CTs.
     *
     * In the case of partially merged trees we can assume that input trees are
     * followed immediately by their output tree (even across levels, e.g. input
     * CTs at level 1 will be followed by an output CT at the start of level 2).
     * Make a copy of the partition key for the first seen input CT and assign
     * this to all subsequent CTs, resetting it once it has been assigned to the
     * output CT. */
    ct          = 0;
    last_merge  = NULL;
    pk          = NULL;
    pk_next     = NULL;
    keys        = proxy->keys;
    for (level = 0; level < MAX_DA_LEVEL; level++)
    {
        struct list_head *l;

        list_for_each(l, &da->levels[level].trees)
        {
            struct castle_da_cts_proxy_ct *proxy_ct;
            struct castle_component_tree *ct_p;

            /* Skip if the CT is not queriable. */
            ct_p = list_entry(l, struct castle_component_tree, da_list);
            if (!CASTLE_CT_QUERIABLE(ct_p))
                continue;

            /* Add this CT, take a reference. */
            proxy_ct            = &proxy->cts[ct++];
            proxy_ct->ct        = ct_p;
            proxy_ct->ext_refs  = (c_ct_ext_ref_t *)ext_refs;
            castle_ct_get(proxy_ct->ct, READ /*rw*/, proxy_ct->ext_refs);
            VERIFY_PROXY_CT(proxy_ct->ct, da);
            ext_refs += sizeof(c_ct_ext_ref_t)
                + proxy_ct->ext_refs->nr_refs * sizeof(((c_ct_ext_ref_t *)0)->refs[0]);

            if (!test_bit(CASTLE_CT_PARTIAL_TREE_BIT, &proxy_ct->ct->flags))
            {
                /* CT is complete. */
                proxy_ct->state     = NO_REDIR;
                proxy_ct->pk        = NULL;
                proxy_ct->pk_next   = NULL;
            }
            else
            {
                /* CT is a merge input or output tree. */
                BUG_ON(!proxy_ct->ct->merge);
                BUG_ON(level < 1);

                if (test_bit(CASTLE_CT_MERGE_INPUT_BIT, &proxy_ct->ct->flags))
                {
                    proxy_ct->state = REDIR_INTREE;

                    debug("%s::CT %d at level %d redirects to CT %d\n",
                            __FUNCTION__, proxy_ct->ct->seq, i,
                            proxy_ct->ct->merge->out_tree->seq);
                }
                else if (test_bit(CASTLE_CT_MERGE_OUTPUT_BIT, &proxy_ct->ct->flags))
                    proxy_ct->state = REDIR_OUTTREE;
                else
                    BUG(); /* must be INTREE or OUTTREE */

                if (last_merge != proxy_ct->ct->merge)
                {
                    /* New merge.  Copy the partition key and key_next(partition
                     * key) to our keys buffer and maintain pointers to each. */
                    struct castle_btree_type *btree;
                    void *merge_pk;
                    size_t key_len;

                    BUG_ON(proxy_ct->state == REDIR_OUTTREE);

                    btree = castle_btree_type_get(proxy_ct->ct->btree_type);
                    merge_pk = proxy_ct->ct->merge->redirection_partition.key;

                    /* Copy the partition key. */
                    key_len     = keys_rem;
                    pk          = btree->key_copy(merge_pk, keys, &key_len);
                    BUG_ON(!pk); /* we allocated space for all copies */
                    keys_rem   -= key_len;
                    keys       += key_len;

                    /* Copy key_next(partition key). */
                    key_len     = keys_rem;
                    pk_next     = btree->key_next(merge_pk, keys, &key_len);
                    BUG_ON(!pk_next); /* we allocated space for all copies */
                    keys_rem   -= key_len;
                    keys       += key_len;

                    /* Track this merge. */
                    last_merge = proxy_ct->ct->merge;
                }

                BUG_ON(!pk || !pk_next);
                proxy_ct->pk        = pk;
                proxy_ct->pk_next   = pk_next;

                if (test_bit(CASTLE_CT_MERGE_OUTPUT_BIT, &proxy_ct->ct->flags))
                {
                    /* Invalidate these pointers if we hit an output tree. */
                    pk      = NULL;
                    pk_next = NULL;
                }
            }
        }
    }

    /* Finalise proxy structure. */
    BUG_ON(ct > nr_cts);
    proxy->nr_cts     = ct;
    proxy->btree_type = da->btree_type;
    proxy->da         = da;
    atomic_set(&proxy->ref_cnt, 2); /* 1: DA, 2: caller */

    /* Make this DA CT's proxy live for DA. */
    BUG_ON(da->cts_proxy);
    da->cts_proxy = proxy; /* still under DA write lock */

    castle_printk(LOG_DEBUG, "%s: created proxy=%p, da=%p, da_id=%d\n",
            __FUNCTION__, proxy, da, da->id);

    write_unlock(&da->lock);

    return proxy;

err3:
    castle_free(proxy->keys);
err2:
    castle_free(proxy->cts);
err:
    castle_free(proxy);

    return NULL;
}

/**
 * Get a reference to the CTs proxy for this DA, creating it, if necessary.
 *
 * @return  *       Pointer to CTs proxy (with reference taken)
 * @return  NULL    Failed to allocate CTs proxy
 */
static struct castle_da_cts_proxy* castle_da_cts_proxy_get(struct castle_double_array *da)
{
    struct castle_da_cts_proxy *proxy;
    int already_creating;

retry:
    read_lock(&da->lock);
    proxy = da->cts_proxy;

    if (likely(proxy))
    {
        /* Take a reference to an existing proxy. */
        atomic_inc(&proxy->ref_cnt);
        read_unlock(&da->lock);

        return proxy;
    }
    else
    {
        /* Create a new proxy (or wait on creation). */
        already_creating = test_and_set_bit(CASTLE_DA_CTS_PROXY_CREATE_BIT, &da->flags);
        read_unlock(&da->lock);

        if (unlikely(already_creating))
        {
            /* Wait for another thread to create proxy. */
            msleep(10);

            goto retry;
        }

        /* Create a new proxy. */
        proxy = castle_da_cts_proxy_create(da); /* ref_cnt == 2 */
        clear_bit(CASTLE_DA_CTS_PROXY_CREATE_BIT, &da->flags);

        return proxy; // may be NULL
    }
}

/**
 * Release CTs proxy extent references and free proxy.
 *
 * @param   data    castle_da_cts_proxy pointer
 */
static inline void _castle_da_cts_proxy_put(struct castle_da_cts_proxy *proxy)
{
    int ct;

    BUG_ON(atomic_read(&proxy->ref_cnt) != 0);
    castle_printk(LOG_DEBUG, "%s: ref_cnt==0, proxy=%p, da=%p\n",
            __FUNCTION__, proxy, proxy->da);

    for (ct = 0; ct < proxy->nr_cts; ct++)
    {
        if (proxy->cts[ct].state != NO_REDIR)
            BUG_ON(!proxy->cts[ct].pk);
        else
            BUG_ON(proxy->cts[ct].pk);
        castle_ct_put(proxy->cts[ct].ct, READ /*rw*/, proxy->cts[ct].ext_refs);
    }

    castle_free(proxy->ext_refs);
    castle_free(proxy->keys);
    castle_free(proxy->cts);
    castle_free(proxy);
}

/**
 * Put a reference on the DA CTs proxy, freeing it, if necessary.
 *
 * @param   proxy       CTs proxy to release reference on
 *
 * NOTE: See castle_da_cts_proxy{} for description of why we do not need to
 *       update da->cts_proxy pointer if dropping the last reference.
 */
void castle_da_cts_proxy_put(struct castle_da_cts_proxy *proxy)
{
    int ref_cnt;

    ref_cnt = atomic_dec_return(&proxy->ref_cnt);

    /* Drop CT references and free proxy if we put the last reference. */
    if (ref_cnt == 0)
        _castle_da_cts_proxy_put(proxy);
    else
        BUG_ON(ref_cnt < 0);
}

/**
 * Invalidate an existing DA CTs proxy, if one exists.
 *
 * NOTE: Caller must not hold either DA lock or DA hash lock.
 */
static void castle_da_cts_proxy_invalidate(struct castle_double_array *da)
{
    struct castle_da_cts_proxy *proxy = NULL;

    write_lock(&da->lock);
    proxy = da->cts_proxy;
    if (proxy)
        da->cts_proxy = NULL;
    write_unlock(&da->lock);

    if (proxy)
    {
        castle_printk(LOG_DEBUG, "%s: Putting proxy=%p, da=%p, da_id=%d\n",
                __FUNCTION__, proxy, da, da->id);
        castle_da_cts_proxy_put(proxy);
    }
}

/**
 * DA hash iterate callback to store proxy pointer and update DA pointer.
 *
 * @param   da      Doubling array to invalidate
 * @param   private castle_da_cts_proxy_all_invalidate pointer
 */
static inline int _castle_da_cts_proxy_all_invalidate(struct castle_double_array *da, void *private)
{
    struct castle_da_cts_proxy_all_invalidate *invalidate = private;

    write_lock(&da->lock);
    if (da->cts_proxy)
    {
        castle_da_get(da);
        invalidate->proxies[invalidate->proxy++] = da->cts_proxy;
        da->cts_proxy = NULL;
    }
    write_unlock(&da->lock);

    return 0;
}

/**
 * Iterate all DA hash and invalidate all CTs proxies without locks held.
 */
static void castle_da_cts_proxy_all_invalidate(void)
{
    struct castle_da_cts_proxy_all_invalidate invalidate;
    struct castle_da_cts_proxy **proxies;
    struct castle_double_array *da;
    unsigned long flags;
    int nr_das, i;

retry:
    nr_das = castle_da_nr_entries_get();
    if (nr_das == 0)
        return;
    else
        nr_das += 5; /* overestimate to help prevent reallocation */

    proxies = castle_alloc(nr_das * sizeof(struct castle_da_cts_proxy *));
    if (!proxies)
        goto retry; /* this could be a nasty loop... */

    read_lock_irqsave(&castle_da_hash_lock, flags);
    if (__castle_da_nr_entries_get() > nr_das)
    {
        /* Number of DAs in the hash changed, drop lock and try again. */
        read_unlock_irqrestore(&castle_da_hash_lock, flags);
        castle_free(proxies);
        goto retry;
    }
    /* Initialise invalidate structure then iterate DA hash to store active
     * proxy pointers at the same time as marking no active proxy for DA. */
    invalidate.proxies = proxies;
    invalidate.proxy   = 0;
    __castle_da_hash_iterate(_castle_da_cts_proxy_all_invalidate, &invalidate);
    read_unlock_irqrestore(&castle_da_hash_lock, flags);

    /* Put proxies with no locks held.  If we're dropping the last reference
     * castle_free() is called, which may sleep. */
    for (i = 0; i < invalidate.proxy; i++)
    {
        da = invalidate.proxies[i]->da;
        castle_da_cts_proxy_put(invalidate.proxies[i]);
        castle_da_put(da);
    }

    castle_free(proxies);

    castle_printk(LOG_DEBUG, "%s: Put %d proxies\n", __FUNCTION__, i);
}

/**
 * Invalidate all exists DA CTs proxys.
 */
static void castle_da_cts_proxy_timeout(void *unused)
{
    castle_da_cts_proxy_all_invalidate();
}

#define CASTLE_DA_CTS_PROXY_TIMEOUT_FREQ    (10)    /* Timeout all DA CT's proxies every 10s.   */
static DECLARE_WORK(castle_da_cts_proxy_timeout_work, castle_da_cts_proxy_timeout, 0 /*da_locked*/);
static struct timer_list castle_da_cts_proxy_timer;
static void castle_da_cts_proxy_timer_fire(unsigned long first)
{
    /* Timeout any existing DA CTs proxy structures. */
    schedule_work(&castle_da_cts_proxy_timeout_work);

    /* Reschedule ourselves. */
    setup_timer(&castle_da_cts_proxy_timer, castle_da_cts_proxy_timer_fire, 0);
    mod_timer(&castle_da_cts_proxy_timer, jiffies + HZ * CASTLE_DA_CTS_PROXY_TIMEOUT_FREQ);
}


/**
 * Return next CT from CTs proxy matching point c_bvec.
 *
 * @param   proxy   [in]    DA CTs proxy structure
 * @param   index   [both]  Index into DA CT's proxy structure to start search
 * @param   key     [in]    Search key
 */
static struct castle_component_tree* castle_da_cts_proxy_ct_next(struct castle_da_cts_proxy *proxy,
                                                                 int *index,
                                                                 void *key)
{
    struct castle_da_cts_proxy_ct *proxy_ct;
    int i;

    BUG_ON(!proxy);

    for (i = *index + 1; i < proxy->nr_cts; i++)
    {
        proxy_ct = &proxy->cts[i];

        if (proxy_ct->pk)
        {
            /* CT has a partition key. */
            struct castle_btree_type *btree;
            int cmp;

            BUG_ON(proxy_ct->state == NO_REDIR);

            btree = castle_btree_type_get(proxy->btree_type);
            cmp = btree->key_compare(proxy_ct->pk, key);

            if ((proxy_ct->state == REDIR_INTREE && cmp < 0)
                    || (proxy_ct->state == REDIR_OUTTREE && cmp >= 0))
                /* Matching candidate found. */
                goto found;
            else
                continue; /* implicit */
        }
        else
            /* No partition key, matching candidate found. */
            goto found;
    }

    *index = i; /* proxy->nr_cts */

    return NULL;

found:
    *index = i;

    return proxy_ct->ct;
}

/**
 * Let t = cvt->user_timestamp, returns a +ve if the ct's max timestamp is > t,
 * -ve if it's < t, 0 if it's == t.
 */
static signed int castle_da_ct_timestamp_compare(struct castle_component_tree *ct,
                                              castle_user_timestamp_t candidate_timestamp)
{
    uint64_t max_ct_ts_for_cvt = atomic64_read(&ct->max_user_timestamp);
    BUILD_BUG_ON(sizeof(castle_user_timestamp_t) != sizeof(uint64_t));

    if(max_ct_ts_for_cvt == candidate_timestamp)
        return 0;
    else if(max_ct_ts_for_cvt < candidate_timestamp)
        return -1;
    else
        return 1;
        /* Further work: If we come up with something more fine-grained than the max timestamp of
                         all the entries in the ct, then here is probably where we would set an
                         improved guess for max_ct_ts_for_cvt and redo the comparisons. */
}

/**
 * Callback handler when castle_bloom_key_exists() returns a result.
 *
 * @param   private     c_bvec pointer
 * @param   key_exists  Whether c_bvec->key exists in c_bvec->tree
 *
 * NOTE: Called directly from castle_bloom_key_exists() if it needed to go
 *       asynchronous to issue read I/O.
 *
 * NOTE: Called from _castle_da_bloom_submit() if castle_bloom_key_exists()
 *       returned a result synchronously.
 *
 * @also _castle_da_bloom_submit()
 */
inline void castle_da_bloom_submit_cb(void *private, int key_exists)
{
    c_bvec_t *c_bvec = private;

    BUG_ON(key_exists < 0);

    /* If we are debugging bloom filters, record cases where the bloom filter
     * advised us not to query the current tree and query it anyway. */
    c_bvec->bloom_skip = castle_bloom_debug && !key_exists;
    if (unlikely(c_bvec->bloom_skip))
        key_exists = 1;

    if (key_exists)
    {
        /* Key may exist, submit request to btree. */
#ifdef CASTLE_BLOOM_FP_STATS
        if (key_exists == 1)
            c_bvec->bloom_positive = 1;
#endif
        castle_btree_submit(c_bvec, 0 /*go_async*/);
    }
    else
        /* Key doesn't exist in btree, try next CT. */
        castle_da_next_ct_read(c_bvec);
}

static inline void _castle_da_bloom_submit(void *data)
{
    c_bvec_t *c_bvec = data;
    int key_exists;

    key_exists = castle_bloom_key_exists(&c_bvec->bloom_lookup,
                                         &c_bvec->tree->bloom,
                                         c_bvec->key,
                                         HASH_WHOLE_KEY,
                                         castle_da_bloom_submit_cb,
                                         c_bvec);

    if (key_exists < 0)
        /* Bloom lookup went asynchronous, CB will be fired asynchronously. */
        return;

    castle_da_bloom_submit_cb(c_bvec, key_exists);
}

/**
 * Perform a lookup in the entire bloom filter.
 *
 * @param   c_bvec      Point read key to look for
 * @param   go_async    Whether to immediately go asynchronous
 *
 * Only CTs which have been merged can have bloom filters.
 */
void castle_da_bloom_submit(c_bvec_t *c_bvec, int go_async)
{
    if (c_bvec->tree->bloom_exists)
    {
        /* Search in bloom filter. */
        INIT_WORK(&c_bvec->work, _castle_da_bloom_submit, c_bvec);
        if (go_async)
            /* Submit asynchronously. */
            queue_work_on(c_bvec->cpu, castle_wqs[19], &c_bvec->work);
        else
            /* Submit synchronously. */
            _castle_da_bloom_submit(&c_bvec->work);
    }
    else
    {
        /* Submit directly to btree. */
        c_bvec->bloom_skip = 0;
        castle_btree_submit(c_bvec, go_async);
    }
}

/**
 * Submit request to the next candidate CT, or terminate if exhausted.
 */
void castle_da_next_ct_read(c_bvec_t *c_bvec)
{
    /* loop over every tree, until we find a break/return clause */
    do {

        /* Find next candidate tree from DA CT's proxy structure. */
        c_bvec->tree = castle_da_cts_proxy_ct_next(c_bvec->cts_proxy,
                                                  &c_bvec->cts_index,
                                                   c_bvec->key);
        if (!c_bvec->tree)
        {
            /* No more candidate trees available.  Let submit_complete()
             * handle this case for us. */
            c_bvec->submit_complete(c_bvec, 0, INVAL_VAL_TUP);

            return; /* no trees left */
        }
        else if (castle_da_user_timestamping_check(c_bvec->tree->da))
        {
            if(CVT_INVALID(c_bvec->accum) || (CVT_ANY_COUNTER(c_bvec->accum)))
                break; /* no candidate return object yet, or it's a counter */

            /* We have a tree, we have a previously found object that is not a counter, and we are
               timestamping this DA; let's compare timestamps to see if we need to query this tree,
               or if we can go on to the next tree right away. The comparison is '>' instead of '>='
               because we only care about objects with a timestamp greater than the timestamp of
               the current accumulated cvt; if the timestamp is equal, then the current accumulated
               cvt will be the return candidate anyway, due to insertion order. */
            if (castle_da_ct_timestamp_compare(c_bvec->tree, c_bvec->accum.user_timestamp) > 0)
                break; /* this tree might have something newer (according to user_timestamp) */
            else
            {
                struct castle_double_array *da = c_bvec->tree->da;
                BUG_ON(!da);
                atomic64_inc(&da->stats.user_timestamps.ct_max_uts_negatives);
            }
        }
        else break; /* not timestamping */

    } while(1);

    debug_verbose("Scheduling btree read in %s tree: %d.\n",
            c_bvec->tree->dynamic ? "dynamic" : "static", c_bvec->tree->seq);

    castle_da_bloom_submit(c_bvec, 1 /*async*/);
}

/**
 * Callback for completing a Component Tree read.
 *
 * Arranges to search the next CT in DA if:
 * - Doing counter accumulation
 * - Doing timestamp accumulation
 * - Key not found in CT
 *
 * Completes if:
 * - All candidate CTs have been searched
 * - Key found (and no accumulation is performed)
 * - Key found (and signals the end of the current accumulation)
 * - An error occurred
 */
static void castle_da_ct_read_complete(c_bvec_t *c_bvec, int err, c_val_tup_t cvt)
{
    void (*callback)(c_bvec_t *c_bvec, int err, c_val_tup_t cvt) = c_bvec->orig_complete;

    BUG_ON(c_bvec_data_dir(c_bvec) != READ);
    BUG_ON(atomic_read(&c_bvec->reserv_nodes));

#ifdef CASTLE_DEBUG
    atomic_inc(&c_bvec->read_passes);
#endif

    if (!err && c_bvec->tree)   /* haven't run out of trees yet */
    {
        /* No key found, go to the next tree. */
        if (CVT_INVALID(cvt))
        {
#ifdef CASTLE_BLOOM_FP_STATS
            if (c_bvec->tree->bloom_exists && c_bvec->bloom_positive)
            {
                atomic64_inc(&c_bvec->tree->bloom.false_positives);
                c_bvec->bloom_positive = 0;
            }
#endif
            castle_da_next_ct_read(c_bvec);
            return;
        }

        /* Fail if we find a key in a CT the bloom filter told us to skip. */
        else if (c_bvec->bloom_skip)
            BUG();

        /* Handle counter accumulation. */
        else if (CVT_ANY_COUNTER(cvt) &&
                 (CVT_INVALID(c_bvec->accum) || CVT_ANY_COUNTER(c_bvec->accum)))
        {
            if (CVT_INVALID(c_bvec->accum))
            {
                CVT_COUNTER_LOCAL_ADD_INIT(c_bvec->accum, 0);
                c_bvec->accum.user_timestamp = 0;
            }

            if (!castle_counter_simple_reduce(&c_bvec->accum, cvt)) /* not done yet */
            {
                c_bvec->val_put(&cvt);
                castle_da_next_ct_read(c_bvec);
                return;
            }
            /* otherwise fall through to the end of the function */
        }

        /* Handle timestamp accumulation. */
        else if (!CVT_ANY_COUNTER(cvt) &&
                 (CVT_INVALID(c_bvec->accum) || !CVT_ANY_COUNTER(c_bvec->accum)))
        {
            if (castle_da_user_timestamping_check(c_bvec->tree->da))
            {
                if (CVT_INVALID(c_bvec->accum))
                {
                    c_bvec->accum = cvt;
                }
                else if (cvt.user_timestamp > c_bvec->accum.user_timestamp)
                {
                    c_bvec->val_put(&c_bvec->accum);
                    c_bvec->accum = cvt;
                }
                else
                {
                    c_bvec->val_put(&cvt);
                    atomic64_inc(&c_bvec->tree->da->stats.user_timestamps.ct_max_uts_false_positives);
                }

                castle_da_next_ct_read(c_bvec);
                return;
            }

            else                /* non-timestamped DA; simply return the value */
            {
                BUG_ON(!CVT_INVALID(c_bvec->accum));
                callback(c_bvec, err, cvt);
                return;
            }
        }

        /* If we've fallen through here, we don't need the value we got any more. */
        c_bvec->val_put(&cvt);
    }

    /* Terminate now.  One of the following conditions must be true:
     *
     * 1) no more candidate trees were available
     * 2) an error occurred
     * 3) we received a counter SET, which terminated the counter accumulation
     * 4) we received a counter while accumulating timestamps
     * 5) we received a non-counter while accumulating counters
     *
     * In the error case, we drop the accumulated value and return whatever we got (which
     * won't be used anyway). In all other cases, we drop the value we just received (if
     * any) and return the accumulated value (again, if any).
     */
    BUG_ON(!c_bvec->tree && !CVT_INVALID(cvt));
    if (err)
    {
        /* Drop the CT proxy reference on error, as the client will not. This is because,
         * in case of an error, the proxy reference might not have been taken in the
         * first place. */
        castle_da_cts_proxy_put(c_bvec->cts_proxy);
        c_bvec->val_put(&c_bvec->accum);
    }
    else cvt = c_bvec->accum;
    CVT_INVALID_INIT(c_bvec->accum);
    callback(c_bvec, err, cvt);
}

/**
 * This function implements the btree write callback. At the moment it is expected that
 * space to do the btree write was preallocated and -ENOSPC error code will never happen
 * (this function is capable of handling this, but castle_da_write_bvec_start is not reentrant).
 *
 * Btree write is handled by releasing any unused preallocated btree extent space,
 * and calling back to the client.
 */
static void castle_da_ct_write_complete(c_bvec_t *c_bvec, int err, c_val_tup_t cvt)
{
    void (*callback) (struct castle_bio_vec *c_bvec, int err, c_val_tup_t cvt);
    struct castle_component_tree *ct;
    struct castle_double_array *da;

    callback = c_bvec->orig_complete;
    ct = c_bvec->tree;
    da = ct->da;

    /*
     * If the insert space failed, create a new ct, and continue.
     * At the moment we don't expect btree insert to fail, because space is always preallocated.
     */
    BUG_ON(err == -ENOSPC);
    if(err == -ENOSPC)
    {
        /* Release the reference to the tree. */
        castle_ct_put(ct, WRITE /*rw*/, NULL);
        /*
         * For now all inserts reserve space, and castle_da_write_bvec_start is not reentrant,
         * therefore err should never be -ENOSPC.
         */
        BUG();
        castle_da_write_bvec_start(da, c_bvec);
        return;
    }
    BUG_ON(c_bvec_data_dir(c_bvec) != WRITE);
    debug_verbose("Finished with DA, calling back.\n");
    /* Release the preallocated space in the btree extent. */
    castle_double_array_unreserve(c_bvec);
    BUG_ON(CVT_MEDIUM_OBJECT(cvt) && (cvt.cep.ext_id != c_bvec->tree->data_ext_free.ext_id));

    /* Don't release the ct reference in order to hold on to medium objects array, etc. */
    callback(c_bvec, err, cvt);
}

/**
 * Hand-off write request (bvec) to DA.
 *
 * - Fail request if there is no free space
 * - Get T0 CT for bvec
 * - Configure completion handlers
 * - Submit immediately to btree
 *
 * @also castle_da_read_bvec_start()
 * @also castle_btree_submit()
 */
static void castle_da_write_bvec_start(struct castle_double_array *da, c_bvec_t *c_bvec)
{
    int reserved;

    debug(LOG_DEBUG, "%s::Doing DA write for da_id=%d\n", __FUNCTION__, da->id);
    BUG_ON(c_bvec_data_dir(c_bvec) != WRITE);

    /* Medium, and only medium inserts must have reserved the space (in leaf nodes extent,
       and in the medium objects extent). */
    reserved = (c_bvec->tree != NULL);

    /* If space was reserved, start the insert immediately. */
    if(reserved)
        goto insert;

    /* If no disk space left, the best we can do is return an error. */
    if (castle_da_no_disk_space(da))
    {
        c_bvec->submit_complete(c_bvec, -ENOSPC, INVAL_VAL_TUP);
        return;
    }

    /* Get a reference to the current RW CT (a new one may be created). */
    c_bvec->tree = castle_da_rwct_acquire(da, c_bvec->cpu_index);
    if (!c_bvec->tree)
    {
        c_bvec->submit_complete(c_bvec, -ENOSPC, INVAL_VAL_TUP);
        return;
    }

insert:
    c_bvec->orig_complete   = c_bvec->submit_complete;
    c_bvec->submit_complete = castle_da_ct_write_complete;

    debug_verbose("Looking up in ct=%d\n", c_bvec->tree->seq);

    /* Submit directly to btree. */
    castle_btree_submit(c_bvec, 0 /*go_async*/);
}

/**
 * Hand-off read request (bvec) to DA via bloom filter.
 *
 * - Get first CT for bvec (not necessarily a RWCT)
 * - Configure callback handlers
 * - Pass off to the bloom layer
 *
 * @also castle_da_write_bvec_start()
 * @also castle_bloom_submit()
 */
static void castle_da_read_bvec_start(struct castle_double_array *da, c_bvec_t *c_bvec)
{
    debug_verbose("Doing DA read for da_id=%d\n", da_id);
    BUG_ON(c_bvec_data_dir(c_bvec) != READ);

    /* Get this DA's CT proxy structure. */
    c_bvec->cts_proxy = castle_da_cts_proxy_get(da);
    if (!c_bvec->cts_proxy)
    {
        c_bvec->submit_complete(c_bvec, -ENOMEM, INVAL_VAL_TUP);
        return;
    }

    /* Find first candidate tree and initialise request. */
    c_bvec->cts_index       = -1;
    c_bvec->tree            = castle_da_cts_proxy_ct_next(c_bvec->cts_proxy,
                                                         &c_bvec->cts_index,
                                                          c_bvec->key);
    if (!c_bvec->tree)
    {
        /* No candidate trees available, so the requested key cannot exist.
         * Let submit_complete() handle this case for us. */
        castle_da_cts_proxy_put(c_bvec->cts_proxy);
        c_bvec->submit_complete(c_bvec, 0, INVAL_VAL_TUP);
        return;
    }
    c_bvec->orig_complete   = c_bvec->submit_complete;
    c_bvec->submit_complete = castle_da_ct_read_complete;

    debug_verbose("Looking up in ct=%d\n", c_bvec->tree->seq);

    /* Submit request (via bloom filter). */
#ifdef CASTLE_BLOOM_FP_STATS
    c_bvec->bloom_positive = 0;
#endif
    castle_da_bloom_submit(c_bvec, 0 /*go_async*/);
}

/**
 * Return the btree type structure associated with a particular DA.
 */
struct castle_btree_type *castle_double_array_btree_type_get(struct castle_attachment *att)
{
    return castle_btree_type_get(att->col.da->btree_type);
}

/**
 * Return the user_timestamping flag associated with a particular DA.
 */
uint8_t castle_da_user_timestamping_check(struct castle_double_array *da)
{
    BUG_ON(!da);
    return (!(da->creation_opts & CASTLE_DA_OPTS_NO_USER_TIMESTAMPING));
}
uint8_t castle_attachment_user_timestamping_check(struct castle_attachment *att)
{
    return castle_da_user_timestamping_check(att->col.da);
}

/**
 * Submit request to DA, write IOs are queued if inserts are disabled.
 *
 * Read requests:
 * - Processed immediately
 *
 * Write requests:
 * - Hold appropriate write queue spinlock to guarantee ordering
 * - If da->inserts_enabled and pending write queue is empty, submit immediately
 * - Otherwise queue write IO and wait for queue kick when inserts reenabled
 *
 * @also castle_da_bvec_queue()
 * @also castle_da_read_bvec_start()
 * @also castle_da_write_bvec_start()
 */
void castle_double_array_submit(c_bvec_t *c_bvec)
{
    struct castle_double_array *da = c_bvec->c_bio->attachment->col.da;

    /* orig_complete should be null it is for our private use */
    BUG_ON(c_bvec->orig_complete);

    if (c_bvec_data_dir(c_bvec) == READ)
        /* Start the read bvecs without any queueing. */
        castle_da_read_bvec_start(da, c_bvec);
    else
        castle_da_write_bvec_start(da, c_bvec);
}

/**
 * Gets write reference to the appropriate T0 (for the cpu_index stored in c_bvec) and
 * reserves space in btree and medium object extents (for medium object writes).
 * It calls back to the client through queue_complete() callback, on success or failure.
 */
static void castle_da_reserve(struct castle_double_array *da, c_bvec_t *c_bvec)
{
    struct castle_component_tree *ct;
    uint64_t value_len, req_btree_space, req_medium_space;
    int ret;

    if (castle_da_no_disk_space(da))
    {
        c_bvec->queue_complete(c_bvec, -ENOSPC);
        return;
    }

    value_len = c_bvec->c_bio->replace->value_len;
again:
    ct = castle_da_rwct_get(da, c_bvec->cpu_index);
    BUG_ON(!ct);

    /* Attempt to preallocate space in the btree and m-obj extents for writes. */

    /* We may have to create up to 2 new leaf nodes in this write. Preallocate
       the space for this. */
    req_btree_space = 2 * ct->node_sizes[0] * C_BLK_SIZE;
    if (castle_ext_freespace_prealloc(&ct->tree_ext_free, req_btree_space) < 0)
        goto new_ct;
    /* Save how many nodes we've pre-allocated. */
    atomic_set(&c_bvec->reserv_nodes, 2);

    /* Preallocate (ceil to C_BLK_SIZE) space for the medium object. */
    req_medium_space = ((value_len - 1) / C_BLK_SIZE + 1) * C_BLK_SIZE;
    if ( is_medium(value_len) &&
        (castle_ext_freespace_prealloc(&ct->data_ext_free, req_medium_space) < 0))
    {
        /* We failed to preallocate space for the medium object. Free the space in btree extent. */
        castle_ext_freespace_free(&ct->tree_ext_free, req_btree_space);
        atomic_set(&c_bvec->reserv_nodes, 0);
        goto new_ct;
    }
    /* Save the CT in bvec. */
    c_bvec->tree = ct;

    c_bvec->queue_complete(c_bvec, 0);
    return;

new_ct:
    debug("Number of items in component tree %d, # items %ld. Trying to add a new rwct.\n",
            ct->seq, atomic64_read(&ct->item_count));
    /* Drop reference for old CT. */
    castle_ct_put(ct, WRITE /*rw*/, NULL);

    ret = castle_da_rwct_create(da, c_bvec->cpu_index, 0 /* in_tran */);
    if((ret == 0) || (ret == -EAGAIN))
        goto again;

    BUG_ON(atomic_read(&c_bvec->reserv_nodes) != 0);

    c_bvec->queue_complete(c_bvec, ret);
}

/**
 * Unreserves any nodes reserved in the btree extent associated with the write request provided.
 */
void castle_double_array_unreserve(c_bvec_t *c_bvec)
{
    struct castle_component_tree *ct;
    uint32_t reserv_nodes;

    /* Only works for write requests. */
    BUG_ON(c_bvec_data_dir(c_bvec) != WRITE);

    /* If no nodes are reserved, stop. */
    reserv_nodes = atomic_read(&c_bvec->reserv_nodes);
    if(reserv_nodes == 0)
        return;

    /* Free the nodes. */
    ct = c_bvec->tree;
    castle_ext_freespace_free(&ct->tree_ext_free,
                               reserv_nodes * ct->node_sizes[0] * C_BLK_SIZE);
    /* Set the reservation back to 0. Don't use atomic_set() because this doesn't use
       locked prefix. */
    atomic_sub(reserv_nodes, &c_bvec->reserv_nodes);
}

/**
 * Submits write requests to this DA write queue which throttles inserts according to the
 * merge progress. Once the write is scheduled for processing (which could happen immediately
 * in the current thread's context) it reserves btree/medium object extent space, and
 * calls back to the user.
 *
 * @also castle_da_reserve()
 */
void castle_double_array_queue(c_bvec_t *c_bvec)
{
    struct castle_da_io_wait_queue *wq;
    struct castle_double_array *da = c_bvec->c_bio->attachment->col.da;

    BUG_ON(c_bvec_data_dir(c_bvec) != WRITE);

    BUG_ON(atomic_read(&c_bvec->reserv_nodes) != 0);

    /* Write requests only accepted if inserts enabled and no queued writes. */
    wq = &da->ios_waiting[c_bvec->cpu_index];
    spin_lock(&wq->lock);

    /* If the DA is in LFS, fail writes immediately.
     * It is possible this could race with castle_da_queue_kick() but since both
     * functions take wq->lock they are atomic wrt each other. */
    if (castle_da_no_disk_space(da))
    {
        spin_unlock(&wq->lock);
        c_bvec->queue_complete(c_bvec, -ENOSPC);
        return;
    }

    /* Queue this request if inserts are disabled or other write IOs pending. */
    if (test_bit(CASTLE_DA_INSERTS_DISABLED, &da->flags) || !list_empty(&wq->list))
    {
        /* Most likely inserts are disabled.  In the case that there are pending
         * write IOs and inserts enabled we're racing with an already initiated
         * queue kick so there's no need to manually do one now. */
        castle_da_bvec_queue(da, c_bvec);
        spin_unlock(&wq->lock);
        return;
    }

    /* Inserts enabled, no pending IOs, not in LFS.  Schedule write now. */
    spin_unlock(&wq->lock);
    castle_da_reserve(da, c_bvec);
}

/**************************************/
/* Double Array Management functions. */

/**
 * Initialise global doubling array state.
 */
int castle_double_array_init(void)
{
    int ret, cpu, i, j;
    int min_budget, budget;

    ret = -ENOMEM;

    /* Allocate merge workqueues. */
    for (i = 0; i < NR_CASTLE_DA_WQS; i++)
    {
        castle_da_wqs[i] = create_workqueue(castle_da_wqs_names[i]);
        if (!castle_da_wqs[i])
        {
            castle_printk(LOG_ERROR, KERN_ALERT "Error: Could not alloc wq\n");
            goto err0;
        }
    }

    /* Initialise modlist iter mergesort buffer based on cache size.
     * As a minimum we need to be able to merge two full T0s. */
    min_budget = 2 * MAX_DYNAMIC_TREE_SIZE * C_CHK_SIZE;            /* Two full T0s. */
    budget     = (castle_cache_size_get() * PAGE_SIZE) / 10;        /* 10% of cache. */
    if (budget < min_budget)
        budget = min_budget;
    castle_printk(LOG_INIT, "Allocating %lluMB for modlist iter byte budget.\n",
            budget / C_CHK_SIZE);
    atomic_set(&castle_ct_modlist_iter_byte_budget, budget);
    mutex_init(&castle_da_level1_merge_init);

    /* Populate request_cpus with CPU ids ready to handle requests. */
    request_cpus.cpus = castle_alloc(sizeof(int) * num_online_cpus());
    if (!request_cpus.cpus)
        goto err0;
    request_cpus.cnt = 0;
    for_each_online_cpu(cpu)
    {
        request_cpus.cpus[request_cpus.cnt] = cpu;
        request_cpus.cnt++;
    }

    castle_da_hash = castle_da_hash_alloc();
    if(!castle_da_hash)
        goto err1;
    castle_ct_hash = castle_ct_hash_alloc();
    if(!castle_ct_hash)
        goto err2;

    castle_merge_threads_hash = castle_merge_threads_hash_alloc();
    if(!castle_merge_threads_hash)
        goto err3;

    castle_merges_hash = castle_merges_hash_alloc();
    if(!castle_merges_hash)
        goto err4;

    castle_data_exts_hash = castle_data_exts_hash_alloc();
    if(!castle_data_exts_hash)
        goto err5;

    castle_da_hash_init();
    castle_ct_hash_init();
    castle_merge_threads_hash_init();
    castle_merges_hash_init();
    castle_data_exts_hash_init();

    castle_da_cts_proxy_timer_fire(1);

    return 0;

err5:
    castle_free(castle_merges_hash);
err4:
    castle_free(castle_merge_threads_hash);
err3:
    castle_free(castle_ct_hash);
err2:
    castle_free(castle_da_hash);
err1:
    castle_free(request_cpus.cpus);
err0:
    for (j = 0; j < i; j++)
        destroy_workqueue(castle_da_wqs[j]);
    BUG_ON(!ret);
    return ret;
}

void castle_double_array_merges_fini(void)
{
    castle_da_exiting = 1;

    /* Write memory barrier to make sure all threads see castle_da_exiting. */
    wmb();

    castle_da_hash_iterate(castle_da_merge_restart, NULL);

    /* Wait for all merge threads to complete. */
    while (atomic_read(&castle_da_merge_thread_count))
        msleep(1000);

    /* Stop DA CTs proxy timer and invalidate any existing proxies. */
    del_singleshot_timer_sync(&castle_da_cts_proxy_timer);
    castle_da_cts_proxy_all_invalidate();

    /* This is happening at the end of execution. No need for the hash lock. */
    __castle_da_hash_iterate(castle_da_merge_stop, NULL);

    /* Also, wait for merges on deleted DAs. Merges will hold the last references to those DAs. */
    while (atomic_read(&castle_zombie_da_count))
        msleep(10);
}

void castle_double_array_fini(void)
{
    int i;
    debug("%s::start.\n", __FUNCTION__);

    castle_merge_hash_destroy();
    castle_da_hash_destroy();
    castle_ct_hash_destroy();
    castle_data_exts_hash_destroy();

    castle_free(request_cpus.cpus);

    for (i = 0; i < NR_CASTLE_DA_WQS; i++)
        destroy_workqueue(castle_da_wqs[i]);
    debug("%s::end.\n", __FUNCTION__);
}

static int castle_da_merge_check(struct castle_da_merge *merge, void *da)
{
    if (merge->da == da)
        castle_printk(LOG_ERROR, "Merge: %p, DA: %p\n", merge, da);

    BUG_ON(merge->da == da);

    return 0;
}

/**
 * NOTE: Called with transaction lock held.
 */
void castle_da_destroy_complete(struct castle_double_array *da)
{
    int i;

    /* Sanity Checks. */
    BUG_ON(!castle_da_deleted(da));

    BUG_ON(!CASTLE_IN_TRANSACTION);

    castle_printk(LOG_USERINFO, "Cleaning VerTree: %u\n", da->id);

    /* Shouldn't be any outstanding LFS victims. */
    BUG_ON(atomic_read(&da->lfs_victim_count));

    /* Clean-up any space reserved by LFS victims in past. */
    castle_da_lfs_ct_cleanup(&da->l1_merge_lfs);

    /* Invalidate DA CTs proxy structure. */
    castle_da_cts_proxy_invalidate(da);

    /* Destroy Component Trees. */
    for(i=0; i<MAX_DA_LEVEL; i++)
    {
        struct list_head *l, *lt;

        list_for_each_safe(l, lt, &da->levels[i].trees)
        {
            struct castle_component_tree *ct;

            ct = list_entry(l, struct castle_component_tree, da_list);

            /* There should be no outstanding merges. */
            BUG_ON(ct->merge || !MERGE_ID_INVAL(ct->merge_id));

            castle_sysfs_ct_del(ct);

            /* No outstanding merges and active attachments. Component Tree
             * shouldn't be referenced any-where. */
            BUG_ON(atomic_read(&ct->ref_count) != 1);
            BUG_ON(atomic_read(&ct->write_ref_count));

            /* It is possible that, there are few outstanding clients accessing sysfs. Take
             * write lock to avoid race with sysfs functions. */
            write_lock(&da->lock);
            castle_component_tree_del(da, ct);
            write_unlock(&da->lock);

            castle_ct_put(ct, READ /*rw*/, NULL);
        }
    }

    /* Shouldn't have any outstanding */
    castle_merges_hash_iterate(castle_da_merge_check, da);

    /* Destroy Version and Rebuild Version Tree. */
    castle_version_tree_delete(da->root_version);

    castle_sysfs_da_del_check(da);

    /* Dealloc the DA. */
    castle_da_dealloc(da);

    /* Delete the DA from the list of deleted DAs. */
    atomic_dec(&castle_zombie_da_count);
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
        BUG_ON(atomic_read(&da->attachment_cnt) != 0);
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
        BUG_ON(atomic_read(&da->attachment_cnt) != 0);
        BUG_ON((da->hash_list.next != NULL) || (da->hash_list.prev != NULL));
        BUG_ON(!castle_da_deleted(da));
        castle_da_destroy_complete(da);
    }
}

int castle_double_array_alive(c_da_t da_id)
{
    BUG_ON(!CASTLE_IN_TRANSACTION);

    return castle_da_hash_get(da_id) != NULL;
}

static struct castle_double_array *castle_da_ptr_get(c_da_t da_id, int attach)
{
    struct castle_double_array *da;
    unsigned long flags;

    read_lock_irqsave(&castle_da_hash_lock, flags);
    if ((da = __castle_da_hash_get(da_id)))
    {
        castle_da_get(da);
        if (attach)
            atomic_inc(&da->attachment_cnt);
    }

    read_unlock_irqrestore(&castle_da_hash_lock, flags);
    return da;
}

struct castle_double_array *castle_double_array_get(c_da_t da_id)
{
    return castle_da_ptr_get(da_id, 1 /* increase the attachment count */);
}

void castle_double_array_put(struct castle_double_array *da)
{
    /* DA allocated + our ref count on it. */
    BUG_ON(atomic_read(&da->ref_cnt) < 2);

    atomic_dec(&da->attachment_cnt);

    /* Put the ref cnt too. */
    castle_da_put(da);
}

/**
 * Prefetch extents associated with DA da.
 *
 * Blocks until all prefetch IO completes.
 */
int castle_double_array_prefetch(struct castle_double_array *da)
{
    struct castle_da_cts_proxy *proxy;
    int i;

    /* We don't need to take a reference to the DA because our caller should have done
     * that for us. */

    proxy = castle_da_cts_proxy_get(da);
    if (!proxy)
    {
        castle_printk(LOG_USERINFO, "Couldn't get CTs proxy for DA id=0x%x\n", da->id);
        return -EINVAL;
    }
    castle_printk(LOG_INFO, "Prefetching CTs for DA=%p id=0x%d\n", da, da->id);

    /* Prefetch CTs. */
    for (i = 0; i < proxy->nr_cts; i++)
        castle_component_tree_prefetch(proxy->cts[i].ct);

    castle_da_cts_proxy_put(proxy);
    return 0;
}

int castle_double_array_destroy(c_da_t da_id)
{
    struct castle_double_array *da;
    unsigned long flags;
    int ret;
    int attachment_cnt;

    write_lock_irqsave(&castle_da_hash_lock, flags);
    da = __castle_da_hash_get(da_id);
    /* Fail if we cannot find the da in the hash. */
    if (!da)
    {
        castle_printk(LOG_USERINFO, "No Version Tree exists with id: %u\n", da_id);
        ret = -EINVAL;
        goto err_out;
    }

    attachment_cnt = atomic_read(&da->attachment_cnt);
    BUG_ON(attachment_cnt < 0);
    /* Fail if there are attachments to the DA. */
    if (attachment_cnt > 0)
    {
        castle_printk(LOG_USERINFO, "Version Tree %u has %d outstanding attachments\n",
                      da_id, attachment_cnt);
        ret = -EBUSY;
        goto err_out;
    }

    BUG_ON(castle_da_deleted(da));

    /* Now we are happy to delete the DA. */

    /* Remove it from the hash. */
    __castle_da_hash_remove(da);
    da->hash_list.next = da->hash_list.prev = NULL;
    write_unlock_irqrestore(&castle_da_hash_lock, flags);

    /* Send an event to userspace. */
    castle_events_version_tree_destroyed(da->id);

    castle_sysfs_da_del(da);

    /* Invalidate, if there are any outstanding proxy references. */
    BUG_ON(da->cts_proxy && (atomic_read(&da->cts_proxy->ref_cnt) != 1));
    castle_da_cts_proxy_invalidate(da);

    castle_printk(LOG_USERINFO, "Marking DA %u for deletion\n", da_id);
    /* Set the destruction bit, which will stop further merges. */
    castle_da_deleted_set(da);

    /* Restart the merge threads, so that they get to exit, and drop their da refs. */
    castle_da_merge_restart(da, NULL);

    /* Increment count of zombie DAs. */
    atomic_inc(&castle_zombie_da_count);

    /* Put the (usually) last reference to the DA. */
    castle_da_put_locked(da);

    return 0;

err_out:
    write_unlock_irqrestore(&castle_da_hash_lock, flags);
    return ret;
}

/**
 * Set nice value for all merge threads within a DA.
 */
static int __castle_da_threads_priority_set(struct castle_double_array *da, void *_value)
{
    int nice_value = *((int *)_value);

    if (da->l1_merge_thread)
        set_user_nice(da->l1_merge_thread, nice_value + 15);

    return 0;
}

/**
 * Change the priority of merge threads for all doubling arrays.
 */
void castle_da_threads_priority_set(int nice_value)
{
    int i;

    castle_da_hash_iterate(__castle_da_threads_priority_set, &nice_value);

    for(i=0; i<NR_CASTLE_DA_WQS; i++)
        castle_wq_priority_set(castle_da_wqs[i]);
}

/**
 * Golden Nugget.
 */

static int castle_merge_run(void *_data)
{
    struct castle_merge_thread *merge_thread = (struct castle_merge_thread *)_data;
    struct castle_da_merge *merge;
    struct castle_double_array *da = merge_thread->da;
    c_time_interval_t waiting_stats;

    atomic_inc(&castle_da_merge_thread_count);

    /* Note: Already took a reference on da in castle_da_merge_fill_trees. Safe to access
     * da pointer. */

    castle_time_interval_init(&waiting_stats);
    do {
        int ret, ignore;
        uint64_t prev_nr_bytes;
        tree_seq_t out_tree_seq;

        /* Wait for next merge work unit assignment or the exit condition. */
        castle_time_interval_start(&waiting_stats);
        __wait_event_interruptible(da->merge_waitq,
                                   exit_cond || merge_thread->cur_work_size,
                                   ignore);
        castle_time_interval_stop(&waiting_stats);

        merge = castle_merges_hash_get(merge_thread->merge_id);

        /* Merge thread should skip the merge work, and exit. */
        if (exit_cond)
        {
            /* If DA is destroyed, get-rid off merge. */
            if (merge && castle_da_deleted(da))
                castle_da_merge_dealloc(merge, -ESTALE, 0 /* Not in transaction. */);

            break;
        }

        /* Work should be set by wake-up thread. */
        BUG_ON(!merge_thread->cur_work_size);
        BUG_ON(!merge);

        out_tree_seq  = merge->out_tree->seq;
        prev_nr_bytes = merge->nr_bytes;
        ret = castle_da_merge_do(merge, merge_thread->cur_work_size);

        merge_thread->cur_work_size = 0;
        wmb();

        /* Check if merge completed successfully. */
        if (!ret)
        {
            if (castle_ct_hash_get(out_tree_seq))
                castle_events_merge_work_finished(merge_thread->da->id,
                                                  merge_thread->merge_id,
                                                  merge_thread->work_id,
                                                  0, MERGE_COMPLETED);
            else
                castle_events_merge_work_finished(merge_thread->da->id,
                                                  merge_thread->merge_id,
                                                  merge_thread->work_id,
                                                  0, MERGE_COMPLETED_NO_OP_TREE);
            break;
        }
        /* Merge not completed, but work completed successfully.
         *              (or)
         * Merge not completed and work not completed. */
        else
        {
            BUG_ON(merge->nr_bytes < prev_nr_bytes);
            castle_events_merge_work_finished(merge_thread->da->id,
                                              merge_thread->merge_id,
                                              merge_thread->work_id,
                                              merge->nr_bytes - prev_nr_bytes,
                                              MERGE_NOT_COMPLETED);
        }

    } while(1);

    castle_time_interval_fini(&waiting_stats);
    castle_printk(LOG_INFO, "Finished merge: %d. Timing stats:\n", merge_thread->merge_id);
    castle_time_interval_print(LOG_INFO, &waiting_stats, "waiting for");

    merge_thread->merge_id = INVAL_MERGE_ID;

    castle_merge_threads_hash_remove(merge_thread);

    castle_free(merge_thread);

    atomic_dec(&castle_da_merge_thread_count);

    castle_da_put(da);

    /* Note: Merge thread code is not very clean. Changes from user level merge handling to kernel
     * are particularly. Clean it up before v2. */
    BUG_ON(kthread_should_stop());

    do_exit(0);

    return 0;
}

static int castle_merge_thread_create(c_thread_id_t *thread_id, struct castle_double_array *da)
{
    struct castle_merge_thread *merge_thread = castle_alloc(sizeof(struct castle_merge_thread));

    BUG_ON(!CASTLE_IN_TRANSACTION);

    *thread_id = INVAL_THREAD_ID;

    if (!merge_thread)
        return -EINVAL;

    merge_thread->merge_id      = INVAL_MERGE_ID;
    merge_thread->cur_work_size = 0;
    merge_thread->da            = da;
    merge_thread->thread        = kthread_create(castle_merge_run, merge_thread,
                                                 "castle_mt_%u", castle_merge_threads_count);
    if (IS_ERR(merge_thread->thread))
    {
        castle_printk(LOG_USERINFO, "Failed to create merge thread\n");
        castle_free(merge_thread);
        return -ENOMEM;
    }

    *thread_id = merge_thread->id = castle_merge_threads_count++;

    castle_merge_threads_hash_add(merge_thread);

    wake_up_process(merge_thread->thread);

    return 0;
}

static int castle_da_merge_fill_trees(uint32_t nr_arrays, c_array_id_t *array_ids,
                                      struct castle_component_tree **in_trees,
                                      struct castle_double_array *da)
{
    int i, found, ret;
    struct list_head *lh;

    /* Take read lock on DA, to make sure neither CTs nor DA would go away while looking at the
     * list. */
    read_lock(&da->lock);

    found = i = ret = 0;
    list_for_each(lh, &da->levels[2].trees)
    {
        struct castle_component_tree *ct = list_entry(lh, struct castle_component_tree, da_list);

        /* Skip trees, until we find the first one. */
        if (!found && ct->seq != array_ids[0])
            continue;

        found = 1;

        /* Once we find the first tree, trees should be in the same order. */
        if (ct->seq != array_ids[i])
        {
            BUG_ON(i == 0);
            castle_printk(LOG_USERINFO, "Expected contiguous arrays in the order latest(data) "
                                        "array first. But, array 0x%llx is not following 0x%llx\n",
                                        array_ids[i], array_ids[i-1]);
            ret = C_ERR_MERGE_ARRAYS_OOO;
            goto out;
        }

        /* Check if the tree is already marked for merge. */
        if (ct->merge)
        {
            castle_printk(LOG_USERINFO, "Array is already merging: 0x%llx\n", array_ids[i]);
            ret = C_ERR_MERGE_ARRAY_BUSY;
            goto out;
        }

        /* Btree types must always be the same. */
        BUG_ON(i && in_trees[i-1]->btree_type != ct->btree_type);

        /* Shouldn't be any outstanding write references. */
        BUG_ON(atomic_read(&ct->write_ref_count) != 0);

        /* Shouldn't be a empty tree. */
        BUG_ON(atomic64_read(&ct->item_count) == 0);

        in_trees[i++] = ct;

        /* If found all the trees in sequence, break. */
        if (i == nr_arrays)
            break;
    }

out:
    read_unlock(&da->lock);

    if (ret)
        return ret;

    if (i != nr_arrays)
    {
        castle_printk(LOG_USERINFO, "Couldn't find the array 0x%llx in the array list\n",
                                     array_ids[i]);
        return C_ERR_MERGE_INVAL_ARRAY;
    }

    return 0;
}

int castle_merge_start(c_merge_cfg_t *merge_cfg, c_merge_id_t *merge_id, int level)
{
    struct castle_component_tree **in_trees = NULL;
    struct castle_double_array *da = NULL;
    struct castle_da_merge *merge = NULL;
    int ret = 0;
    int i, j;
    c_thread_id_t thread_id = INVAL_THREAD_ID;

    *merge_id = INVAL_MERGE_ID;

    if (merge_cfg->nr_arrays == 0)
    {
        ret = C_ERR_MERGE_0TREES;
        castle_printk(LOG_USERINFO, "Can't do merge on 0 trees\n");
        goto err_out;
    }

    /* Allocate memory for list of input arrays. */
    in_trees = castle_alloc(sizeof(void *) * merge_cfg->nr_arrays);
    if (!in_trees)
    {
        ret = C_ERR_NOMEM;
        goto err_out;
    }

    /* Get a reference on the DA. */
    da = castle_da_ptr_get(merge_cfg->vertree,
                           0 /* don't increase the attachment count */);
    if (!da)
    {
        ret = C_ERR_MERGE_INVAL_DA;
        castle_printk(LOG_USERINFO, "Couldn't find DA with ID: 0x%x\n", merge_cfg->vertree);
        goto err_out;
    }

    /* Get array objects from IDs. */
    ret = castle_da_merge_fill_trees(merge_cfg->nr_arrays, merge_cfg->arrays, in_trees, da);
    if (ret)
        goto err_out;

    if (merge_cfg->nr_data_exts == MERGE_ALL_DATA_EXTS)
    {
        int k;

        /* Find the total number of data extents. */
        merge_cfg->nr_data_exts = 0;
        for (i=0; i<merge_cfg->nr_arrays; i++)
            merge_cfg->nr_data_exts += in_trees[i]->nr_data_exts;

        BUG_ON(merge_cfg->data_exts != NULL);
        merge_cfg->data_exts = castle_alloc(sizeof(c_ext_id_t) * merge_cfg->nr_data_exts);
        if (!merge_cfg->data_exts)
        {
            castle_printk(LOG_USERINFO, "Failed to allocate memory\n");
            ret = C_ERR_NOMEM;
            goto err_out;
        }

        for (i=0, k=0; i<merge_cfg->nr_arrays; i++)
        {
            memcpy(&merge_cfg->data_exts[k], in_trees[i]->data_exts,
                   sizeof(c_ext_id_t) * in_trees[i]->nr_data_exts);
            k += in_trees[i]->nr_data_exts;
        }

        BUG_ON(k != merge_cfg->nr_data_exts);

        /* FIXME: There could be duplicate data extents in this list, if we allow multiple
         * CTs referring same data extent. Review the code once. */
    }

    /* Check if any of the data extents are not valid. */
    for (i=0; i<merge_cfg->nr_data_exts; i++)
    {
        if (castle_data_exts_hash_get(merge_cfg->data_exts[i]) == NULL)
        {
            castle_printk(LOG_USERINFO, "Data extent %llu is not valid\n",
                                        merge_cfg->data_exts[i]);
            ret = C_ERR_MERGE_INVAL_EXT;
            goto err_out;
        }
    }

    /* Data extents should belong to one of the input trees. */
    for (i=0; i<merge_cfg->nr_data_exts; i++)
    {
        for (j=0; j<merge_cfg->nr_arrays; j++)
            if (check_dext_list(merge_cfg->data_exts[i], in_trees[j]->data_exts,
                                in_trees[j]->nr_data_exts))
                break;

        if (j == merge_cfg->nr_arrays)
        {
            castle_printk(LOG_USERINFO, "Data extent %llu is not linked to any of the in-trees\n",
                                        merge_cfg->data_exts[i]);
            ret = C_ERR_MERGE_ORPHAN_EXT;
            goto err_out;
        }
    }

    /* Allocate and init merge structure. */
    merge = castle_da_merge_alloc(merge_cfg->nr_arrays, 2, da, INVAL_MERGE_ID, in_trees,
                                  merge_cfg->nr_data_exts, merge_cfg->data_exts);
    if (!merge)
    {
        castle_printk(LOG_USERINFO, "Couldn't allocate merge structure.\n");
        ret = C_ERR_NOMEM;
        goto err_out;
    }
    castle_check_free(in_trees);

    ret = castle_da_merge_init(merge, NULL);
    if (ret < 0)
    {
        castle_printk(LOG_USERINFO, "Failed to init merge.\n");

        if (ret == -ENOSPC)
            ret = C_ERR_NOSPC;
        else if (ret == -ENOMEM)
            ret = C_ERR_NOMEM;
        else
            ret = C_ERR_MERGE_INIT;

        /* merge_init() would deallocate on failure. */
        merge = NULL;
        goto err_out;
    }

    *merge_id = merge->id;

    if (castle_merge_thread_create(&thread_id, da) < 0)
    {
        ret = C_ERR_MERGE_THREAD;
        castle_printk(LOG_USERINFO, "Failed to create merge thread\n");
        goto err_out;
    }

    /* Attach merge thread to merge. */
    BUG_ON(castle_merge_thread_attach(merge->id, thread_id) < 0);

    return 0;

err_out:

    if (da)
        castle_da_put(da);

    /* All user-space errors are +ve. */
    BUG_ON(ret <= 0);
    if (merge)
        castle_da_merge_dealloc(merge, ret, 1 /* In transaction. */);

    castle_check_free(in_trees);

    return ret;
}

int castle_merge_do_work(c_merge_id_t merge_id, c_work_size_t work_size, c_work_id_t *work_id)
{
    struct castle_da_merge *merge = castle_merges_hash_get(merge_id);
    struct castle_merge_thread *merge_thread = NULL;
    int ret = 0;

    *work_id = INVAL_WORK_ID;

    if (!merge)
    {
        castle_printk(LOG_WARN, "Failed to find an active merge with id: %u\n", merge_id);
        ret = C_ERR_MERGE_INVAL_ID;
        goto err_out;
    }

    if (THREAD_ID_INVAL(merge->thread_id))
    {
        castle_printk(LOG_WARN, "Can't do merge as it is not attached to any thread: %u\n",
                      merge_id);
        ret = C_ERR_MERGE_ERROR;
        goto err_out;
    }

    merge_thread = castle_merge_threads_hash_get(merge->thread_id);
    BUG_ON(!merge_thread);
    BUG_ON(merge_thread->merge_id != merge_id);

    if (merge_thread->cur_work_size)
    {
        castle_printk(LOG_WARN, "Can't do merge as it is already doing work: %u\n", merge_id);
        ret = C_ERR_MERGE_RUNNING;
        goto err_out;
    }

    merge_thread->cur_work_size = work_size;
    wmb();

    merge_thread->work_id = *work_id = castle_merge_max_work_id++;

    wake_up(&merge_thread->da->merge_waitq);

    return 0;

err_out:
    /* All user-space errors are +ve. */
    BUG_ON(ret <= 0);

    return ret;
}

int castle_merge_stop(c_merge_id_t merge_id)
{
    return 0;
}

static int castle_merge_thread_attach(c_merge_id_t merge_id, c_thread_id_t thread_id)
{
    struct castle_da_merge *merge = castle_merges_hash_get(merge_id);
    struct castle_merge_thread *merge_thread = NULL;
    int ret = 0;

    if (!merge)
    {
        castle_printk(LOG_WARN, "Failed to find an active merge with id: %u\n", merge_id);
        ret = -EINVAL;
        goto err_out;
    }

    if (!THREAD_ID_INVAL(merge->thread_id))
    {
        castle_printk(LOG_WARN, "Merge (%u) is already attached to thread (%u)\n",
                      merge_id, merge->thread_id);
        ret = -EINVAL;
        goto err_out;
    }

    merge_thread = castle_merge_threads_hash_get(thread_id);
    if (!merge_thread)
    {
        castle_printk(LOG_WARN, "Failed to find a thread with id: %u\n", thread_id);
        ret = -EINVAL;
        goto err_out;
    }

    if (!MERGE_ID_INVAL(merge_thread->merge_id))
    {
        castle_printk(LOG_WARN, "Thread (%u) is already attached to merge (%u)\n",
                      thread_id, merge_thread->merge_id);
        ret = -EINVAL;
        goto err_out;
    }

    merge_thread->merge_id = merge_id;
    merge->thread_id       = thread_id;
    wmb();

    return 0;

err_out:
    return ret;
}

int castle_da_vertree_tdp_set(c_da_t da_id, uint64_t seconds)
{
    struct castle_double_array *da = castle_da_hash_get(da_id);
    if (da == NULL)
    {
        castle_printk(LOG_WARN, "Cannot set tombstone discard period on invalid da: %u\n", da_id);
        return -EINVAL;
    }
    atomic64_set(&da->tombstone_discard_threshold_time_s, seconds);
    castle_printk(LOG_USERINFO, "Set tombstone discard period on da %u to %llu seconds\n",
            da_id, seconds);
    return 0;
}

/**
 * Iterate over all cts in a doubling array associated with a merge, and return the
 * min timestamp of all trees not associated with the merge.
 *
 * Needed for tombstone discard.
 *
 * @also __castle_da_foreach_tree
 */
castle_user_timestamp_t castle_da_min_ts_cts_exclude_this_merge_get(struct castle_da_merge *merge)
{
    struct castle_component_tree *ct;
    struct list_head *lh;
    int i;
    castle_user_timestamp_t min_ts = ULLONG_MAX;

    BUG_ON(!merge);

    /* Assert that the input trees of the merge have been sufficiently initialised */
    FOR_EACH_MERGE_TREE(i, merge)
    {
        BUG_ON(merge->in_trees[i]->merge_id != merge->id);
    }
    BUG_ON(merge->out_tree->merge_id != merge->id);

    /* Take read lock on DA, to make sure neither CTs nor DA would go away while looking at the
     * list. */
    read_lock(&merge->da->lock);
    for(i=0; i<MAX_DA_LEVEL; i++)
    {
        list_for_each(lh, &merge->da->levels[i].trees)
        {
            ct = list_entry(lh, struct castle_component_tree, da_list);
            if (ct->merge_id != merge->id)
                min_ts = min(min_ts, (uint64_t)atomic64_read(&ct->min_user_timestamp));
        }
    }
    read_unlock(&merge->da->lock);

    return min_ts;
}

