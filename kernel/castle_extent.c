#include <linux/mm.h>
#include <linux/kthread.h>
#include <linux/vmalloc.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/random.h>
#include <linux/delay.h>

#include "castle.h"
#include "castle_debug.h"
#include "castle_utils.h"
#include "castle_rda.h"
#include "castle_freespace.h"
#include "castle_extent.h"
#include "castle_cache.h"
#include "castle_da.h"
#include "castle_rebuild.h"
#include "castle_events.h"
#include "castle_freespace.h"
#include "castle_mstore.h"

/* Extent manager - Every disk reserves few chunks in the begining of the disk to
 * store meta data. Meta data for freespace management (for each disk) would be
 * stored only on specific disk. Meta data for extent management is stored
 * across multiple disks. This meta data is stored in terms of special extents.
 *
 * Super Extent - One for each disk. Located on initial chunks [SUP_EXT_SIZE] for
 * each disk. First chunk contains super block. Next subsequent chunks contain the
 * freespace data structures.
 *
 * Micro Extent - Contains mappings for meta extent. Replicated on all disks.
 *
 * Meta Extent - One extent for the complete system to store extent manager's
 * structures i.e. extent strcuture and chunk mappings. This extent is spread
 * and replicated across all disks to reduce the riscue of failure. Meta data of
 * this extent is stored on all disks (in Super extent).
 */

//#define DEBUG
#ifdef DEBUG
#define debug(_f, _a...)        (castle_printk(LOG_DEBUG, _f, ##_a))
#define debug_mask(_f, _a...)   (castle_printk(LOG_DEBUG, _f, ##_a))
#define debug_resize(_f, _a...) (castle_printk(LOG_DEBUG, _f, ##_a))
#define debug_schks(_f, _a...)  (castle_printk(LOG_DEBUG, _f, ##_a))
#define debug_ext_ref(_f, _a...)  (castle_printk(LOG_DEBUG, _f, ##_a))
#define debug_res_pools(_f, _a...)  (castle_printk(LOG_DEBUG, _f, ##_a))
#else
#define debug(_f, ...)          ((void)0)
#define debug_mask(_f, ...)     ((void)0)
#define debug_resize(_f, ...)   ((void)0)
#define debug_schks(_f, ...)    ((void)0)
#define debug_ext_ref(_f, _a...)  ((void)0)
#define debug_res_pools(_f, _a...)  ((void)0)
#endif

#if 0
#undef debug_res_pools
#define debug_res_pools(_f, _a...)  (printk(_f, ##_a))
#endif

#if 0
#undef debug_resize
#define debug_resize(_f, _a...)  (printk(_f, ##_a))
#endif

#define MAP_IDX(_ext, _i, _j)       (((_ext)->k_factor * _i) + _j)
#define CASTLE_EXTENTS_HASH_SIZE    100

#define GET_LATEST_MASK(_ext)   ((!list_empty(&(_ext)->mask_list))?                          \
                                 (list_entry((_ext)->mask_list.next, c_ext_mask_t, list)):   \
                                 NULL)
#define GET_OLDEST_MASK(_ext)   ((!list_empty(&(_ext)->mask_list))?                          \
                                 (list_entry((_ext)->mask_list.prev, c_ext_mask_t, list)):   \
                                 NULL)

#define IS_OLDEST_MASK(_ext, _mask)     list_is_last(&((_mask)->list), &((_ext)->mask_list))

#define SUPER_CHUNK_STRUCT(chk_idx)  ((c_chk_seq_t){chk_idx, CHKS_PER_SLOT})

/* Note: load_extent_from_mentry() deals with complete extent deserialization. This
 * is just a helper function. */
#ifdef CASTLE_PERF_DEBUG
#define CONVERT_MENTRY_TO_EXTENT(_ext, _me)                                 \
        (_ext)->ext_id      = (_me)->ext_id;                                \
        (_ext)->size        = (_me)->size;                                  \
        (_ext)->type        = (_me)->type;                                  \
        (_ext)->k_factor    = (_me)->k_factor;                              \
        (_ext)->maps_cep    = (_me)->maps_cep;                              \
        (_ext)->curr_rebuild_seqno = (_me)->curr_rebuild_seqno;             \
        (_ext)->ext_type    = (_me)->ext_type;                              \
        (_ext)->da_id       = (_me)->da_id;                                 \
        (_ext)->dirtytree->ext_size = (_me)->size;                          \
        (_ext)->dirtytree->ext_type = (_me)->ext_type;
#else
#define CONVERT_MENTRY_TO_EXTENT(_ext, _me)                                 \
        (_ext)->ext_id      = (_me)->ext_id;                                \
        (_ext)->size        = (_me)->size;                                  \
        (_ext)->type        = (_me)->type;                                  \
        (_ext)->k_factor    = (_me)->k_factor;                              \
        (_ext)->maps_cep    = (_me)->maps_cep;                              \
        (_ext)->curr_rebuild_seqno = (_me)->curr_rebuild_seqno;             \
        (_ext)->ext_type    = (_me)->ext_type;                              \
        (_ext)->da_id       = (_me)->da_id;
#endif

#define CONVERT_EXTENT_TO_MENTRY(_ext, _me)                                 \
        (_me)->ext_id       = (_ext)->ext_id;                               \
        (_me)->size         = (_ext)->size;                                 \
        (_me)->type         = (_ext)->type;                                 \
        (_me)->k_factor     = (_ext)->k_factor;                             \
        (_me)->maps_cep     = (_ext)->maps_cep;                             \
        (_me)->curr_rebuild_seqno = (_ext)->curr_rebuild_seqno;             \
        (_me)->ext_type     = (_ext)->ext_type;                             \
        (_me)->cur_mask     = GET_LATEST_MASK(_ext)->range;                 \
        (_me)->prev_mask    = (_ext)->global_mask;                          \
        (_me)->da_id        = (_ext)->da_id;

#define FAULT_CODE EXTENT_FAULT

#define cemr_cstr           "[%u:%u)"
#define cemr2str(_r)        (_r).start, (_r).end

c_chk_cnt_t meta_ext_size = 0;

struct castle_extents_superblock castle_extents_global_sb;
static DEFINE_MUTEX(castle_extents_mutex);

struct castle_extent;

/**
 * Structure to keep the partial superchunks that extent owns.
 *
 * Rebuild makes extent space mapping un-predictable. We can't assume any layout for a
 * given superchunk. With extent resize operations, it is possible to delete parts of
 * extents seperately. So, we maintain outstadning partial superchunks in the extent.
 */
typedef struct castle_partial_schk {
    uint32_t            slave_id;       /**< Slave ID, this superchunk belongs to.      */
    c_chk_cnt_t         first_chk;      /**< First chunk's offset.                      */
    uint8_t             count;          /**< Number of chunks left in this super chunk. */
    struct list_head    list;           /**< Link to extent.                            */
} c_part_schk_t;

/**
 * Extent mask represents a range of logical chunks in extent space. It gives a view
 * of the valid chunks in extent. When the reference count of mask becomes zero, it is
 * safe to delete mask and also chunks that are invalid after this mask.
 */
typedef struct castle_extent_mask {
    c_ext_mask_id_t         mask_id;        /**< Unique mask ID.                        */
    c_ext_mask_range_t      range;
    atomic_t                ref_count;      /**< Number of references on this mask.     */
    struct list_head        list;           /**< Link to extent mask list.              */
    struct list_head        hash_list;      /**< Link to hash list.                     */
    struct castle_extent   *ext;            /**< Extent that this mask belongs to.      */
} c_ext_mask_t;

static int castle_extent_mask_create(c_ext_t          *ext,
                                     c_ext_mask_range_t range,
                                     c_ext_mask_id_t   prev_mask_id);

static inline c_ext_pos_t castle_extent_map_cep_get(c_ext_pos_t     map_start,
                                                    c_chk_t         chk_idx,
                                                    uint32_t        k_factor);

static c_ext_mask_id_t castle_extent_get_ptr(c_ext_id_t ext_id, c_ext_t **ext);

#define CASTLE_EXTENT_MASK_HASH_SIZE 100

static struct list_head *castle_extent_mask_hash = NULL;

static DECLARE_WAIT_QUEUE_HEAD (castle_ext_mask_gc_wq);

DEFINE_HASH_TBL(castle_extent_mask, castle_extent_mask_hash, CASTLE_EXTENT_MASK_HASH_SIZE,
                c_ext_mask_t, hash_list, c_ext_mask_id_t, mask_id);

static struct list_head *castle_extents_hash = NULL;
static c_ext_free_t meta_ext_free;

atomic_t castle_extents_gc_q_size = ATOMIC(0);

static LIST_HEAD(castle_ext_mask_free_list);

static atomic_t castle_extent_max_mask_id = ATOMIC(0);
/**
 * Low freespace victim handling structure.
 */
typedef struct c_ext_event {
    c_ext_event_callback_t  callback;              /**< Callback to be called when more
                                                     *< disk space is available.          */
    void                   *data;
    struct list_head        list;
} c_ext_event_t;

static c_ext_id_t _castle_extent_alloc(c_rda_type_t   rda_type,
                                       c_da_t         da_id,
                                       c_ext_type_t   ext_type,
                                       c_chk_cnt_t    ext_size,
                                       c_chk_cnt_t    alloc_size,
                                       c_ext_id_t     ext_id,
                                       c_ext_event_t *hdl);
void __castle_extent_dirtytree_put(c_ext_dirtytree_t *dirtytree, int check_hash);

static void castle_extent_mask_reduce(c_ext_t             *ext,
                                      c_ext_mask_range_t   base,
                                      c_ext_mask_range_t   range1,
                                      c_ext_mask_range_t  *global_mask,
                                      int                  do_free);

DEFINE_HASH_TBL(castle_extents, castle_extents_hash, CASTLE_EXTENTS_HASH_SIZE,
                c_ext_t, hash_list, c_ext_id_t, ext_id);

#define CASTLE_RES_POOL_HASH_SIZE 100
static struct list_head *castle_res_pool_hash = NULL;

DEFINE_HASH_TBL(castle_res_pool, castle_res_pool_hash, CASTLE_RES_POOL_HASH_SIZE, c_res_pool_t, hash_list, c_res_pool_id_t, id);

static c_res_pool_id_t castle_next_res_pool_id = 0;

c_ext_t sup_ext = {
    .ext_id         = SUP_EXT_ID,
    .size           = SUP_EXT_SIZE,
    .type           = SUPER_EXT,
    .k_factor       = 2,
    .maps_cep       = INVAL_EXT_POS,
};

uint8_t extent_init_done = 0;
uint8_t extents_allocable = 0; /**< Stops non-logical extent allocation before
                                    the filesystem initialisation gets far enough
                                    (in particular that it completes a checkpoint
                                     after meta extent compation). */

static LIST_HEAD            (castle_lfs_victim_list);

/* Extent processing (rebuild, rebalance) definitions.*/
struct workqueue_struct     *castle_extproc_workq;  /* Used to queue async I/O */
static wait_queue_head_t    process_waitq;      /* Controls activity of processing thread. */
struct task_struct          *extproc_thread;
static struct list_head     extent_list;        /* Extents to be processed. */
static struct list_head     processed_list;     /* Extent ranges that have had data processed. */
static struct list_head     writeback_list;     /* Extent ranges that can have maps written back. */

static struct list_head     verify_list;        /* Used for testing. */

#define IO_SLEEP_TIME 100 // In microseconds.

/* Used for sync with checkpoint thread. */
wait_queue_head_t           process_syncpoint_waitq;
atomic_t                    castle_extents_presyncvar  = ATOMIC_INIT(0);
atomic_t                    castle_extents_postsyncvar = ATOMIC_INIT(0);

static int                  rebuild_required(void);

/*
 * A difference between current_rebuild_seqno and rebuild_to_seqno indicates that
 * current_rebuild_seqno has changed doing a rebuild. This can be due to a slave going
 * out-of-service or being evacuated. If a difference is discovered the rebuild is
 * restarted when it finishes it's current run to pick up and remap any extents that
 * have already been remapped to the (old) current_rebuild_seqno.
 */
atomic_t                    current_rebuild_seqno;/* The current sequence number */
static int                  rebuild_to_seqno;     /* The sequence number being rebuilt to */

/* Persistent (via mstore) count of chunks remapped during rebuild run. */
long                        castle_extents_chunks_remapped = 0;

static int submit_async_remap_io(c_ext_t *ext, int chunkno, c_disk_chk_t *remap_chunks,
                                 int remap_idx);

static atomic_t             castle_extents_dead_count = ATOMIC(0);

struct task_struct         *extents_gc_thread;

static struct kmem_cache   *castle_partial_schks_cache = NULL;

static int                  min_rda_lvl = RDA_2; /* Keep track of minimum RDA used for extents. */

/**
 * Reservation pools.
 */

static USED void castle_res_pool_print(c_res_pool_t *pool)
{
    struct list_head *lh;

    if (RES_POOL_INVAL(pool->id))
        debug_res_pools("INVAL_RES_POOL\n");
    else
        debug_res_pools("%u\n", pool->id);

    rcu_read_lock();

    /* Go through all live slaves and remove reservations for them for this pool. */
    list_for_each_rcu(lh, &castle_slaves.slaves)
    {
        struct castle_slave *slave = list_entry(lh, struct castle_slave, list);

        /* If the slave is OOS, no point in keeping track of reservations. */
        if (test_bit(CASTLE_SLAVE_OOS_BIT, &slave->flags))
            continue;

        debug_res_pools("%u - %d:%u:%u\n", slave->id,
                                           pool->reserved_schks[slave->id],
                                           pool->freed_schks[slave->id],
                                           pool->frozen_freed_schks[slave->id]);
    }

    rcu_read_unlock();
}

c_chk_cnt_t castle_res_pool_available_space(c_res_pool_t *pool, struct castle_slave *cs)
{
    c_signed_chk_cnt_t space = pool->reserved_schks[cs->id];

    if (space > 0)
        return (c_chk_cnt_t)space;

    return 0;
}

static void castle_res_pool_unreserve(c_res_pool_t *pool)
{
    struct list_head *lh;

    BUG_ON(!castle_extent_in_transaction());

    debug_res_pools("Unreserving all reserved chunks from pool: %u\n", pool->id);

    rcu_read_lock();

    /* Go through all live slaves and remove reservations for them for this pool. */
    list_for_each_rcu(lh, &castle_slaves.slaves)
    {
        struct castle_slave *slave = list_entry(lh, struct castle_slave, list);

        /* If the slave is OOS, no point in keeping track of reservations. */
        if (test_bit(CASTLE_SLAVE_OOS_BIT, &slave->flags))
            continue;

        debug_res_pools("\t%d super chunks from slave: 0x%x\n",
                        pool->reserved_schks[slave->id], slave->uuid);

        /* If we got any reserved superchunks, this function will give them back to freespace.
         * If we have overallocated superchunks, just ignore them; freespace counters don't
         * keep-track the overallocated superchunks. If we got outstanding freed-superchunks,
         * we can ignore them as well; These chunks will be added to un-reserved space. */
        /* Unreserve all the space from this slave. */
        castle_freespace_slave_superchunks_unreserve(slave, 0, pool);
    }

    rcu_read_unlock();
}

static void castle_res_pool_append(c_res_pool_t *pool1, c_res_pool_t *pool2)
{
    struct list_head *lh;

    rcu_read_lock();

    /* Go through all live slaves and append reservations for pool2 to pool1. */
    list_for_each_rcu(lh, &castle_slaves.slaves)
    {
        struct castle_slave *slave = list_entry(lh, struct castle_slave, list);
        int id = slave->id;

        pool1->reserved_schks[id]        += pool2->reserved_schks[id];
        pool1->frozen_freed_schks[id]    += pool2->frozen_freed_schks[id];
        pool1->freed_schks[id]           += pool2->freed_schks[id];

        pool2->reserved_schks[id] = pool2->frozen_freed_schks[id] = pool2->freed_schks[id] = 0;
    }

    rcu_read_unlock();
}

static void castle_res_pool_init(c_res_pool_t *pool)
{
    memset(pool, 0, sizeof(c_res_pool_t));

    atomic_set(&pool->ref_count, 1);

    pool->id = INVAL_RES_POOL;
    INIT_LIST_HEAD(&pool->hash_list);
}

int castle_res_pool_is_alive(c_res_pool_id_t pool_id)
{
    if (castle_res_pool_hash_get(pool_id))
        return 1;

    return 0;
}

/**
 * Reserves space for the pool, based on RDA_TYPE provided.
 *
 * @param [in]      rda_type        Type of the RDA that should be used to pick slaves and layout.
 * @param [in]      logical_chk_cnt Number of logical chunks client is looking for, RDA decides
 *                                  how many physical chunks to be used from each slave.
 * @param [inout]   pool            Reservation pool that reserved chunks to be added to.
 *
 * @return 0 SUCCESS  Reservation succeeded.
 *        -1 FAILURE  Couldn't find space on slaves.
 */
int __castle_extent_space_reserve(c_rda_type_t       rda_type,
                                  c_chk_cnt_t        logical_chk_cnt,
                                  c_res_pool_t      *pool)
{
    BUG_ON(!castle_extent_in_transaction());

    /* This part of the RDA code is very specific to RDA type. Review the code when we add
     * more RDA types. */
    BUG_ON((rda_type != RDA_1) && (rda_type != RDA_2) &&
           (rda_type != SSD_RDA_2) && (rda_type != SSD_RDA_3) && (rda_type != SSD_ONLY_EXT));

    debug_res_pools("Reserving %u chunks for pool: %u for RDA: %s\n",
                    logical_chk_cnt, pool->id, castle_rda_type_str[rda_type]);

    /* Handle SSD_RDA as a special case. */
    if ((rda_type == SSD_RDA_2) || (rda_type == SSD_RDA_3))
    {
        c_res_pool_t *local_pool;
        int ret;

        local_pool = castle_alloc(sizeof(c_res_pool_t));
        if (!local_pool)
            return -ENOSPC;

        /* All reservation pool operations are done first on a local pool, and updated to
         * the client pool only on success. As, it is hard to find-out how many superchunks
         * are reserved in this session, in case of failure. If it is a local pool, we just
         * destroy it on failure. */
        /* All freespace pool functions can/should work on pools without any valid ID (so
         * not in hash). They just depend on pool object. */
        castle_res_pool_init(local_pool);

        /* First reserve some space on hard drives. */
        ret = castle_rda_space_reserve(castle_ssdrda_to_rda(rda_type),
                                       logical_chk_cnt,
                                       local_pool);
        if (ret < 0)
        {
            debug_res_pools("Failed to reserve %u chunks for pool: %u for RDA: %s\n",
                             logical_chk_cnt, pool->id,
                             castle_rda_type_str[castle_ssdrda_to_rda(rda_type)]);
            castle_free(local_pool);
            return -ENOSPC;
        }

        /* Reserve space on SSDs. */
        ret = castle_rda_space_reserve(SSD_ONLY_EXT, logical_chk_cnt, local_pool);
        /* Failed to allocate space on SSDs. */
        if (ret < 0)
        {
            debug_res_pools("Failed to reserve %u chunks for pool: %u for RDA: %s\n",
                             logical_chk_cnt, pool->id,
                             castle_rda_type_str[SSD_ONLY_EXT]);
            /* Unreserve space allocated on hard drives. */
            castle_res_pool_unreserve(local_pool);
            castle_free(local_pool);
            return -ENOSPC;
        }

        /* Move space from local pool to reserved pool. */
        castle_res_pool_append(pool, local_pool);

        castle_free(local_pool);

        return 0;
    }

    /* Reserve space for SSD_ONLY_EXT or DEFAULT_RDA. */
    return castle_rda_space_reserve(rda_type, logical_chk_cnt, pool);
}

int castle_extent_space_reserve(c_rda_type_t       rda_type,
                                c_chk_cnt_t        logical_chk_cnt,
                                c_res_pool_id_t    pool_id)
{
    c_res_pool_t *pool;
    int ret;

    castle_extent_transaction_start();

    pool = castle_res_pool_hash_get(pool_id);

    /* Pool should be a valid one. */
    BUG_ON(!pool);

    /* Call low level function. */
    ret = __castle_extent_space_reserve(rda_type, logical_chk_cnt, pool);

    castle_extent_transaction_end();

    return ret;
}

/**
 * Creates a new reservation pool.
 *
 * Space allocation has to be done RDA specific and actual space allocation happens within
 * freespace. Freespace modules need reservation pool in hash before adding space. Seperating
 * space allocation from pool_create().
 *
 * @also castle_da_merge_init()
 */
c_res_pool_id_t castle_res_pool_create(c_rda_type_t rda_type, c_chk_cnt_t logical_chk_cnt)
{
    c_res_pool_t *pool;

    /* Should be part of a extent transaction, to avoid race with checkpoints. */
    castle_extent_transaction_start();

    pool = castle_alloc(sizeof(c_res_pool_t));
    if (!pool)
        goto out;

    /* Init the pool. */
    castle_res_pool_init(pool);

    /* Reserve space for it. */
    if (logical_chk_cnt && __castle_extent_space_reserve(rda_type, logical_chk_cnt, pool))
    {
        /* Failed to allocate space for pool. */
        castle_extent_transaction_end();
        castle_free(pool);

        return INVAL_RES_POOL;
    }

    /* Get a new pool ID. */
    pool->id = castle_next_res_pool_id++;

    /* Add to the hash table. */
    castle_res_pool_hash_add(pool);

    debug_res_pools("Created reservation pool: %u and reserved %u chunks\n",
                     pool->id, logical_chk_cnt);

out:
    castle_extent_transaction_end();

    return (pool? pool->id: INVAL_RES_POOL);
}

void __castle_res_pool_destroy(c_res_pool_t *pool)
{
    castle_printk(LOG_DEBUG, "Destroying pool: %u\n", pool->id);

    castle_res_pool_print(pool);

    castle_res_pool_unreserve(pool);

    castle_res_pool_print(pool);

    castle_res_pool_hash_remove(pool);

    BUG_ON(castle_res_pool_hash_get(pool->id));

    castle_free(pool);
}

void castle_res_pool_destroy(c_res_pool_id_t pool_id)
{
    c_res_pool_t *pool;

    castle_extent_transaction_start();

    pool = castle_res_pool_hash_get(pool_id);

    if (atomic_dec_return(&pool->ref_count) == 0)
        __castle_res_pool_destroy(pool);

    castle_extent_transaction_end();
}

void __castle_res_pool_extent_attach(c_res_pool_t *pool, c_ext_t *ext)
{
    BUG_ON(!castle_extent_in_transaction());

    ext->pool = pool;
    atomic_inc(&pool->ref_count);
}

void castle_res_pool_extent_attach(c_res_pool_id_t pool_id, c_ext_id_t ext_id)
{
    c_res_pool_t *pool;
    c_ext_t *ext;

    castle_extent_transaction_start();

    pool = castle_res_pool_hash_get(pool_id);
    ext = castle_extents_hash_get(ext_id);

    /* If we can't get extent or pool, something is wrong with client. */
    BUG_ON(!pool || !ext);

    __castle_res_pool_extent_attach(pool, ext);

    debug_res_pools("Attached reservation pool %u to extent %llu\n", pool->id, ext->ext_id);

    castle_extent_transaction_end();
}

void __castle_res_pool_extent_detach(c_ext_t *ext)
{
    c_res_pool_t *pool = ext->pool;

    BUG_ON(!castle_extent_in_transaction());

    BUG_ON(!pool);

    if (atomic_dec_return(&pool->ref_count) == 0)
        __castle_res_pool_destroy(pool);

    ext->pool = NULL;
}

void castle_res_pool_extent_detach(c_ext_id_t ext_id)
{
    c_ext_t *ext;

    castle_extent_transaction_start();

    ext = castle_extents_hash_get(ext_id);

    /* If we can't get extent or pool, something is wrong with client. */
    BUG_ON(!ext);

    debug_res_pools("Detached reservation pool %u to extent %llu\n", ext->pool->id, ext->ext_id);

    __castle_res_pool_extent_detach(ext);

    castle_extent_transaction_end();
}

/* rlist_entry is too big to keep it on stack, and it is un-necessary to allocate for each pool.
 * Checkpoint is anyway serialised process. Just use this global buffer. */
struct castle_rlist_entry global_rentry_buffer;

/* Should be called with extent lock held. Keeps freespace and extents in sync. */
static int castle_res_pool_writeback(c_res_pool_t *pool, void *store)
{
    c_mstore_t *mstore = store;
    struct castle_rlist_entry *entry = &global_rentry_buffer;
    struct list_head *lh;
    int i = 0;

    /* Reservation pools, extents and freespace consistency is very much tied to extent transaction
     * lock. Very important to hold this. */
    BUG_ON(!castle_extent_in_transaction());

    debug_res_pools("Writing back reservation pool %u\n", pool->id);
    BUG_ON(pool->id >= castle_next_res_pool_id);

    /* FIXME: Current checkpoint error handling is not handled properly. Even passing error
     * wouldn't help much. */
    BUG_ON(!entry);

    /* Set entry to 0. */
    memset(entry, 0, sizeof(struct castle_rlist_entry));

    /* Set frozen counters to 0. */
    memset(pool->frozen_freed_schks, 0, sizeof(c_chk_cnt_t) * MAX_NR_SLAVES);

    /* Set the reservation pool ID. */
    entry->id = pool->id;

    rcu_read_lock();

    /* Go through all live slaves and commit the reservations for them for this pool. */
    list_for_each_rcu(lh, &castle_slaves.slaves)
    {
        struct castle_slave *slave = list_entry(lh, struct castle_slave, list);
        int id = slave->id;

        /* If the slave is OOS, no point in keeping track of reservations. */
        if (test_bit(CASTLE_SLAVE_OOS_BIT, &slave->flags))
            continue;

        castle_res_pool_counter_check(pool, id);

        /* Commit only non-zero reservations. During init, we stop looking when we see
         * zero reservation. */
        if (pool->reserved_schks[id] + ((c_signed_chk_cnt_t)pool->freed_schks[id]) == 0)
            goto skip_slave;

        /* We maintian freed superchunks only for the sake of not over using reserved space.
         * If we already over-allocating space, it should compenstate freed space. Never
         * include overallocated chunks in freed_schks. */
        BUG_ON((pool->reserved_schks[id] < 0) && pool->freed_schks[id]);

        /* Calculate the reserved_schks count. */
        entry->slaves[i].reserved_schks = pool->reserved_schks[id] +
                                         ((c_signed_chk_cnt_t)pool->freed_schks[id]);

        /* Prepare mstore entry. */
        entry->slaves[i].uuid           = slave->uuid;

        debug_res_pools("\t%d chunks from slave: 0x%x\n", entry->slaves[i].reserved_schks,
                                                          slave->uuid);

        i++;

skip_slave:
        /* Reset freed_schks. */
        pool->frozen_freed_schks[id]   = pool->freed_schks[id];
    }

    rcu_read_unlock();

    /* Set free counters to 0. */
    memset(pool->freed_schks, 0, sizeof(c_chk_cnt_t) * MAX_NR_SLAVES);

    /* Insert entry into mstore: could sleep. */
    castle_mstore_entry_insert(mstore, entry, sizeof(struct castle_rlist_entry));

    return 0;
}

static int castle_res_pools_writeback(void)
{
    c_mstore_t *castle_res_pool_mstore = NULL;

    BUG_ON(!castle_extent_in_transaction());

    castle_res_pool_mstore = castle_mstore_init(MSTORE_RES_POOLS);
    if(!castle_res_pool_mstore)
        return -ENOMEM;

    /* All reservation pool opertions are protected by extent lock. Doesn't need to run
     * with hash lock. */
    __castle_res_pool_hash_iterate(castle_res_pool_writeback, castle_res_pool_mstore);

    castle_mstore_fini(castle_res_pool_mstore);

    return 0;
}

static int castle_res_pool_post_checkpoint(c_res_pool_t *pool, void *unused)
{
    struct list_head *lh;

    /* Reservation pools, extents and freespace consistency is very much tied to extent transaction
     * lock. Very important to hold this. */
    BUG_ON(!castle_extent_in_transaction());

    rcu_read_lock();

    /* Go through all live slaves and commit the reservations for them for this pool. */
    list_for_each_rcu(lh, &castle_slaves.slaves)
    {
        struct castle_slave *slave = list_entry(lh, struct castle_slave, list);

        castle_res_pool_counter_check(pool, slave->id);

        /* If the reserved_schks are +ve, just add the freed_schks in since last checkpoint to
         * pool/global reserved_schks counts. */
        if (pool->reserved_schks[slave->id] >= 0)
        {
            /* Calculate the reserved_schks count. */
            pool->reserved_schks[slave->id] +=
                                    ((c_signed_chk_cnt_t)pool->frozen_freed_schks[slave->id]);

            /* Update global count normally. */
            slave->reserved_schks += pool->frozen_freed_schks[slave->id];
        }
        else
        {
            /* If reserved_schks count is -ve, update reserved_schks count normally. */
            pool->reserved_schks[slave->id] +=
                                    ((c_signed_chk_cnt_t)pool->frozen_freed_schks[slave->id]);

            /* But, don't update global counter for over-allocated schks. */
            if (pool->reserved_schks[slave->id] > 0)
                slave->reserved_schks += pool->reserved_schks[slave->id];
        }

        castle_res_pool_counter_check(pool, slave->id);
    }

    rcu_read_unlock();

    return 0;
}

void castle_res_pools_post_checkpoint(void)
{
    BUG_ON(!castle_extent_in_transaction());

    __castle_res_pool_hash_iterate(castle_res_pool_post_checkpoint, NULL);
}

int castle_res_pools_read(void)
{
    struct castle_mstore_iter *iterator = NULL;
    c_res_pool_t *pool = NULL;
    struct list_head *lh;
    int ret = 0;

    /* Create an iterator for the mstore. */
    iterator = castle_mstore_iterate(MSTORE_RES_POOLS);
    if (!iterator)
    {
        ret = -EINVAL;
        goto error_out;
    }

    /* Go through all entries in the mstore. */
    while (castle_mstore_iterator_has_next(iterator))
    {
        struct castle_rlist_entry *entry = &global_rentry_buffer;
        size_t entry_size;
        struct castle_slave *cs;
        int i;

        /* Get the next entry. */
        castle_mstore_iterator_next(iterator, entry, &entry_size);
        BUG_ON(entry_size != sizeof(struct castle_rlist_entry));

        /* Allocate space for new pool. */
        pool = castle_alloc(sizeof(c_res_pool_t));
        if (!pool)
        {
            ret = -ENOMEM;
            goto error_out;
        }

        castle_res_pool_init(pool);

        pool->id = entry->id;

        debug_res_pools("Reading reservation pool: %u\n", pool->id);

        for (i=0; i<MAX_NR_SLAVES; i++)
        {
            /* If we see zero length reservations, no more reservations left from this pool. */
            if (entry->slaves[i].reserved_schks == 0)
                break;

            cs = castle_slave_find_by_uuid(entry->slaves[i].uuid);

            /* There should be a slave corresponding to this uuid. */
            if (!cs)
            {
                castle_printk(LOG_ERROR, "Reservation pools mstore seems to be corrupted.\n");
                BUG();
                /* TODO: Crash for now, just to not miss this issue. Change later to error. */
#if 0
                ret = -EINVAL;
                goto error_out;
#endif
            }

            /* If the slave is dead, no need to maintain reservation. */
            if (test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags))
                continue;

            /* There shouldn't be another entry for this pool and this slave. */
            BUG_ON(pool->reserved_schks[cs->id]);

            /* Add the reservation to pool. */
            pool->reserved_schks[cs->id] = entry->slaves[i].reserved_schks;

            /* Add to slave count. For the sake of sanity check. */
            if (entry->slaves[i].reserved_schks > 0)
                cs->reserved_schks += ((c_chk_cnt_t)entry->slaves[i].reserved_schks);

            debug_res_pools("\t%d chunks from slave 0x%x\n", pool->reserved_schks[cs->id],
                                                             entry->slaves[i].uuid);
            castle_res_pool_counter_check(pool, i);
        }

        /* Shouldn't be in the hash yet. */
        BUG_ON(castle_res_pool_hash_get(pool->id));

        /* Add to the hash. */
        castle_res_pool_hash_add(pool);

        /* Update next_res_pool_id. */
        castle_next_res_pool_id = (castle_next_res_pool_id <= pool->id)?
                                   (pool->id + 1):
                                   castle_next_res_pool_id;
    }

    /* Done with the iterator, destroy it. */
    castle_mstore_iterator_destroy(iterator);
    iterator = NULL;

    /* Do sanity check on slaves. */
    rcu_read_lock();
    list_for_each_rcu(lh, &castle_slaves.slaves)
    {
        struct castle_slave *slave = list_entry(lh, struct castle_slave, list);

        /* If the slave is OOS, no point in keeping track of reservations. */
        if (test_bit(CASTLE_SLAVE_OOS_BIT, &slave->flags))
            continue;

        /* Just try to reserve 0 super chunks, this would do some checks on cs->reserved_schks. */
        castle_freespace_slave_superchunks_reserve(slave, 0, NULL);
    }
    rcu_read_unlock();

error_out:
    if (iterator)
        castle_mstore_iterator_destroy(iterator);

    return ret;
}

/**
 * Partial Superchunks handling.
 */

c_chk_cnt_t castle_extent_free_chunks_count(c_ext_t *ext, uint32_t slave_id)
{
    struct list_head *pos;
    c_chk_cnt_t count = 0;

    BUG_ON(!ext);

    list_for_each(pos, &ext->schks_list)
    {
        c_part_schk_t *part_schk = list_entry(pos, c_part_schk_t, list);

        if (part_schk->slave_id == slave_id)
            count += part_schk->count;
    }

    return count;
}

static c_part_schk_t *__castle_extent_part_schk_get(c_ext_t *ext, struct castle_slave *slave)
{
    struct list_head *pos;

    list_for_each(pos, &ext->schks_list)
    {
        c_part_schk_t *part_schk = list_entry(pos, c_part_schk_t, list);

        if (part_schk->slave_id == slave->id)
            return part_schk;
    }

    return NULL;
}

static c_chk_seq_t castle_extent_part_schk_get(c_ext_t *ext, struct castle_slave *slave)
{
    c_chk_seq_t chk_seq;
    c_part_schk_t *part_schk;

    BUG_ON(!castle_extent_in_transaction());

    if (!(part_schk = __castle_extent_part_schk_get(ext, slave)))
        return INVAL_CHK_SEQ;

    /* Partial superchunks can't be bigger than a superchunk. */
    BUG_ON(part_schk->count > CHKS_PER_SLOT);

    chk_seq.first_chk = part_schk->first_chk;
    chk_seq.count = part_schk->count;

    /* No need to keep this in list anymore. Get rid of it. */
    list_del(&part_schk->list);

    kmem_cache_free(castle_partial_schks_cache, part_schk);

    return chk_seq;
}

static int castle_extent_part_schks_merge(c_part_schk_t  *part_schk,
                                          uint32_t        slave_id,
                                          c_chk_t         first_chk,
                                          c_chk_cnt_t     count)
{
    /* If the super chuink belongs to different slave, skip. */
    if (slave_id != part_schk->slave_id)
        return -1;

    /* If its a different superchunk, skip. */
    if (SUPER_CHUNK(first_chk) != SUPER_CHUNK(part_schk->first_chk))
        return -1;

    /* Check if it is appendable at end. */
    if (first_chk == (part_schk->first_chk + part_schk->count))
    {
        part_schk->count += count;
        return 0;
    }

    /* Check if it is appendable at start. */
    if (part_schk->first_chk == (first_chk + count))
    {
        part_schk->first_chk = first_chk;
        part_schk->count += count;
        return 0;
    }

    return -1;
}

static void castle_extent_part_schk_free(c_part_schk_t *part_schk, c_res_pool_t *pool)
{
    BUG_ON(part_schk->count != CHKS_PER_SLOT);

    /* First chunk should be aligned to superchunk. */
    BUG_ON(part_schk->first_chk % CHKS_PER_SLOT);

    debug_schks("Freeing superchunk %u\n", part_schk->first_chk);

    /* Free super chunk. */
    castle_freespace_slave_superchunk_free(castle_slave_find_by_id(part_schk->slave_id),
                                           SUPER_CHUNK_STRUCT(part_schk->first_chk), pool);

    /* Delete from list. */
    list_del(&part_schk->list);

    /* Free space. */
    kmem_cache_free(castle_partial_schks_cache, part_schk);
}

/* Note: Ordering of chunks of a superchunk in extent space - As there can't be any
 * grow after shrink, chunks of a given superchunk should be in increasing order in
 * a given extent space.
 *
 *                     However, because of rebuild, which can take partial superchunks
 * created by a shrink/truncate and could use them to rebuild any part of extent. So,
 * shouldn't have any assumptions on chunk ordering. And partial superchunk code has
 * no assumtions on ordering and can create multiple partial schks for a given superchunk
 * as long as they are not contiguous. */

static void castle_extent_part_schk_save(c_ext_t       *ext,
                                         uint32_t       slave_id,
                                         c_chk_t        first_chk,
                                         c_chk_cnt_t    count)
{
    struct list_head *pos;
    c_part_schk_t *part_schk = NULL;

    /* Never save 0 chunks. */
    BUG_ON(count == 0);

    /* Should be in transaction. */
    BUG_ON(!castle_extent_in_transaction());

    /* Slave ID should be valid. */
    BUG_ON(castle_slave_find_by_id(slave_id) == NULL);

    /* Don't try to save more than one super chunk at a time. */
    BUG_ON(SUPER_CHUNK(first_chk) != SUPER_CHUNK(first_chk + count - 1));

    /* Go over all existing super chunks and try to append to them. */
    list_for_each(pos, &ext->schks_list)
    {
        part_schk = list_entry(pos, c_part_schk_t, list);

        /* Shouldn't have any empty partial super chunks in the list. */
        BUG_ON(part_schk->count == 0);

        if (castle_extent_part_schks_merge(part_schk, slave_id, first_chk, count) == 0)
            break;
    }

    /* Check if we stopped in between. */
    if (pos != &ext->schks_list)
    {
        /* If we stopped in between, there should be a matching superchunk. And Superchunk
         * size should be sane. */
        BUG_ON(part_schk == NULL || part_schk->count > CHKS_PER_SLOT);

        /* If the superchunk is full, free it. */
        if (part_schk->count == CHKS_PER_SLOT)
            castle_extent_part_schk_free(part_schk, ext->pool);

        return;
    }

    /* If we are here, we couldn't find any appropriate superchunk in the list. */
    /* Allocate memory. */
    part_schk = kmem_cache_alloc(castle_partial_schks_cache, GFP_KERNEL);
    BUG_ON(!part_schk);

    /* Init and add to the list. */
    part_schk->slave_id     = slave_id;
    part_schk->first_chk    = first_chk;
    part_schk->count        = count;
    list_add(&part_schk->list, &ext->schks_list);
}

/* TODO: Works not efficent. Re-check. */
static void castle_extent_part_schks_converge(c_ext_t *ext)
{
    struct list_head *pos, *tmp, *pos1;
    c_part_schk_t *part_schk, *part_schk1;
    LIST_HEAD(free_list);
    uint32_t nr_schks;

    BUG_ON(!castle_extent_in_transaction());

    list_for_each_safe(pos, tmp, &ext->schks_list)
    {
        struct castle_slave *cs;

        part_schk = list_entry(pos, c_part_schk_t, list);

        cs = castle_slave_find_by_id(part_schk->slave_id);
        if (test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags))
        {
            list_del(pos);
            /* Free space. */
            kmem_cache_free(castle_partial_schks_cache, part_schk);

            continue;
        }

        /* Check if we can merge this superchunk. */
        list_for_each(pos1, &ext->schks_list)
        {
            part_schk1 = list_entry(pos1, c_part_schk_t, list);

            if (castle_extent_part_schks_merge(part_schk1, part_schk->slave_id,
                                               part_schk->first_chk, part_schk->count) == 0)
            {
                list_del(pos);
                kmem_cache_free(castle_partial_schks_cache, part_schk);

                break;
            }
        }
    }

    nr_schks = 0;
    /* Free superchunks, that are full. */
    list_for_each_safe(pos, tmp, &ext->schks_list)
    {
        part_schk = list_entry(pos, c_part_schk_t, list);

        /* If the superchunk is full, free it. */
        if (part_schk->count == CHKS_PER_SLOT)
            castle_extent_part_schk_free(part_schk, ext->pool);
        else
            nr_schks++;
    }

    if (nr_schks > 100)
        castle_printk(LOG_WARN, "Extent %llu has ended-up more than 100 superchunks: %u.\n",
                                ext->ext_id, nr_schks);
}

static int castle_extent_part_schks_writeback(c_ext_t *ext, void *store)
{
    struct list_head *pos;
    struct castle_plist_entry mstore_entry;
    c_mstore_t *castle_part_schks_mstore = store;

    /* Go over all existing super chunks and write them to mstore. */
    list_for_each(pos, &ext->schks_list)
    {
        c_part_schk_t *part_schk = list_entry(pos, c_part_schk_t, list);
        struct castle_slave *cs = castle_slave_find_by_id(part_schk->slave_id);

        if (test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags))
            continue;

        mstore_entry.ext_id     = ext->ext_id;
        mstore_entry.slave_uuid = cs->uuid;
        mstore_entry.first_chk  = part_schk->first_chk;
        mstore_entry.count      = part_schk->count;

        castle_mstore_entry_insert(castle_part_schks_mstore,
                                   &mstore_entry,
                                   sizeof(struct castle_plist_entry));
    }

    return 0;
}

static int castle_extents_part_schks_writeback(void)
{
    c_mstore_t *castle_part_schks_mstore;

    BUG_ON(!castle_extent_in_transaction());

    castle_part_schks_mstore = castle_mstore_init(MSTORE_PART_SCHKS);
    if (!castle_part_schks_mstore)
        return -ENOMEM;

    __castle_extents_hash_iterate(castle_extent_part_schks_writeback, castle_part_schks_mstore);

    castle_mstore_fini(castle_part_schks_mstore);

    return 0;
}

static int castle_extents_part_schks_read(void)
{
    struct castle_plist_entry entry;
    size_t entry_size;
    struct castle_mstore_iter *iterator = NULL;

    iterator = castle_mstore_iterate(MSTORE_PART_SCHKS);
    if (!iterator)
        goto error_out;

    while (castle_mstore_iterator_has_next(iterator))
    {
        c_ext_t *ext;
        struct castle_slave *cs;

        castle_mstore_iterator_next(iterator, &entry, &entry_size);
        BUG_ON(entry_size != sizeof(struct castle_plist_entry));

        ext = castle_extents_hash_get(entry.ext_id);
        cs = castle_slave_find_by_uuid(entry.slave_uuid);

        /* TODO: Handle gracefully. */
        BUG_ON(!ext || !cs);

        /* This shouldn't really free any superchunks. */
        castle_extent_part_schk_save(ext, cs->id,
                                     entry.first_chk,
                                     entry.count);
    }

    castle_mstore_iterator_destroy(iterator);

    return 0;

error_out:
    if (iterator)
        castle_mstore_iterator_destroy(iterator);

    return -1;
}

/**
 * Calculates flush priority on the basis of extent type, and its size.
 * Smaller flush prio means that extent is more likely to be flushed out.
 * The priorities are arranged in such a way that btree + medium object extents of small
 * CTs are least likely to be flushed out.
 */
c_ext_flush_prio_t castle_ext_flush_prio_get(c_ext_type_t type, c_chk_cnt_t size)
{
    switch(type)
    {
        case EXT_T_META_DATA:
            return META_FLUSH_PRIO;

        case EXT_T_GLOBAL_BTREE:
        case EXT_T_BLOCK_DEV:
        case EXT_T_BLOOM_FILTER:
            return DEFAULT_FLUSH_PRIO;

        case EXT_T_T0_INTERNAL_NODES:
        case EXT_T_T0_LEAF_NODES:
        case EXT_T_T0_MEDIUM_OBJECTS:
            return SMALL_CT_FLUSH_PRIO;

        case EXT_T_INTERNAL_NODES:
        case EXT_T_LEAF_NODES:
        case EXT_T_MEDIUM_OBJECTS:
            /* If extents are smaller than 1/4 of the cache size, alloc them to medium
               ct flush prio, otherwise large ct flush prio. */
            if(size < castle_cache_size_get() / (4 * BLKS_PER_CHK))
                return MEDIUM_CT_FLUSH_PRIO;
            else
                return LARGE_CT_FLUSH_PRIO;

        case EXT_T_LARGE_OBJECT:
            return LARGE_OBJS_FLUSH_PRIO;
        default:
            castle_printk(LOG_ERROR, "Unknown extent type: %d\n", type);
            BUG();
    }
}


/**
 * Allocate and initialise extent and per-extent dirtytree structures.
 */
static c_ext_t * castle_ext_alloc(c_ext_id_t ext_id)
{
    c_ext_t *ext = castle_zalloc(sizeof(c_ext_t));
    if (!ext)
        return NULL;
    ext->dirtytree = castle_zalloc(sizeof(c_ext_dirtytree_t));
    if (!ext->dirtytree)
    {
        castle_free(ext);
        return NULL;
    }

    /* Extent structure. */
    ext->ext_id             = ext_id;
    ext->alive              = 1;
    ext->maps_cep           = INVAL_EXT_POS;
    ext->ext_type           = EXT_T_INVALID;
    ext->da_id              = INVAL_DA;
    ext->pool               = NULL;
    atomic_set(&ext->link_cnt, 1);
    ext->use_shadow_map     = 0;
    ext->shadow_map         = NULL;
    spin_lock_init(&ext->shadow_map_lock);

    INIT_LIST_HEAD(&ext->mask_list);
    INIT_LIST_HEAD(&ext->schks_list);
    ext->rebuild_mask_id    = INVAL_MASK_ID;

    /* Per-extent RB dirtytree structure. */
    ext->dirtytree->ext_id     = ext_id;
    ext->dirtytree->ref_cnt    = ATOMIC(1);
    ext->dirtytree->rb_root    = RB_ROOT;
    ext->dirtytree->flush_prio = (uint8_t)-1;
    INIT_LIST_HEAD(&ext->dirtytree->list);
    spin_lock_init(&ext->dirtytree->lock);
#ifdef CASTLE_PERF_DEBUG
    ext->dirtytree->ext_size= 0;
    ext->dirtytree->ext_type= ext->ext_type;
#endif
    ext->global_mask = EMPTY_MASK_RANGE;

    debug("Allocated extent ext_id=%lld.\n", ext->ext_id);

    return ext;
}

static int castle_extent_print(c_ext_t *ext, void *unused)
{
    debug("Print   Extent   %llu\n", ext->ext_id);
    debug("        Size     %u chunks\n", ext->size);
    debug("        Maps at  "cep_fmt_str_nl, cep2str(ext->maps_cep));

    return 0;
}

void castle_extent_mark_live(c_ext_id_t ext_id, c_da_t da_id)
{
    c_ext_t *ext = castle_extents_hash_get(ext_id);

    if (ext)
    {
        /* Extent should belong to the same DA. */
        BUG_ON(ext->da_id != da_id);

        /* Mark the extent as alive. */
        ext->alive = 1;
    }
}

/* Check if the extent is alive or not.
 * Extent is alive if it referenced by one of
 *  - Component Trees in a DA
 *      - Tree Extent
 *      - Medium Object Extent
 *      - Large Object Extent
 *  - Logical Extents
 *
 *  Other wise free it.
 */
static int castle_extent_check_alive(c_ext_t *ext, void *unused)
{
    /* Logical extents are always alive. */
    if (LOGICAL_EXTENT(ext->ext_id))
        return 0;

    if (ext->alive == 0)
    {
        castle_printk(LOG_INFO, "Found dead extent: %llu\n", ext->ext_id);
        castle_extent_free(ext->ext_id);
    }

    return 0;
}

int castle_extents_restore(void)
{
    __castle_extents_hash_iterate(castle_extent_check_alive, NULL);
    return 0;
}

static int castle_extents_garbage_collector(void *unused);

int castle_extents_init(void)
{
    debug("Initing castle extents\n");

    /* Initialise extents garbage collector. */
    extents_gc_thread = kthread_run(castle_extents_garbage_collector, NULL,
                                    "castle-extents-gc");
    if (IS_ERR(extents_gc_thread))
    {
        castle_printk(LOG_INIT, "Could not start garbage collector thread for extents\n");
        goto err_out;
    }

    /* Initialise hash table for extents. */
    castle_extents_hash = castle_extents_hash_alloc();
    if (!castle_extents_hash)
    {
        castle_printk(LOG_INIT, "Could not allocate extents hash.\n");
        kthread_stop(extents_gc_thread);

        goto err_out;
    }
    castle_extents_hash_init();

    /* Initialise hash table for extent masks. */
    castle_extent_mask_hash = castle_extent_mask_hash_alloc();
    if (!castle_extent_mask_hash)
    {
        castle_printk(LOG_INIT, "Could not allocate extents hash.\n");
        kthread_stop(extents_gc_thread);

        goto err_out;
    }
    castle_extent_mask_hash_init();

    /* Initialise hash table for reservation pools. */
    castle_res_pool_hash = castle_res_pool_hash_alloc();
    if (!castle_res_pool_hash)
    {
        castle_printk(LOG_INIT, "Could not allocate extents hash.\n");
        kthread_stop(extents_gc_thread);

        goto err_out;
    }
    castle_res_pool_hash_init();

    /* Init kmem_cache for in_flight counters for extent_flush. */
    castle_partial_schks_cache = kmem_cache_create("castle_partial_schks_cache",
                                            sizeof(c_part_schk_t),
                                            0,   /* align */
                                            0,   /* flags */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
                                            NULL, NULL); /* ctor, dtor */
#else
                                            NULL); /* ctor */
#endif
    if (!castle_partial_schks_cache)
    {
        castle_printk(LOG_INIT,
                      "Could not allocate kmem cache for castle_partial_schks_cache.\n");
        goto err_out;
    }

    return EXIT_SUCCESS;

err_out:
    castle_extents_fini();
    return -ENOMEM;
}

/* Cleanup all extents from hash table. Called at finish. */
static int castle_extent_hash_remove(c_ext_t *ext, void *unused)
{
    c_ext_mask_t *mask = GET_LATEST_MASK(ext);
    struct list_head *pos, *tmp;

    castle_printk(LOG_DEBUG, "%s::Freeing extent #%llu\n", __FUNCTION__, ext->ext_id);

    /* Should have only one valid mask. */
    BUG_ON(!list_is_last(&mask->list, &ext->mask_list));

    /* And its reference count should be equal to number of links. */
    if (atomic_read(&mask->ref_count) != 1)
        printk("%s: Extent ref count Freeing extent #%llu\n", __FUNCTION__, ext->ext_id);

    BUG_ON(atomic_read(&mask->ref_count) != 1);

    /* There shouldn't be any outstanding extents for deletion on exit. */
    __castle_extents_hash_remove(ext);

    if (SUPER_EXTENT(ext->ext_id))
    {
        struct castle_slave *cs =
                castle_slave_find_by_id(sup_ext_to_slave_id(ext->ext_id));

        castle_free(cs->sup_ext_maps);
    }
    __castle_extent_dirtytree_put(ext->dirtytree, 0 /*check_hash*/);

    /* Free memory occupied by superchunk strcutures. */
    list_for_each_safe(pos, tmp, &ext->schks_list)
    {
        c_part_schk_t *schk = list_entry(pos, c_part_schk_t, list);

        kmem_cache_free(castle_partial_schks_cache, schk);
    }

    castle_free(mask);
    castle_free(ext);

    return 0;
}

static void castle_extents_super_block_init(void)
{
    castle_extents_global_sb.ext_id_seq           = EXT_SEQ_START;
    castle_extents_global_sb.nr_exts              = 0;
    castle_extents_global_sb.micro_ext.ext_id     = INVAL_EXT_ID;
    castle_extents_global_sb.meta_ext.ext_id      = INVAL_EXT_ID;
    castle_extents_global_sb.mstore_ext[0].ext_id = INVAL_EXT_ID;
    castle_extents_global_sb.mstore_ext[1].ext_id = INVAL_EXT_ID;
}

static void castle_extents_super_block_read(void)
{
    struct castle_fs_superblock *sblk;

    BUG_ON(!castle_extent_in_transaction());

    sblk = castle_fs_superblocks_get();
    memcpy(&castle_extents_global_sb, &sblk->extents_sb,
           sizeof(struct castle_extents_superblock));
    castle_fs_superblocks_put(sblk, 0);
}

static void castle_extents_super_block_writeback(void)
{ /* Should be called with castle_extents_mutex held. */
    struct castle_fs_superblock *sblk;

    sblk = castle_fs_superblocks_get();

    memcpy(&sblk->extents_sb, &castle_extents_global_sb,
           sizeof(struct castle_extents_superblock));

    castle_fs_superblocks_put(sblk, 1);

    INJECT_FAULT;
}

/**
 * Start an extent transaction. An extent transaction makes sure that all extent operations in
 * transaction are atomic.
 */
void castle_extent_transaction_start(void)
{
    mutex_lock(&castle_extents_mutex);
}

/**
 * End the extent transaction.
 */
void castle_extent_transaction_end(void)
{
    mutex_unlock(&castle_extents_mutex);
}

int castle_extent_in_transaction(void)
{
    return mutex_is_locked(&castle_extents_mutex);
}

/**
 * Get global extent superblock. Dont try to get mutex. Function is called with mutex.
 */
struct castle_extents_superblock* _castle_extents_super_block_get(void)
{
    return &castle_extents_global_sb;
}

struct castle_extents_superblock* castle_extents_super_block_get(void)
{
    /* Doesn't make sense to get superblock without being in transaction. */
    BUG_ON(!castle_extent_in_transaction());

    return &castle_extents_global_sb;
}

/**
 * Adds a new slave into the micro_maps. Used during claims after fs init.
 *
 * @param cs    The slave to add to the micro extent maps
 */
void castle_extent_micro_ext_update(struct castle_slave * cs)
{
    c_ext_t * micro_ext;
    struct castle_extents_superblock *castle_extents_sb;
    c_disk_chk_t *micro_maps;
    c2_block_t *c2b;
    c_ext_pos_t cep;
    c_ext_mask_id_t mask_id;

    mask_id = castle_extent_get_ptr(MICRO_EXT_ID, &micro_ext);
    BUG_ON(!micro_ext || (micro_ext->size > 1));

    /* Read in the micro extent using the old micro map. */
    cep.ext_id = MICRO_EXT_ID;
    cep.offset = 0;

    c2b = castle_cache_block_get(cep, BLKS_PER_CHK);
    write_lock_c2b(c2b);
    if(!c2b_uptodate(c2b))
        BUG_ON(submit_c2b_sync(READ, c2b));

    /* Update the micro map to include the new slave. */
    castle_extent_transaction_start();

    castle_extents_sb = castle_extents_super_block_get();
    micro_maps = castle_extents_sb->micro_maps;

    micro_maps[micro_ext->k_factor].slave_id = cs->uuid;
    micro_maps[micro_ext->k_factor].offset   = MICRO_EXT_START;
    micro_ext->k_factor++;

    castle_extent_transaction_end();

    /* Write out the micro extent using the updated micro map. */
    dirty_c2b(c2b);
    BUG_ON(submit_c2b_sync(WRITE, c2b));
    write_unlock_c2b(c2b);
    put_c2b(c2b);

    castle_extent_put(mask_id);
}

static int castle_extent_micro_ext_create(void)
{
    struct castle_extents_superblock *castle_extents_sb = castle_extents_super_block_get();
    c_disk_chk_t *micro_maps = castle_extents_sb->micro_maps;
    c_ext_t *micro_ext;
    struct list_head *l;
    int i = 0;

    BUG_ON(!castle_extent_in_transaction());

    micro_ext = castle_ext_alloc(MICRO_EXT_ID);
    if (!micro_ext)
        return -ENOMEM;

    micro_ext->size                  = MICRO_EXT_SIZE;
    micro_ext->type                  = MICRO_EXT;
    micro_ext->ext_type              = EXT_T_META_DATA;
    micro_ext->da_id                 = 0;
    micro_ext->maps_cep              = INVAL_EXT_POS;
    micro_ext->dirtytree->flush_prio = castle_ext_flush_prio_get(EXT_T_META_DATA, MICRO_EXT_SIZE);
#ifdef CASTLE_PERF_DEBUG
    micro_ext->dirtytree->ext_size   = micro_ext->size;
    micro_ext->dirtytree->ext_type   = micro_ext->ext_type;
#endif

    memset(micro_maps, 0, sizeof(castle_extents_sb->micro_maps));
    rcu_read_lock();
    list_for_each_rcu(l, &castle_slaves.slaves)
    {
        struct castle_slave *cs = list_entry(l, struct castle_slave, list);

        /* Don't add maps for ghost slaves. */
        if (test_bit(CASTLE_SLAVE_REMAPPED_BIT, &cs->flags))
            continue;

        BUG_ON(MICRO_EXT_SIZE != 1);

        micro_maps[i].slave_id = cs->uuid;
        micro_maps[i].offset   = MICRO_EXT_START;
        i++;
    }
    rcu_read_unlock();
    BUG_ON(i > MAX_NR_SLAVES);
    micro_ext->k_factor = i;

    /* Create a mask for it. */
    BUG_ON(castle_extent_mask_create(micro_ext,
                                     MASK_RANGE(0, micro_ext->size),
                                     INVAL_MASK_ID) < 0);

    CONVERT_EXTENT_TO_MENTRY(micro_ext, &castle_extents_sb->micro_ext);

    castle_extents_hash_add(micro_ext);

    return 0;
}

static int castle_extent_meta_ext_create(void)
{
    int k_factor = (castle_rda_spec_get(RDA_2))->k_factor, i = 0;
    struct castle_extents_superblock *castle_extents_sb;
    struct list_head *l;
    c_ext_t *meta_ext;
    c_ext_id_t ext_id;

    BUG_ON(!castle_extent_in_transaction());

    rcu_read_lock();
    list_for_each_rcu(l, &castle_slaves.slaves)
        i++;
    rcu_read_unlock();

    /* Allocate meta extent size to be however much we allocated in all the
       slaves, divided by the k-factor (2) */
    meta_ext_size = META_SPACE_SIZE * MAX_NR_SLAVES / k_factor;

    ext_id = _castle_extent_alloc(RDA_2, 0,
                                  EXT_T_META_DATA,
                                  meta_ext_size,
                                  meta_ext_size,
                                  META_EXT_ID,
                                  NULL);
    if (ext_id != META_EXT_ID)
    {
        castle_printk(LOG_WARN, "Meta Extent Allocation Failed\n");
        return -ENOSPC;
    }

    castle_extents_sb = castle_extents_super_block_get();
    meta_ext = castle_extents_hash_get(META_EXT_ID);
    CONVERT_EXTENT_TO_MENTRY(meta_ext, &castle_extents_sb->meta_ext);

    debug("Done with intialization of meta extent mappings\n");

    return 0;
}

static int castle_extent_mstore_ext_create(void)
{
    struct   list_head *l;
    int      i = 0;
    c_ext_t *mstore_ext;
    struct   castle_extents_superblock *castle_extents_sb;
    c_ext_id_t ext_id;
    int      k_factor = (castle_rda_spec_get(RDA_2))->k_factor;

    BUG_ON(!castle_extent_in_transaction());

    i = 0;
    rcu_read_lock();
    list_for_each_rcu(l, &castle_slaves.slaves)
        i++;
    rcu_read_unlock();

    ext_id = _castle_extent_alloc(RDA_2, 0,
                                  EXT_T_META_DATA,
                                  MSTORE_SPACE_SIZE * i / k_factor,
                                  MSTORE_SPACE_SIZE * i / k_factor,
                                  MSTORE_EXT_ID,
                                  NULL);
    if (ext_id != MSTORE_EXT_ID)
        return -ENOSPC;

    ext_id = _castle_extent_alloc(RDA_2, 0,
                                  EXT_T_META_DATA,
                                  MSTORE_SPACE_SIZE * i / k_factor,
                                  MSTORE_SPACE_SIZE * i / k_factor,
                                  MSTORE_EXT_ID+1,
                                  NULL);
    if (ext_id != MSTORE_EXT_ID+1)
        return -ENOSPC;

    castle_extents_sb = castle_extents_super_block_get();

    mstore_ext = castle_extents_hash_get(MSTORE_EXT_ID);
    CONVERT_EXTENT_TO_MENTRY(mstore_ext, &castle_extents_sb->mstore_ext[0]);
    mstore_ext = castle_extents_hash_get(MSTORE_EXT_ID+1);
    CONVERT_EXTENT_TO_MENTRY(mstore_ext, &castle_extents_sb->mstore_ext[1]);

    return 0;
}

int castle_extents_create(void)
{
    int ret = 0;

    BUG_ON(extent_init_done);

    castle_extent_transaction_start();

    castle_extents_super_block_init();

    if ((ret = castle_extent_micro_ext_create()))
        goto out;

    if ((ret = castle_extent_meta_ext_create()))
        goto out;

    castle_ext_freespace_init(&meta_ext_free, META_EXT_ID);

    INJECT_FAULT;

    if ((ret = castle_extent_mstore_ext_create()))
        goto out;

    extent_init_done = 2;

out:
    castle_extent_transaction_end();

    return ret;
}

/**
 * Inserts all extent stats into the stats mstore. At the moment just the rebulid progress counter.
 */
void castle_extents_stats_writeback(c_mstore_t *stats_mstore)
{
    struct castle_slist_entry mstore_entry;

    mstore_entry.stat_type = STATS_MSTORE_REBUILD_PROGRESS;
    mstore_entry.key = -1;
    mstore_entry.val = castle_extents_chunks_remapped;

    castle_mstore_entry_insert(stats_mstore,
                               &mstore_entry,
                               sizeof(struct castle_slist_entry));
}

/**
 * Reads extent stats. At the moment just a single entry of STATS_MSTORE_REBUILD_PROGRESS expected.
 */
void castle_extents_stat_read(struct castle_slist_entry *mstore_entry)
{
    BUG_ON(mstore_entry->stat_type != STATS_MSTORE_REBUILD_PROGRESS);
    BUG_ON(mstore_entry->key != (uint64_t)-1);

    /* Temporarily high logging level. */
    castle_printk(LOG_INFO,
                  "Read %lld chunks remapped from mstore.\n",
                  mstore_entry->val);
    castle_extents_chunks_remapped += mstore_entry->val;
}

int nr_exts = 0;

/* @TODO who should handle errors in writeback? */
static int castle_extent_writeback(c_ext_t *ext, void *store)
{
    struct castle_elist_entry mstore_entry;
    c_mstore_t *castle_extents_mstore = store;

    /* Shouldnt be any outstanding deletions before last checkpoint. */
    if(castle_last_checkpoint_ongoing && (atomic_read(&ext->link_cnt) == 0))
        castle_printk(LOG_DEBUG, "%s::ext %p ext_id %d\n", __FUNCTION__, ext, ext->ext_id);
    BUG_ON(castle_last_checkpoint_ongoing && (atomic_read(&ext->link_cnt) == 0));

    if (LOGICAL_EXTENT(ext->ext_id))
        return 0;

    debug("Writing back extent %llu\n", ext->ext_id);

    CONVERT_EXTENT_TO_MENTRY(ext, &mstore_entry);

    castle_mstore_entry_insert(castle_extents_mstore,
                               &mstore_entry,
                               sizeof(struct castle_elist_entry));

    nr_exts++;

    INJECT_FAULT;
    return 0;
}

int castle_extents_writeback(void)
{
    struct castle_extents_superblock *ext_sblk;
    c_mstore_t *castle_extents_mstore = NULL;

    if (!extent_init_done)
        return 0;

    /* Don't exit with out-standing dead extents. They are scheduled to get freed on
     * system work queue. */
    if (castle_last_checkpoint_ongoing)
        while (atomic_read(&castle_extents_gc_q_size) || atomic_read(&castle_extents_dead_count))
            msleep_interruptible(1000);

    castle_extents_mstore = castle_mstore_init(MSTORE_EXTENTS);
    if(!castle_extents_mstore)
        return -ENOMEM;

    castle_extent_transaction_start();

    /* Note: This is important to make sure, nothing changes in extents. And
     * writeback() relinquishes hash spin_lock() while doing writeback. */
    ext_sblk = castle_extents_super_block_get();
    /* Writeback new copy. */
    nr_exts = 0;
    __castle_extents_hash_iterate(castle_extent_writeback, castle_extents_mstore);

    if (ext_sblk->nr_exts != nr_exts)
    {
        castle_printk(LOG_ERROR, "%llx:%x\n", ext_sblk->nr_exts, nr_exts);
        BUG();
    }

    castle_mstore_fini(castle_extents_mstore);

    /* Writeback maps freespace structure into extent superblock. */
    castle_ext_freespace_marshall(&meta_ext_free, &ext_sblk->meta_ext_free_bs);

    /* Flush micro extent. */
    castle_cache_extent_flush_schedule(MICRO_EXT_ID, 0, 0);

    /* Flush the complete meta extent onto disk, before completing writeback. */
    BUG_ON(!castle_ext_freespace_consistent(&meta_ext_free));
    castle_cache_extent_flush_schedule(META_EXT_ID, 0,
                                       atomic64_read(&meta_ext_free.used));

    INJECT_FAULT;

    /* Write list of partial superchunks for all extents into mstore. */
    castle_extents_part_schks_writeback();

    /* It is important to complete freespace_writeback() under extent lock, to
     * make sure freesapce and extents are in sync. */
    castle_freespace_writeback();

    castle_res_pools_writeback();

    castle_extents_super_block_writeback();

    castle_extent_transaction_end();

    return 0;
}

static int load_extent_from_mentry(struct castle_elist_entry *mstore_entry)
{
    c_ext_t *ext = NULL;
    int ret;

    /* Load micro extent. */
    ext = castle_ext_alloc(mstore_entry->ext_id);
    if (!ext)
    {
        ret = -ENOMEM;
        goto err1;
    }

    /* ext_alloc() would set the alive bit to 1. Shouldn't do that during module reload.
     * Instead, extent owner would mark it alive. */
    ext->alive = 0;

    CONVERT_MENTRY_TO_EXTENT(ext, mstore_entry);
    ext->dirtytree->flush_prio = castle_ext_flush_prio_get(ext->ext_type, ext->size);
    if (EXT_ID_INVAL(ext->ext_id))
    {
        ret = -EINVAL;
        goto err2;
    }

    /* Record if this extent was created with 1 RDA. */
    if (ext->type == RDA_1)
        min_rda_lvl = RDA_1;

    /* Create the initial masks. */
    BUG_ON(castle_extent_mask_create(ext,
                                     mstore_entry->prev_mask,
                                     INVAL_MASK_ID) < 0);

    castle_extents_hash_add(ext);

    /* This would delete the previous mask, as it doesnt have any references. */
    BUG_ON(castle_extent_mask_create(ext,
                                     mstore_entry->cur_mask,
                                     GET_LATEST_MASK(ext)->mask_id) < 0);

    castle_extent_print(ext, NULL);

    return 0;

err2:
    castle_free(ext->dirtytree);
    castle_free(ext);
err1:
    return ret;
}

int castle_extents_read(void)
{
    int ret = EXIT_SUCCESS;

    struct castle_extents_superblock *ext_sblk = NULL;

    BUG_ON(extent_init_done);

    castle_extent_transaction_start();

    castle_extents_super_block_read();

    castle_extent_micro_ext_create();

    ext_sblk = castle_extents_super_block_get();

    /* Read maps freespace structure from extents superblock. */
    castle_ext_freespace_unmarshall(&meta_ext_free, &ext_sblk->meta_ext_free_bs);

    if ((ret = load_extent_from_mentry(&ext_sblk->meta_ext)))
        goto out;

    if ((ret = load_extent_from_mentry(&ext_sblk->mstore_ext[0])))
        goto out;

    if ((ret = load_extent_from_mentry(&ext_sblk->mstore_ext[1])))
        goto out;

    atomic_set(&current_rebuild_seqno, ext_sblk->current_rebuild_seqno);

    meta_ext_size = castle_extent_size_get(META_EXT_ID);

    /* Read reservation pools from mstore. */
    castle_res_pools_read();

    extent_init_done = 1;

out:
    castle_extent_transaction_end();
    return ret;
}

void castle_extents_start(void)
{
    extents_allocable = 1;
}

#define map_chks_per_page(_k_factor)    (PAGE_SIZE / (_k_factor * sizeof(c_disk_chk_t)))
#define map_size(_ext_chks, _k_factor)  (1 + (_ext_chks-1) / map_chks_per_page(_k_factor))

//#define COMPACTION_DRY_RUN
struct castle_meta_compactor {
    void *bitmap;
    unsigned long bitmap_size;
    unsigned long bitmap_size_bits;
    int compaction_idx;
    int err;
};

static int castle_extent_meta_mark(c_ext_t *ext, void *compactor_p)
{
    struct castle_meta_compactor *compactor = (struct castle_meta_compactor *)compactor_p;
    uint32_t map_size_pgs;
    int bit_nr;

    if(ext->maps_cep.ext_id != META_EXT_ID)
    {
        castle_printk(LOG_USERINFO,
                      "Extent: %lld doesn't use meta extent for its maps, it uses %lld.\n",
                      ext->ext_id, ext->maps_cep.ext_id);
        return 0;
    }

    map_size_pgs = map_size(ext->size, ext->k_factor);
    if(ext->maps_cep.offset % PAGE_SIZE != 0)
    {
        castle_printk(LOG_ERROR,
                      "Map for ext: %lld not page aligned: "cep_fmt_str_nl,
                       ext->ext_id, cep2str(ext->maps_cep));
        compactor->err = -EINVAL;
        return 1;
    }

    castle_printk(LOG_USERINFO,
                  "Maps for ext: %lld at cep: "cep_fmt_str" size: %d pgs.\n",
                  ext->ext_id, cep2str(ext->maps_cep), map_size_pgs);
    bit_nr = ext->maps_cep.offset / PAGE_SIZE;
    while(map_size_pgs-- > 0)
    {
        set_bit(bit_nr, compactor->bitmap);
        bit_nr++;
    }

    return 0;
}

static int castle_extent_meta_unused_find(struct castle_meta_compactor *compactor, uint32_t pgs)
{
    int candidate;
    int i;

    candidate = compactor->compaction_idx;
    i = 0;
    while(candidate + i < compactor->bitmap_size_bits)
    {
        if(i >= pgs)
            break;

        if(test_bit(candidate + i, compactor->bitmap))
        {
            candidate = candidate + i + 1;
            i = -1;
        }

        i++;
    }

    if(i < pgs)
        return -1;

    compactor->compaction_idx = candidate + pgs;

    return candidate;
}

static unsigned long castle_extent_max_meta_offset_get(struct castle_meta_compactor *compactor)
{
    unsigned long max_offset;

    max_offset = (unsigned long)compactor->compaction_idx * PAGE_SIZE;
    if(atomic64_read(&meta_ext_free.used) > max_offset)
        max_offset = atomic64_read(&meta_ext_free.used);

    return max_offset;
}

static int castle_extent_meta_copy(c_ext_t *ext, void *compactor_p)
{
    struct castle_meta_compactor *compactor = (struct castle_meta_compactor *)compactor_p;
    uint32_t map_size_pgs;
    int unused_idx;
    c_ext_pos_t new_maps_cep;
#ifndef COMPACTION_DRY_RUN
    int i;
#endif

    if(ext->maps_cep.ext_id != META_EXT_ID)
        return 0;

    /* Don't copy if the location of the map for this extents is earlier than current
       compaction_idx. */
    if(compactor->compaction_idx > ext->maps_cep.offset / PAGE_SIZE)
    {
        castle_printk(LOG_ERROR,
                      "Extent %lld has map in early part of meta ext "cep_fmt_str", not copying.\n",
                      ext->ext_id, cep2str(ext->maps_cep));
        return 0;
    }

    map_size_pgs = map_size(ext->size, ext->k_factor);
    unused_idx = castle_extent_meta_unused_find(compactor, map_size_pgs);
    if(unused_idx < 0)
    {
        castle_printk(LOG_ERROR, "Failed to find empty space for %d map pages.\n",
                map_size_pgs);
        compactor->err = -ENOSPC;
        return 1;
    }

    /* Found space to copy the meta extent to, do it, page by page. */
    new_maps_cep.ext_id = ext->maps_cep.ext_id;
    new_maps_cep.offset = (unsigned long)unused_idx * PAGE_SIZE;
    castle_printk(LOG_USERINFO,
            "Copying %d map pages for ext: %lld from: "cep_fmt_str", to: "cep_fmt_str_nl,
            map_size_pgs, ext->ext_id, cep2str(ext->maps_cep), cep2str(new_maps_cep));
#ifndef COMPACTION_DRY_RUN
    for(i=0; i<map_size_pgs; i++)
    {
        c2_block_t *s_c2b, *d_c2b;
        c_ext_pos_t s_cep, d_cep;

        s_cep.ext_id = ext->maps_cep.ext_id;
        s_cep.offset = ext->maps_cep.offset + i * PAGE_SIZE;

        d_cep.ext_id = new_maps_cep.ext_id;
        d_cep.offset = new_maps_cep.offset + i * PAGE_SIZE;

        s_c2b = castle_cache_page_block_get(s_cep);
        d_c2b = castle_cache_page_block_get(d_cep);

        write_lock_c2b(s_c2b);
        write_lock_c2b(d_c2b);
        if(!c2b_uptodate(s_c2b))
            BUG_ON(submit_c2b_sync(READ, s_c2b));
        update_c2b(d_c2b);
        memcpy(c2b_buffer(d_c2b), c2b_buffer(s_c2b), PAGE_SIZE);
        dirty_c2b(d_c2b);
        submit_c2b_sync(WRITE, d_c2b);
        write_unlock_c2b(d_c2b);
        write_unlock_c2b(s_c2b);
        put_c2b(s_c2b);
        put_c2b(d_c2b);
    }

    /* Now that map has been copied, update the maps_cep in ext structure. */
    ext->maps_cep = new_maps_cep;
#endif

    return 0;
}

#define META_EXT_COMPACT_DEFAULT_PCT 50
int castle_meta_ext_compact_pct = META_EXT_COMPACT_DEFAULT_PCT;

static void castle_extents_meta_compact(int *force_checkpoint)
{
    void *used_meta_bitmap;
    unsigned long nr_meta_pgs, bitmap_size;
    struct castle_meta_compactor compactor;
    unsigned long new_used;

    castle_printk(LOG_INIT, "Meta extent freespace: used=%lld, size=%lld\n",
            atomic64_read(&meta_ext_free.used), meta_ext_free.ext_size);

    if ((castle_meta_ext_compact_pct < 0) || (castle_meta_ext_compact_pct > 100))
        castle_meta_ext_compact_pct = META_EXT_COMPACT_DEFAULT_PCT;
    if(castle_meta_ext_compact_pct && ((100 * atomic64_read(&meta_ext_free.used)) <
            (meta_ext_free.ext_size * castle_meta_ext_compact_pct)))
    {
        castle_printk(LOG_INIT, "Less than %d percent meta extent used, not compacting.\n",
            castle_meta_ext_compact_pct);
        goto out;
    }

    castle_printk(LOG_WARN, "More than %d percent meta extent used. Attempting compaction.\n",
        castle_meta_ext_compact_pct);
    nr_meta_pgs = meta_ext_free.ext_size / PAGE_SIZE;
    bitmap_size = nr_meta_pgs / 8 + 1;
    castle_printk(LOG_USERINFO, "Allocating %lld bitmap for %lld pages of meta ext.\n",
            bitmap_size, nr_meta_pgs);
    used_meta_bitmap = castle_alloc(bitmap_size);
    if(!used_meta_bitmap)
    {
        castle_printk(LOG_ERROR, "Couldn't allocate used bitmap.\n");
        goto out;
    }

    castle_printk(LOG_USERINFO, "Used meta pages bitmap at: %p, compactor: %p\n",
            used_meta_bitmap, &compactor);
    /* Initialise compactor structure. */
    memset(used_meta_bitmap, 0, bitmap_size);
    compactor.bitmap           = used_meta_bitmap;
    compactor.bitmap_size      = bitmap_size;
    compactor.bitmap_size_bits = nr_meta_pgs;
    compactor.err              = 0;
    compactor.compaction_idx   = 0;

    /* Go through all extents and record which pages of the meta extent they use. */
    __castle_extents_hash_iterate(castle_extent_meta_mark, &compactor);
    if(compactor.err != 0)
    {
        castle_printk(LOG_ERROR, "Failed compaction on meta mark.\n");
        goto err_out_dealloc;
    }

    /* Copy all the extent maps. */
    __castle_extents_hash_iterate(castle_extent_meta_copy, &compactor);
    if(compactor.err != 0)
    {
        /* Some extents could have had their maps copied over,
           make sure that the meta extent freespace structure includes all those copies
           and force a checkpoint. */
        castle_printk(LOG_ERROR, "Failed compaction on meta copy.\n");
        castle_free(used_meta_bitmap);
        *force_checkpoint = 1;

        new_used = castle_extent_max_meta_offset_get(&compactor);
#ifndef COMPACTION_DRY_RUN
        atomic64_set(&meta_ext_free.used,    new_used);
        atomic64_set(&meta_ext_free.blocked, new_used);
#endif
        castle_printk(LOG_USERINFO, "Updated used meta extent counter to: %lld\n", new_used);

        return;
    }

    /* All maps have been copied. Return what cep is now end of the meta extent map. */
    castle_free(used_meta_bitmap);

    *force_checkpoint = 1;
#ifndef COMPACTION_DRY_RUN
    atomic64_set(&meta_ext_free.used,    (unsigned long)compactor.compaction_idx * PAGE_SIZE);
    atomic64_set(&meta_ext_free.blocked, (unsigned long)compactor.compaction_idx * PAGE_SIZE);
#endif
    castle_printk(LOG_USERINFO, "Updated used meta extent counter to: %lld\n",
            (unsigned long)compactor.compaction_idx * PAGE_SIZE);
    return;

err_out_dealloc:
    castle_free(used_meta_bitmap);
out:
    *force_checkpoint = 0;
}

#define META_POOL_SIZE 10000
static unsigned int castle_meta_pool_entries = META_POOL_SIZE;
module_param(castle_meta_pool_entries, uint, S_IRUSR | S_IRGRP);
MODULE_PARM_DESC(castle_meta_pool_entries, "Meta extent pool size");

static meta_pool_entry_t    *meta_extent_pool;

/*
 * The size of the pool may be less than META_POOL_SIZE if there aren't enough unused
 * pages in the meta extent.
 */
static int                  castle_extent_meta_pool_size = 0;

static struct list_head     meta_pool_available;    /* Pool entries available for use. */
static struct list_head     meta_pool_inuse;        /* Pool entries in use. */
static struct list_head     meta_pool_released;     /* Pool entries that have been released. */
static struct list_head     meta_pool_frozen;       /* Temp list for use during checkpoints. */

int                         meta_pool_inited = 0;   /* set once the pool is available for use. */

static int meta_pool_inuse_count = 0;
static int meta_pool_available_count = 0;
static int meta_pool_released_count = 0;
static int meta_pool_frozen_count = 0;

/*
 * Move all freed meta extent pool entries to the frozen list.
 */
void castle_extent_meta_pool_freeze(void)
{
    castle_extent_transaction_start();
    BUG_ON(!list_empty(&meta_pool_frozen));
    BUG_ON(meta_pool_frozen_count != 0);
    BUG_ON((meta_pool_released_count + meta_pool_available_count + meta_pool_inuse_count)
            != castle_extent_meta_pool_size);
    list_splice_init(&meta_pool_released, &meta_pool_frozen);
    meta_pool_frozen_count += meta_pool_released_count;
    meta_pool_released_count = 0;
    castle_extent_transaction_end();
}

/*
 * Scan the meta extent pool frozen list, freeing up any entries onto the available list.
 */
void castle_extent_meta_pool_free(void)
{
    castle_extent_transaction_start();
    list_splice_init(&meta_pool_frozen, &meta_pool_available);
    meta_pool_available_count += meta_pool_frozen_count;
    meta_pool_frozen_count = 0;
    BUG_ON((meta_pool_released_count + meta_pool_available_count + meta_pool_inuse_count)
            != castle_extent_meta_pool_size);
    castle_extent_transaction_end();
}

/*
 * Find and return a meta extent pool entry from the available list.
 *
 * @param offset    The meta extent byte offset being allocated from the pool.
 *
 * @return: The list entry if one was available, else NULL.
 */
meta_pool_entry_t * castle_extent_meta_pool_get(c_byte_off_t * offset)
{
    meta_pool_entry_t * pent;

    BUG_ON(!castle_extent_in_transaction());

    if (!meta_pool_inited || list_empty(&meta_pool_available))
        return NULL;
    else
    {
        pent = list_first_entry(&meta_pool_available, meta_pool_entry_t, list);
        list_del(&pent->list);
        meta_pool_available_count--;
        *offset = pent->offset;
        list_add_tail(&pent->list, &meta_pool_inuse);
        meta_pool_inuse_count++;
        return pent;
    }
}

static meta_pool_entry_t * castle_extent_meta_pool_inuse_get(c_byte_off_t offset)
{
    meta_pool_entry_t * pent;

    BUG_ON(!castle_extent_in_transaction());

    if (list_empty(&meta_pool_inuse))
        return NULL;

    pent = list_first_entry(&meta_pool_inuse, meta_pool_entry_t, list);
    list_del(&pent->list);
    pent->offset = offset;
    meta_pool_inuse_count--;

    return pent;
}

/*
 * Release an entry from the inuse list, placing it on the release list for
 * later processing during checkpoint.
 *
 * @param offset    The meta extent byte offset being released.
 */
void castle_extent_meta_pool_release(c_byte_off_t offset)
{
    meta_pool_entry_t * pent;

    BUG_ON(!castle_extent_in_transaction());

    pent = castle_extent_meta_pool_inuse_get(offset);

    if (!pent)
        return;

    list_add_tail(&pent->list, &meta_pool_released);
    meta_pool_released_count++;
}

/*
 * Put a meta extent pool entry back on the available list.
 * For example, when extent alloc fails.
 *
 * @param pent    The meta extent pool entry being returned.
 */
void castle_extent_meta_pool_replace(c_byte_off_t offset)
{
    meta_pool_entry_t * pent;

    BUG_ON(!castle_extent_in_transaction());

    pent = castle_extent_meta_pool_inuse_get(offset);

    BUG_ON(!pent);

    list_add(&pent->list, &meta_pool_available);
    meta_pool_available_count++;
}

/*
 * Initialise the meta extent pool.
 */
void castle_extents_meta_pool_init(void)
{
    unsigned long                   nr_meta_pgs, bitmap_size;
    void                            *used_meta_bitmap;
    struct castle_meta_compactor    meta_pool;
    int                             i, unused_idx;
    uint64_t                        map_idx;
    c_byte_off_t                    meta_pool_offset;
    c_ext_pos_t                     maps_cep;

    INIT_LIST_HEAD(&meta_pool_available);
    INIT_LIST_HEAD(&meta_pool_inuse);
    INIT_LIST_HEAD(&meta_pool_released);
    INIT_LIST_HEAD(&meta_pool_frozen);

    if (castle_meta_pool_entries <= 0)
    {
        castle_printk(LOG_WARN, "Meta extent pool disabled.\n");
        goto out;
    }
    if (castle_meta_pool_entries > META_POOL_SIZE) castle_meta_pool_entries = META_POOL_SIZE;

    meta_extent_pool = castle_alloc(castle_meta_pool_entries * sizeof(meta_pool_entry_t));
    if (!meta_extent_pool)
    {
        castle_printk(LOG_ERROR, "Couldn't allocate bitmap.\n");
        goto out;
    }

    /* Create a bitmap for use by the meta extent scanner. */
    nr_meta_pgs = meta_ext_free.ext_size / PAGE_SIZE;

    bitmap_size = nr_meta_pgs / 8 + 1;

    used_meta_bitmap = castle_alloc(bitmap_size);
    if(!used_meta_bitmap)
    {
        castle_printk(LOG_ERROR, "Couldn't allocate used bitmap.\n");
        castle_free(meta_extent_pool);
        goto out;
    }

    /* Initialise extent scanner state. */
    memset(used_meta_bitmap, 0, bitmap_size);
    meta_pool.bitmap           = used_meta_bitmap;
    meta_pool.bitmap_size      = bitmap_size;
    meta_pool.bitmap_size_bits = nr_meta_pgs;
    meta_pool.err              = 0;
    meta_pool.compaction_idx   = 0;

    /* Go through all extents and record which pages of the meta extent they use. */
    __castle_extents_hash_iterate(castle_extent_meta_mark, &meta_pool);
    if (meta_pool.err != 0)
    {
        castle_printk(LOG_ERROR, "Failed meta pool init on meta mark.\n");
        castle_free(meta_extent_pool);
        goto err_out_dealloc;
    }

    /* For each meta extent block in the pool ... */
    for (i=0; i<castle_meta_pool_entries; i++)
    {
        /* Find a free meta extent block. */
        unused_idx = castle_extent_meta_unused_find(&meta_pool, 1);
        if (unused_idx == -1)
            break;
        meta_pool_offset = (unsigned long)unused_idx * PAGE_SIZE;

        if (meta_pool_offset >= atomic64_read(&meta_ext_free.used))
            /*
             * Once we have reached meta_ext_free.used the rest of the pool will come from
             * unallocated meta_extent pages.
             */
            break;

        /*
         * This block comes from unused space between the start of the meta extent and
         * meta_ext_free.used. Add this entry to the meta extent pool available list.
         */
        meta_extent_pool[i].offset = meta_pool_offset;
        list_add_tail(&meta_extent_pool[i].list, &meta_pool_available);
        castle_extent_meta_pool_size++;
    }

    /* Check that the index has not got out of sync with castle_extent_meta_pool_size. */
    BUG_ON(i != castle_extent_meta_pool_size);

    castle_printk(LOG_USERINFO, "Meta extent pool using %d unused meta extent pages.\n",
                  castle_extent_meta_pool_size);

    if (castle_extent_meta_pool_size < castle_meta_pool_entries)
    {
        uint64_t    current_used = atomic64_read(&meta_ext_free.used);

        /*
         * We didn't allocate the entire free pool from meta extent pages before
         * meta_ext_free.used. Get this directly in one go using the normal freespace allocator so
         * that meta_ext_free is correctly updated.
         */
        if (castle_ext_freespace_get(&meta_ext_free,
                            (castle_meta_pool_entries - castle_extent_meta_pool_size) * PAGE_SIZE,
                            0,
                            &maps_cep))
        {
            castle_printk(LOG_WARN, "Failed to get %d freespace pages for meta extent pool.\n",
                         (castle_meta_pool_entries - castle_extent_meta_pool_size));
            goto err_out_nofreespace;
        }
        /* Add these entries to the meta extent pool available list. */
        map_idx = 0;
        for (i=castle_extent_meta_pool_size; i<castle_meta_pool_entries; i++, map_idx++)
        {
            meta_pool_offset = (unsigned long)(maps_cep.offset + (map_idx * PAGE_SIZE));
            meta_extent_pool[i].offset = meta_pool_offset;
            list_add_tail(&meta_extent_pool[i].list, &meta_pool_available);
            /*
             * We should never be using an offset at or past meta_ext_free.used, and we should
             * never be using an offset less than meta_ext_free.used before the allocation.
             */
            BUG_ON(meta_pool_offset >= atomic64_read(&meta_ext_free.used));
            BUG_ON(meta_pool_offset < current_used);
        }
        debug("Meta extent pool using %d allocated pages.\n",
              (castle_meta_pool_entries - castle_extent_meta_pool_size));
    }

    /* Check that our index is the same as castle_meta_pool_entries. */
    BUG_ON(i != castle_meta_pool_entries);
    castle_extent_meta_pool_size = castle_meta_pool_entries;

err_out_nofreespace:
    if (castle_extent_meta_pool_size)
    {
        castle_printk(LOG_USERINFO, "Meta extent pool initialised with %d entries.\n",
                      castle_extent_meta_pool_size);
        meta_pool_inited = 1;
        meta_pool_available_count = castle_extent_meta_pool_size;
    } else
    {
        castle_free(meta_extent_pool);
        castle_printk(LOG_WARN,
                      "No free meta extent pages found. Meta extent pool not initialised..\n");
    }

err_out_dealloc:
    castle_free(used_meta_bitmap);
out:
    return;
}

int castle_extents_read_complete(int *force_checkpoint)
{
    struct castle_elist_entry mstore_entry;
    size_t mstore_entry_size;
    struct castle_extents_superblock *ext_sblk = NULL;
    struct castle_mstore_iter *iterator = NULL;

    castle_extent_transaction_start();

    nr_exts = 0;
    iterator = castle_mstore_iterate(MSTORE_EXTENTS);
    if (!iterator)
        goto error_out;

    while (castle_mstore_iterator_has_next(iterator))
    {
        castle_mstore_iterator_next(iterator, &mstore_entry, &mstore_entry_size);
        BUG_ON(mstore_entry_size != sizeof(struct castle_elist_entry));

        BUG_ON(LOGICAL_EXTENT(mstore_entry.ext_id));
        if (load_extent_from_mentry(&mstore_entry))
            goto error_out;

        nr_exts++;
    }
    castle_mstore_iterator_destroy(iterator);

    ext_sblk = castle_extents_super_block_get();
    BUG_ON(ext_sblk->nr_exts != nr_exts);

    /* Read partial superchunks for extents. */
    if (castle_extents_part_schks_read())
        goto error_out;

    INJECT_FAULT;
    castle_extents_meta_compact(force_checkpoint);

    castle_extent_transaction_end();

    extent_init_done = 2;

    return 0;

error_out:
    if (iterator)
        castle_mstore_iterator_destroy(iterator);

    castle_extent_transaction_end();

    return -1;
}

void castle_extents_fini(void)
{
    /* Stop the Garbage collector thread. */
    kthread_stop(extents_gc_thread);

    /* Make sure cache flushed all dirty pages */
    /* Iterate over extents hash with exclusive access. Indeed, we don't need a
     * lock here as this happenes in the module end. */
    if (castle_extents_hash)
        castle_extents_hash_iterate_exclusive(castle_extent_hash_remove, NULL);

    castle_check_free(castle_extents_hash);
    castle_check_free(castle_extent_mask_hash);
    castle_check_free(castle_res_pool_hash);

    if (castle_partial_schks_cache)
        kmem_cache_destroy(castle_partial_schks_cache);

    castle_check_free(meta_extent_pool);
}

#define MAX_K_FACTOR   4
struct castle_extent_state {
    c_ext_t *ext;
    c_chk_t  chunks[MAX_NR_SLAVES][MAX_K_FACTOR];
};

/**
 * Allocates structure used during the extent allocation/destruction in order to
 * maintain the active set of superchunks. Initialises this structure appropriately.
 *
 * @param ext   Extent to allocate/destroy.
 */
static struct castle_extent_state *castle_extent_state_alloc(c_ext_t *ext)
{
    struct castle_extent_state *ext_state;
    int i, j;

    ext_state = castle_alloc(sizeof(struct castle_extent_state));
    if(!ext_state)
        return NULL;

    ext_state->ext = ext;
    for(i=0; i<MAX_NR_SLAVES; i++)
        for(j=0; j<MAX_K_FACTOR; j++)
            ext_state->chunks[i][j] = INVAL_CHK;

    return ext_state;
}

static void castle_extent_state_dealloc(c_ext_t *ext, struct castle_extent_state *ext_state)
{
    int i, j;

    for(i=0; i<MAX_NR_SLAVES; i++)
        for(j=0; j<MAX_K_FACTOR; j++)
            if (!CHK_INVAL(ext_state->chunks[i][j]))
            {
                debug_schks("Left with part_schk after exntent alloc: %u, (%u, %u)\n",
                            ext->ext_id, ext_state->chunks[i][j],
                            CHKS_PER_SLOT - (ext_state->chunks[i][j] % CHKS_PER_SLOT));
                castle_extent_part_schk_save(ext,
                                             i,
                                             ext_state->chunks[i][j],
                                             CHKS_PER_SLOT -
                                                (ext_state->chunks[i][j] % CHKS_PER_SLOT));
            }

    castle_free(ext_state);
}

/**
 * Frees specified number of disk chunks allocated to the specified extent. Called when destroying
 * extents, or during failed allocations, to return already allocated disk space.
 *
 * @param   ext     Extent to free the disk space for.
 * @parm    start   LOGICAL chunk to start free from.
 * @param   count   Number of PHYSICAL chunks to free.
 *
 * Note: Make sure PHYSICAL/LOGICAL counts are being used properly.
 * @FIXME Cannot handle kmalloc failure. We should retry freeing extent freespace,
 * once memory becomes available.
 */
static void _castle_extent_space_free(c_ext_t *ext, c_chk_cnt_t start, c_chk_cnt_t count)
{
    c_chk_cnt_t                 chks_per_page;
    c_ext_pos_t                 map_cep;
    c2_block_t                  *map_c2b;
    c_disk_chk_t                *map_buf;
    struct castle_slave         *cs;

    debug("Freeing %d disk chunks from extent %lld\n", count, ext->ext_id);
    chks_per_page = map_chks_per_page(ext->k_factor);

    /* Find map cep for the start chunk. */
    map_cep = castle_extent_map_cep_get(ext->maps_cep, start, ext->k_factor);
    map_c2b = NULL;
    debug("Map at cep: "cep_fmt_str_nl, cep2str(map_cep));
    while(count>0)
    {
        c_chk_cnt_t logical_chunk;

        /* If this is the first page, set first logical_chunk accordingly.*/
        logical_chunk = (map_c2b)? 0: (start % chks_per_page);

        /* Get page-worth of extent map. */
        debug("Processing map page at cep: "cep_fmt_str_nl, cep2str(map_cep));
        map_cep = PG_ALIGN_CEP(map_cep);
        map_c2b = castle_cache_page_block_get(map_cep);
        write_lock_c2b(map_c2b);
        if(!c2b_uptodate(map_c2b))
            BUG_ON(submit_c2b_sync(READ, map_c2b));
        map_buf = c2b_buffer(map_c2b);

        /* For each logical chunk, look through each copy. */
        for (; (logical_chunk < chks_per_page) && (count > 0); logical_chunk++)
        {
            int copy;
            for(copy=0; (copy<ext->k_factor) && (count > 0); copy++)
            {
                cs = castle_slave_find_by_uuid(
                    map_buf[logical_chunk*ext->k_factor + copy].slave_id);
                BUG_ON(!cs);

                if (!test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags))
                    castle_extent_part_schk_save(ext,
                                                 cs->id,
                                                 map_buf[logical_chunk * ext->k_factor + copy].offset,
                                                 1);
                count--;
            }
        }

        write_unlock_c2b(map_c2b);
        put_c2b(map_c2b);

        map_cep.offset += C_BLK_SIZE;
    }

    castle_extent_part_schks_converge(ext);
}

/**
 * Frees specified number of disk chunks allocated to the specified extent. Called when destroying
 * extents, or during failed allocations, to return already allocated disk space.
 *
 * @param   ext     Extent to free the disk space for.
 * @parm    start   LOGICAL chunk to start free from.
 * @param   count   Number of LOGICAL chunks to free.
 */
static void castle_extent_space_free(c_ext_t *ext, c_chk_cnt_t start, c_chk_cnt_t count)
{
    _castle_extent_space_free(ext, start, count * ext->k_factor);
}
/**
 * Allocates disk chunks for particular extent (specified by the extent state struct).
 * Allocates chunks from the specified slave, takes the copy id into account, to make sure
 * continous reads perform well. Gets superchunks from the freespace periodically, and
 * chops them up into individual chunks.
 *
 * @param da_id     Doubling array id for which the extent is to be allocated.
 * @param slave     Disk slave to allocate disk chunk from.
 * @param copy_id   Which copy in the k-RDA set we are trying to allocate.
 */
static c_disk_chk_t castle_extent_disk_chk_alloc(c_da_t da_id,
                                                 struct castle_extent_state *ext_state,
                                                 struct castle_slave *slave,
                                                 int copy_id)
{
    c_disk_chk_t disk_chk;
    c_chk_seq_t chk_seq;
    c_chk_t *chk;

    disk_chk = INVAL_DISK_CHK;
    disk_chk.slave_id = slave->uuid;
    /* Work out which chunk sequence we are using. */
    chk = &ext_state->chunks[slave->id][copy_id];
    debug("*chk: %d/0x%x\n", *chk, *chk);

    /* If there are no chunks in the buffer, get them from partial superchunk buffer for the
     * extent. */
    if (CHK_INVAL(*chk) &&
            !CHK_SEQ_INVAL(chk_seq = castle_extent_part_schk_get(ext_state->ext, slave)))
    {
        /* Check if the partial superchunk is properly aligned. This has to be true as no grow
         * happens after shrink or truncate. */
        /* Note: Rebuild can happen after shrink or truncate. But, rebuild doesn't go through
         * this code flow. */
        if ((chk_seq.first_chk + chk_seq.count) % CHKS_PER_SLOT)
            printk("%p %u %u\n", ext_state, chk_seq.first_chk, chk_seq.count);
        BUG_ON((chk_seq.first_chk + chk_seq.count) % CHKS_PER_SLOT);

        /* Update the chunk buffer in extent state. */
        *chk = chk_seq.first_chk;
    }

    if(!CHK_INVAL(*chk))
    {
        disk_chk.offset = *chk;
        *chk = *chk + 1;
        /* If we've run out of the superchunk, set the chunk to invalid. */
        if(SUPER_CHUNK(*chk) != SUPER_CHUNK(disk_chk.offset))
            *chk = INVAL_CHK;

        return disk_chk;
    }

    /* If we got here, we need to allocate a new superchunk. */
    chk_seq = castle_freespace_slave_superchunk_alloc(slave, da_id, ext_state->ext->pool);
    if (CHK_SEQ_INVAL(chk_seq))
    {
        /*
         * We get here if the slave is either out-or-service, or out of space. If the slave is
         * out-of-service then just return INVAL_DISK_CHK so calling stack can retry.
         */
        if ((!test_bit(CASTLE_SLAVE_OOS_BIT, &slave->flags)) &&
            (!(slave->cs_superblock.pub.flags & CASTLE_SLAVE_SSD)))
        {
            /* Slave is not out-of-service so we are out of space.  */
            castle_printk(LOG_WARN, "Failed to get freespace from slave: 0x%x\n", slave->uuid);
            castle_freespace_stats_print();
        }
        return INVAL_DISK_CHK;
    }
    /* Chunk sequence must represent a single superchunk. */
    BUG_ON(chk_seq.count != CHKS_PER_SLOT);

    debug("Allocated disk superchunk: %d, for extent: %lld\n",
            chk_seq.first_chk, ext_state->ext->ext_id);
    disk_chk.offset = chk_seq.first_chk;
    *chk = chk_seq.first_chk + 1;

    return disk_chk;
}

/**
 * Gets location of the map for given chunk, given the start of the map, and k_factor.
 *
 * @param map_start     Location of the start of the map (usually in the meta extent).
 * @param chk_idx       Which chunk is the map location requested for.
 * @param k_factor      K-factor of the RDA scheme used by the particular extent.
 */
static inline c_ext_pos_t castle_extent_map_cep_get(c_ext_pos_t map_start,
                                                    c_chk_t chk_idx,
                                                    uint32_t k_factor)
{
    c_chk_t chks_per_page;

    /* Work out how many chunks fit in one page. */
    chks_per_page = map_chks_per_page(k_factor);
    map_start.offset += PAGE_SIZE * (chk_idx / chks_per_page);
    map_start.offset += k_factor * sizeof(c_disk_chk_t) * (chk_idx % chks_per_page);

    return map_start;
}

/**
 * Allocates disk space for given extent.
 *
 * @param ext   Extent to allocate the space for.
 * @param da_id Doubling array ID.
 *
 * @return -ENOMEM: Could not allocate memory for state structure.
 * @return -EINVAL: RDA spec failed to initialise.
 * @return -ENOSPC: Not enough disk space left to create this extent (for the particular set of
 *                  slaves chosen by the RDA spec).
 * @return  0:      Success.
 */
int castle_extent_space_alloc(c_ext_t *ext, c_da_t da_id, c_chk_cnt_t alloc_size)
{
    struct castle_extent_state *ext_state;
    struct castle_slave *slaves[ext->k_factor];
    c_rda_spec_t *rda_spec;
    c_chk_cnt_t chunk;
    void *rda_state;
    c_ext_pos_t map_cep;
    c2_block_t *map_c2b;
    c_disk_chk_t disk_chk, *map_page;
    int map_page_idx, max_map_page_idx, err, j;
    c_chk_cnt_t start;

    /* Nothing to allocate. */
    if (!alloc_size)
        return 0;

    BUG_ON(LOGICAL_EXTENT(ext->ext_id) && (ext->ext_id < META_EXT_ID));

    /* Should be in transaction. */
    BUG_ON(!castle_extent_in_transaction());

    /* Initialise all the variables checked in the out: block. */
    map_c2b = NULL;
    rda_state = NULL;
    ext_state = NULL;

    /* Get the RDA spec structure. */
    rda_spec = castle_rda_spec_get(ext->type);
    BUG_ON(rda_spec->k_factor != ext->k_factor);
    /* Initialise our own state first. */
    ext_state = castle_extent_state_alloc(ext);
    if(!ext_state)
    {
        castle_printk(LOG_WARN, "Couldn't malloc extent allocation structure.\n");
        err = -ENOMEM;
        goto out;
    }
    /* Initialise the RDA spec state. */
    rda_state = rda_spec->extent_init(ext, ext->size, alloc_size, ext->type);
    if (!rda_state)
    {
        debug("Couldn't initialise RDA state.\n");
        /* FIXME: It is also possible that the error is -ENOMEM. */
        err = -ENOSPC;
        goto out;
    }

    debug("Allocating physical space for extent: %lld, k_factor: %d\n", ext->ext_id, ext->k_factor);
    /* Get k_factor disk chunks for each logical chunk, and save them in the meta extent. */
    max_map_page_idx = map_chks_per_page(ext->k_factor);

retry:
    start = ext->global_mask.end;
    map_cep = castle_extent_map_cep_get(ext->maps_cep, start, ext->k_factor);
    map_cep.offset = MASK_BLK_OFFSET(map_cep.offset);
    map_page_idx = start % max_map_page_idx;
    map_page = NULL;
    map_c2b = NULL;
    for(chunk=0; chunk<alloc_size; chunk++)
    {
        debug("Map_page_idx: %d/%d\n", map_page_idx, max_map_page_idx);
        /* Move to the next map page, once the index overflows the max. */
        if(!map_c2b || (map_page_idx >= max_map_page_idx))
        {
            /* Release the previous map_c2b, if one exists. */
            if(map_c2b)
            {
                debug("Putting old map_c2b for cep: "cep_fmt_str_nl, cep2str(map_c2b->cep));
                dirty_c2b(map_c2b);
                write_unlock_c2b(map_c2b);
                put_c2b(map_c2b);

                /* Reset the index. */
                map_page_idx = 0;
            }
            /* Get the next map_c2b. */
            debug("Getting map c2b, for cep: "cep_fmt_str_nl, cep2str(map_cep));
            map_c2b = castle_cache_page_block_get(map_cep);
            write_lock_c2b(map_c2b);

            /* Read old maps, if we are allocating from in-between. */
            if (map_page_idx && !c2b_uptodate(map_c2b))
                BUG_ON(submit_c2b_sync(READ, map_c2b));
            else
                update_c2b(map_c2b);

            /* Reset the map pointer. */
            map_page = c2b_buffer(map_c2b);
            /* Advance the map cep. */
            map_cep.offset += C_BLK_SIZE;
        }

        /* Ask the RDA spec which slaves to use. */
        if (rda_spec->next_slave_get( slaves,
                                      rda_state,
                                      chunk) < 0)
        {
            castle_printk(LOG_WARN, "Failed to get next slave for extent: %llu\n", ext->ext_id);
            err = -ENOSPC;
            goto out;
        }

        /* Allocate disk chunks from each slave designated by the rda spec. */
        for (j=0; j<ext->k_factor; j++)
        {
            disk_chk = castle_extent_disk_chk_alloc(da_id,
                                                    ext_state,
                                                    slaves[j], j);
            debug("Allocation for (logical_chunk=%d, copy=%d) -> (slave=0x%x, "disk_chk_fmt")\n",
                chunk, j, slaves[j]->uuid, disk_chk2str(disk_chk));
            if(DISK_CHK_INVAL(disk_chk))
            {
                debug("Invalid disk chunk, freeing the extent.\n");
                /* Release map c2b, so that castle_extent_space_free() can use it. */
                dirty_c2b(map_c2b);
                write_unlock_c2b(map_c2b);
                put_c2b(map_c2b);
                map_c2b = NULL;
                _castle_extent_space_free(ext, start, ext->k_factor * chunk + j);
                if (test_bit(CASTLE_SLAVE_OOS_BIT, &slaves[j]->flags))
                    /*
                     * The slave went out-of-service since the 'next_slave_get'. Retry, and the
                     * next time around the slave should be excluded from the map.
                     */
                    goto retry;
                err = -ENOSPC;
                goto out;
            }
            /* Save the disk chunk in the map. */
            map_page[ext->k_factor * map_page_idx + j] = disk_chk;
        }
        map_page_idx++;
    }
    /* Succeeded alocating everything. */
    err = 0;

out:
    if(map_c2b)
    {
        dirty_c2b(map_c2b);
        write_unlock_c2b(map_c2b);
        put_c2b(map_c2b);
    }
    if(rda_state)
        rda_spec->extent_fini(rda_state);
    if(ext_state)
        castle_extent_state_dealloc(ext, ext_state);

    return err;
}

c_ext_id_t castle_extent_alloc_sparse(c_rda_type_t             rda_type,
                                      c_da_t                   da_id,
                                      c_ext_type_t             ext_type,
                                      c_chk_cnt_t              ext_size,
                                      c_chk_cnt_t              alloc_size,
                                      int                      in_tran,
                                      void                    *data,
                                      c_ext_event_callback_t   callback)
{
    int ret = 0;
    c_ext_event_t *event_hdl = NULL;

    /* Either get both parameters or none. */
    BUG_ON((callback && !data) || (!callback && data));

    /* Allocate event handler structure and call low level extent alloc(). */
    if (callback)
    {
        event_hdl = castle_zalloc(sizeof(c_ext_event_t));

        if (!event_hdl)
            return INVAL_EXT_ID;

        event_hdl->callback = callback;
        event_hdl->data     = data;
    }

    /* If the caller is not already in transaction. start a transaction. */
    if (!in_tran)   castle_extent_transaction_start();

    ret = _castle_extent_alloc(rda_type, da_id, ext_type, ext_size, alloc_size, INVAL_EXT_ID, event_hdl);

    /* End the transaction. */
    if (!in_tran)   castle_extent_transaction_end();

    return ret;
}

/**
 * Allocate an extent.
 *
 * @param rda_type      [in]    RDA algorithm to be used.
 * @param da_id         [in]    Double-Array that this extent belongs to.
 * @param ext_type      [in]    Type of data, that will be stored in extent.
 * @param ext_size      [in]    Size of extent (in chunks). Extent could occupy more space
 *                              than this, depends on RDA algorithm and freespace algos.
 * @param in_tran       [in]    Already in the extent transaction.
 * @param data          [in]    Data to be used in event handler.
 * @param callback      [in]    Extent Event handler. Current events are just low space events.
 *
 * @return Extent ID.
 *
 * @also _castle_extent_alloc
 */
c_ext_id_t castle_extent_alloc(c_rda_type_t             rda_type,
                               c_da_t                   da_id,
                               c_ext_type_t             ext_type,
                               c_chk_cnt_t              ext_size,
                               int                      in_tran,
                               void                    *data,
                               c_ext_event_callback_t   callback)
{
    return castle_extent_alloc_sparse(rda_type, da_id, ext_type, ext_size, ext_size,
                                      in_tran, data, callback);
}

/**
 * Add the low freespace callback to the victim list.
 */
static void castle_extent_lfs_callback_add(c_ext_event_t *event_hdl)
{
    BUG_ON(!castle_extent_in_transaction());

    /* Add the victim handler to the list of handlers of specific type. This handler gets
     * called, when more space is available. */
    if (event_hdl)
    {
        /* Add to the end, to maintain FIFO. */
        list_add_tail(&event_hdl->list, &castle_lfs_victim_list);
    }
}

/**
 * Allocate a new extent.
 *
 * @param rda_type      [in]    RDA algorithm to be used.
 * @param da_id         [in]    Double-Array that this extent belongs to.
 * @param ext_type      [in]    Type of data, that will be stored in extent.
 * @param count         [in]    Size of extent (in chunks). Extent could occupy more space
 *                              than this, depends on RDA algorithm and freespace algos.
 * @param ext_id        [in]    Specify an extent ID, for logical extents. INVAL_EXT_ID for
 *                              normal extents.
 * @param event_hdl     [in]    Low space event handler structure.
 *
 * @return  Extent ID of the newly created extent.
 *
 * @also castle_extent_alloc
 * @also CONVERT_MENTRY_TO_EXTENT()
 * @also castle_extent_micro_ext_create()
 * @also castle_extent_sup_ext_init()
 */
static c_ext_id_t _castle_extent_alloc(c_rda_type_t     rda_type,
                                       c_da_t           da_id,
                                       c_ext_type_t     ext_type,
                                       c_chk_cnt_t      ext_size,
                                       c_chk_cnt_t      alloc_size,
                                       c_ext_id_t       ext_id,
                                       c_ext_event_t   *event_hdl)
{
    c_ext_t *ext = NULL;
    int ret = 0;
    c_rda_spec_t *rda_spec = castle_rda_spec_get(rda_type);
    struct castle_extents_superblock *castle_extents_sb;
    c_res_pool_t *pool = NULL;
    uint32_t     nr_blocks;
    int allocated_from_meta_pool = 0;

    BUG_ON(!castle_extent_in_transaction());
    BUG_ON(!extent_init_done && !LOGICAL_EXTENT(ext_id));

    /* ext_id would be passed only for logical extents and they musn't be in the hash. */
    BUG_ON(castle_extents_hash_get(ext_id));

    if (!LOGICAL_EXTENT(ext_id) && !extents_allocable)
    {
        castle_printk(LOG_ERROR,
                "Attempted to allocate extent before fs was initialised fully.\n");
        WARN_ON(1);
        return INVAL_EXT_ID;
    }

    debug("Creating extent of size: %u/%u\n", ext_size, alloc_size);
    ext = castle_ext_alloc(0);
    if (!ext)
    {
        castle_printk(LOG_WARN, "Failed to allocate memory for extent\n");
        goto __hell;
    }
    castle_extents_sb       = castle_extents_super_block_get();

    ext->ext_id                = EXT_ID_INVAL(ext_id) ? castle_extents_sb->ext_id_seq : ext_id;
    ext->dirtytree->ext_id     = ext->ext_id;
    ext->size                  = ext_size;
    ext->type                  = rda_type;
    ext->k_factor              = rda_spec->k_factor;
    ext->ext_type              = ext_type;
    ext->da_id                 = da_id;
    ext->use_shadow_map        = 0;
    ext->shadow_map            = NULL;
    ext->dirtytree->flush_prio = castle_ext_flush_prio_get(ext->ext_type, ext->size);
#ifdef CASTLE_PERF_DEBUG
    ext->dirtytree->ext_size= ext->size;
    ext->dirtytree->ext_type= ext->ext_type;
#endif

    /* Record if this extent is 1 RDA. */
    if (ext->type == RDA_1)
        min_rda_lvl = RDA_1;

    /* The rebuild sequence number that this extent starts off at */
    ext->curr_rebuild_seqno = atomic_read(&current_rebuild_seqno);
    ext->remap_seqno = 0;

    /* Try to reserve space on disk. */
    if (alloc_size)
    {
        pool = castle_alloc(sizeof(c_res_pool_t));
        if (!pool)
            goto __hell;

        /* This is just a temporary pool, just to make allocation much simpler. This is not
         * added to hash table and so can't be checkpointed. And the life time of this pool
         * is just during extent_alloc(). */
        castle_res_pool_init(pool);

        if (__castle_extent_space_reserve(rda_type, alloc_size, pool) < 0)
        {
            debug_res_pools("Failed to reserve space for extent allocation: %u, %s\n",
                             alloc_size, castle_rda_type_str[rda_type]);
            castle_free(pool);
            pool = NULL;

            goto __low_space;
        }

        __castle_res_pool_extent_attach(pool, ext);
    }

    /* Block aligned chunk maps for each extent. */
    nr_blocks = map_size(ext_size, rda_spec->k_factor);
    if (ext->ext_id == META_EXT_ID)
    {
        ext->maps_cep.ext_id = MICRO_EXT_ID;
        ext->maps_cep.offset = 0;
    }
    else if ((nr_blocks == 1) &&
             (castle_extent_meta_pool_get(&ext->maps_cep.offset)))
    {
        allocated_from_meta_pool = 1;
        ext->maps_cep.ext_id = META_EXT_ID;
    }
    else
    {
        if (castle_ext_freespace_get(&meta_ext_free, (nr_blocks * C_BLK_SIZE), 0, &ext->maps_cep))
        {
            castle_printk(LOG_WARN, "Too big of an extent/crossing the boundry.\n");
            goto __hell;
        }
        debug("Allocated extent map at: "cep_fmt_str_nl, cep2str(ext->maps_cep));
        if((ext->maps_cep.offset >> 20) !=
           (ext->maps_cep.offset + nr_blocks * C_BLK_SIZE) >> 20)
            castle_printk(LOG_USERINFO, "Metaext, used=0x%llx, size=0x%llx\n",
                   atomic64_read(&meta_ext_free.used), meta_ext_free.ext_size);
    }

    BUG_ON(BLOCK_OFFSET(ext->maps_cep.offset));

    if (alloc_size == 0)
        goto alloc_done;

    /* We must have already set the pool. */
    BUG_ON(ext->pool == NULL || ext->pool != pool);

    if ((ret = castle_extent_space_alloc(ext, da_id, alloc_size)) == -ENOSPC)
    {
        debug("Extent alloc failed to allocate space for %u chunks\n", alloc_size);
        goto __low_space;
    }
    else if (ret < 0)
    {
        debug("Extent alloc failed for %u chunks\n", alloc_size);
        goto __hell;
    }

    /* Pool is just local, destroy it before returning. */
    __castle_res_pool_extent_detach(ext);
    castle_res_pool_unreserve(pool);
    castle_free(pool);
    pool = NULL;

alloc_done:
    /* Successfully allocated space for extent. Create a mask for it. */
    BUG_ON(castle_extent_mask_create(ext,
                                     MASK_RANGE(0, alloc_size),
                                     INVAL_MASK_ID) < 0);

    /* Add extent and extent dirtylist to hash tables. */
    castle_extents_hash_add(ext);

    castle_extent_print(ext, NULL);

    if (EXT_ID_INVAL(ext_id))
    {
        castle_extents_sb->nr_exts++;
        castle_extents_sb->ext_id_seq++;
    }

    /* Extent allocation is SUCCESS. No need of event handler. Free it. */
    castle_check_free(event_hdl);

    return ext->ext_id;

__low_space:
    castle_printk(LOG_INFO, "Failed to create extent for DA: %u of type %s for %u chunks\n",
                  da_id,
                  castle_ext_type_str[ext_type],
                  alloc_size);
    /* Add the victim handler to the list of handlers of specific type. This handler gets
     * called, when more space is available. */
    castle_extent_lfs_callback_add(event_hdl);

__hell:
    if (pool)
    {
        __castle_res_pool_extent_detach(ext);
        castle_res_pool_unreserve(pool);
        castle_free(pool);
    }

    /* If we allocated from the meta extent pool, put it back ... */
    if (allocated_from_meta_pool)
        castle_extent_meta_pool_replace(ext->maps_cep.offset);

    if (ext)
    {
        castle_free(ext->dirtytree);
        castle_free(ext);
    }

    return INVAL_EXT_ID;
}

/**
 * Low freespace handling
 * === ========= ========
 *
 * Lewis notes from meeting:
 * ----- ----- ---- -------
 *
 * When a thread calls castle_extent_alloc() that fails it passes a work_struct to
 * the extent layer.  This work_struct might be a CB handler (which wakes another
 * thread up, etc.) or a full-blown function.
 *
 * When the extent layer has more freespace available for allocation it schedules
 * the work_structs which will retry their various allocations, potentially calling
 * back into the extent layer to requeue themselves if allocations still fail.
 *
 * By keeping the list of work items sensibly sorted we could fairly share access
 * to freespace as it becomes available.  Big non-atomic consumers (e.g.
 * castle_da_all_rwcts_create() which makes multiple small allocations) could be
 * scheduled in an atomic fashion and eventually bubble to the top of the CB list.
 * Atomic allocations would also bubble up but are less likely to fail as a result
 * of races from other threads.
 *
 * e.g.
 * a merge thread that failed to allocate an output extent would call into the
 * extent layer to be notified when more freespace is available.
 *
 * e.g.
 * a castle_da_rwct_create() that failed to allocate a T0 extent would call into
 * the extent layer to be notified when more freespace is available.  It would also
 * set the DA's frozen bit, preventing any further inserts until a new T0 could be
 * created.  [ could this frozen bit be per T0 RWCT? ]
 *
 * e.g.
 * castle_da_all_rwcts_create() fails to allocate an extent and calls into the
 * extent layer to be notified when more freespace is available.  It would set the
 * DA frozen bit, preventing further inserts.
 *
 * Design:
 * ------
 *
 * Every consumer of freespace that has failed to allocate would add itself to a list of
 * victims. And also registers a callback. All operations on this victim list are atomic.
 *
 * LIST_HEAD(castle_freespace_victim_list)
 *
 * When more freespace is available (checkpoints potentially release space), go through
 * victim list and runs callback function for each victim in sequence. Each victim can
 * also mark the priority.
 */

/**
 * Call low free space handlers of all victims. Stop if any of the handler fails.
 */
void castle_extent_lfs_victims_wakeup(void)
{
    struct list_head head;

    castle_extent_transaction_start();

    /* Take the snapshot of the list and clean it. */
    list_replace_init(&castle_lfs_victim_list, &head);

    castle_extent_transaction_end();

    /* Call each handler for each victim in sequence. */
    /* Note: Don't use list_for_each_safe as it is possible that someone else could be changing
     * the list. */
    while (!list_empty(&head))
    {
        c_ext_event_t *hdl = list_first_entry(&head, c_ext_event_t, list);

        /* No need to call handlers in case module is exiting. No point of creating more extents
         * for components just before they die. */
        if (!castle_last_checkpoint_ongoing)
            hdl->callback(hdl->data);

         /* Handled low free space successfully. Get rid of event handler. */
         list_del(&hdl->list);
         castle_free(hdl);
    }
}

/* Free the resources taken by extent. This function gets executed on system work queue.
 *
 * @param data void pointer to extent structure that to be freed.
 *
 * @also castle_extent_put
 * @also castle_extent_unlink
 */
static void castle_extent_resource_release(void *data)
{
    c_ext_t *ext = data;
    struct castle_extents_superblock *castle_extents_sb = NULL;
    c_ext_id_t ext_id = ext->ext_id;
    struct list_head *pos, *tmp;
    int nr_blocks;

    /* Should be in transaction. */
    BUG_ON(!castle_extent_in_transaction());

    /*
     * Shouldn't have partial superchunks left, unless there is a leak.
     * Currently only rebuild leaks freespace.
     */
    list_for_each_safe(pos, tmp, &ext->schks_list)
    {
        c_part_schk_t *schk = list_entry(pos, c_part_schk_t, list);

        /* Delete from list. */
        list_del(pos);

        /* Free space. */
        kmem_cache_free(castle_partial_schks_cache, schk);

        castle_printk(LOG_DEBUG, "%llu: Superchunk: (%u:%u) on slave 0x%x.\n",
                ext_id, schk->first_chk, schk->count, schk->slave_id);
    }

    BUG_ON(!list_empty(&ext->schks_list));

    /* Shouldn't have any live masks left. */
    BUG_ON(!list_empty(&ext->mask_list));

    /* If extent is attached to any reservation pool, detach it first. */
    if (ext->pool)
        __castle_res_pool_extent_detach(ext);

    /* Reference count should be zero. */
    if (atomic_read(&ext->link_cnt))
    {
        castle_printk(LOG_ERROR, "Couldn't delete the referenced extent %llu, %d\n",
                                 ext_id,
                                 atomic_read(&ext->link_cnt));
        BUG();
    }

    /* Get the extent lock, to prevent checkpoint happening parallely. */
    castle_extents_sb = castle_extents_super_block_get();

    /*
     * If this allocation used only 1 page of the meta extent, and the meta extent pool
     * is not full, then add this page to the meta exetnt pool released list.
     */
    nr_blocks = map_size(ext->size, ext->k_factor);
    if (nr_blocks == 1)
    {
        BUG_ON(ext->maps_cep.ext_id != META_EXT_ID);
        castle_extent_meta_pool_release(ext->maps_cep.offset);
    }

    /* Remove extent from hash. */
    castle_extents_hash_remove(ext);

    /* We have already freed-up all the space, consequently marked all dirty c2bs in
     * that space as clean, there shouldn't be any more dirty c2bs. */
    BUG_ON(ext->dirtytree->nr_pages);

    /* Drop 'extent exists' reference on c2b dirtytree. */
    castle_cache_dirtytree_demote(ext->dirtytree);
    castle_extent_dirtytree_put(ext->dirtytree);

    castle_free(ext);

    debug("Completed deleting ext: %lld\n", ext_id);

    castle_extents_sb->nr_exts--;

    /* Decrement the dead count. Module can't exit with outstanding dead extents.  */
    atomic_dec(&castle_extents_dead_count);
}

uint32_t castle_extent_kfactor_get(c_ext_id_t ext_id)
{
    unsigned long flags;
    c_ext_t *ext;
    uint32_t ret = 0;

    read_lock_irqsave(&castle_extents_hash_lock, flags);

    ext = __castle_extents_hash_get(ext_id);
    if (ext)
        ret = ext->k_factor;

    read_unlock_irqrestore(&castle_extents_hash_lock, flags);

    return ret;
}

/**
 * Return the size of extent ext_id in chunks.
 */
c_chk_cnt_t castle_extent_size_get(c_ext_id_t ext_id)
{
    c_ext_t *ext = castle_extents_hash_get(ext_id);

    if (ext)
        return ext->size;
    return 0;
}

/**
 * Return the number of (optionally active) slaves for ext_id.
 *
 * @param ext_id        Extent ID to return slave count for
 * @param only_active   Return only active slaves if set
 */
static int _castle_extent_slave_count_get(c_ext_id_t ext_id, int only_active)
{
    c_ext_t *ext = castle_extents_hash_get(ext_id);

    if (ext)
    {
        /* @TODO currently we return the total number of slaves, this needs to
         * be updated to return the number of slaves for a given extent. */
        struct list_head *lh;
        int slaves = 0;

        rcu_read_lock();
        list_for_each_rcu(lh, &castle_slaves.slaves)
        {
            slaves++;
        }
        rcu_read_unlock();

        return slaves;
    }
    else
        return 0;
}

/**
 * Return the total number of slaves for ext_id.
 */
int castle_extent_slave_count_get(c_ext_id_t ext_id)
{
    return _castle_extent_slave_count_get(ext_id, 0);
}

/**
 * Return the number of active slaves for ext_id.
 */
int castle_extent_active_slave_count_get(c_ext_id_t ext_id)
{
    return _castle_extent_slave_count_get(ext_id, 1);
}

/**
 * Determines whether an extent ID exists.
 *
 * @param   ext_id  Extent ID to check
 *
 * @return  1   Extent exists
 * @return  0   No such extent
 */
int castle_extent_exists(c_ext_id_t ext_id)
{
    if (castle_extents_hash_get(ext_id))
        return 1;

    return 0;
}

static void __castle_extent_map_get(c_ext_t *ext, c_chk_t chk_idx, c_disk_chk_t *chk_map)
{
    c_ext_pos_t map_page_cep, map_cep;
    c2_block_t *map_c2b;
    uint64_t offset;

    debug("Seeking map for ext: %llu, chunk: %u\n", ext->ext_id, chk_idx);
    offset = (chk_idx * ext->k_factor * sizeof(c_disk_chk_t));
    if (SUPER_EXTENT(ext->ext_id))
    {
        struct castle_slave *cs;

        cs = castle_slave_find_by_id(sup_ext_to_slave_id(ext->ext_id));
        BUG_ON((cs->sup_ext_maps == NULL) || (ext->k_factor != sup_ext.k_factor));
        memcpy(chk_map,
               (((uint8_t *)cs->sup_ext_maps) + offset),
               ext->k_factor * sizeof(c_disk_chk_t));
    }
    else if (ext->ext_id == MICRO_EXT_ID)
    {
        /* Accessing castle_extents_global_sb without lock. extent_space_alloc()
         * calls this function with lock held, which could lead to deadlock. */
        BUG_ON(chk_idx != 0);
        memcpy(chk_map, castle_extents_global_sb.micro_maps, ext->k_factor * sizeof(c_disk_chk_t));
    }
    else
    {
        debug("Maps cep="cep_fmt_str_nl, cep2str(ext->maps_cep));
        map_cep = castle_extent_map_cep_get(ext->maps_cep, chk_idx, ext->k_factor);
        /* Make the map_page_cep offset block aligned. */
        memcpy(&map_page_cep, &map_cep, sizeof(c_ext_pos_t));
        map_page_cep.offset = MASK_BLK_OFFSET(map_page_cep.offset);
        /* Get the c2b coresponding to map_page_cep. */
        map_c2b = castle_cache_page_block_get(map_page_cep);
        if (!c2b_uptodate(map_c2b))
        {
            debug("Scheduling read to get chunk mappings for ext: %llu\n",
                        ext->ext_id);
            write_lock_c2b(map_c2b);
            /* Need to recheck whether it's uptodate after getting the lock. */
            if(!c2b_uptodate(map_c2b))
            {
                set_c2b_no_resubmit(map_c2b);
                submit_c2b_sync(READ, map_c2b);
                if (!c2b_uptodate(map_c2b))
                {
                    /*
                     * The I/O has failed. This may be because we had a slave die on us. That I/O
                     * fail should have resulted in future I/O submissions by-passing that dead
                     * slave. So, try again, just once, and we should be able to read successfully
                     * from the other slave for this c2b. Assumes no_resubmit still set on c2b.
                     */
                    BUG_ON(submit_c2b_sync(READ, map_c2b));
                }
                clear_c2b_no_resubmit(map_c2b);
            }
            write_unlock_c2b(map_c2b);
        }
        read_lock_c2b(map_c2b);
        /* Check that the mapping for the chunk fits in the page. */
        BUG_ON(BLOCK_OFFSET(map_cep.offset) + (ext->k_factor * sizeof(c_disk_chk_t)) > C_BLK_SIZE);
        /* Copy. */
        memcpy(chk_map,
               c2b_buffer(map_c2b) + BLOCK_OFFSET(map_cep.offset),
               ext->k_factor * sizeof(c_disk_chk_t));
#ifdef DEBUG
        /* Print the mapping. */
        {
            int i;
            for(i=0; i<ext->k_factor; i++)
                debug("Mapping read: ext_id=%lld, logical_chunk=%d, copy=%d -> "disk_chk_fmt_nl,
                    ext->ext_id, chk_idx, i, disk_chk2str(chk_map[i]));
        }
#endif
        /* Release the cache block. */
        read_unlock_c2b(map_c2b);
        put_c2b(map_c2b);

        INJECT_FAULT;
    }
}

/**
 * Get the mapping of disk chunk layout for a given logical chunk in extent.
 *
 * Note: Caller should be holding a reference on the extent.
 */
uint32_t castle_extent_map_get(c_ext_id_t     ext_id,
                               c_chk_t        offset,
                               c_disk_chk_t  *chk_map,
                               int            rw, c_byte_off_t boff)
{
    c_ext_t *ext = castle_extents_hash_get(ext_id);
    int i, j;
    uint32_t idx = ext->k_factor;

    if(ext == NULL)
        return 0;

    if (offset >= ext->size)
    {
        castle_printk(LOG_ERROR, "BUG in %s\n", __FUNCTION__);
        castle_printk(LOG_ERROR, "    Extent: %llu\n", ext->ext_id);
        castle_printk(LOG_ERROR, "    Offset: %u\n", offset);
        castle_printk(LOG_ERROR, "    Extent Size: %u\n", ext->size);
        BUG();
    }

    if ((offset < ext->global_mask.start) || (offset >= ext->global_mask.end))
        return 0;

    __castle_extent_map_get(ext, offset, chk_map);

    /*
     * This extent may be being remapped, in which case writes may also need to be directed via its
     * shadow map. This needs to be checked under the shadow map lock, but that lock and the
     * 'use_shadow_map' flag are only initialised for 'normal' extents, hence the extent id checks.
     */
    if ((rw == WRITE) && (!SUPER_EXTENT(ext->ext_id)) && !(ext->ext_id == MICRO_EXT_ID))
    {
        spin_lock(&ext->shadow_map_lock);
        if (ext->use_shadow_map &&
          ((offset >= ext->shadow_map_range.start) && (offset < ext->shadow_map_range.end)))
        {
            /*
             * We've already loaded the first half of the chk_map with the 'on-disk' map for this
             * logical chunk. Now look to see if there are any other disk chunks in the shadow map
             * that are *not* already present in the chk_map. Any we find must be added.
             * These extra chunks are the remapped ones, and the data must be updated there too.
             * We only need to check slave_id, because this cannot be duplicated in the map.
             */
            for (i=0; i<ext->k_factor; i++)
            {
                int chunk_already_mapped = 0;
                for (j=0; j<ext->k_factor; j++)
                {
                    BUG_ON((offset >= ext->shadow_map_range.end) ||
                           (offset < ext->shadow_map_range.start));
                    if (chk_map[j].slave_id == ext->shadow_map[offset*ext->k_factor+i].slave_id)
                    {
                        chunk_already_mapped = 1;
                        break;
                    }
                }
                if (!chunk_already_mapped)
                    memcpy(chk_map+idx++, &ext->shadow_map[offset*ext->k_factor+i],
                           sizeof(c_disk_chk_t));
            }
        }
        spin_unlock(&ext->shadow_map_lock);
    }

    /* Return the number of chunks in the map (may be > k_factor for remap I/O) */
    return idx;
}

c_ext_id_t castle_extent_sup_ext_init(struct castle_slave *cs)
{
    c_ext_t      *ext;
    c_rda_spec_t *rda_spec = castle_rda_spec_get(SUPER_EXT);
    int           i, j;

    ext = castle_ext_alloc(slave_id_to_sup_ext(cs->id));
    if (!ext)
    {
        castle_printk(LOG_WARN, "Failed to allocate memory for extent\n");
        goto err1;
    }
    ext->size                  = sup_ext.size;
    ext->type                  = sup_ext.type;
    ext->k_factor              = sup_ext.k_factor;
    ext->maps_cep              = sup_ext.maps_cep;
    ext->ext_type              = EXT_T_META_DATA;
    ext->da_id                 = 0;
    ext->dirtytree->flush_prio = castle_ext_flush_prio_get(ext->ext_type, ext->size);
#ifdef CASTLE_PERF_DEBUG
    ext->dirtytree->ext_size    = ext->size;
    ext->dirtytree->ext_type    = ext->ext_type;
#endif

    cs->sup_ext_maps = castle_alloc(sizeof(c_disk_chk_t) * ext->size * rda_spec->k_factor);
    BUG_ON(rda_spec->k_factor != ext->k_factor);
    if (!cs->sup_ext_maps)
    {
        castle_printk(LOG_WARN, "Failed to allocate memory for extent chunk "
                "maps of size %u:%u chunks\n",
        ext->size, rda_spec->k_factor);
        goto err2;
    }

    for (i=0; i<ext->size; i++)
    {
        for (j=0; j<rda_spec->k_factor; j++)
        {
            cs->sup_ext_maps[MAP_IDX(ext, i, j)].slave_id   = cs->uuid;
            cs->sup_ext_maps[MAP_IDX(ext, i, j)].offset     = i + (j * ext->size);
        }
    }
    ext->maps_cep = INVAL_EXT_POS;

    castle_extent_transaction_start();

    /* Create a mask for it. */
    BUG_ON(castle_extent_mask_create(ext,
                                     MASK_RANGE(0, ext->size),
                                     INVAL_MASK_ID) < 0);

    castle_extents_hash_add(ext);
    cs->sup_ext = ext->ext_id;

    castle_extent_transaction_end();

    debug("Created super extent %llu for slave 0x%x\n", ext->ext_id, cs->uuid);

    return ext->ext_id;

err2:
    castle_free(ext->dirtytree);
    castle_free(ext);
err1:
    return INVAL_EXT_ID;
}

void castle_extent_sup_ext_close(struct castle_slave *cs)
{
    c_ext_id_t ext_id;
    c_ext_t *ext;

    ext_id = slave_id_to_sup_ext(cs->id);
    ext = castle_extents_hash_get(ext_id);
    if (ext)
    {
        c_ext_mask_t *mask = GET_LATEST_MASK(ext);

        BUG_ON(atomic_read(&mask->ref_count) != 1);
        castle_extents_hash_remove(ext);
        castle_free(ext);
    }
    castle_free(cs->sup_ext_maps);

    return;
}

/**
 * Extents Reference Counting:
 *
 * Extent structures can be referenced two ways..
 *      - links
 *      - transient references
 *
 * Links are used to link extents to multiple sources. For ex, large objects could be linked and
 * unlinked between component trees during merges. Links also take a transient reference on the
 * extent. Removing the last link to an extent, would mark the extent for deletion. Other than
 * that, it wouldn't do anything else. Also leaves the extent in the hash, to make sure no
 * outstanding operations would fail. It is not possible to get any references or links after
 * releasing the last link.
 *
 * Transient references are taken on extents to preserve them while doing some task(mostly io).
 * It is not possible to get a reference on an extent with no active links. After deleting last
 * reference, schedule the free function and also add the extent to a deleted extents list.
 * Last checkpoint of extent code should wait on this list to get exmpty to make sure there are
 * no outstanding deletes.
 *
 * Synchronization for Reference Counting:
 *
 * Both counts ref_cnt and link_count would be atomic variables to make sure multiple writes to
 * these variables won't race. Four operations we need for this are get(), put(), link() and
 * unlink(). It is okay to run get() and link() to run together. They just get references. Only
 * races that are possible are when the last link and last reference are released, link() and get()
 * should see it in consistent way. So, run unulink() and put() under write lock and get() and
 * link() under read lock.
 */

#define LIVE_EXTENT(_ext) ((_ext) && atomic_read(&(_ext)->link_cnt))

/**
 * Get a reference on the latest mask. Don't give a reference, if the extent doesn't have
 * any active links.
 *
 * @param ext_id    [in]    Extent that the reference is seeking for.
 *
 * @return mask_id  ID of the mask that reference is given for.
 */
c_ext_mask_id_t castle_extent_mask_get(c_ext_id_t ext_id)
{
    c_ext_t *ext = __castle_extents_hash_get(ext_id);
    uint32_t val;

    /* Expected to hold atleast read_lock. */
    BUG_ON(write_can_lock(&castle_extents_hash_lock));

    /* Don't give reference if extent is not alive. */
    if (LIVE_EXTENT(ext))
    {
        /* Get the latest mask for this extent. */
        c_ext_mask_t *mask = GET_LATEST_MASK(ext);

        /* Get a reference on latest mask. Count shouldn't be zero, before increment. */
        BUG_ON((val = atomic_inc_return(&mask->ref_count)) == 1);

        //castle_printk(LOG_DEVEL, "GET: %u "cemr_cstr"%u\n", mask->mask_id, cemr2str(mask->range), val);

        BUG_ON(castle_extent_mask_hash_get(mask->mask_id) == NULL);

        /* Return the mask ID. put() needs to be called with the same ID. */
        return mask->mask_id;
    }

    /* Extent is not alive. Return error. */
    return INVAL_MASK_ID;
}

/**
 * Release reference on the extent mask. Locks are already taken. If releasing last
 * reference, add the mask to the free list. It get's deleted by the extent garbage
 * collector thread.
 *
 * Can't free the resources from this function as that would be sleeping function and
 * the function could be in interrupt context. Instead, offload the task.
 *
 * @param mask_id [inout]   Extent mask that reference has to be released.
 */
void castle_extent_mask_put(c_ext_mask_id_t mask_id)
{
    /* Get the mask structure. */
    c_ext_mask_t *mask = castle_extent_mask_hash_get(mask_id);
    uint32_t val;

    /* Expected to hold atleast read_lock. */
    BUG_ON(write_can_lock(&castle_extents_hash_lock));

    /* Mask should be alive. */
    BUG_ON(mask == NULL);

    /* Reference count shouldn't be zero. */
    if (atomic_read(&mask->ref_count) == 0)
    {
        castle_printk(LOG_ERROR, "mask: %p\n", mask);
        BUG();
    }

    val = atomic_dec_return(&mask->ref_count);
    //castle_printk(LOG_DEVEL, "PUT: %u "cemr_cstr"%u\n", mask->mask_id, cemr2str(mask->range), val);
    /* Release reference and also check if this is the last referece; if so, schedule mask
     * for deletion. */
    if (val == 0)
    {
        static DEFINE_SPINLOCK(mask_ref_release_lock);
        unsigned long flags;
        int release_mask = 0;

        /* Take lock to make sure, no other last reference release for other in this
         * extent is racgin. */
        spin_lock_irqsave(&mask_ref_release_lock, flags);

        if (IS_OLDEST_MASK(mask->ext, mask))
            release_mask = 1;
        else
        {
            c_ext_mask_t *next_mask = list_entry(mask->list.next, c_ext_mask_t, list);

            /* If the next mask is not in hash, then it is already marked for deletion. And
             * this mask can be deleted. */
            if (!castle_extent_mask_hash_get(next_mask->mask_id))
                release_mask = 1;
        }

        if (release_mask)
        {
            c_ext_t *ext = mask->ext;
            struct list_head *pos;

            /* Update global mask. */
            list_for_each_prev(pos, &ext->mask_list)
            {
                c_ext_mask_t *pos_mask = list_entry(pos, c_ext_mask_t, list);

                /* Already scheduled for release. */
                if (castle_extent_mask_hash_get(pos_mask->mask_id) == NULL)
                    continue;

                /* Not yet ready for release. */
                if (atomic_read(&pos_mask->ref_count))
                    break;

#if 0
                castle_printk(LOG_DEVEL, "Scheduling mask %u "cemr_cstr" for free\n",
                                         pos_mask->mask_id, cemr2str(pos_mask->range));
#endif
                /* If this is the last mask, there should be no active links. */
                BUG_ON(list_is_singular(&ext->mask_list) && atomic_read(&ext->link_cnt));

                castle_extent_mask_hash_remove(pos_mask);

                /* Add to the free list, it would get destroyed later by the GC thread. */
                list_add_tail(&pos_mask->hash_list, &castle_ext_mask_free_list);

                atomic_inc_return(&castle_extents_gc_q_size);
            }

            /* Wakeup the garbage collector. */
            wake_up(&castle_ext_mask_gc_wq);
        }

        spin_unlock_irqrestore(&mask_ref_release_lock, flags);
    }
}

/**
 * Take a reference on extent to preserve extent from being deleted.
 *
 * @param   ext_id  [in]    Extent id that reference to be taken.
 *
 * @return  Pointer of extent, if SUCCESS
 *          NULL, if FAILURE
 */
c_ext_mask_id_t castle_extent_get(c_ext_id_t ext_id)
{
    static USED int count=0;
    unsigned long flags;
    c_ext_mask_id_t mask_id;

    /* Read lock is good enough as ref count is atomic. */
    read_lock_irqsave(&castle_extents_hash_lock, flags);

    /* Call low level get function. */
    mask_id = castle_extent_mask_get(ext_id);

    debug_ext_ref("%s::count = %d\n", __FUNCTION__, count++);
    read_unlock_irqrestore(&castle_extents_hash_lock, flags);

    return mask_id;
}

/**
 * Take a reference on all extent views by taking reference on latest and oldest masks.
 *
 * @param   ext_id  [in]    Extent id that reference to be taken.
 *
 * @return  Pointer of extent, if SUCCESS
 *          NULL, if FAILURE
 */
c_ext_mask_id_t castle_extent_get_all(c_ext_id_t ext_id)
{
    unsigned long flags;
    c_ext_mask_id_t mask_id;

    /* Call low level get function. */
    mask_id = castle_extent_get(ext_id);

    /* Take reference on oldest mask. */
    if (!MASK_ID_INVAL(mask_id))
    {
        c_ext_mask_t *mask, *oldest_mask;
        struct list_head *pos;

        /* Take writelock to make sure last valid mask is not getting released. */
        write_lock_irqsave(&castle_extents_hash_lock, flags);

        mask = castle_extent_mask_hash_get(mask_id);
        if (!mask)
        {
            castle_printk(LOG_ERROR, "%llu %u\n", ext_id, mask_id);
            BUG();
        }

        list_for_each_prev(pos, &mask->ext->mask_list)
        {
            oldest_mask = list_entry(pos, c_ext_mask_t, list);

            if (atomic_read(&oldest_mask->ref_count))
            {
                uint32_t val;
                BUG_ON((val = atomic_inc_return(&oldest_mask->ref_count)) == 1);
                //castle_printk(LOG_DEVEL, "get: %u "cemr_cstr"%u\n", oldest_mask->mask_id, cemr2str(oldest_mask->range), val);
                BUG_ON(castle_extent_mask_hash_get(oldest_mask->mask_id) == NULL);
                break;
            }
        }

        write_unlock_irqrestore(&castle_extents_hash_lock, flags);
    }

    return mask_id;
}

/**
 * Puts the reference. (Interrupt Context)
 *
 * @also: castle_extent_resource_release
 */
void castle_extent_put(c_ext_mask_id_t mask_id)
{
    static USED int count = 0;
    unsigned long flags;

    read_lock_irqsave(&castle_extents_hash_lock, flags);

    /* Call low level put function. */
    castle_extent_mask_put(mask_id);
    debug_ext_ref(LOG_DEBUG, "%s::count = %d\n", __FUNCTION__, count++);

    read_unlock_irqrestore(&castle_extents_hash_lock, flags);
}

/**
 * Puts the reference on oldest mask and latest mask. (Interrupt Context)
 *
 * @also: castle_extent_resource_release
 */
void castle_extent_put_all(c_ext_mask_id_t mask_id)
{
    unsigned long flags;
    c_ext_mask_t *mask, *oldest_mask;
    struct list_head *pos;

    read_lock_irqsave(&castle_extents_hash_lock, flags);

    mask = castle_extent_mask_hash_get(mask_id);

    /* Release reference on oldest mask. */
    list_for_each_prev(pos, &mask->ext->mask_list)
    {
        oldest_mask = list_entry(pos, c_ext_mask_t, list);

        if (atomic_read(&oldest_mask->ref_count))
        {
            castle_extent_mask_put(oldest_mask->mask_id);
            break;
        }
    }

    /* Call low level put function on latest mask. */
    castle_extent_mask_put(mask_id);

    read_unlock_irqrestore(&castle_extents_hash_lock, flags);
}

static c_ext_mask_id_t castle_extent_get_ptr(c_ext_id_t ext_id, c_ext_t **ext)
{
    c_ext_mask_id_t mask_id = castle_extent_get(ext_id);

    if (MASK_ID_INVAL(mask_id))
    {
        *ext = NULL;
        return mask_id;
    }

    *ext = castle_extents_hash_get(ext_id);
    BUG_ON(*ext == NULL);

    return mask_id;
}

static void castle_extent_mask_read(c_ext_mask_id_t mask_id, c_chk_cnt_t *start, c_chk_cnt_t *end)
{
    c_ext_mask_t *mask;

    read_lock_irq(&castle_extents_hash_lock);

    mask = castle_extent_mask_hash_get(mask_id);

    *start = mask->range.start;
    *end   = mask->range.end;

    read_unlock_irq(&castle_extents_hash_lock);
}

static void castle_extent_latest_mask_read(c_ext_t *ext, c_chk_cnt_t *start, c_chk_cnt_t *end)
{
    c_ext_mask_t *mask;

    read_lock_irq(&castle_extents_hash_lock);

    mask = GET_LATEST_MASK(ext);

    *start = mask->range.start;
    *end   = mask->range.end;

    read_unlock_irq(&castle_extents_hash_lock);
}

/**
 * Create a new link to the extent. New links can't be created if extent has no active links
 * (extent is dead).
 *
 * Link to an extent also takes a reference to the extent.
 *
 * @param   ext_id  [in]    Extent ID, link to be created.
 *
 * @return  0   SUCCESS
 *          -1  FAILURE
 */
int castle_extent_link(c_ext_id_t ext_id)
{
    c_ext_t *ext;
    c_ext_mask_id_t mask_id;
    unsigned long flags;

    /* Read lock is good enough as link count is atomic and unlink works under write lock. */
    read_lock_irqsave(&castle_extents_hash_lock, flags);

    /* Try to get a reference on the extent. Would fail, if the extent is already dead. */
    mask_id = castle_extent_mask_get(ext_id);
    if (MASK_ID_INVAL(mask_id))
    {
        /* Shouldn't have tried to create links on a dead extent. BUG. */
        castle_printk(LOG_ERROR, "%s::cannot do get on ext with id %d.\n", __FUNCTION__, ext_id);
        BUG();
    }

    ext = __castle_extents_hash_get(ext_id);

    /* Shouldn't be a dead extent. */
    BUG_ON(atomic_read(&ext->link_cnt) == 0);

    /* Increment link count. */
    atomic_inc(&ext->link_cnt);

    /* Unlock hash lock. */
    read_unlock_irqrestore(&castle_extents_hash_lock, flags);

    return 0;
}

/**
 * Remove a link for extent. Removing the last link would mark extent for deletion. No more
 * references or links can be created after that.
 *
 * @param   ext_id  [in]    Extent ID, to be unlinked.
 *
 * @return  0   SUCCESS
 *          -1  FAILURE
 */
int castle_extent_unlink(c_ext_id_t ext_id)
{
    c_ext_t *ext;
    c_ext_mask_id_t mask_id;
    unsigned long flags;

    /* Get a write lock, to make sure there are no parallel get() or link(). */
    write_lock_irqsave(&castle_extents_hash_lock, flags);

    ext = __castle_extents_hash_get(ext_id);
    /* Can't unlink an extent not in hash. BUG. */
    if(!ext)
    {
        castle_printk(LOG_ERROR, "%s::cannot do unlink on ext with id %d.\n", __FUNCTION__, ext_id);
        BUG();
    }

    /* Shouldn't try to unlink a deleted extent. */
    BUG_ON(atomic_read(&ext->link_cnt) == 0);

    /* Reduce the link count and check if this is the last link. */
    if (atomic_dec_return(&ext->link_cnt) == 0)
    {
        debug_ext_ref("%s::extent %lld\n", __FUNCTION__, ext_id);
        /* All merges and request would have completed before setting castle_last_checkpoint_ongoing.
         * There shouldn't be any free()/unlink() after that. */
        BUG_ON(castle_last_checkpoint_ongoing);

        /* Increment the count of scheduled extents for deletion. Last checkpoint, conseqeuntly,
         * castle_exit waits for all outstanding dead extents to get destroyed. */
        atomic_inc(&castle_extents_dead_count);
    }

    /* There should be atleast one mask. */
    BUG_ON(list_empty(&ext->mask_list));

    /* This link has a reference on current latest mask. */
    mask_id = GET_LATEST_MASK(ext)->mask_id;

    write_unlock_irqrestore(&castle_extents_hash_lock, flags);

    /* Release the reference on latest mask. */
    castle_extent_put(mask_id);

    return 0;
}

/**
 * It's exactly same as castle_extent_unlink(). Unlink function would be used with extents with
 * multiple links. Just to be clear with terminology adding one more function castle_extent_free()
 * to remove the only link normal(non-large object) extents have.
 *
 * @param   ext_id  [in]    Extent ID, to be unlinked.
 *
 * @return  0   SUCCESS
 *          -1  FAILURE
 */
int castle_extent_free(c_ext_id_t ext_id)
{
    c_ext_t *ext = castle_extents_hash_get(ext_id);

    /* Free should be called to remove the the last/only link extent has. */
    BUG_ON(atomic_read(&ext->link_cnt) != 1);

    return castle_extent_unlink(ext_id);
}

#ifdef CASTLE_PERF_DEBUG
/**
 * Increment the number of up2date/not up2date chunks prefetched (or not).
 *
 * @param   up2date If set, increment the number of chunks that did not need
 *                  to be prefetched
 *                  If unset, increment the number of chunks that needed to
 *                  be prefetched
 */
void _castle_extent_efficiency_inc(c_ext_id_t ext_id, int up2date)
{
    c_ext_t *ext;
    c_ext_mask_id_t mask_id;

    mask_id = castle_extent_get_ptr(ext_id, &ext);
    BUG_ON(!ext);

    if (up2date)
        atomic_inc(&ext->pref_chunks_up2date);
    else
        atomic_inc(&ext->pref_chunks_not_up2date);

    castle_extent_put(mask_id);
}

/**
 * Increment the number of prefetched chunks for extent.
 */
void castle_extent_not_up2date_inc(c_ext_id_t ext_id)
{
    _castle_extent_efficiency_inc(ext_id, 0 /*up2date*/);
}

/**
 * Increment the number of chunks that did not need to be prefetched for extent.
 */
void castle_extent_up2date_inc(c_ext_id_t ext_id)
{
    _castle_extent_efficiency_inc(ext_id, 1 /*up2date*/);
}

/**
 * Return and reset the number of up2date/not up2date chunks prefetched (or not).
 *
 * @param   up2date If set, get/reset the number of chunks that did not need
 *                  to be prefetched
 *                  If unset, get/reset the number of chunks that needed to
 *                  be prefetched
 */
int _castle_extent_efficiency_get_reset(c_ext_id_t ext_id, int up2date)
{
    c_ext_t *ext;
    int amount;
    c_ext_mask_id_t mask_id;

    mask_id = castle_extent_get_ptr(ext_id, &ext);
    BUG_ON(!ext);

    if (up2date)
    {
        amount = atomic_read(&ext->pref_chunks_up2date);
        atomic_sub(amount, &ext->pref_chunks_up2date);
    }
    else
    {
        amount = atomic_read(&ext->pref_chunks_not_up2date);
        atomic_sub(amount, &ext->pref_chunks_not_up2date);
    }

    castle_extent_put(mask_id);

    return amount;
}

/**
 * Get/reset the number of chunks that needed to be prefetched.
 */
int castle_extent_not_up2date_get_reset(c_ext_id_t ext_id)
{
    return _castle_extent_efficiency_get_reset(ext_id, 0 /*up2date*/);
}

/**
 * Get/reset the number of chunks that did not need to be prefetched.
 */
int castle_extent_up2date_get_reset(c_ext_id_t ext_id)
{
    return _castle_extent_efficiency_get_reset(ext_id, 1 /*up2date*/);
}
#endif

/**
 * Get and hold a reference to RB-tree dirtytree for extent ext_id.
 *
 * All dirtytree gets by extent ID must occur while the extent exists
 * within the hash (e.g. checkpoint extent flush and dirty_c2b()).
 *
 * @also castle_cache_extent_flush()
 * @also dirty_c2b()
 *
 * @also castle_extent_dirtytree_get()
 * @also castle_extent_dirtytree_put()
 */
c_ext_dirtytree_t* castle_extent_dirtytree_by_id_get(c_ext_id_t ext_id)
{
    c_ext_t *ext;
    c_ext_dirtytree_t *dirtytree;
    unsigned long flags;

    read_lock_irqsave(&castle_extents_hash_lock, flags);
    ext = __castle_extents_hash_get(ext_id);
    if (!ext)
    {
        castle_printk(LOG_ERROR, "%s::no extent %lld\n",
                __FUNCTION__, ext_id);\
        read_unlock_irqrestore(&castle_extents_hash_lock, flags);
        BUG();
    }
    BUG_ON(!ext);
    BUG_ON(atomic_inc_return(&ext->dirtytree->ref_cnt) < 2);
    dirtytree = ext->dirtytree;
    read_unlock_irqrestore(&castle_extents_hash_lock, flags);

    return dirtytree;
}

/**
 * Take an additional reference to per-extent dirtytree.
 *
 * Extent structure specified by dirtytree->ext_id does not need to exist
 * within the extents hash.
 *
 * @also castle_cache_flush()
 *
 * @also castle_extent_dirtytree_by_id_get()
 * @also castle_extent_dirtytree_put()
 */
void castle_extent_dirtytree_get(c_ext_dirtytree_t *dirtytree)
{
    /* Per-extent dirtytrees are freed when the ref_cnt reaches 0. */
    BUG_ON(atomic_inc_return(&dirtytree->ref_cnt) <= 1);
}

/**
 * Drop a reference to per-extent dirtytree.
 *
 * @param   dirtytree   Dirtytree to drop reference on
 * @param   check_hash  Whether to verify the dirtytree's extent is not in hash
 *
 * Extent structure specified by dirtytree->ext_id does not need to exist
 * within the extents hash.
 *
 * Frees the per-extent dirtytree if the reference count reaches 0.
 *
 * @also castle_extent_dirtytree_get()
 */
void __castle_extent_dirtytree_put(c_ext_dirtytree_t *dirtytree, int check_hash)
{
    if (unlikely(atomic_dec_return(&dirtytree->ref_cnt) == 0))
    {
        if (check_hash)
            /* cannot be in hash now */
            BUG_ON(!MASK_ID_INVAL(castle_extent_get(dirtytree->ext_id)));
        BUG_ON(!RB_EMPTY_ROOT(&dirtytree->rb_root));    /* must be empty */
        castle_free(dirtytree);
    }
}

/**
 * Drop a reference to per-extent dirtytree.
 *
 * @also __castle_extent_dirtytree_put()
 */
void castle_extent_dirtytree_put(c_ext_dirtytree_t *dirtytree)
{
    __castle_extent_dirtytree_put(dirtytree, 1 /*check_hash*/);
}

int castle_extent_rebuild_ext_get(c_ext_t *ext, int is_locked)
{
    /* There shouldn't be an outstanding reference. */
    BUG_ON(!MASK_ID_INVAL(ext->rebuild_mask_id));

    if (is_locked)
        ext->rebuild_mask_id = castle_extent_mask_get(ext->ext_id);
    else
        ext->rebuild_mask_id = castle_extent_get(ext->ext_id);

    if (MASK_ID_INVAL(ext->rebuild_mask_id))
        return -1;

    return 0;
}

void castle_extent_rebuild_ext_put(c_ext_t *ext, int is_locked)
{
    /* There should be an outstanding reference. */
    BUG_ON(MASK_ID_INVAL(ext->rebuild_mask_id));

    if (is_locked)
        castle_extent_mask_put(ext->rebuild_mask_id);
    else
        castle_extent_put(ext->rebuild_mask_id);

    ext->rebuild_mask_id = INVAL_MASK_ID;
}

/*
 * Add an extent to the extent processing list.
 *
 * @param ext       The extent to check and add to the rebuild list.
 *
 * @return 0:       Always return 0 so that castle_extents_hash_iterate continues.
 */
static int rebuild_list_add(c_ext_t *ext, void *unused)
{
    /*
     * We are not handling logical extents. The extent is not already at current_rebuild_seqno. The
     * extent is not marked for deletion (it is a live extent).
     */
    if ((!SUPER_EXTENT(ext->ext_id) && !(ext->ext_id == MICRO_EXT_ID)) &&
        (ext->curr_rebuild_seqno < atomic_read(&current_rebuild_seqno)))
    {
        /*
         * Take a reference to the extent. We will drop this when we have finished remapping
         * the extent.
         */
        if (castle_extent_rebuild_ext_get(ext, 1) < 0)
            /* Extent is already dead. */
            return 0;

        debug("Adding extent %llu to rebuild list for extent seqno %u, global seqno %u\n",
               ext->ext_id, ext->curr_rebuild_seqno, atomic_read(&current_rebuild_seqno));
        list_add_tail(&ext->process_list, &extent_list);
    }
    return 0;
}

/*
 * These structures keeps track of the current 'remapping state' - which slaves can be used for
 * remapping, and for each of those slaves a set of chunks to use for remapping, and an indication
 * of which chunk to use next.
 */
typedef struct live_slave {
    c_chk_t         first_chk;
    c_chk_cnt_t     count;
    uint32_t        uuid;                   /* Uuid for slave. */
    uint32_t        state;                  /* State flags for slave. */
} live_slave_t;

#define SSD_BIT         0
#define SLAVE_TRIED_BIT 1

static struct process_state {
    int             nr_live_slaves;              /* Number of slaves available for processing. */
    live_slave_t    *live_slaves[MAX_NR_SLAVES];
} process_state;

/* This structure is used to maintain information about each individual remap chunk I/O. */
typedef struct process_work_item {
    int                 rw;             /* Read, Write, Remap, Cleanup. */
    c2_block_t          *c2b;
    c_ext_t             *ext;
    c_disk_chk_t        *remap_chunks;  /* The chunk(s) that need to be remapped */
    int                 remap_idx;      /* The number of chunk(s) to be remapped */
    struct list_head    free_list;      /* Free list of unused work items. */
    struct list_head    error_list;     /* List of chunks that have had I/O errors */
    struct work_struct  work;           /* Used for queueing work */
    int                 chunkno;        /* The chunk offset in the extent */
    uint32_t            has_cleanpages; /* Set if this chunk has any freepages */
} process_work_item_t;

/*
 * The rw field uses the standard READ and WRITE (0 and 1) states, overloaded with REMAP and
 * CLEANUP. The states and sequence is is follows:
 *
 * READ: Only if the remap c2b is not uptodate.
 * WRITE: Standard 'submit_c2b_rda' to pre-write-out c2b to non-remap slaves if c2b has dirty pages.
 * REMAP: submit_c2b_remap_rda to write out c2b to remap slave(s).
 * CLEANUP: post-I/O cleanup - unlocking c2b, work item back on freelist etc.
 */

#define REMAP   2
#define CLEANUP 3

#define                     MAX_WORK_ITEMS 512
#define                     MIN_WORK_ITEMS 16
#define                     MAX_CACHE_USAGE 15 /* Max percentage of cache work items can use. */
static int castle_nr_work_items = MAX_WORK_ITEMS;

static process_work_item_t  process_work_items[MAX_WORK_ITEMS];

spinlock_t io_list_lock; /* Serialise access to io free and error lists. */
static struct list_head     io_free_list;
static struct list_head     io_error_list;
wait_queue_head_t           process_io_waitq;

atomic_t                    wi_in_flight = ATOMIC(0); /* Keeps track of work itesm in-flight */

/*
 * Populate the list of 'live' slaves. This is the list that can currently be used as a
 * source of replacement slaves for remapping.
 */
static void castle_extents_process_state_init(void)
{
    struct list_head        *lh;
    struct castle_slave     *cs;
    int                     i;

    rcu_read_lock();
    list_for_each_rcu(lh, &castle_slaves.slaves)
    {
        cs = list_entry(lh, struct castle_slave, list);
        if ((!test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags)) &&
            (!test_bit(CASTLE_SLAVE_EVACUATE_BIT, &cs->flags)))
        {
            process_state.live_slaves[process_state.nr_live_slaves] =
                castle_zalloc(sizeof(live_slave_t));
            BUG_ON(!process_state.live_slaves[process_state.nr_live_slaves]);
            process_state.live_slaves[process_state.nr_live_slaves]->uuid = cs->uuid;
            if (cs->cs_superblock.pub.flags & CASTLE_SLAVE_SSD)
                set_bit(SSD_BIT, &process_state.live_slaves[process_state.nr_live_slaves]->state);
            process_state.nr_live_slaves++;
        }
    }
    rcu_read_unlock();
    for (i=process_state.nr_live_slaves; i<MAX_NR_SLAVES; i++)
        process_state.live_slaves[i++] = NULL;
}

/*
 * Refresh the list of 'live' slaves. Check and revise the set of live slaves if any
 * slave(s) have become unavailable or have been added. If the reset_tried_flag is non-zero
 * then the SLAVE_TRIED bit will be cleared for all live slaves. If this function is called
 * multiple times, the SLAVE_TRIED flags will only be cleared the first time as long as the
 * caller does not make reset_tried_flag non-zero again.
 *
 * @param reset_tried_flag  If non-zero the SLAVE_TRIED flag should be cleared in all the live
                            slave state flags.
 */
static void castle_extents_process_state_refresh(int reset_tried_flag)
{
    struct list_head        *lh;
    struct castle_slave     *cs;
    int                     i;
    /* First, check for slave unavailability. */
    for (i=0; i<process_state.nr_live_slaves; i++)
    {
        /* Previous refreshes may have left 'holes' in process_state.live_slaves. */
        if (process_state.live_slaves[i])
        {
            cs = castle_slave_find_by_uuid(process_state.live_slaves[i]->uuid);
            BUG_ON(!cs);
            if ((test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags)) ||
                (test_bit(CASTLE_SLAVE_EVACUATE_BIT, &cs->flags)))
            {
                /*
                 * A previously-live slave is now no longer available for remapping.
                 * Leave the slave as a 'hole' in process_state.live_slaves.
                 */
                BUG_ON(!process_state.live_slaves[i]);
                castle_free(process_state.live_slaves[i]);
                process_state.live_slaves[i] = NULL;
            } else if (reset_tried_flag)
            {
                /* Still alive, and we want the SLAVE_TRIED flag reset. */
                clear_bit(SLAVE_TRIED_BIT, &process_state.live_slaves[i]->state);
            }
        }
    }
    /* Now, check if any slaves have been added. */
    rcu_read_lock();
    list_for_each_rcu(lh, &castle_slaves.slaves)
    {
        int slave_exists = 0;
        cs = list_entry(lh, struct castle_slave, list);

        /* For each slave, check if it already exists. */
        for (i=0; i<process_state.nr_live_slaves; i++)
        {
            if (process_state.live_slaves[i] && process_state.live_slaves[i]->uuid == cs->uuid)
            {
                slave_exists = 1;
                break;
            }
        }
        /* This slave was not found. Add it if it is available for remapping. */
        if (!slave_exists &&
           !test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags) &&
           !test_bit(CASTLE_SLAVE_EVACUATE_BIT, &cs->flags))
        {
            process_state.live_slaves[process_state.nr_live_slaves] =
                castle_zalloc(sizeof(live_slave_t));
            BUG_ON(!process_state.live_slaves[process_state.nr_live_slaves]);
            process_state.live_slaves[process_state.nr_live_slaves]->uuid = cs->uuid;
            if (cs->cs_superblock.pub.flags & CASTLE_SLAVE_SSD)
                set_bit(SSD_BIT, &process_state.live_slaves[process_state.nr_live_slaves]->state);
            process_state.nr_live_slaves++;
        }
    }
    rcu_read_unlock();
}

/*
 * Frees any data associated with the process_state structure.
 */
static void castle_extents_process_state_fini(void)
{
    int i;

    for (i=0; i<MAX_NR_SLAVES; i++)
    {
        castle_check_free(process_state.live_slaves[i]);
        process_state.nr_live_slaves = 0;
    }
}

/*
 * Populates the process_state.chunks array for the passed slave with a superchunk's
 * worth of of disk chunks.
 *
 * @param slave_idx The index into the process_state chunks / live_slaves array.
 *
 * @return EXIT_SUCCESS:       Success.
 * @return -ENOSPC:            Slave is out of space.
 */
static int castle_extent_remap_superchunks_alloc(c_ext_t *ext, int slave_idx)
{
    c_chk_seq_t         chk_seq;
    struct castle_slave *cs;

    cs = castle_slave_find_by_uuid(process_state.live_slaves[slave_idx]->uuid);
    BUG_ON(!cs);
    BUG_ON(test_bit(CASTLE_SLAVE_GHOST_BIT, &cs->flags));

    BUG_ON(process_state.live_slaves[slave_idx]->count);

    castle_extent_transaction_start();

    /* Get partial superchunks from exntent, if any available. */
    /* Note: Rebuild can happen after shrink and truncate, so no assumptions can be made
     * on chunk sequence it can start some where in the middle and end in the middle. */
    chk_seq = castle_extent_part_schk_get(ext, cs);
    if (!CHK_SEQ_INVAL(chk_seq))
    {
        castle_extent_transaction_end();
        goto fill_chks;
    }

    /*
     * Allocate a superchunk.
     */
    chk_seq = castle_freespace_slave_superchunk_alloc(cs, 0, NULL);

    castle_extent_transaction_end();

    if (CHK_SEQ_INVAL(chk_seq))
    {
        /*
         * We get here if the slave is either out-or-service, or out of space. If the slave is
         * out-of-service then just return ENOSPC so calling stack can retry.
         */
        if ((!test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags)) &&
            (!(cs->cs_superblock.pub.flags & CASTLE_SLAVE_SSD)))
        {
            /* Slave is not out-of-service so we are out of space */
            castle_printk(LOG_WARN, "Error: failed to get freespace from slave: 0x%x [%s].\n",
                    cs->uuid, cs->bdev_name);

            castle_freespace_stats_print();
            return -ENOSPC;
        } else
        {
            castle_printk(LOG_WARN, "Warning - Failed allocating superchunk from "
                    "out-of-service slave: 0x%x [%s].", cs->uuid, cs->bdev_name);
            /*
             * Slave is now out-of-service. Re-initialise remap state and retry.
             */
            return -EAGAIN;
        }
    }

    /* Chunk sequence must represent a single superchunk. */
    BUG_ON(chk_seq.count != CHKS_PER_SLOT);

fill_chks:

    process_state.live_slaves[slave_idx]->first_chk = chk_seq.first_chk;
    process_state.live_slaves[slave_idx]->count = chk_seq.count;

    return EXIT_SUCCESS;
}

static int slave_not_usable(c_ext_t *ext, int chunkno, int idx, int want_ssd)
{
    int chunk_idx;

    if (process_state.live_slaves[idx] == NULL)
        /* This slave is no longer available. */
        return 1;

    if ((test_bit(SSD_BIT, &process_state.live_slaves[idx]->state) && !want_ssd) ||
       (!(test_bit(SSD_BIT, &process_state.live_slaves[idx]->state)) && want_ssd))
        /*
         * Slave is an SSD, but we want to allocate from non-SSD slaves, or slave is not an
         * SSD, but we want to allocate from SSD slaves. Do not use this slave.
         */
        return 1;

    if (test_bit(SLAVE_TRIED_BIT, &process_state.live_slaves[idx]->state))
        /* Skip slaves that caller has already tried, but failed to allocate space from. */
        return 1;

    for (chunk_idx=0; chunk_idx<ext->k_factor; chunk_idx++)
        if (ext->shadow_map[(chunkno*ext->k_factor)+chunk_idx].slave_id ==
            process_state.live_slaves[idx]->uuid)
            /* Don't use a slave already represented in this logical chunk. */
            return 1;
    return 0;
}

/*
 * Return the slave index to use for remapping a chunk. Scans the process_state.live_slaves
 * array for a slave which is not already used in the disk chunk.
 *
 * @param ext           The extent for which the remapping is being done.
 * @param chunkno       The logical chunk being remapped.
 * @param want_ssd      Flag set if we want to remap onto an SSD (if possible).
 * @param ssds_tried    The number of SSDs we have tried, but failed to allocate space from.
 *
 * @return          The index into the process_state arrays to use for allocation
 */
static int castle_extent_slave_get_random(c_ext_t *ext,
                                          int chunkno,
                                          int want_ssd)
{
    int         idx, nr_slaves_to_use;
    int         slaves_to_use[MAX_NR_SLAVES];
    uint16_t    r;

    /* For each slave in process_state.live_slaves (the list of potential remap slaves). */
retry:
    nr_slaves_to_use = 0;
    for (idx=0; idx<process_state.nr_live_slaves; idx++)
    {
        if (slave_not_usable(ext, chunkno, idx, want_ssd))
            continue;

        /*
         * This slave is not already used in this logical chunk - add it to set of potential
         * target slaves for remapping this chunk.
         */
        slaves_to_use[nr_slaves_to_use++] = idx;
    }

    if (!nr_slaves_to_use)
    {
        if (want_ssd)
        {
            /* We want an SSD, but we could not find one - retry for a non-SSD. */
            debug("Wanted to remap to SSD, but failed to find one. Retrying from non-SSD\n");
            want_ssd = 0;
            goto retry;
        }
        /* We've run out of potential slaves to choose from (caller has exhausted them). */
        if (!nr_slaves_to_use)
            return(-1);
    }

    /*
     * Now slaves_to_use is an array of indexes into process_state.live_slaves that reflect
     * potential target slaves for remapping for this logical chunk. Pick one at random.
     */
    get_random_bytes(&r, 2);
    r = r % nr_slaves_to_use;

    BUG_ON(test_and_set_bit(SLAVE_TRIED_BIT, &process_state.live_slaves[slaves_to_use[r]]->state));

    return slaves_to_use[r];
}

extern      castle_freespace_t * freespace_sblk_get(struct castle_slave *cs);
extern void freespace_sblk_put(struct castle_slave *cs);

/*
 * Return the slave index to use for remapping a chunk. Scans the process_state.live_slaves
 * array for a slave which is not already used in the disk chunk.
 *
 * @param ext           The extent for which the remapping is being done.
 * @param chunkno       The logical chunk being remapped.
 * @param want_ssd      Flag set if we want to remap onto an SSD (if possible).
 * @param ssds_tried    The number of SSDs we have tried, but failed to allocate space from.
 * @param slave_idx     The index into the process_state arrays to use for allocation
 *
 * @return              EXIT_SUCCESS if we found a candidate slave, otherwise -ENOENT
 */

/* Percentage threshold of freespace above which a slave is a candidate */
#define FREESPACE_THRESHOLD_DEFAULT 5
int castle_rebuild_freespace_threshold = FREESPACE_THRESHOLD_DEFAULT;

static int castle_extent_slave_get_by_freespace(c_ext_t *ext,
                                                int chunkno,
                                                int want_ssd,
                                                int *slave_idx)
{
    int                 idx, chosen_slave=MAX_NR_SLAVES, potential_slaves;
    int                 avg_freespace, max_freespace, slave_freespace;
    struct castle_slave *cs;

    /* For each slave in process_state.live_slaves (the list of potential remap slaves). */
    potential_slaves = avg_freespace = max_freespace = 0;
    for (idx=0; idx<process_state.nr_live_slaves; idx++)
    {
        if (slave_not_usable(ext, chunkno, idx, want_ssd))
            continue;

        potential_slaves++;

        cs = castle_slave_find_by_uuid(process_state.live_slaves[idx]->uuid);
        BUG_ON(!cs);

        castle_extent_transaction_start();
        /* Work out how many free superchunks there are ATM. */
        slave_freespace = castle_freespace_free_superchunks(cs);
        castle_extent_transaction_end();

        if (slave_freespace > max_freespace)
        {
            /* This slave has more freespace. */
            chosen_slave = idx;
            max_freespace = slave_freespace;
        }

        /* Re-compute average. */
        avg_freespace = ((avg_freespace * (potential_slaves - 1)) + slave_freespace)
                        / potential_slaves;
    }

    if (max_freespace <=
        (avg_freespace + (avg_freespace * castle_rebuild_freespace_threshold) / 100))
        return -ENOENT;

    BUG_ON(test_and_set_bit(SLAVE_TRIED_BIT, &process_state.live_slaves[chosen_slave]->state));

    *slave_idx = chosen_slave;
    return EXIT_SUCCESS;
}

/*
 * Find a replacement disk chunk for an out-of-service or evacuating slave.
 *
 * @param ext       The extent for which the remapping is being done.
 * @param chunkno   The logical chunk being remapped.
 *
 * @return          The disk chunk to use.
 */
c_disk_chk_t castle_extent_remap_disk_chunk_alloc(c_ext_t *ext, struct castle_slave *cs,
                                                  int chunkno)
{
    c_disk_chk_t        disk_chk = INVAL_DISK_CHK;
    int                 slave_idx= -1;
    struct castle_slave *target_slave;
    int                 ret=0;
    int                 want_ssd;
    int                 reset_tried_flags = 1;

retry:
    /* First time through, clear the slave TRIED flags. */
    castle_extents_process_state_refresh(reset_tried_flags);
    reset_tried_flags = 0;

    want_ssd = cs->cs_superblock.pub.flags & CASTLE_SLAVE_SSD;

    /*
     * Default is to choose a slave using freespace, defined by the module param
     * castle_rebuild_freespace_threshold. If this is negative, finding a slave
     * by freespace is turned off.
     */
    if (castle_rebuild_freespace_threshold >= 0)
        ret = castle_extent_slave_get_by_freespace(ext, chunkno, want_ssd, &slave_idx);
    if ((castle_rebuild_freespace_threshold < 0) || (ret == -ENOENT))
        /*
         * Choosing slave by freespace is turned off, or we could not find a slave with enough
         * excess freespace. Revert to random search.
         */
        slave_idx = castle_extent_slave_get_random(ext, chunkno, want_ssd);

    if (slave_idx == -1)
    {
        /* Ran out of slaves to to try to allocate from. */
        return INVAL_DISK_CHK;
    }

    target_slave = castle_slave_find_by_uuid(process_state.live_slaves[slave_idx]->uuid);
    BUG_ON(!target_slave);

    if ((test_bit(CASTLE_SLAVE_OOS_BIT, &target_slave->flags)) ||
        (test_bit(CASTLE_SLAVE_EVACUATE_BIT, &target_slave->flags)))
    {
        /* Tried to use a now-dead slave for remapping. Repopulate the process_state and retry. */
        debug("Rebuild tried using a now-dead slave - retrying\n");
        goto retry;
    }

    if (!process_state.live_slaves[slave_idx]->count)
    {
        /* We've run out of chunks on this slave, allocate another set. */
        ret = castle_extent_remap_superchunks_alloc(ext, slave_idx);
        if ((ret == -EAGAIN) || (ret == -ENOSPC))
        {
            /*
             * Tried to use a now-dead slave for superchunk allocation, or slave is out of
             * freespace. Repopulate the process_state and retry.
             */
            debug("Rebuild failed to allocate from a slave - retrying\n");
            goto retry;
        }
        BUG_ON(ret);
    }

    BUG_ON(process_state.live_slaves[slave_idx]->count == 0);

    disk_chk.slave_id   = process_state.live_slaves[slave_idx]->uuid;
    disk_chk.offset     = process_state.live_slaves[slave_idx]->first_chk;

    process_state.live_slaves[slave_idx]->first_chk++;
    process_state.live_slaves[slave_idx]->count--;

    BUG_ON(DISK_CHK_INVAL(disk_chk));

    return disk_chk;
}

/*
 * Check if a slave needs remapping.
 *
 * @param slave_id  The slave uuid.
 *
 * @return:         A pointer to the castle_slave if it needs remapping, else NULL.
 */
static struct castle_slave *slave_needs_remapping(uint32_t slave_id)
{
    struct castle_slave *cs;

    cs = castle_slave_find_by_uuid(slave_id);
    BUG_ON(!cs);

    if ((test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags)) ||
        (test_bit(CASTLE_SLAVE_EVACUATE_BIT, &cs->flags)))
        return cs;
    else
        return NULL;
}

/* Save all the left-over superchunks back to extent again. */
static void castle_extent_remap_space_cleanup(c_ext_t *ext)
{
    int i;

    castle_extent_transaction_start();

    for (i=0; i<process_state.nr_live_slaves; i++)
    {
        if (process_state.live_slaves[i] && process_state.live_slaves[i]->count)
        {
            struct castle_slave *cs = castle_slave_find_by_uuid(process_state.live_slaves[i]->uuid);

            castle_extent_part_schk_save(ext, cs->id,
                                         process_state.live_slaves[i]->first_chk,
                                         process_state.live_slaves[i]->count);

            process_state.live_slaves[i]->count = 0;
        }
    }

    castle_extent_part_schks_converge(ext);

    castle_extent_transaction_end();
}

/* This structure keeps track of extent ranges that have been processed. */
typedef struct writeback_info {
    struct list_head    list;
    c_ext_id_t          ext_id;
    int                 start_chunk;
    int                 end_chunk;
    int                 ext_finished;
} writeback_info_t;

/* The state a processed extent can be in. */
enum {
    PROCESSING,   /* Processing is in progress. */
    INTERRUPTED,  /* Extent has been interrupted (e.g. not live, or kthread stopping) */
    COMPLETE      /* Extent has been fully processed. */
};

/*
 * Initialise a writeback_info structure.
 * @param ext_id  The extent.
 * @param start   The start chunk in the extent for this range.
 * @param end     The end chunk in the extent for this range.
 *
 * @return:       The initialised writeback_info structure.
 */
static writeback_info_t *alloc_writeback_info(c_ext_id_t ext_id, int start, int end)
{
    writeback_info_t    *writeback_info;

    writeback_info = castle_alloc(sizeof(writeback_info_t));
    BUG_ON(!writeback_info);

    INIT_LIST_HEAD(&writeback_info->list);
    writeback_info->ext_id = ext_id;
    writeback_info->start_chunk = start;
    writeback_info->end_chunk = start + (end - 1);
    writeback_info->ext_finished = PROCESSING;

    return writeback_info;
}

/*
 * Free a writeback_info structure.
 */
static void free_writeback_info(writeback_info_t *writeback_info)
{
    castle_free(writeback_info);
}

static int rebuild_exit_check(void);

/* The type of extent processing we are doing. */
typedef enum {
    REBUILDING,
    REBALANCING,
    EXITING
} castle_extent_process_type_t;

/* Per-extent-processing-type (e.g. rebuild or rebalance) function vector. */
typedef struct {
    castle_extent_process_type_t type;
    int     (*init)            (void);
    void    (*finish)          (int interrupted);
    int     (*find_next_frame) (c_ext_t *ext,
                                int *curr_chunk,
                                c_chk_cnt_t ext_end);
    int     (*process_chunk)   (c_ext_t *ext,
                                int source_chunks,
                                int chunk_index, int chunkno);
    void    (*do_writeback)    (writeback_info_t *writeback_info);
    int     (*exit_check)      (void);
    int     (*list_add)        (c_ext_t *ext, void *unused);
} castle_extent_process_state_t;

castle_extent_process_state_t   *procstate = NULL;

/*
 * Initialise rebuild state.
 */
int rebuild_init(void)
{
    struct castle_fs_superblock *fs_sb;

    castle_printk(LOG_DEVEL, "Starting rebuild run.\n");

    fs_sb = castle_fs_superblocks_get();
    fs_sb->fs_in_rebuild = 1;
    castle_fs_superblocks_put(fs_sb, 1);

    rebuild_to_seqno = atomic_read(&current_rebuild_seqno);

    // State is initialised here, and each time another slave goes oos. */
    castle_extents_process_state_init();

    return 1;
}

/*
 * Handles work to be done when rebuild has finished.
 * @param interrupted  The rebuild was interrupted.
 */
void rebuild_finish(int interrupted)
{
    struct castle_fs_superblock *fs_sb;
    struct list_head            *entry;
    struct castle_slave         *cs;

    if (rebuild_required())
        /*
         * Rebuild has more work to do, for example if it was interrupted by another slave going
         * oos or evacuating.
         */
        return;

    castle_extents_process_state_fini();

    if (interrupted)
        /*
         * The rebuild has not yet finished, so break out before updating slave and superblock
         * states.
         */
        return;

    fs_sb = castle_fs_superblocks_get();
    fs_sb->fs_in_rebuild = 0;
    castle_fs_superblocks_put(fs_sb, 1);
    castle_extents_chunks_remapped = 0;

    /* We can now convert any evacuating or out-of-service slaves to remapped state. */
    rcu_read_lock();
    list_for_each_rcu(entry, &castle_slaves.slaves)
    {
        cs = list_entry(entry, struct castle_slave, list);
        if (test_bit(CASTLE_SLAVE_EVACUATE_BIT, &cs->flags) &&
           !test_bit(CASTLE_SLAVE_REMAPPED_BIT, &cs->flags) &&
           !test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags))
        {
            BUG_ON(test_bit(CASTLE_SLAVE_GHOST_BIT, &cs->flags));
            castle_printk(LOG_USERINFO, "Finished remapping evacuated slave 0x%x.\n",
                        cs->uuid);
            set_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags);
            set_bit(CASTLE_SLAVE_REMAPPED_BIT, &cs->flags);
            clear_bit(CASTLE_SLAVE_EVACUATE_BIT, &cs->flags);
            if (atomic_read(&cs->io_in_flight) == 0 &&
                test_bit(CASTLE_SLAVE_BDCLAIMED_BIT, &cs->flags))
                castle_release_device(cs);
        }
        if (test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags) &&
           !test_bit(CASTLE_SLAVE_REMAPPED_BIT, &cs->flags))
        {
            castle_printk(LOG_USERINFO, "Finished remapping out-of-service slave 0x%x.\n",
                          cs->uuid);
            set_bit(CASTLE_SLAVE_REMAPPED_BIT, &cs->flags);
            if (atomic_read(&cs->io_in_flight) == 0 &&
                test_bit(CASTLE_SLAVE_BDCLAIMED_BIT, &cs->flags))
                castle_release_device(cs);
        }
    }
    rcu_read_unlock();

    castle_printk(LOG_USERINFO, "Rebuild completed.\n");
    return;
}

/*
 * Find the next chunk to be rebuilt.
 * @param ext           The extent.
 * @param curr_chunk    (Input) the last chunk processed
 *                      (Output) the next chunk to process
 * @param end           The end chunk in the range for this extent.
 *
 * @return:             1 If there is a chunk to be processed.
 */
int find_next_rebuild_chunk(c_ext_t *ext, int *curr_chunk, c_chk_cnt_t end_chunk)
{
    int chunkno, chunkidx;

    for (chunkno=*curr_chunk; chunkno<end_chunk; chunkno++)
    {
        for (chunkidx=0; chunkidx<ext->k_factor; chunkidx++)
        {
            if (slave_needs_remapping(ext->shadow_map[(chunkno*ext->k_factor)+chunkidx].slave_id))
            {
                *curr_chunk = chunkno;
                /* For rebuild, return frame size (number of chunks) = 1. */
                return 1;
            }
        }
    }

    return 0; /* No chunks to process. */
}

/*
 * Process a rebuild chunk.
 * @param ext           The extent.
 * @param chunkno       The chunk to process
 *
 * @return:             1 If there is a chunk to be processed.
 */
int process_rebuild_chunk(c_ext_t *ext, int chunkno, int unused1, int unused2)
{
    uint32_t            k_factor = castle_extent_kfactor_get(ext->ext_id);
    int                 idx, remap_idx;
    struct castle_slave *cs;
    int ret=0;
    c_disk_chk_t *remap_chunks;


    remap_chunks = castle_alloc(k_factor*sizeof(c_disk_chk_t));
    BUG_ON(!remap_chunks);

    ext->use_shadow_map = 1;

    /*
     * Populate the remap chunks array that will be used to write out remapped data.
     * Disk chunks for remapped slaves go at the start. Disk chunks for non-remapped slaves
     * go at the end. This split allows lower level code to submit I/O only for remapped
     * slaves, or for all slaves, as required. Remap_idx will define the boundary between
     * the two sets in the remap chunks array.
     */

retry:

    for (idx=0, remap_idx=0; idx<k_factor; idx++)
    {
        c_disk_chk_t disk_chk;
        if ((cs = slave_needs_remapping(ext->shadow_map[(chunkno*k_factor)+idx].slave_id)))
        {
            /* This slave needs remapping. Get a replacement disk chunk. */
            disk_chk = castle_extent_remap_disk_chunk_alloc(ext, cs, chunkno);
            if (DISK_CHK_INVAL(disk_chk))
            {
                /* Failed to allocate a disk chunk (all slaves out of space). */
                castle_printk(LOG_WARN, "Rebuild could not allocate a disk chunk.\n");
                return -ENOSPC;
            }
            /*
            * Lock the shadow map here because we don't want the read/write path to access
            * a chunk in mid-remap.
            */
            spin_lock(&ext->shadow_map_lock);
            ext->shadow_map[(chunkno*k_factor)+idx].slave_id = disk_chk.slave_id;
            ext->shadow_map[(chunkno*k_factor)+idx].offset = disk_chk.offset;
            spin_unlock(&ext->shadow_map_lock);

            /* Store the chunks that need remapping. */
            remap_chunks[remap_idx].slave_id = disk_chk.slave_id;
            remap_chunks[remap_idx++].offset = disk_chk.offset;
        }
    }

    FAULT(REBUILD_FAULT2);

   /*
     * The remap_chunks array now contains all the disk chunks for this chunkno.
     */
    if (remap_idx)
    {
        /*
         * If a chunk has been remapped, read it in (via the old map) and write it out (using
         * the remap_chunks array as the map).
         */
        ret = submit_async_remap_io(ext, chunkno, remap_chunks, remap_idx);

        if (ret)
        {
            switch (ret)
            {
                case -EAGAIN:
                    goto retry;
                case -ENOENT:
                    /* No free work items - wait for one to become free. */
                    castle_free(remap_chunks);
                    return ret;
                default:
                    BUG();
            }
        }
    }

    /* Keep count of the chunks that have actually been remapped. */
    castle_extents_chunks_remapped += remap_idx;

    return EXIT_SUCCESS;
}

/*
 * end_io for extent processing.
 */
static void castle_extent_process_async_end(c2_block_t *c2b)
{
    process_work_item_t *wi = c2b->private;
    unsigned long flags;

    switch (wi->rw) {
        case READ:
            /* This was a remap chunk read request. */

            if (c2b_eio(wi->c2b))
            {
                /* Slave is no longer live. Abandon the I/O. */
                spin_lock_irqsave(&io_list_lock, flags);
                list_add_tail(&wi->error_list, &io_error_list);
                spin_unlock_irqrestore(&io_list_lock, flags);
                wake_up(&process_io_waitq);
            } else
            {
                /* We cannot handle the read failing to update the c2b. */
                BUG_ON(!c2b_uptodate(wi->c2b));

                /* Now schedule the write. */
                wi->rw = WRITE;
                BUG_ON(!queue_work(castle_extproc_workq, &wi->work));
            }
            break;
        case WRITE:
            /*
             * This was the pre-writeout of the remap chunk.
             * Next step is to schedule the remap writeout.
             */
            if (c2b_eio(wi->c2b))
            {
                /* Slave is no longer live. Abandon the I/O. */
                spin_lock_irqsave(&io_list_lock, flags);
                list_add_tail(&wi->error_list, &io_error_list);
                spin_unlock_irqrestore(&io_list_lock, flags);
                wake_up(&process_io_waitq);
            } else
            {
                BUG_ON(c2b_dirty(wi->c2b)); /* c2b should not be dirty. */

                /*
                 * If the c2b was entirely populated with dirty pages, then the submit_c2b_rda will
                 * have written all pages to the remap slave disk chunk, so a further
                 * submit_c2b_remap_rda is not needed.
                 */
                if (wi->has_cleanpages)
                    wi->rw = REMAP;
                else
                    wi->rw = CLEANUP;
                BUG_ON(!queue_work(castle_extproc_workq, &wi->work));
            }
            break;
        case REMAP:
            /* This was the remap writeout. We're all done apart from error handling. */
            if (c2b_eio(wi->c2b))
            {
                /* Slave is no longer live. Abandon the I/O. */
                spin_lock_irqsave(&io_list_lock, flags);
                list_add_tail(&wi->error_list, &io_error_list);
                spin_unlock_irqrestore(&io_list_lock, flags);
                wake_up(&process_io_waitq);
            } else
            {
                BUG_ON(c2b_dirty(wi->c2b)); /* c2b should not be dirty. */
                /*
                 * Finally, we are finished with the c2b now. If the c2b has eio set, then we are
                 * handling the end_io for a failed write. submit_c2b_remap_rda will know about it
                 * when it returns (if it hasn't already), so leave submit_c2b_remap_rda to handle
                 * the CLEANUP.
                 */
                wi->rw = CLEANUP;
                BUG_ON(!queue_work(castle_extproc_workq, &wi->work));
            }
            break;
        default:
            BUG();
    }
}

/*
 * Handle queued up extent process work out of interrupt context.
 */
void process_io_do_work(struct work_struct *work)
{
    process_work_item_t *wi = container_of(work, process_work_item_t, work);
    unsigned long flags;

    BUG_ON(!wi || wi->rw == READ);

    switch (wi->rw) {
        case WRITE:
            /* Need to do a (non-remap) write of the c2b data. */
            set_c2b_in_flight(wi->c2b);
            submit_c2b_rda(wi->rw, wi->c2b);
            break;
        case REMAP:
            /* Need to do a (remap) write of the c2b data. */
            set_c2b_in_flight(wi->c2b);
            submit_c2b_remap_rda(wi->c2b, wi->remap_chunks, wi->remap_idx);
            break;
        case CLEANUP:
            /* Clean up the I/O structures. */
            write_unlock_c2b(wi->c2b);

            BUG_ON(c2b_eio(wi->c2b));

            /*
             * This c2b is not needed any more, and it pollutes the cache, so destroy it (if there
             * is nobody else using it).
             */
            castle_cache_block_destroy(wi->c2b);

            castle_free(wi->remap_chunks);

            spin_lock_irqsave(&io_list_lock, flags);
            list_add_tail(&wi->free_list, &io_free_list);
            spin_unlock_irqrestore(&io_list_lock, flags);
            atomic_dec(&wi_in_flight);

            /* In case we are ratelimit waiting. */
            wake_up(&process_io_waitq);
            break;
        default:
            BUG();
    }
    return;
}

/*
 * Initialise the work io list from the work_items array.
 */
static void init_io_work(void)
{
    int i;

    INIT_LIST_HEAD(&io_free_list);
    INIT_LIST_HEAD(&io_error_list);

    spin_lock_init(&io_list_lock);

    init_waitqueue_head(&process_io_waitq);

    /*
     * Limit the number of work items we can use based on the castle_cache_size.
     * MAX_CACHE_USAGE defines the percentage of the cache that we should limit the number of
     * concurrent 1m work items to.
     * The number of work items is bounded by MIN_WORK_ITEMS/MAX_WORK_ITEMS to ensure there is
     * a reasonable minimum, and that the size of the work_item array is not exceeded.
     */
    castle_nr_work_items = ((castle_cache_size_get() / 100) * MAX_CACHE_USAGE)
                            / BLKS_PER_CHK;

    if (castle_nr_work_items < MIN_WORK_ITEMS) castle_nr_work_items = MIN_WORK_ITEMS;
    if (castle_nr_work_items > MAX_WORK_ITEMS) castle_nr_work_items = MAX_WORK_ITEMS;

    castle_printk(LOG_USERINFO, "Rebuild limited to %d concurrent chunk I/Os\n",
                  castle_nr_work_items);

    for (i=0; i<castle_nr_work_items; i++)
    {
        CASTLE_INIT_WORK(&process_work_items[i].work, process_io_do_work);
        list_add_tail(&process_work_items[i].free_list, &io_free_list);
    }
}

/*
 * Get the next free work item in the list.
 */
process_work_item_t *get_free_work_item(void)
{
    process_work_item_t *wi;

    spin_lock_irq(&io_list_lock);
    if (list_empty(&io_free_list))
    {
        wi = NULL;
    } else
    {
        wi = list_first_entry(&io_free_list, process_work_item_t, free_list);
        list_del(&wi->free_list);
    }
    spin_unlock_irq(&io_list_lock);
    return wi;
}

/*
 * Initialise a work item.
 */
void init_io_work_item(process_work_item_t *wi,
                       c2_block_t *c2b,
                       c_ext_t *ext,
                       c_disk_chk_t *remap_chunks,
                       int remap_idx,
                       int chunkno)
{
    wi->rw = c2b_uptodate(c2b) ? WRITE : READ;
    wi->c2b = c2b;
    wi->ext = ext;
    wi->remap_chunks = remap_chunks;
    wi->remap_idx = remap_idx;
    wi->chunkno = chunkno;
    wi->has_cleanpages = 0;
}

/* Keeps track of how many chunks I/Os we are handling. */
static int rebuild_read_chunks = 0;
int rebuild_write_chunks = 0; /* Not static - needs to be accessed from castle cache code. */

/*
 * Submit async remap I/O work
 * @param ext           The extent.
 * @param chunkno       The chunk to process
 * @param remap_chunks  The chunk(s) to process
 * @param remap_idx     The number of chunk(s) to process
 *
 * @return:             -ENOENT If there are no free work items (caller can throttle).
 *                      EXIT_SUCCESS if I/O submitted successfully.
 */
int submit_async_remap_io(c_ext_t *ext, int chunkno, c_disk_chk_t *remap_chunks, int remap_idx)
{
    c2_block_t *c2b;
    c_ext_pos_t cep;
    process_work_item_t *wi;
    int ret = 0;

    cep.ext_id = ext->ext_id;
    cep.offset = chunkno*C_CHK_SIZE;

    c2b = castle_cache_block_get(cep, BLKS_PER_CHK);
    write_lock_c2b(c2b);

    /*
     * Remap c2bs are handled slightly differently in the cache, as we can
     * have clean c2bs with dirty pages.
    */
    set_c2b_remap(c2b);

    wi = get_free_work_item();
    if (!wi)
        // No free entries. Return error so caller can throttle
        return -ENOENT;

    atomic_inc(&wi_in_flight);

    c2b->end_io = castle_extent_process_async_end;
    init_io_work_item(wi, c2b, ext, remap_chunks, remap_idx, chunkno);
    c2b->private = wi;

    /* Find out (before we do any writes) if the c2b has any dirty pages. */
    if (c2b_has_clean_pages(c2b))
        wi->has_cleanpages = 1;

    if (!c2b_uptodate(c2b))
    {
        /* Read will read from one chunk only. */
        rebuild_read_chunks++;
        /* Submit read only. Read c2b endio will schedule the write. */
        BUG_ON(submit_c2b(READ, c2b));
    } else
    {
        /* The c2b was already uptodate - we don't need to read the chunk. */
        set_c2b_in_flight(c2b);

        ret = submit_c2b_rda(WRITE, c2b);
        if (ret)
        {
            spin_lock_irq(&io_list_lock);
            list_add(&wi->free_list, &io_free_list);
            spin_unlock_irq(&io_list_lock);
            atomic_dec(&wi_in_flight);
            return ret;
        }
    }
    return EXIT_SUCCESS;
}

/*
 * Finish processing extent
 * @param ext           The extent.
 * @param update_seqno  The rebuild seqence number to update the extent to.
 */
void cleanup_extent(c_ext_t *ext, int update_seqno)
{
    spin_lock(&ext->shadow_map_lock);
    ext->use_shadow_map = 0;
    spin_unlock(&ext->shadow_map_lock);

    if (ext->shadow_map)
    {
        castle_vfree(ext->shadow_map);
        ext->shadow_map = NULL;
    }

    /* It is now safe to update the (LIVE) extent with the rebuild sequence number. */
    if (LIVE_EXTENT(ext) && update_seqno)
    {
        ext->curr_rebuild_seqno = ext->remap_seqno;

        /*
         * For superblock meta extents, update the superblock too, because that's what will get
         * written out to disk.
         */
        if ((ext->ext_id == META_EXT_ID) ||
            (ext->ext_id == MSTORE_EXT_ID) ||
            (ext->ext_id == MSTORE_EXT_ID+1))
        {
            struct castle_extents_superblock* castle_extents_sb;

            castle_extent_transaction_start();
            castle_extents_sb = castle_extents_super_block_get();
            switch (ext->ext_id) {
                case META_EXT_ID:
                    castle_extents_sb->meta_ext.curr_rebuild_seqno = ext->remap_seqno;
                    break;
                case MSTORE_EXT_ID:
                    castle_extents_sb->mstore_ext[0].curr_rebuild_seqno = ext->remap_seqno;
                    break;
                case MSTORE_EXT_ID+1:
                    castle_extents_sb->mstore_ext[1].curr_rebuild_seqno = ext->remap_seqno;
                    break;
            }
            castle_extent_transaction_end();
        }
    }
    castle_extent_rebuild_ext_put(ext, 0);
}

/*
 * Write back the maps for a range of chunks in an extent, defined by the writeback_info.
 */
static void writeback_rebuild_chunk(writeback_info_t *writeback_info)
{
    c_ext_pos_t map_cep;
    c2_block_t *map_c2b, *reserve_c2b;
    int chunkno;
    c_ext_t             *ext = __castle_extents_hash_get(writeback_info->ext_id);
    uint32_t            k_factor = castle_extent_kfactor_get(writeback_info->ext_id);
    int                 last_map_page, last_map_page_partial;
    int                 map_page_idx, maps_in_a_page, max_map_page_idx;
    int chunks;

    /* Shadow map must be page aligned. */
    BUG_ON((unsigned long)ext->shadow_map % PAGE_SIZE);

    /* Get the map cep for the page containing the first chunk in the range. */
    map_cep = castle_extent_map_cep_get(ext->maps_cep, writeback_info->start_chunk, ext->k_factor);
    map_cep.offset = MASK_BLK_OFFSET(map_cep.offset);

    /* The number of map chunks per page. */
    maps_in_a_page = map_chks_per_page(ext->k_factor);
    /* The max index (starting from 0) of a chunk in a page. */
    max_map_page_idx = maps_in_a_page - 1;

    /* Initial index into the page for the start chunk. */
    map_page_idx = writeback_info->start_chunk % maps_in_a_page;

    /* The page index of the last chunk in the extent that has been processed by rebuild. */
    last_map_page = writeback_info->end_chunk / maps_in_a_page;
    /* last_map_page_partial will be 'true' if the last map page is a partial one. */
    last_map_page_partial = (writeback_info->end_chunk + 1) % maps_in_a_page;

    map_c2b = NULL;
    reserve_c2b = NULL;

    for (chunkno = writeback_info->start_chunk; chunkno<=writeback_info->end_chunk; chunkno++)
    {
        BUG_ON((chunkno >= ext->shadow_map_range.end) || (chunkno < ext->shadow_map_range.start));
        if (!map_c2b)
        {
            /* Get the c2b for the page containing the map cep.
             *
             * In order to prevent a situation where we have no reserve c2b/c2ps
             * for the flush thread, make a single page c2b reservation and
             * release it once we've finished dirtying the map_c2b.
             */
            reserve_c2b = castle_cache_page_block_reserve();
            map_c2b = castle_cache_page_block_get(map_cep);
            write_lock_c2b(map_c2b);

            /*
             * If this is the last page for the shadow map range, and we are only writing back a
             * partial page, then read in the page first, if it is not updodate. This is because
             * external threads (e.g. extent grow) may have updated the contents of the part of
             * the page that we are not overwriting, and we do not want to write back stale data.
             * (If we are changing the contents of an entire page, then we don't care what the old
             * contents were).
             */
            if ((((chunkno / maps_in_a_page) == last_map_page) && last_map_page_partial) &&
                !c2b_uptodate(map_c2b))
                BUG_ON(submit_c2b_sync(READ, map_c2b));

            /* Next (if any) cache block get will be for the next page in the map. */
            map_cep.offset += C_BLK_SIZE;
        }

        BUG_ON(!map_c2b);

        /*
         * If we have reached the end of the page, or the end of the extent section, we are
         * remapping. Update the buffer with the relevant section of the shadow map for the chunk.
         */
        if ((map_page_idx == max_map_page_idx) || (chunkno == writeback_info->end_chunk))
        {
            /* How many chunks remapped in this page. */
            chunks = (chunkno % maps_in_a_page) + 1;

            memcpy(c2b_buffer(map_c2b),
                (char *)(MASK_BLK_OFFSET((unsigned long)&ext->shadow_map[chunkno*k_factor])),
                sizeof(c_disk_chk_t)*k_factor*chunks);

            dirty_c2b(map_c2b);
            update_c2b(map_c2b);
            write_unlock_c2b(map_c2b);
            put_c2b(map_c2b);
            map_c2b = NULL;

            castle_cache_page_block_unreserve(reserve_c2b);

            /* Reset the index. */
            map_page_idx = 0;
        } else
            map_page_idx++;
    }

    /* Make sure the updated map is flushed out. */
    castle_cache_extent_flush(META_EXT_ID, 0, 0, 0);

    if (writeback_info->ext_finished)
        /* Now the shadow map has become the default map, we can stop redirecting write I/O. */
        cleanup_extent(ext, (writeback_info->ext_finished == COMPLETE));
}

/*
 * Simple check if rebuild should exit.
 */
static int rebuild_exit_check(void)
{
    /* The only reason that a rebuild run should halt processing is:
     * If another slave has gone out-of-serice or evacuated.
     */
    if (rebuild_required())
        return 1;
    else
        return 0;
}

/*
 * Populate the extent process array with rebuild functions.
 */
castle_extent_process_state_t rebuild_process = {   REBUILDING,
                                                    rebuild_init,
                                                    rebuild_finish,
                                                    find_next_rebuild_chunk,
                                                    process_rebuild_chunk,
                                                    writeback_rebuild_chunk,
                                                    rebuild_exit_check,
                                                    rebuild_list_add
                                                };

/*
 * Test if rebuild is required.
 */
static int rebuild_required(void)
{
    if (atomic_read(&current_rebuild_seqno) > rebuild_to_seqno)
    {
        procstate = &rebuild_process;
        return 1;
    } else
    {
        return 0;
    }
}

/*
 * Per-extent state initialisation.
 */
static void initialise_extent_state(c_ext_t * ext)
{
    int k_factor = ext->k_factor;
    int map_size;
    int chunkno;
    int i;

    map_size =
        (ext->shadow_map_range.end-ext->shadow_map_range.start)*k_factor*sizeof(c_disk_chk_t);
    ext->shadow_map = castle_vmalloc(map_size);
    if (!ext->shadow_map)
    {
        castle_printk(LOG_ERROR, "ERROR: could not allocate shadow map of size %lu\n", map_size);
        BUG();
    }

    /* Shadow map must be page aligned. */
    BUG_ON((unsigned long)ext->shadow_map % PAGE_SIZE);

    /* Populate the shadow map - a copy of the existing mapping. */
    for (chunkno = ext->shadow_map_range.start; chunkno<ext->shadow_map_range.end; chunkno++)
        __castle_extent_map_get(ext, chunkno, &ext->shadow_map[chunkno*k_factor]);

    /*
     * As we are remapping a new extent, we need to stop using any pre-existing superchunks.
     * Setting next_chk to 0 will force new superchunk(s) to be allocated for this extent.
     */
    for (i=0; i<process_state.nr_live_slaves; i++)
        if (process_state.live_slaves[i])
            BUG_ON(process_state.live_slaves[i]->count);

   /*
     * Save the rebuild sequence number we have rebuilt the extent to.
     * This can't be saved in the extent until the remap writeback because if a checkpoint
     * and crash occurs before the writeback, the extent will have the wrong sequence number.
     */
    debug("Setting extent %llu to rebuild seqno %d\n", ext->ext_id, rebuild_to_seqno);
    ext->remap_seqno = rebuild_to_seqno;
}

/*
 * extent processing freespace state.
 */
static int  out_of_freespace = 0;
static int  freespace_added = 0;

void castle_extents_process_callback(void *data)
{
    freespace_added = 1;
    wake_up(&process_io_waitq);
}

static int freespace_available(void)
{
    if (out_of_freespace)
    {
        if (freespace_added)
        {
            out_of_freespace = freespace_added = 0;
            return 1;
        } else
            return 0;
    } else
        return 1;
}

/*
 * Initialise extent processing low-freespace handler.
 */
static void init_lfs_handler(void)
{
    c_ext_event_t *event_hdl = NULL;

    event_hdl = castle_zalloc(sizeof(c_ext_event_t));
    if (!event_hdl)
        BUG();

    event_hdl->callback = castle_extents_process_callback;
    event_hdl->data     = NULL;

    castle_extent_transaction_start();
    castle_extent_lfs_callback_add(event_hdl);
    castle_extent_transaction_end();
}

#define SHORT_CHECKPOINT_PERIOD 5

/* Controls whether castle_periodic_checkpoint needs to synchronise with extent processor. */
int castle_checkpoint_syncing = 0;

void writeback_list_walk(struct list_head * lh)
{
    struct list_head *writeback_entry;
    writeback_info_t *wentry;

    list_for_each(writeback_entry, lh)
        wentry = list_entry(writeback_entry, writeback_info_t, list);
}

/*
 * Check I/O function for extent processing wait queue.
 * Has three return code ranges:
 * Return (negative) non-zero for a genuine I/O error.
 * Return (positive) non-zero if there are free work items
 * Return zero if there are no free work items
 */
int work_io_check(void)
{
    struct list_head    *io_error_entry, *tmp, *writeback_entry;
    process_work_item_t *wi;
    int err = 0;

    spin_lock_irq(&io_list_lock);
    if (!list_empty(&io_error_list))
    {
        /*
         * Scan through all the errors on the list. We should only see -EAGAIN for a failed I/O
         */
        list_for_each_safe(io_error_entry, tmp, &io_error_list)
        {
            wi = list_entry(io_error_entry, process_work_item_t, error_list);
            list_del(io_error_entry);
            if (c2b_eio(wi->c2b))
            {
                err = -EAGAIN;
                clear_c2b_eio(wi->c2b);
            }
            else
                BUG();

            /*
             * This process_work_item represents a disk chunk that has failed write I/O, but it will
             * already have been added to the processed list as part of the range covered by one of
             * its writeback info structures.
             * For a chunk 'Y', scan through the processed list, looking for the for the extent
             * where the range covered, X through Z is such that X <= Y <= Z. If it is found, reduce
             * the range to X through (Y-1). This means that the map for Y will not get written out,
             * but will allow all other maps to be written.
             * If there are subsequent failed I/Os with a lower chunk number, these can curtail
             * the range even further. If (as is more likely), there are subsequent I/Os with higher
             * chunk numbers, then the wi range will already exclude them.
             */
            list_for_each(writeback_entry, &processed_list)
            {
                writeback_info_t *winfop;
                winfop = list_entry(writeback_entry, writeback_info_t, list);
                if ((wi->ext->ext_id == winfop->ext_id) &&
                    (winfop->start_chunk <= wi->chunkno) && (wi->chunkno <= winfop->end_chunk))
                {
                    winfop->end_chunk = wi->chunkno - 1;
                    break;
                }
            }

            write_unlock_c2b(wi->c2b);
            //BUG_ON(castle_cache_block_destroy(wi->c2b) && LOGICAL_EXTENT(wi->ext->ext_id));
            put_c2b(wi->c2b);
            castle_free(wi->remap_chunks);

            list_add_tail(&wi->free_list, &io_free_list);
            atomic_dec(&wi_in_flight);
        }
        spin_unlock_irq(&io_list_lock);
        return err;
    }
    spin_unlock_irq(&io_list_lock);

    if (atomic_read(&wi_in_flight) < castle_nr_work_items)
        return 1;

    return 0;
}

/* Extent processing ratelimiting. */
unsigned long expected_time;
unsigned long delta_time;
#define BATCHSIZE 10        /* 100 x 1m I/Os per process I/O batch. */
#define RATELIMIT_DEFAULT 0
#define RATELIMIT_MIN 0     /* No ratelimiting */
#define RATELIMIT_MAX 10000 /* 10Gb/s max */
int castle_extents_process_ratelimit = RATELIMIT_DEFAULT;

/*
 * Disable synchronisation between extent processing and checkpoint thread.
 */
static void disable_checkpoint_sync(void)
{
    castle_checkpoint_syncing = 0;
    atomic_set(&castle_extents_presyncvar, 0);
    atomic_set(&castle_extents_postsyncvar, 0);
    /* In case checkpoint was already waiting ... */
    wake_up(&process_syncpoint_waitq);
}

/*
 * Main extent processing kthread.
 */
static int castle_extents_process(void *unused)
{
    struct list_head                *process_entry, *writeback_entry, *ptmp, *wtmp;
    c_ext_t                         *ext;
    int                             process_exiting, process_interrupted, extent_interrupted=0;
    int                             process_drop_extents = 0;
    int                             ret;
    int                             i;
    writeback_info_t                *writeback_info=NULL;
    int                             saved_checkpoint_period=0;
    int                             batch;
    int                             io_error = 0;

    INIT_LIST_HEAD(&extent_list);
    INIT_LIST_HEAD(&processed_list);
    INIT_LIST_HEAD(&writeback_list);

    init_waitqueue_head(&process_waitq);
    init_waitqueue_head(&process_syncpoint_waitq);

    init_io_work();

    debug("Starting extent process thread ...\n");
    do {
        /*
         * Normal wait state - will be woken under the following circumstances:
         * 1: A slave goes out-of-service or is evacuated (current_rebuild_seqno > rebuild_to_seqno)
         * 2: Slaves need rebalancing (rebalance_required() == TRUE)
         * 3: kthread_stop has been called (on module exit)
         */
        wait_event_interruptible(process_waitq,
                                 rebuild_required()             ||
                                 kthread_should_stop());

        if (kthread_should_stop())
        {
            debug("Extent processing thread terminating.\n");
            goto out;
        }

        /* Generic initialisation. */
        castle_checkpoint_syncing = 1;
        process_exiting = 0;
        process_interrupted = 0;
        process_drop_extents = 0;

        BUG_ON(!procstate);

        /*
         * Per-state initialisation. Includes rebuild creating a set of rebuild-from and rebuild-to
         * slaves.
         */
        procstate->init();

        /* Initialisation for I/O ratelimiting. */
        batch = BATCHSIZE; /* 10 x 1m I/Os per batch. */
        delta_time = jiffies;

        /*
         * Build the list of extents to process. Extent transaction protected to avoid racing
         * with extent alloc and extent grow using oos or evacuating slaves.
         */
        castle_extent_transaction_start();
        castle_extents_hash_iterate(procstate->list_add, NULL);
        castle_extent_transaction_end();

        if (list_empty(&extent_list))
        {
            debug(LOG_WARN, "Extent process: no extents found.\n");
            goto finished;
        }

        list_for_each_safe(process_entry, ptmp, &extent_list)
        {
            int chunk_index;
            c_chk_cnt_t ext_start, ext_end;
            int curr_chunk, nr_chunks = 0;
            int chunk_found = 0;
            int chunkno=0;

            extent_interrupted = 0;

            ext = list_entry(process_entry, c_ext_t, process_list);
            list_del(process_entry);

            /* Dropping extents (for early exit), nothing to do for this extent. */
            if (process_drop_extents)
            {
                castle_extent_rebuild_ext_put(ext, 0);
                continue;
            }

            BUG_ON(MASK_ID_INVAL(ext->rebuild_mask_id));

            /* Get extent current range. */
            castle_extent_mask_read(ext->rebuild_mask_id, &ext_start, &ext_end);

            ext->shadow_map_range.start = ext_start;
            ext->shadow_map_range.end = ext_end;

            /* Don't process extent chunks if it is not live, or if our mask range is empty. */
            if (((ext_end - ext_start) == 0) || !LIVE_EXTENT(ext))
                goto skip_extent;

            initialise_extent_state(ext);

            curr_chunk = ext_start;

            /* Index into extent chunks (1 for rebuild, N for rebalance) that need to be
            processed. nr_chunks = chunks in start_chunk (1 or N). */
            while (LIVE_EXTENT(ext) &&
                  (nr_chunks = procstate->find_next_frame(ext, &curr_chunk, ext_end)))
            {
                chunk_found = 1;
                chunkno++;
finishing:
                if (process_exiting)
                    wait_event_interruptible(process_syncpoint_waitq,
                                             atomic_read(&castle_extents_presyncvar) == 1);

                if (atomic_read(&castle_extents_presyncvar))
                {
                    /*
                     * Checkpoint has indicated it is about to update freespace. Move all current
                     * entries on the processed list to the writeback list (at the tail, because
                     * there may already be entries there, and their order is important).
                     * First drain any outstanding IO, to ensure that all data chunks are on disk
                     * before their mappings are written. Check for any resultant errors.
                     */
                    while (atomic_read(&wi_in_flight))
                    {
                        io_error = work_io_check();
                        if (io_error < 0)
                        {
                            /* We had an I/O error at some stage for this extent. */
                            switch (io_error) {
                                case -EAGAIN:
                                    /*
                                     * We found a dead slave during one of the chunk I/Os. This
                                     * means that extent processing will restart, so there's nothing
                                     * to do here.
                                     */
                                    break;
                                default:
                                    BUG();
                            }
                        }
                        msleep(IO_SLEEP_TIME);
                    }

                    list_splice_init(&processed_list, writeback_list.prev);

                    /* Current writeback_info should no longer be used. */
                    writeback_info = NULL;

                    /* Reset I/O ratelimiting so we don't get a burst when chunk I/O restarts */
                    if (list_empty(&extent_list))
                        rebuild_read_chunks = rebuild_write_chunks = 0;

                    BUG_ON(atomic_read(&castle_extents_postsyncvar));
                    atomic_set(&castle_extents_presyncvar, 0);
                    wake_up(&process_syncpoint_waitq);
                }

                if (!process_exiting)
                {
                    for (i=0; i<nr_chunks; i++, chunk_index++)
                    {
retry:
                        /* Stop here if we have been ratelimited. */
                        wait_event_interruptible(process_io_waitq,
                                        ((io_error = work_io_check()) && freespace_available()) ||
                                         kthread_should_stop());
                        /*
                         * Checkpoint syncing will have been disabled if we were waiting for
                         * freespace. Re-enable it here.
                         */
                        castle_checkpoint_syncing = 1;

                        if (kthread_should_stop())
                            break;

                        if (io_error < 0)
                        {
                            switch (io_error) {
                                case -EAGAIN:
                                    /*
                                     * We found a dead slave during one of the chunk I/Os. This
                                     * means that extent processing will restart, so there's nothing
                                     * to do here.
                                     */
                                    break;
                                default:
                                    BUG();
                            }
                        }

                        /* Process the chunk. */
                        ret = procstate->process_chunk(ext, curr_chunk, i, chunkno);
                        if (ret)
                        {
                            switch (ret) {
                                case -ENOSPC:
                                    out_of_freespace = 1;
                                    init_lfs_handler();
                                    /*
                                     * We're going to park, waiting for freespace.  Disable
                                     * checkpoint sync in the meantime (otherwise checkpoint will
                                     * hang until we get freespace).
                                     */
                                    disable_checkpoint_sync();
                                case -ENOENT:
                                    goto retry;
                                    break;
                                default:
                                    BUG();
                            }
                        }

                        if ((rebuild_read_chunks + rebuild_write_chunks) >= batch)
                        {
                            if (castle_extents_process_ratelimit < RATELIMIT_MIN)
                                castle_extents_process_ratelimit = RATELIMIT_MIN;
                            if (castle_extents_process_ratelimit > RATELIMIT_MAX)
                                castle_extents_process_ratelimit = RATELIMIT_MAX;
                            if (castle_extents_process_ratelimit)
                            {
                                expected_time = (rebuild_read_chunks + rebuild_write_chunks) * 1000
                                                / castle_extents_process_ratelimit;
                                delta_time = jiffies - delta_time;
                                if (expected_time > jiffies_to_msecs(delta_time))
                                    msleep(expected_time - jiffies_to_msecs(delta_time));
                                delta_time = jiffies;
                                rebuild_read_chunks = rebuild_write_chunks = 0;
                            }
                        }
                    }
                }

                if (process_exiting)
                    wait_event_interruptible(process_syncpoint_waitq,
                                             atomic_read(&castle_extents_postsyncvar) == 1);

                if (atomic_read(&castle_extents_postsyncvar))
                {
                    atomic_set(&castle_extents_postsyncvar, 0);
                    list_for_each_safe(writeback_entry, wtmp, &writeback_list)
                    {
                        writeback_info_t *winfop;
                        winfop = list_entry(writeback_entry, writeback_info_t, list);
                        list_del(writeback_entry);
                        procstate->do_writeback(winfop);
                        free_writeback_info(winfop);
                    }
                }

                if (process_exiting)
                {
                    castle_checkpoint_period = saved_checkpoint_period;
                    break;
                }

                if (!process_exiting)
                {
                    if (writeback_info && (ext->ext_id == writeback_info->ext_id))
                        writeback_info->end_chunk = curr_chunk + (nr_chunks-1);
                    else
                    {
                        /*
                         * This is a new extent, or we've written back the previous writeback_info.
                         */
                        writeback_info = alloc_writeback_info(ext->ext_id, curr_chunk, nr_chunks);
                        BUG_ON(!writeback_info);
                        list_add_tail(&writeback_info->list, &processed_list);
                    }
                }

                if (procstate->exit_check() || kthread_should_stop())
                {
                    /*
                     * Finish this extent early. Assume that not all the work has been completed.
                     * This may not always be true. The last chunk of the last extent might have
                     * just completed processing, but we can't know that, so we assume the worst.
                     */
                    extent_interrupted = 1;
                    break; /* ... out of process_chunk loop. */
                }
            }

skip_extent:
            FAULT(REBUILD_FAULT1);

            if (!process_exiting)
            {
                /*
                 * Finished with this extent. Drain I/O and check for errors.
                 */

                /* Clean up any chunks left over from this extent. */
                castle_extent_remap_space_cleanup(ext);

                if (!chunk_found)
                {
                    /*
                     * No chunks were found for this extent. Clean up and drop its ref now.
                     * DO NOT reference the extent after this point!.
                     */
                    cleanup_extent(ext, 1);
                }
                else if (writeback_info)
                {
                    BUG_ON(writeback_info->ext_id != ext->ext_id);
                    if (extent_interrupted || !LIVE_EXTENT(ext))
                        writeback_info->ext_finished = INTERRUPTED;
                    else
                        writeback_info->ext_finished = COMPLETE;
                }

                while (atomic_read(&wi_in_flight))
                {
                    io_error = work_io_check();
                    if (io_error < 0)
                    {
                        switch (io_error) {
                            case -EAGAIN:
                                /*
                                 * We found a dead slave during one of the chunk I/Os. This
                                 * means that extent processing will restart, so there's nothing
                                 * to do here.
                                 */
                                break;
                            default:
                                BUG();
                        }
                    }
                    msleep(IO_SLEEP_TIME);
                }

                writeback_info = NULL;

                /*
                 * At this point we'll check to see if the extent processor needs to terminate
                 * early, or has finished processing all the extents. Note that we do not use
                 * the natural termination of the per-extent for loop, because we want to do one
                 * final pass through the logic in 'process_exiting' mode. So we check if
                 * extent_list is empty here to trigger that final pass.
                 */
                if (list_empty(&extent_list) || procstate->exit_check() || kthread_should_stop())
                {
                    if (!list_empty(&extent_list))
                        process_interrupted = 1;
                    process_exiting = 1;
                    saved_checkpoint_period = castle_checkpoint_period;
                    castle_checkpoint_period = 5;
                    goto finishing;
                }
            }

            if (process_exiting)
                /* Drop the rest of the extents before we finish. */
                process_drop_extents = 1;
        }

finished:
        disable_checkpoint_sync();

        /* Per-state cleanup, includes rebuild setting slave state bits. */
        procstate->finish(process_interrupted||extent_interrupted);

    } while (1);
out:
    return EXIT_SUCCESS;
}

/*
 * Kick the rebuild thread to start the rebuild process (e.g. when a slave dies or is evacuated).
 */
void castle_extents_rebuild_wake(void)
{
    atomic_inc(&current_rebuild_seqno);
    castle_events_slave_rebuild_notify();
    wake_up(&process_waitq);
}

/*
 * Main initialisation function for extent processor.
 *
 * @return 0:       Success.
 */
int castle_extents_process_init(void)
{

    castle_extproc_workq = create_workqueue("castle_extproc");
    if (!castle_extproc_workq)
    {
        castle_printk(LOG_ERROR, KERN_ALERT "Error: Could not alloc extproc wq\n");
        return -ENOMEM;
    }

    extproc_thread = kthread_run(castle_extents_process, NULL, "castle-extproc");

    if(!extproc_thread)
        return -ENOMEM;

    return 0;
}

/*
 * Main fini function for extent processor.
 */
void castle_extents_process_fini(void)
{
    kthread_stop(extproc_thread);

    destroy_workqueue(castle_extproc_workq);
}

/*
 * Check if rebuild needs to be started on fs startup.
 */
void castle_extents_rebuild_startup_check(int need_rebuild)
{
    struct castle_fs_superblock *fs_sb;

    /*
     * If fs init decided that we need a rebuild, then bumping current_rebuild_seqno will force all
     * extents to be checked.
     */
    if (need_rebuild)
        atomic_inc(&current_rebuild_seqno);

    fs_sb = castle_fs_superblocks_get();
    /*
     * If fs_in_rebuild is non-zero or need_rebuild is set we need to (re)start rebuild. Setting
     * rebuild_to_seqno to current_rebuild_seqno-1 will force the rebuild thread to start the
     * rebuild.
     */
    if (fs_sb->fs_in_rebuild || need_rebuild)
    {
        rebuild_to_seqno = atomic_read(&current_rebuild_seqno) - 1;
        castle_printk(LOG_USERINFO, "Rebuild startup check: Starting rebuild.\n");

        /* Wake the rebuild thread */
        wake_up(&process_waitq);
    }
    castle_fs_superblocks_put(fs_sb, 1);
}

/*
 * Add an extent to the verify list if it is potentially remappable.
 *
 * @param ext       The extent to check and add to the verify list.
 *
 * @return 0:       Always return 0 so that castle_extents_hash_iterate continues.
 */
static int castle_extent_verify_list_add(c_ext_t *ext, void *unused)
{
    /* We are not handling logical extents or extents scheduled for deletion. */
    if (!SUPER_EXTENT(ext->ext_id) && !(ext->ext_id == MICRO_EXT_ID))
    {
        /*
         * Take a reference to the extent. We will drop this when we have finished remapping
         * the extent.
         */
        if (castle_extent_rebuild_ext_get(ext, 1) < 0)
            /* Extent is already dead. */
            return 0;

        list_add_tail(&ext->verify_list, &verify_list);
    }
    return 0;
}

/*
 * Scanb the map for an extent, looking for references to a slave.
 *
 * @param ext       The extent to check.
 * @param uuid      The slave to scan for.
 *
 * @return nr_refs: The number of references to the uuid in this extent
 */
static int castle_extent_scan_uuid(c_ext_t *ext, uint32_t uuid)
{
    int chunkno, nr_refs=0, idx=0;
    c_disk_chk_t chunks[ext->k_factor];
    c_chk_cnt_t ext_start, ext_end;

    castle_extent_latest_mask_read(ext, &ext_start, &ext_end);

    for (chunkno = ext_start; chunkno<ext_end; chunkno++)
    {
        __castle_extent_map_get(ext, chunkno, chunks);
        for (idx=0; idx<ext->k_factor; idx++)
        {
            if (chunks[idx].slave_id == uuid)
                nr_refs++;
        }
    }
    return nr_refs;
}

/**
 * Scan all extents in the hash, looking for disk chunks using that slave.
 *
 * @param uuid      The slave to check for
 * return           Returns EBUSY if a rebuild is in progress, so a scan may be invalid.
 *                  Returns EEXIST if at least one chunk is found for the slave.
 *                  Returns ENOENT if extents found to check.
 *                  Returns EXIT_SUCCESS if no chunk is found for the slave.
 */
int castle_extents_slave_scan(uint32_t uuid)
{
    struct castle_fs_superblock *fs_sb;
    struct list_head            *entry, *tmp;
    c_ext_t *ext;
    int     nr_refs=0;

    fs_sb = castle_fs_superblocks_get();
    /*
     * If fs_in_rebuild is non-zero a rebuild is still in progress, so a scan may be invalid.
     */
    if (fs_sb->fs_in_rebuild)
    {
        castle_printk(LOG_DEVEL, "REBUILD_VERIFY returning EBUSY\n");
        castle_fs_superblocks_put(fs_sb, 1);
        return -EBUSY;
    }
    castle_fs_superblocks_put(fs_sb, 1);

    /* Initialise the verify list. */
    INIT_LIST_HEAD(&verify_list);

    debug("castle_extents_slave_scan started on slave 0x%x\n", uuid);
    castle_extents_hash_iterate(castle_extent_verify_list_add, NULL);

    if (list_empty(&verify_list))
    {
        castle_printk(LOG_DEVEL, "REBUILD_VERIFY: list is empty.\n");
        return -ENOENT;
    }

    list_for_each_safe(entry, tmp, &verify_list)
    {
        ext = list_entry(entry, c_ext_t, verify_list);
        list_del(entry);

        nr_refs += castle_extent_scan_uuid(ext, uuid);
        castle_extent_rebuild_ext_put(ext, 0);
    }

    if (nr_refs)
    {
        castle_printk(LOG_DEVEL, "REBUILD_VERIFY: %d references found to uuid 0x%xd\n",
                      nr_refs, uuid);
        return -EEXIST;
    }
    else
        return 0;
}

signed int castle_extent_link_count_get(c_ext_id_t ext_id)
{
    c_ext_t *ext;
    ext = castle_extents_hash_get(ext_id);
    if(!ext) return -1;
    return ((signed int)atomic_read(&ext->link_cnt));
}

c_ext_type_t castle_extent_type_get(c_ext_id_t ext_id)
{
    c_ext_t *ext;
    ext = castle_extents_hash_get(ext_id);
    if(!ext) return EXT_T_INVALID;
    return ext->ext_type;
}


/**
 * Extents Resize
 */

/**
 * Create new extent mask and add it to the extent as latest mask.
 *
 * @param   ext         [inout]     Create a new mask for this extent.
 * @param   start       [in]        First chunk offset of mask.
 * #param   end         [in]        Last chunk offset of mask.
 * @param   prev_mask_id[in]        ID of the mask that the new mask is relative to. If that
 *                                  doesn't match, then racing with other mask_create. Just,
 *                                  return error. Caller will try again.
 *
 * @return  mask_id     ID of the new mask that is created.
 */
static int castle_extent_mask_create(c_ext_t            *ext,
                                     c_ext_mask_range_t  range,
                                     c_ext_mask_id_t     prev_mask_id)
{
    c_ext_mask_t *mask = castle_alloc(sizeof(c_ext_mask_t));
    c_ext_mask_t *prev_mask = NULL;

    /* Should be in of the extent transaction. */
    BUG_ON(!castle_extent_in_transaction());

    debug_mask("Creating mask " cemr_cstr "for extent %llu\n",
               cemr2str(range), ext->ext_id);

    /* Sanity checks. */
    CHECK_MASK_RANGE(range);

    /* Shouldn't cross extent boundary. */
    BUG_ON(range.end > ext->size);

    /* No memory available return error. */
    if (!mask)
        return -ENOMEM;

    /* Init mask structure. */
    mask->mask_id   = atomic_inc_return(&castle_extent_max_mask_id);
    mask->range     = range;
    mask->ext       = ext;

    /* Get hold of extents hash lock, to make sure no one else is accessing the extents
     * mask_list and no references are being acquired parallely. */
    write_lock_irq(&castle_extents_hash_lock);

    /* Extent link count should not be 0. Should be alive. */
    BUG_ON(atomic_read(&ext->link_cnt) == 0);

    /* This is the latest mask. Should represent number links in reference count. */
    atomic_set(&mask->ref_count, atomic_read(&ext->link_cnt));

    /* If there is no previous mask, list should be empty. Same the other way. */
    BUG_ON(!!MASK_ID_INVAL(prev_mask_id) ^ !!list_empty(&ext->mask_list));

    /* If there is a previous mask. */
    if (!MASK_ID_INVAL(prev_mask_id))
    {
        /* Get the previous mask structure. */
        prev_mask = GET_LATEST_MASK(ext);

        /* If it doesn't match the ID passed by the caller, then racing with some other
         * mask_create on the same extent, return error and caller would try again. */
        BUG_ON((prev_mask->mask_id != prev_mask_id));
    }
    else
        /* Extent just got created link count should be 1. */
        BUG_ON(atomic_read(&ext->link_cnt) != 1);

    /* Add the mask as latest mask to the extent. */
    list_add(&mask->list, &ext->mask_list);

    /* Add mask to hash. */
    castle_extent_mask_hash_add(mask);

    /* Update global mask.
     *
     * Note:  Global mask gets updated by mask_create() and mask_destroy(). mask_create()
     * changes the global mask only in case of grow().
     */
    if (MASK_RANGE_EMPTY(ext->global_mask))
    {
        ext->global_mask = mask->range;
    }
    else
    {
        if (ext->global_mask.start > mask->range.start)
            ext->global_mask.start = mask->range.start;

        if (ext->global_mask.end < mask->range.end)
            ext->global_mask.end = mask->range.end;
    }

    debug_mask("Updated global mask to " cemr_cstr "\n", cemr2str(ext->global_mask));

    /* Release link references from previous mask. */
    if (!MASK_ID_INVAL(prev_mask_id))
    {
        BUG_ON(castle_extent_mask_hash_get(prev_mask->mask_id) == NULL);

        BUG_ON(atomic_read(&prev_mask->ref_count) < atomic_read(&ext->link_cnt));

        /* This is not latest any more. Doesn't represent the reference count. Leave one
         * extra reference, to release by mask_put() as it could be the last reference on
         * mask. */
        atomic_sub(atomic_read(&ext->link_cnt) - 1, &prev_mask->ref_count);

        /* Release last link reference also. */
        castle_extent_mask_put(prev_mask_id);
    }

    /* Done with create, release the lock. */
    write_unlock_irq(&castle_extents_hash_lock);

    return 0;
}

/**
 * Delete extent mask from mask list and free the resources that would become invalid after
 * the deletion.
 *
 * 1. If the extent has older masks than this mask, then just delete this mask from list,
 * nothing more to do.
 * 2. If this is the oldest mask, commit the mask operation
 *      a. Shrink - Free the space in shrinked range.
 *      b. Grow - Nothing to do, space is already allocated and being used.
 *      c. Truncate - Free the space in truncated range.
 *
 * @param   mask    [in]    Destroy the mask.
 */
static int castle_extent_mask_destroy(c_ext_mask_t *mask)
{
    struct list_head *head;
    c_ext_t *ext;
    int ext_free = 0;

    debug_mask("Destroying mask " cemr_cstr " on extent: %llu\n",
                             cemr2str(mask->range), mask->ext->ext_id);

    /* Should be in extent transaction. */
    BUG_ON(!castle_extent_in_transaction());

    /* Get hold of extent mask lock, to make sure no one else accessing the extents mask_list. */
    write_lock_irq(&castle_extents_hash_lock);

    /* Should be the oldest mask. */
    BUG_ON(!IS_OLDEST_MASK(mask->ext, mask));

    /* Shouldn't be any references left. */
    BUG_ON(atomic_read(&mask->ref_count));

    ext = mask->ext;
    head = &ext->mask_list;

    /* Remove the mask from the list. */
    list_del(&mask->list);

    if (list_empty(head))
        ext_free = 1;

    write_unlock_irq(&castle_extents_hash_lock);

    if (ext_free)
        /* Last mask to be freed. */
        castle_extent_mask_reduce(ext, mask->range, EMPTY_MASK_RANGE,
                                  &ext->global_mask, 1);
    else
        castle_extent_mask_reduce(ext, mask->range, GET_OLDEST_MASK(ext)->range,
                                  &ext->global_mask, 1);

    if (ext_free)
        /* Free the extent resources. */
        castle_extent_resource_release(mask->ext);

    castle_free(mask);

    return 0;
}

static int castle_extents_garbage_collector(void *unused)
{
    LIST_HEAD(gc_list);

    castle_printk(LOG_INIT, "Starting Extents garbage collector thread: %p\n", &gc_list);

    /* Wait for all the extents to get initialized. */
    while((extent_init_done != 2) && !kthread_should_stop())
        msleep(1000);

    do {
        int ignore;
        struct list_head *tmp, *pos;

        /* Wait for some one to schedule a mask to free or thread to stop. */
        __wait_event_interruptible(castle_ext_mask_gc_wq,
                                   (kthread_should_stop() ||
                                            atomic_read(&castle_extents_gc_q_size)),
                                   ignore);

        /* If the file sytem is exiting break the loop. */
        if (kthread_should_stop())
        {
            /* By this time, it shouldn't have any more extents to free. Should have
             * completed last checkpoint by now. */
            BUG_ON(atomic_read(&castle_extents_gc_q_size));

            /* Break the loop, and exit the thread. */
            break;
        }

        /* Start an extent transaction, to make sure no checkpoint happening in parellel. */
        castle_extent_transaction_start();

        /* Don't want any parallel additions to the list. */
        write_lock_irq(&castle_extents_hash_lock);

        BUG_ON(list_empty(&castle_ext_mask_free_list));

        /* Make a duplicate copy of the list. */
        list_splice_init(&castle_ext_mask_free_list, &gc_list);

        write_unlock_irq(&castle_extents_hash_lock);

        /* Go over the list of masks, and call destroy on them. */
        list_for_each_safe(pos, tmp, &gc_list)
        {
            c_ext_mask_t *mask = list_entry(pos, c_ext_mask_t, hash_list);

            /* Remove from GC list. */
            list_del(pos);

            /* Removes mask from extent and also free-up any resources occupied by it. */
            BUG_ON(castle_extent_mask_destroy(mask) < 0);

            atomic_dec_return(&castle_extents_gc_q_size);
        }

        castle_extent_transaction_end();
    } while(1);

    return 0;
}

/**
 * Get the extents global view.
 */
void castle_extent_mask_read_all(c_ext_id_t     ext_id,
                                 c_chk_cnt_t   *start,
                                 c_chk_cnt_t   *end)
{
    c_ext_t *ext;
    struct list_head *pos;

    *start = *end = 0;

    write_lock_irq(&castle_extents_hash_lock);

    ext = __castle_extents_hash_get(ext_id);

    list_for_each_prev(pos, &ext->mask_list)
    {
        c_ext_mask_t *mask = list_entry(pos, c_ext_mask_t, list);

        if (atomic_read(&mask->ref_count) == 0)
            continue;

        if (*start > mask->range.start)
            *start = mask->range.start;

        if (*end < mask->range.end)
            *end = mask->range.end;
    }

    *end = *end - 1;

    write_unlock_irq(&castle_extents_hash_lock);
}

static void castle_extent_reduce_global_mask(c_ext_mask_range_t *global_mask,
                                             c_ext_mask_range_t  free_range)
{
    int set = 0;

    if (MASK_RANGE_EMPTY(free_range))
        return;

    /* Check the borders. */
    BUG_ON(free_range.start < global_mask->start);
    BUG_ON(free_range.end > global_mask->end);

    /* Update global mask. */
    if (free_range.start == global_mask->start)
    {
        global_mask->start = free_range.end;
        set++;
    }

    if (free_range.end == global_mask->end)
    {
        global_mask->end = free_range.start;
        set++;
    }

    /* If both ranges are same, deleting everything. */
    if (set == 2)
        *global_mask = EMPTY_MASK_RANGE;

    debug_mask("Updated global mask to " cemr_cstr "\n", cemr2str(*global_mask));

    BUG_ON(!set);
}

/* Resize functions. */

/**
 * Grow the extent by given number of chunks.
 *
 * @param   ext_id  [inout]     ID of the extent that has to grow.
 * @param   count   [in]        Number of chunks to be grown.
 *
 * @return  0   SUCCESS - Extent is successfully grown.
 *          <0  FAILURE
 */
int castle_extent_grow(c_ext_id_t ext_id, c_chk_cnt_t count)
{
    c_ext_t *ext = castle_extents_hash_get(ext_id);
    c_ext_mask_t *mask;
    int ret = 0;

    /* Extent should be alive, something is wrong with client. */
    BUG_ON(!ext);

    debug_resize("Grow the extent by %u chunks\n", count);

    castle_extent_transaction_start();

    if (ext->pool)
        castle_res_pool_print(ext->pool);

    /* Allocate space to the extent. */
    ret = castle_extent_space_alloc(ext, INVAL_DA, count);
    if (ret < 0)
    {
        castle_printk(LOG_WARN, "Failed to allocate space for extent %u\n", ext_id);
        goto out;
    }

    /* Get the current latest mask. */
    mask = GET_LATEST_MASK(ext);

    if (!mask)
    {
        castle_printk(LOG_ERROR, "%s::failed to recover a mask for extent %d\n", ext->ext_id);
        BUG();
    }

    /* Grow shouldn't try to cross extent boundary. */
    BUG_ON(mask->range.end + count > ext->size);

    /* Create new mask for the extent and set as latest. */
    ret = castle_extent_mask_create(ext,
                                    MASK_RANGE(mask->range.start, mask->range.end + count),
                                    mask->mask_id);
    if (ret < 0)
    {
        castle_extent_space_free(ext, mask->range.end, count);
        goto out;
    }

    if (ext->pool)
        castle_res_pool_print(ext->pool);

out:
    castle_extent_transaction_end();

    return ret;
}

/**
 * Shrink the extent to the given chunk offset.
 *
 * @param   ext_id      [inout]     ID of the extent to be shrunk.
 * @param   chunk       [in]        Chunk to be shrunk to. Everything upto (chunk-1)
 *                                  becomes invalid.
 *
 * @return      0 SUCCESS
 *            < 0 FAILURE
 */
int castle_extent_shrink(c_ext_id_t ext_id, c_chk_cnt_t chunk)
{
    c_ext_t *ext = castle_extents_hash_get(ext_id);
    c_ext_mask_t *mask;
    int ret = 0;

    /* Extent should be alive, something is wrong with client. */
    BUG_ON(!ext);

    debug_resize("Shrink the extent upto %u chunk (%u is valid)\n", chunk, chunk);

    castle_extent_transaction_start();

    if (ext->pool)
        castle_res_pool_print(ext->pool);

    /* Get the current latest mask. */
    mask = GET_LATEST_MASK(ext);

    /* Can't shrink if the latest mask doesnt cover that range. */
    BUG_ON(mask->range.start > chunk);

    /* Create new mask for the extent and set as latest. */
    ret = castle_extent_mask_create(ext,
                                    MASK_RANGE(chunk, mask->range.end),
                                    mask->mask_id);
    if (ret < 0)
    {
        debug_resize("Fail to shrink the extent: %llu\n", ext_id);
        goto out;
    }

    if (ext->pool)
        castle_res_pool_print(ext->pool);

out:
    castle_extent_transaction_end();

    return ret;
}

/**
 * Truncate the extent to the given chunk offset.
 *
 * @param   ext_id      [inout]     ID of the extent to be shrunk.
 * @param   chunk       [in]        Chunk to be truncate to. Everything from (chunk+1)
 *                                  becomes invalid.
 *
 * @return      0 SUCCESS
 *            < 0 FAILURE
 */
int castle_extent_truncate(c_ext_id_t ext_id, c_chk_cnt_t chunk)
{
    c_ext_t *ext = castle_extents_hash_get(ext_id);
    c_ext_mask_t *mask;
    int ret = 0;

    debug_resize("Truncate extent upto %u chunk(%u is valid)\n", chunk, chunk);

    /* Extent should be alive, something is wrong with client. */
    BUG_ON(!ext);

    castle_extent_transaction_start();

    /* Get the current latest mask. */
    mask = GET_LATEST_MASK(ext);

    castle_printk(LOG_DEBUG, "%s::ext %lld; latest mask range: %lld -> %lld; truncate chunk %d\n",
            __FUNCTION__, ext_id, mask->range.start, mask->range.end, chunk);

    /* Can't shrink if the latest mask doesnt cover that range. */
    BUG_ON(mask->range.end <= chunk);

    /* Create new mask for the extent and set as latest. */
    ret = castle_extent_mask_create(ext,
                                    MASK_RANGE(mask->range.start, chunk + 1),
                                    mask->mask_id);
    if (ret < 0)
    {
        castle_printk(LOG_WARN, "Fail to shrink the extent: %u\n", ext_id);
        goto out;
    }

out:
    castle_extent_transaction_end();

    return ret;
}

static void castle_extent_mask_split(c_ext_mask_range_t   range,
                                     c_ext_mask_range_t   separator,
                                     c_ext_mask_range_t  *split1,
                                     c_ext_mask_range_t  *split2)
{
    *split1 = *split2 = EMPTY_MASK_RANGE;

    /* If the base range is empty just return. Do nothing. */
    if (MASK_RANGE_EMPTY(range))
        return;

    /* Get the first half before separator, if any. */
    if (range.start < separator.start)
    {
        split1->start   = range.start;
        split1->end     = (range.end < separator.start)? range.end: separator.start;
    }

    /* Get the second half after separator, if any. */
    if (range.end > separator.end)
    {
        split2->start   = (range.start > separator.end)? range.start: separator.end;
        split2->end     = range.end;
    }

    debug_mask("Splitting " cemr_cstr " by " cemr_cstr " into " cemr_cstr " and " cemr_cstr "\n",
                  cemr2str(range), cemr2str(separator), cemr2str(*split1), cemr2str(*split2));

}

static void castle_extent_free_range(c_ext_t               *ext,
                                     c_ext_mask_range_t     range)
{
    if (MASK_RANGE_EMPTY(range))
        return;

    debug_mask("Freeing space " cemr_cstr " from extent: %llu\n",
                             cemr2str(range), ext->ext_id);

    castle_cache_extent_evict(ext->dirtytree,
                              range.start,
                              (range.end - range.start));

    castle_extent_space_free(ext, range.start, (range.end - range.start));
}

static void castle_extent_mask_reduce(c_ext_t             *ext,
                                      c_ext_mask_range_t   base,
                                      c_ext_mask_range_t   range1,
                                      c_ext_mask_range_t  *global_mask,
                                      int                  do_free)
{
    c_ext_mask_range_t split1, split2;

    debug_mask("Reducing mask " cemr_cstr " from extent %llu\n",
                             cemr2str(base), ext->ext_id);

    /* If the base range is empty just return. Do nothing. */
    if (MASK_RANGE_EMPTY(base))
        return;

    /* Find the parts of base range that are not overlapped by range1. */
    castle_extent_mask_split(base, range1, &split1, &split2);

    castle_extent_reduce_global_mask(global_mask, split1);
    if (do_free)    castle_extent_free_range(ext, split1);

    castle_extent_reduce_global_mask(global_mask, split2);
    if (do_free)    castle_extent_free_range(ext, split2);
}

/*
 * Return the minimum RDA level used by any extent in this fs.
 */
int castle_extent_min_rda_lvl_get(void)
{
    return min_rda_lvl;
}
