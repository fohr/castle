#include <linux/sched.h>
#include <linux/bio.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/kthread.h>
#include <linux/vmalloc.h>
#include <linux/rbtree.h>
#include <linux/delay.h>
#include <linux/blkdev.h>
#include <linux/hash.h>

#include "castle_public.h"
#include "castle.h"
#include "castle_cache.h"
#include "castle_vmap.h"
#include "castle_debug.h"
#include "castle_trace.h"
#include "castle_utils.h"
#include "castle_btree.h"
#include "castle_extent.h"
#include "castle_freespace.h"
#include "castle_da.h"
#include "castle_ctrl.h"
#include "castle_versions.h"
#include "castle_time.h"
#include "castle_rebuild.h"
#include "castle_mstore.h"

#ifndef DEBUG
#define debug(_f, ...)           ((void)0)
#else
#define PREF_DEBUG  /* ensure pref_debug* messages are printed too. */
#define debug(_f, _a...)         (castle_printk(LOG_DEBUG, "%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

#ifndef PREF_DEBUG
#define pref_debug(d, _f, _a...) ((void)0)
#else
#define pref_debug(_d, _f, _a...) if (_d) castle_printk(LOG_DEBUG, "%s:%.4d %s: " _f,           \
                                                        FLE, __LINE__ , __func__, ##_a);
#endif


/**********************************************************************************************
 * Cache descriptor structures (c2b & c2p), and related accessor functions.
 */
enum c2b_state_bits {
    C2B_uptodate,           /**< Block is uptodate within the cache.                              */
    C2B_dirty,              /**< Block is dirty within the cache.                                 */
    C2B_flushing,           /**< Block is being flushed out to disk.                              */
    C2B_transient,
    C2B_prefetch,           /**< Block is part of an active prefetch window.                      */
    C2B_prefetched,         /**< Block was prefetched.                                            */
    C2B_windowstart,        /**< Block is the first chunk of an active prefetch window.           */
    C2B_bio_error,          /**< Block had at least one bio I/O error.                            */
    C2B_no_resubmit,        /**< Block must not be resubmitted after I/O error.                   */
    C2B_remap,              /**< Block is for a remap.                                            */
    C2B_in_flight,          /**< Block is currently in-flight (un-set in c2b_multi_io_end()).     */
    C2B_barrier,            /**< Block in write IO, and should be used as a barrier write.        */
    C2B_eio,                /**< Block failed to write to slave(s)                                */
};

#define INIT_C2B_BITS (0)
#define C2B_FNS(bit, name)                                          \
inline void set_c2b_##name(c2_block_t *c2b)                         \
{                                                                   \
    set_bit(C2B_##bit, &(c2b)->state);                              \
}                                                                   \
inline void clear_c2b_##name(c2_block_t *c2b)                       \
{                                                                   \
    clear_bit(C2B_##bit, &(c2b)->state);                            \
}                                                                   \
inline int c2b_##name(c2_block_t *c2b)                              \
{                                                                   \
    return test_bit(C2B_##bit, &(c2b)->state);                      \
}

#define C2B_TAS_FNS(bit, name)                                      \
inline int test_set_c2b_##name(c2_block_t *c2b)                     \
{                                                                   \
    return test_and_set_bit(C2B_##bit, &(c2b)->state);              \
}                                                                   \
inline int test_clear_c2b_##name(c2_block_t *c2b)                   \
{                                                                   \
    return test_and_clear_bit(C2B_##bit, &(c2b)->state);            \
}

C2B_FNS(uptodate, uptodate)
C2B_FNS(dirty, dirty)
C2B_TAS_FNS(dirty, dirty)
C2B_FNS(flushing, flushing)
C2B_TAS_FNS(flushing, flushing)
C2B_FNS(transient, transient)
C2B_TAS_FNS(transient, transient)
C2B_FNS(prefetch, prefetch)
C2B_TAS_FNS(prefetch, prefetch)
C2B_FNS(prefetched, prefetched)
C2B_FNS(windowstart, windowstart)
C2B_FNS(bio_error, bio_error)
C2B_FNS(no_resubmit, no_resubmit)
C2B_FNS(remap, remap)
C2B_FNS(in_flight, in_flight)
C2B_FNS(barrier, barrier)
C2B_FNS(eio, eio)

/* c2p encapsulates multiple memory pages (in order to reduce overheads).
   NOTE: In order for this to work, c2bs must necessarily be allocated in
         integer multiples of c2bs. Otherwise this could happen:
            // Dirty of sub-c2p
            c2b = castle_cache_block_get(cep, 1);
            write_lock_c2b(c2b);
            update_c2b(c2b);
            memset(c2b_buffer(c2b), 0xAB, PAGE_SIZE);
            dirty_c2b(c2b);
            write_unlock_c2b(c2b);
            // Sub-c2p read
            c2b = castle_cache_block_get(cep + PAGE_SIZE, 1);
            write_lock_c2b(c2b);
            // c2b_buffer(c2b) has never been read in, but c2b is clean
 */
#define PAGES_PER_C2P   (1)
typedef struct castle_cache_page {
    c_ext_pos_t           cep;
    struct page          *pages[PAGES_PER_C2P];
    union {
        struct hlist_node hlist;
        struct list_head  list;         /**< Position on freelist/meta-extent reserve freelist. */
    };
    struct rw_semaphore   lock;
    unsigned long         state;
    uint16_t              count;
#ifdef CASTLE_DEBUG
    uint32_t              id;
#endif
} c2_page_t;

enum c2p_state_bits {
    C2P_uptodate,
    C2P_dirty,
};

struct castle_cache_flush_entry {
    c_ext_mask_id_t     mask_id;        /**< Reference of the extent, release after completion. */
    c_ext_id_t          ext_id;
    uint64_t            start;
    uint64_t            count;
    struct list_head    list;
};

typedef struct castle_extent_inflight {
    atomic_t           *in_flight;      /**< Global inflight counter.                           */
    atomic_t            ext_in_flight;  /**< Extent specific inflight counter.                   */
    c_ext_mask_id_t     mask_id;        /**< Reference ID on extent.                            */
} c_ext_inflight_t;

#define INIT_C2P_BITS (0)
#define C2P_FNS(bit, name)                                          \
inline void set_c2p_##name(c2_page_t *c2p)                          \
{                                                                   \
    set_bit(C2P_##bit, &(c2p)->state);                              \
}                                                                   \
inline void clear_c2p_##name(c2_page_t *c2p)                        \
{                                                                   \
    clear_bit(C2P_##bit, &(c2p)->state);                            \
}                                                                   \
inline int c2p_##name(c2_page_t *c2p)                               \
{                                                                   \
    return test_bit(C2P_##bit, &(c2p)->state);                      \
}

#define TAS_C2P_FNS(bit, name)                                      \
inline int test_set_c2p_##name(c2_page_t *c2p)                      \
{                                                                   \
    return test_and_set_bit(C2P_##bit, &(c2p)->state);              \
}                                                                   \
inline int test_clear_c2p_##name(c2_page_t *c2p)                    \
{                                                                   \
    return test_and_clear_bit(C2P_##bit, &(c2p)->state);            \
}

C2P_FNS(uptodate, uptodate)
C2P_FNS(dirty, dirty)
TAS_C2P_FNS(dirty, dirty)

static inline int castle_cache_pages_to_c2ps(int nr_pages)
{
    /* If nr_pages divides into PAGES_PER_C2P the expression below is fine because:
        let   nr_pages = n * PAGES_PER_C2P;
        then (nr_pages - 1 ) / PAGES_PER_C2P + 1 =
             (n * PAGES_PER_C2P - 1) / PAGES_PER_C2P + 1 =
             (n - 1) + 1 =
              n
       Otherwise, nr_pages doesn't divide into PAGES_PER_C2P, the expression is still ok:
        let   nr_pages = n * PAGES_PER_C2P + k, where k=[1, PAGES_PER_C2P-1]
        then (nr_pages - 1) / PAGES_PER_C2P + 1 =
             (n * PAGES_PER_C2P + k - 1) / PAGES_PER_C2P + 1 =
              n + 1
     */
    return (nr_pages - 1) / PAGES_PER_C2P + 1;
}

static inline int castle_cache_c2b_to_pages(c2_block_t *c2b)
{
    return castle_cache_pages_to_c2ps(c2b->nr_pages) * PAGES_PER_C2P;
}

/* Macros to iterate over all c2ps and pages in a c2b. Also provide
   cep corresponding to the c2p/page.
    Usage:
        c2b_for_each_c2p_start(c2p, cep, c2b_to_iterate_over)
        {
            $(block of code)
        }
        c2b_for_each_c2p_end(c2p, cep, c2b_to_iterate_over)
    Similarly for iterating over pages.
    NOTE: continue in $(block of code) mustn't use continue, because this
          would skip the block of code in c2b_for_each_c2p_end().
 */
#define c2b_for_each_c2p_start(_c2p, _cep, _c2b, _start)                 \
{                                                                        \
    int _a, _nr_c2ps;                                                    \
    _nr_c2ps = castle_cache_pages_to_c2ps((_c2b)->nr_pages);             \
    _cep = (_c2b)->cep;                                                  \
    for(_a=_start; _a<_nr_c2ps; _a++)                                    \
    {                                                                    \
        _c2p = (_c2b)->c2ps[_a];

#define c2b_for_each_c2p_end(_c2p, _cep, _c2b, _start)                   \
        (_cep).offset += (PAGES_PER_C2P * PAGE_SIZE);                    \
    }                                                                    \
}

#define c2b_for_each_page_start(_page, _c2p, _cep, _c2b)                 \
{                                                                        \
    c_ext_pos_t __cep;                                                   \
    int _i, _cnt;                                                        \
    _cnt = 0;                                                            \
    c2b_for_each_c2p_start(_c2p, __cep, _c2b, 0)                         \
    {                                                                    \
        (_cep) = __cep;                                                  \
        for(_i=0; (_i<PAGES_PER_C2P) && (_cnt < (_c2b)->nr_pages); _i++) \
        {                                                                \
            _page = (_c2p)->pages[_i];

#define c2b_for_each_page_end(_page, _c2p, _cep, _c2b)                   \
            (_cep).offset += PAGE_SIZE;                                  \
            _cnt++;                                                      \
        }                                                                \
    }                                                                    \
    c2b_for_each_c2p_end(_c2p, __cep, _c2b, 0)                           \
}

int                   castle_last_checkpoint_ongoing = 0;

/**********************************************************************************************
 * Static variables.
 */
#define               CASTLE_CACHE_MIN_SIZE         75      /* In MB */
#define               CASTLE_CACHE_MIN_HARDPIN_SIZE 1000    /* In MB */
static int            castle_cache_size           = 20000;  /* In pages */

module_param(castle_cache_size, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(castle_cache_size, "Cache size");

static int                     castle_cache_stats_timer_interval = 0; /* in seconds. NOTE: this need
                                                                         to be set to 0, because we
                                                                         rely on it to work out
                                                                         whether to delete the timer
                                                                         on castle_cache_fini() or
                                                                         not.
                                                                         ALSO: don't export as module
                                                                         parameter, until the fini()
                                                                         logic is fixed. */

#define                        CASTLE_MIN_CHECKPOINT_RATELIMIT  (25 * 1024)  /* In KB/s */
static unsigned int            castle_checkpoint_ratelimit;
module_param(castle_checkpoint_ratelimit, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(castle_checkpoint_ratelimit, "Checkpoint ratelimit in KB/s");


static c2_block_t             *castle_cache_blks = NULL;
static c2_page_t              *castle_cache_pgs  = NULL;

static int                     castle_cache_block_hash_buckets;
static DEFINE_RWLOCK(castle_cache_block_hash_lock);
static DEFINE_SPINLOCK(castle_cache_block_lru_lock);
static struct hlist_head      *castle_cache_block_hash = NULL;

#define PAGE_HASH_LOCK_PERIOD  1024
static int                     castle_cache_page_hash_buckets;
static spinlock_t             *castle_cache_page_hash_locks = NULL;
static struct hlist_head      *castle_cache_page_hash = NULL;

static struct kmem_cache      *castle_io_array_cache = NULL;
static struct kmem_cache      *castle_flush_cache = NULL;

/* Following LIST_HEADs are protected by castle_cache_block_lru_lock. */
static struct list_head        castle_cache_extent_dirtylists[NR_EXTENT_FLUSH_PRIOS];
                                                                    /**< Lists of dirtytrees      */
static               LIST_HEAD(castle_cache_cleanlist);             /**< Clean c2bs               */
static atomic_t                castle_cache_extent_dirtylist_sizes[NR_EXTENT_FLUSH_PRIOS];
                                                                    /**< Number of dirty extents  */
static atomic_t                castle_cache_cleanlist_size;         /**< Blocks on the cleanlist  */
static atomic_t                castle_cache_cleanlist_softpin_size; /**< Softpin blks on cleanlist*/
static atomic_t                castle_cache_block_victims;          /**< #clean blocks evicted    */
static atomic_t                castle_cache_softpin_block_victims;  /**< #softpin blocks evicted  */
static atomic_t                castle_cache_dirty_pages;
static atomic_t                castle_cache_clean_pages;

/* Extent related stats */
typedef struct castle_cache_extent_stats {
    atomic_t        hits;                   /**< c2b_get() where c2b_uptodate(c2b)                */
    atomic_t        misses;                 /**< c2b_get() where !c2b_uptodate(c2b)               */
    atomic_t        ios_cnt;                /**< Number of submit_c2b_io() calls                  */
} c2_extent_stats_t;

/* Merge related stats */
static atomic_t merge_misses;
static atomic_t merge_hits;
static atomic_t non_merge_misses;
static atomic_t non_merge_hits;

static c2_extent_stats_t       extent_stats[EXT_T_INVALID];

static atomic_t                c2_pref_active_window_size;  /**< Number of chunk-sized c2bs that are
                                                    marked as C2B_prefetch and covered by a prefetch
                                                    window currently in the tree.                 */
static int                     c2_pref_total_window_size;   /**< Sum of all windows in the tree in
                                                    chunks.  Overlapping blocks are counted multiple
                                                    times.  Protected by c2_prefetch_lock.        */
static int                     castle_cache_allow_hardpinning;      /**< Is hardpinning allowed?  */

static         DEFINE_SPINLOCK(castle_cache_freelist_lock);     /**< Lock for page/block freelists*/
static int                     castle_cache_page_freelist_size; /**< Num c2ps on freelist         */
static               LIST_HEAD(castle_cache_page_freelist);     /**< Freelist of c2ps             */
static int                     castle_cache_block_freelist_size;/**< Num c2bs on freelist         */
static               LIST_HEAD(castle_cache_block_freelist);    /**< Freelist of c2bs             */

/* The reservelist is an additional list of free c2bs and c2ps that are held
 * for the exclusive use of the flush thread.  The flush thread gets single c2p
 * c2bs and these are used to perform I/O on the metaextent to allow RDA chunk
 * disks+disk offsets to be looked up. */
#define CASTLE_CACHE_FLUSH_BATCH_SIZE   64                          /**< Number of c2bs to flush per
                                                                         batch in _flush()        */
#define CASTLE_CACHE_RESERVELIST_QUOTA  2*CASTLE_CACHE_FLUSH_BATCH_SIZE /**< Number of c2bs/c2ps to
                                                                             reserve for _flush() */
static         DEFINE_SPINLOCK(castle_cache_reservelist_lock);      /**< Lock for reservelists    */
static atomic_t                castle_cache_page_reservelist_size;  /**< Num c2ps on reservelist  */
static               LIST_HEAD(castle_cache_page_reservelist);      /**< Reservelist of c2ps      */
static atomic_t                castle_cache_block_reservelist_size; /**< Num c2bs on reservelist  */
static               LIST_HEAD(castle_cache_block_reservelist);     /**< Reservelist of c2bs      */
static DECLARE_WAIT_QUEUE_HEAD(castle_cache_page_reservelist_wq);   /**< Reservelist c2p waiters  */
static DECLARE_WAIT_QUEUE_HEAD(castle_cache_block_reservelist_wq);  /**< Reservelist c2b waiters  */

#define CASTLE_CACHE_VMAP_PGS   256
typedef struct page *castle_cache_vmap_pgs_t[CASTLE_CACHE_VMAP_PGS];
DEFINE_PER_CPU(castle_cache_vmap_pgs_t, castle_cache_vmap_pgs);
DEFINE_PER_CPU(struct mutex, castle_cache_vmap_lock);

struct task_struct     *castle_cache_flush_thread;
static DECLARE_WAIT_QUEUE_HEAD(castle_cache_flush_wq);
static atomic_t                castle_cache_flush_seq;

static atomic_t                castle_cache_read_stats = ATOMIC_INIT(0);
static atomic_t                castle_cache_write_stats = ATOMIC_INIT(0);

struct timer_list              castle_cache_stats_timer;

static               LIST_HEAD(castle_cache_flush_list);

static atomic_t                castle_cache_logical_ext_pages = ATOMIC_INIT(0);

int                            castle_checkpoint_period = 60;        /* Checkpoint default of once in every 60secs. */

struct                  task_struct  *checkpoint_thread;
/**********************************************************************************************
 * Prototypes.
 */
static void c2_pref_c2b_destroy(c2_block_t *c2b);

/**********************************************************************************************
 * Core cache.
 */

/**
 * Report various cache statistics.
 *
 * @also castle_cache_stats_timer_tick()
 */
void castle_cache_stats_print(int verbose)
{
    int hits, misses, count1, count2, i;
    int reads = atomic_read(&castle_cache_read_stats);
    int writes = atomic_read(&castle_cache_write_stats);
    atomic_sub(reads, &castle_cache_read_stats);
    atomic_sub(writes, &castle_cache_write_stats);

    if (verbose)
        castle_printk(LOG_PERF, "castle_cache_stats_timer_tick: %d, %d, %d, %d, %d\n",
            atomic_read(&castle_cache_dirty_pages),
            atomic_read(&castle_cache_clean_pages),
            castle_cache_page_freelist_size * PAGES_PER_C2P,
            reads, writes);
    castle_trace_cache(TRACE_VALUE,
                       TRACE_CACHE_CLEAN_PGS_ID,
                       atomic_read(&castle_cache_clean_pages), 0);
    castle_trace_cache(TRACE_VALUE,
                       TRACE_CACHE_DIRTY_PGS_ID,
                       atomic_read(&castle_cache_dirty_pages), 0);
    castle_trace_cache(TRACE_VALUE,
                       TRACE_CACHE_FREE_PGS_ID,
                       castle_cache_page_freelist_size * PAGES_PER_C2P, 0);
    castle_trace_cache(TRACE_VALUE,
                       TRACE_CACHE_RESERVE_PGS_ID,
                       atomic_read(&castle_cache_page_reservelist_size), 0);
    castle_trace_cache(TRACE_VALUE,
                       TRACE_CACHE_CLEAN_BLKS_ID,
                       atomic_read(&castle_cache_cleanlist_size), 0);
    castle_trace_cache(TRACE_VALUE,
                       TRACE_CACHE_FREE_BLKS_ID,
                       castle_cache_block_freelist_size, 0);
    castle_trace_cache(TRACE_VALUE,
                       TRACE_CACHE_RESERVE_BLKS_ID,
                       atomic_read(&castle_cache_block_reservelist_size), 0);
    castle_trace_cache(TRACE_VALUE,
                       TRACE_CACHE_SOFTPIN_BLKS_ID,
                       atomic_read(&castle_cache_cleanlist_softpin_size), 0);
    count1 = atomic_read(&castle_cache_block_victims);
    atomic_sub(count1, &castle_cache_block_victims);
    castle_trace_cache(TRACE_VALUE, TRACE_CACHE_BLOCK_VICTIMS_ID, count1, 0);
    count1 = atomic_read(&castle_cache_softpin_block_victims);
    atomic_sub(count1, &castle_cache_softpin_block_victims);
    castle_trace_cache(TRACE_VALUE, TRACE_CACHE_SOFTPIN_VICTIMS_ID, count1, 0);
    castle_trace_cache(TRACE_VALUE, TRACE_CACHE_READS_ID, reads, 0);
    castle_trace_cache(TRACE_VALUE, TRACE_CACHE_WRITES_ID, writes, 0);

    hits = misses = 0;
    for (i = 0; i < EXT_T_INVALID; i++)
    {
        count1 = atomic_read(&extent_stats[i].ios_cnt);
        atomic_sub(count1, &extent_stats[i].ios_cnt);
        castle_trace_cache(TRACE_VALUE, TRACE_CACHE_META_DATA_IOS_ID + i, count1, 0);

        count1 = atomic_read(&extent_stats[i].hits);
        atomic_sub(count1, &extent_stats[i].hits);
        hits += count1;

        count2 = atomic_read(&extent_stats[i].misses);
        atomic_sub(count2, &extent_stats[i].misses);
        misses += count2;

        if(i == EXT_T_T0_INTERNAL_NODES) {
            castle_trace_cache(TRACE_PERCENTAGE, TRACE_CACHE_BLK_T0_INT_HIT_MISS_ID,
                               count1, count2);
        }
        else if(i == EXT_T_T0_LEAF_NODES) {
            castle_trace_cache(TRACE_PERCENTAGE, TRACE_CACHE_BLK_T0_LEAF_HIT_MISS_ID,
                               count1, count2);
        }
        else if(i == EXT_T_INTERNAL_NODES) {
            castle_trace_cache(TRACE_PERCENTAGE, TRACE_CACHE_BLK_INT_HIT_MISS_ID,
                               count1, count2);
        }
        else if(i == EXT_T_LEAF_NODES) {
            castle_trace_cache(TRACE_PERCENTAGE, TRACE_CACHE_BLK_LEAF_HIT_MISS_ID,
                               count1, count2);
        }
    }
    castle_trace_cache(TRACE_PERCENTAGE, TRACE_CACHE_BLK_GET_HIT_MISS_ID, hits, misses);
    count1 = atomic_read(&merge_hits);
    count2 = atomic_read(&merge_misses);
    atomic_sub(count1, &merge_hits);
    atomic_sub(count2, &merge_misses);
    castle_trace_cache(TRACE_PERCENTAGE, TRACE_CACHE_BLK_MERGE_HIT_MISS_ID, count1,
                       count2);
    count1 = atomic_read(&non_merge_hits);
    count2 = atomic_read(&non_merge_misses);
    atomic_sub(count1, &non_merge_hits);
    atomic_sub(count2, &non_merge_misses);
    castle_trace_cache(TRACE_PERCENTAGE, TRACE_CACHE_BLK_NON_MERGE_HIT_MISS_ID, count1,
                       count2);
}

EXPORT_SYMBOL(castle_cache_stats_print);

/**
 * Get size of castle cache (in pages).
 */
int castle_cache_size_get()
{
    return castle_cache_size;
}

/**
 * Workqueue-queued function which prints cache stats.
 */
static void castle_cache_stats_print_queue(void *unused)
{
    castle_cache_stats_print(0);
}

static DECLARE_WORK(castle_cache_stats_print_work, castle_cache_stats_print_queue, NULL);

/**
 * Tick handler for cache stats.
 *
 * @also castle_cache_stats_print()
 */
static void castle_cache_stats_timer_tick(unsigned long foo)
{
    BUG_ON(castle_cache_stats_timer_interval <= 0);

    schedule_work(&castle_cache_stats_print_work);
    setup_timer(&castle_cache_stats_timer, castle_cache_stats_timer_tick, 0);
    mod_timer(&castle_cache_stats_timer, jiffies + (HZ * castle_cache_stats_timer_interval));
}

static int c2p_write_locked(c2_page_t *c2p)
{
    struct rw_semaphore *sem;
    unsigned long flags;
    int ret;

    sem = &c2p->lock;
    spin_lock_irqsave(&sem->wait_lock, flags);
    ret = (sem->activity < 0);
    spin_unlock_irqrestore(&sem->wait_lock, flags);

    return ret;
}

#ifdef CASTLE_DEBUG
static USED int c2p_read_locked(c2_page_t *c2p)
{
    struct rw_semaphore *sem;
    unsigned long flags;
    int ret;

    sem = &c2p->lock;
    spin_lock_irqsave(&sem->wait_lock, flags);
    ret = (sem->activity > 0);
    spin_unlock_irqrestore(&sem->wait_lock, flags);

    return ret;
}
#endif

static USED int c2p_locked(c2_page_t *c2p)
{
    return rwsem_is_locked(&c2p->lock);
}

/**
 * Downgrade a c2p write-lock to read-lock.
 */
static void downgrade_write_c2p(c2_page_t *c2p)
{
    downgrade_write(&c2p->lock);
}

static void lock_c2p(c2_page_t *c2p, int write)
{
    if(write)
        down_write(&c2p->lock);
    else
        down_read(&c2p->lock);
}

/**
 * Try and lock c2p.
 *
 * @return  1   Success
 * @return  0   Failure
 */
static int trylock_c2p(c2_page_t *c2p, int write)
{
    if (write)
        return down_write_trylock(&c2p->lock);
    else
        return down_read_trylock(&c2p->lock);
}

static void unlock_c2p(c2_page_t *c2p, int write)
{
    if(write)
        up_write(&c2p->lock);
    else
        up_read(&c2p->lock);
}

static void dirty_c2p(c2_page_t *c2p)
{
#ifdef CASTLE_DEBUG
    BUG_ON(!c2p_write_locked(c2p));
#endif
    if(!test_set_c2p_dirty(c2p))
    {
        atomic_sub(PAGES_PER_C2P, &castle_cache_clean_pages);
        atomic_add(PAGES_PER_C2P, &castle_cache_dirty_pages);
    }
}

static void clean_c2p(c2_page_t *c2p)
{
    if(test_clear_c2p_dirty(c2p))
    {
        atomic_sub(PAGES_PER_C2P, &castle_cache_dirty_pages);
        atomic_add(PAGES_PER_C2P, &castle_cache_clean_pages);
    }
}

static inline void lock_c2b_counter(c2_block_t *c2b, int write)
{
    /* Update the lock counter */
    if(write)
    {
#ifdef CASTLE_DEBUG
        /* The counter must be 0, if we succeeded write locking the c2b */
        BUG_ON(atomic_read(&c2b->lock_cnt) != 0);
#endif
        atomic_dec(&c2b->lock_cnt);
    }
    else
    {
#ifdef CASTLE_DEBUG
        /* Counter must be >= 0, if we succeeded read locking the c2b */
        BUG_ON(atomic_read(&c2b->lock_cnt) < 0);
#endif
        atomic_inc(&c2b->lock_cnt);
    }
}

static inline void unlock_c2b_counter(c2_block_t *c2b, int write)
{
    /* Update the lock counter */
    if(write)
    {
#ifdef CASTLE_DEBUG
        /* The counter must be -1. */
        BUG_ON(atomic_read(&c2b->lock_cnt) != -1);
#endif
        atomic_inc(&c2b->lock_cnt);
    }
    else
    {
#ifdef CASTLE_DEBUG
        /* Counter must be > 0. */
        BUG_ON(atomic_read(&c2b->lock_cnt) <= 0);
#endif
        atomic_dec(&c2b->lock_cnt);
    }
}

/**
 * Downgrade a c2b write-lock to read-lock.
 *
 * @param   first   1 => Downgrade first c2p, unlock other c2ps
 *                  0 => Downgrade all c2ps
 *
 * NOTE: This function is expected to be called following performing read I/O on
 *       the c2b.  For this reason the semantic for 'nodes' differs from the
 *       standard read/write lock/unlock functions.
 *       Rather than downgrading just the first c2p to a read lock, we then
 *       proceed to drop all locks on the subsequent c2ps.  This makes sense as
 *       in the case of performing read I/O we still need to write-lock all of
 *       the c2ps and hence we need to downgrade from a write-locked c2b to a
 *       read-locked 'node'.
 */
void __downgrade_write_c2b(c2_block_t *c2b, int first)
{
    c_ext_pos_t cep_unused;
    c2_page_t *c2p;

    unlock_c2b_counter(c2b, 1 /*write*/);
    if (first)
    {
        /* Downgrade the first c2p to a read lock
         * then unlock all of the remaining c2ps. */
        downgrade_write_c2p(c2b->c2ps[0]);
        c2b_for_each_c2p_start(c2p, cep_unused, c2b, 1)
        {
            unlock_c2p(c2p, 1 /*write*/);
        }
        c2b_for_each_c2p_end(c2p, cep_unused, c2b, 1)
    }
    else
    {
        /* Downgrade all of the c2ps to read locks. */
        c2b_for_each_c2p_start(c2p, cep_unused, c2b, 0)
        {
            downgrade_write_c2p(c2p);
        }
        c2b_for_each_c2p_end(c2p, cep_unused, c2b, 0)
    }
    lock_c2b_counter(c2b, 0 /*read*/);
}

/**
 * Lock c2ps associated with c2b.
 *
 * @param   write   1 => Write lock
 *                  0 => Read lock
 * @param   first   1 => Lock only first c2p
 *                  0 => Lock all c2ps
 */
void __lock_c2b(c2_block_t *c2b, int write, int first)
{
    c_ext_pos_t cep_unused;
    c2_page_t *c2p;

    if (first)
        lock_c2p(c2b->c2ps[0], write);
    else
    {
        c2b_for_each_c2p_start(c2p, cep_unused, c2b, 0)
        {
            lock_c2p(c2p, write);
        }
        c2b_for_each_c2p_end(c2p, cep_unused, c2b, 0)
    }
    /* Make sure that c2b counter is updated */
    lock_c2b_counter(c2b, write);
}

/**
 * Try and lock c2ps associated with c2b.
 *
 * @param   write   1 => Try and get write lock
 *                  0 => Try and get read lock
 *
 * @return  1   Success
 * @return  0   Failure
 */
int __trylock_c2b(c2_block_t *c2b, int write)
{
    c_ext_pos_t cep_unused;
    c2_page_t *c2p;
    int success_cnt, ret;

    /* Try and lock all c2ps. */
    success_cnt = 0;
    c2b_for_each_c2p_start(c2p, cep_unused, c2b, 0)
    {
        ret = trylock_c2p(c2p, write);
        if(ret == 0)
            goto fail_out;
        success_cnt++;
    }
    c2b_for_each_c2p_end(c2p, cep_unused, c2b, 0)

    /* Succeeded locking all c2ps. Make sure that c2b counter is updated. */
    lock_c2b_counter(c2b, write);

    return 1;

fail_out:
    c2b_for_each_c2p_start(c2p, cep_unused, c2b, 0)
    {
        if(success_cnt == 0)
            return 0;
        unlock_c2p(c2p, write);
        success_cnt--;
    }
    c2b_for_each_c2p_end(c2p, cep_unused, c2b, 0)

    /* Should never get here */
    BUG();
    return 0;
}

int __trylock_node(c2_block_t *c2b, int write)
{
    return trylock_c2p(c2b->c2ps[0], write);
}

/**
 * Unlock c2ps associated with c2b.
 *
 * @param   write   1 => Release write lock
 *                  0 => Release read lock
 * @param   first   1 => Unlock only first c2p
 *                  0 => Unlock all c2ps
 */
static inline void __unlock_c2b(c2_block_t *c2b, int write, int first)
{
    c_ext_pos_t cep_unused;
    c2_page_t *c2p;

#ifdef CASTLE_DEBUG
    if (write)
    {
        c2b->file = "none";
        c2b->line = 0;
    }
#endif

    unlock_c2b_counter(c2b, write);
    if (first)
        /* Unlock the first c2p only. */
        unlock_c2p(c2b->c2ps[0], write);
    else
    {
        /* Unlock all c2ps. */
        c2b_for_each_c2p_start(c2p, cep_unused, c2b, 0)
        {
            unlock_c2p(c2p, write);
        }
        c2b_for_each_c2p_end(c2p, cep_unused, c2b, 0)
    }
}

void __write_unlock_c2b(c2_block_t *c2b, int first)
{
    BUG_ON(!c2b_write_locked(c2b));
    __unlock_c2b(c2b, 1 /*write*/, first);
}

void __read_unlock_c2b(c2_block_t *c2b, int first)
{
    __unlock_c2b(c2b, 0 /*write*/, first);
}

int c2b_write_locked(c2_block_t *c2b)
{
    return atomic_read(&c2b->lock_cnt) < 0;
}

int c2b_read_locked(c2_block_t *c2b)
{
    return atomic_read(&c2b->lock_cnt) > 0;
}

int c2b_locked(c2_block_t *c2b)
{
    return atomic_read(&c2b->lock_cnt) != 0;
}

/**
 * Increment c2b hardpin count.
 */
void castle_cache_block_hardpin(c2_block_t *c2b)
{
    get_c2b(c2b);
}

/**
 * Decrement c2b hardpin count.
 */
void castle_cache_block_unhardpin(c2_block_t *c2b)
{
    put_c2b(c2b);
}

/**
 * Increment c2b softpin count and do cleanlist accounting.
 *
 * - Atomically increment softpin count
 * - Do softpin cleanlist accounting if necessary
 *
 * @also c2_pref_window_submit() (our primary caller)
 */
void castle_cache_block_softpin(c2_block_t *c2b)
{
    unsigned long old, new;
    struct c2b_state *p_old, *p_new;
    p_old = (struct c2b_state *)&old;
    p_new = (struct c2b_state *)&new;

    do {
        *p_old = *p_new = c2b->state;
        p_new->softpin_cnt++;
    } while (cmpxchg((unsigned long*)&c2b->state, old, new) != old);

    /* Increment softpin cleanlist if it wasn't already softpinnined
     * and if it is a clean block. */
    if ((p_old->softpin_cnt == 0) && !c2b_dirty(c2b))
        atomic_inc(&castle_cache_cleanlist_softpin_size);
}

/**
 * Decrement or clear c2b softpin count and do cleanlist accounting.
 *
 * @param clear Set clears count, otherwise decrements
 *
 * @return  Softpin count following operation
 */
static int _unsoftpin_c2b(c2_block_t *c2b, int clear)
{
    if (c2b->state.softpin_cnt)
    {
        /* The block is currently softpinned but this could change while
         * we're attempting to either clear or decrement the count.  If
         * this happens we must detect it and return immediately, without
         * making any adjustments to the softpin cleanlist. */

        unsigned long old, new;
        struct c2b_state *p_old, *p_new;
        p_old = (struct c2b_state *)&old;
        p_new = (struct c2b_state *)&new;

        do {
            *p_old = *p_new = c2b->state;
            if (p_new->softpin_cnt && clear)    /* clear the count */
                p_new->softpin_cnt = 0;
            else if (p_new->softpin_cnt)        /* decrement count */
                p_new->softpin_cnt--;
            else                                /* zeroed - return */
                return 0;
        } while (cmpxchg((unsigned long*)&c2b->state, old, new) != old);

        /* Decrement softpin cleanlist if we decremented the last
         * softpin hold on a clean block. */
        if ((p_new->softpin_cnt == 0) && !c2b_dirty(c2b))
            BUG_ON(atomic_dec_return(&castle_cache_cleanlist_softpin_size) < 0);
        else
            return p_new->softpin_cnt;
    }

    return 0;
}

/**
 * Decrement c2b softpin count and do cleanlist accounting.
 *
 * - Decrement softpin count
 * - Does cleanlist accounting if necessary
 */
int castle_cache_block_unsoftpin(c2_block_t *c2b)
{
    return _unsoftpin_c2b(c2b, 0);
}

/**
 * Unsoftpin a c2b from the cache and do cleanlist accounting.
 *
 * - Zeroes the c2b softpin count
 * - Does cleanlist accounting (necessary if block is clean)
 */
static void clearsoftpin_c2b(c2_block_t *c2b)
{
    _unsoftpin_c2b(c2b, 1);
}

/**
 * Is c2b softpinned.
 *
 * @return >0   c2b is softpinned
 * @return  0   c2b is not softpinned
 */
static inline int c2b_softpin(c2_block_t *c2b)
{
    return c2b->state.softpin_cnt;
}

/**
 * Remove a c2b from its per-extent dirtytree.
 *
 * c2b holds a reference to the dirtytree.
 *
 * @param c2b   Block to remove
 */
static int c2_dirtytree_remove(c2_block_t *c2b)
{
    c_ext_dirtytree_t *dirtytree;
    unsigned long flags;

    BUG_ON(atomic_read(&c2b->count) == 0);

    /* Get extent dirtytree from c2b. */
    dirtytree = c2b->dirtytree;
    BUG_ON(!dirtytree);
    spin_lock_irqsave(&dirtytree->lock, flags);

    /* Remove c2b from the tree. */
    spin_lock(&castle_cache_block_lru_lock); /* protects clean/dirty union */
    rb_erase(&c2b->rb_dirtytree, &dirtytree->rb_root);
    if (RB_EMPTY_ROOT(&dirtytree->rb_root))
    {
        /* Last dirty c2b for this extent, remove it from the global
         * list of dirty extents. */
        list_del_init(&dirtytree->list);
        BUG_ON(atomic_dec_return(&castle_cache_extent_dirtylist_sizes[dirtytree->flush_prio]) < 0);
    }
    spin_unlock(&castle_cache_block_lru_lock);

    /* Maintain the number of pages in this dirtytree. */
    dirtytree->nr_pages -= c2b->nr_pages;
    BUG_ON(dirtytree->nr_pages < 0);

    /* Release lock and put reference, potentially freeing the dirtytree if
     * the extent has already been freed. */
    c2b->dirtytree = NULL;
    spin_unlock_irqrestore(&dirtytree->lock, flags);
    castle_extent_dirtytree_put(dirtytree);

    return EXIT_SUCCESS;
}

/**
 * Place a c2b onto its per-extent dirtytree.
 *
 * @param c2b   Block to insert
 *
 * In order to dirty a c2b its extent must exist.
 *
 * - Get and hold per-extent dirtytree reference via c2b->cep.ext_id
 * - Lock dirtytree and insert c2b into RB-tree
 * - If RB-tree was previously empty, thread dirtytree onto the global
 *   list of dirty extents (castle_cache_extent_dirtylist)
 * - Don't drop the dirtytree reference (put in c2_dirtytree_remove())
 *
 * @also c2_dirtytree_remove()
 */
static int c2_dirtytree_insert(c2_block_t *c2b)
{
    struct rb_node **p, *parent = NULL;
    c_ext_dirtytree_t *dirtytree;
    c2_block_t *tree_c2b;
    unsigned long flags;
    c_chk_cnt_t start, end;
    int cmp;

    /* Get the current valid extent space. This is not a strict check. Strict check
     * would have to use the mask_id that the client is using. */
    castle_extent_mask_read_all(c2b->cep.ext_id, &start, &end);

    /* End of c2b, shouldn't below current valid extent space. */
    BUG_ON((c2b->cep.offset + (c2b->nr_pages * C_BLK_SIZE)) < (start * C_CHK_SIZE));

    /* Start of c2b, shouldn't be after valid extent space. */
    BUG_ON(c2b->cep.offset >= ((end + 1) * C_CHK_SIZE));

    /* Get dirtytree and hold its lock while we manipulate the tree. */
    dirtytree = castle_extent_dirtytree_by_id_get(c2b->cep.ext_id);
    BUG_ON(!dirtytree);
    spin_lock_irqsave(&dirtytree->lock, flags);

    /* Find position in tree. */
    p = &dirtytree->rb_root.rb_node;
    while (*p)
    {
        parent = *p;
        tree_c2b = rb_entry(parent, c2_block_t, rb_dirtytree);

        cmp = EXT_POS_COMP(c2b->cep, tree_c2b->cep);
        if (cmp < 0)
            p = &(*p)->rb_left;
        else if (cmp > 0)
            p = &(*p)->rb_right;
        else
        {
            /* We found a c2b with the same offset.  Larger to the right. */
            /** @TODO would it make more sense to have C2B_COMP() above that calls
             * EXT_POS_COMP and does below if result == 0? */

            if (c2b->nr_pages < tree_c2b->nr_pages)
                p = &(*p)->rb_left;
            else if (c2b->nr_pages > tree_c2b->nr_pages)
                p = &(*p)->rb_right;
            else
            {
                castle_printk(LOG_ERROR, "c2b with cep "cep_fmt_str_nl" already in tree.\n",
                        cep2str(c2b->cep));
                BUG();
            }
        }
    }

    /* Insert dirty c2b into the tree. */
    spin_lock(&castle_cache_block_lru_lock); /* protects clean/dirty union. */
    if (RB_EMPTY_ROOT(&dirtytree->rb_root))
    {
        /* First dirty c2b for this extent, place it onto the global
         * list of dirty extents. */
        BUG_ON(dirtytree->flush_prio >= NR_EXTENT_FLUSH_PRIOS);
        list_add(&dirtytree->list, &castle_cache_extent_dirtylists[dirtytree->flush_prio]);
        atomic_inc(&castle_cache_extent_dirtylist_sizes[dirtytree->flush_prio]);
    }
    rb_link_node(&c2b->rb_dirtytree, parent, p);
    rb_insert_color(&c2b->rb_dirtytree, &dirtytree->rb_root);
    spin_unlock(&castle_cache_block_lru_lock);

    /* Maintain the number of pages in this dirtytree. */
    dirtytree->nr_pages += c2b->nr_pages;

    /* Keep the reference until the c2b is clean but drop the lock. */
    c2b->dirtytree = dirtytree;
    spin_unlock_irqrestore(&dirtytree->lock, flags);

    return EXIT_SUCCESS;
}

/**
 * Demote tree of dirty blocks (dirtytree) when the extent is being deleted.
 * This prioritises flushing the blocks of this extent out of the cache.
 *
 * @param c2b   Dirtytree to demote.
 *
 * @also c2_dirtytree_remove()
 */
void castle_cache_dirtytree_demote(c_ext_dirtytree_t *dirtytree)
{
    spin_lock_irq(&castle_cache_block_lru_lock);
    if (likely(!RB_EMPTY_ROOT(&dirtytree->rb_root)))
    {
        atomic_dec(&castle_cache_extent_dirtylist_sizes[dirtytree->flush_prio]);
        list_del(&dirtytree->list);
        dirtytree->flush_prio = DEAD_EXT_FLUSH_PRIO;
        list_add(&dirtytree->list, &castle_cache_extent_dirtylists[dirtytree->flush_prio]);
        atomic_inc(&castle_cache_extent_dirtylist_sizes[dirtytree->flush_prio]);
    }
    spin_unlock_irq(&castle_cache_block_lru_lock);
}

/**
 * Mark c2b and associated c2ps dirty and place on dirtytree.
 *
 * @param c2b   c2b to mark as dirty.
 *
 * - Insert c2b into per-extent RB-tree dirtytree
 * - Move c2b from cleanlist to dirtytree
 *   (also occurs when we free blocks in hash_clean())
 * - Update cleanlist accounting.
 *
 * By maintaining a per-extent list of dirty c2bs we can flush dirty data out
 * in a contiguous fashion to reduce disk seeks.
 *
 * @also castle_cache_block_hash_clean()
 */
void dirty_c2b(c2_block_t *c2b)
{
    unsigned long flags;
    int i, nr_c2ps;

    BUG_ON(!c2b_write_locked(c2b));
    /* With overlapping c2bs we cannot rely on this c2b being dirty.
     * We have to dirty all c2ps. */
    nr_c2ps = castle_cache_pages_to_c2ps(c2b->nr_pages);
    for (i = 0; i < nr_c2ps; i++)
        dirty_c2p(c2b->c2ps[i]);

    /* Place c2b on per-extent dirtytree if it is not already dirty. */
    if (!c2b_dirty(c2b))
    {
        spin_lock_irqsave(&castle_cache_block_lru_lock, flags);

        /* Don't continue if we've raced another thread. */
        if (c2b_dirty(c2b))
        {
            spin_unlock_irqrestore(&castle_cache_block_lru_lock, flags);
            return;
        }

        /* Remove from cleanlist and do cachelist accounting. */
        list_del(&c2b->clean);
        BUG_ON(atomic_dec_return(&castle_cache_cleanlist_size) < 0);
        if (c2b_softpin(c2b))
            BUG_ON(atomic_dec_return(&castle_cache_cleanlist_softpin_size) < 0);
        set_c2b_dirty(c2b);
        spin_unlock_irqrestore(&castle_cache_block_lru_lock, flags);

        /* Place dirty c2b onto per-extent dirtytree. */
        c2_dirtytree_insert(c2b);
    }
}

/**
 * Mark c2b and associated c2ps clean and place on cleanlist.
 *
 * @param c2b   c2b to mark as clean.
 *
 * - Remove c2b from per-extent RB-tree dirtytree
 * - Place c2b onto cache cleanlist
 *   (also occurs in hash_insert() for new c2bs)
 * - Update cleanlist accounting.
 * - Handles special case of remap c2bs which can have a clean c2b but dirty c2ps
 *
 * @also castle_cache_block_hash_insert()
 * @also c2_dirtytree_remove()
 * @also I/O callback handlers (callers)
 */
void clean_c2b(c2_block_t *c2b)
{
    unsigned long flags;
    int i, nr_c2ps;

    BUG_ON(!c2b_locked(c2b));
    BUG_ON(!c2b_dirty(c2b) && (!c2b_remap(c2b)));

    /* Clean all c2ps. */
    nr_c2ps = castle_cache_pages_to_c2ps(c2b->nr_pages);
    for (i = 0; i < nr_c2ps; i++)
        clean_c2p(c2b->c2ps[i]);

    if (c2b_remap(c2b) && !c2b_dirty(c2b))
        return;

    /* Remove from per-extent dirtytree. */
    c2_dirtytree_remove(c2b);

    /* Insert onto cleanlist and do cache list accounting. */
    spin_lock_irqsave(&castle_cache_block_lru_lock, flags);
    BUG_ON(atomic_read(&c2b->count) == 0);
    list_add_tail(&c2b->clean, &castle_cache_cleanlist);
    atomic_inc(&castle_cache_cleanlist_size);
    if (c2b_softpin(c2b))
        atomic_inc(&castle_cache_cleanlist_softpin_size);
    clear_c2b_dirty(c2b);
    spin_unlock_irqrestore(&castle_cache_block_lru_lock, flags);
}

void update_c2b(c2_block_t *c2b)
{
    int i, nr_c2ps;

    BUG_ON(!c2b_write_locked(c2b));

    /* Update all c2ps. */
    nr_c2ps = castle_cache_pages_to_c2ps(c2b->nr_pages);
    for(i=0; i<nr_c2ps; i++)
    {
        c2_page_t *c2p = c2b->c2ps[i];

        BUG_ON(!c2p_write_locked(c2p));
        set_c2p_uptodate(c2p);
    }
    /* Finally set the entire c2b uptodate. */
    set_c2b_uptodate(c2b);
}

struct bio_info {
    int                 rw;
    struct bio          *bio;
    c2_block_t          *c2b;
    uint32_t            nr_pages;
    struct block_device *bdev;
    struct completion   completion;
    int                 err;
};

static void c2b_remaining_io_sub(int rw, int nr_pages, c2_block_t *c2b)
{
    BUG_ON(!c2b_in_flight(c2b));
    if(!atomic_sub_and_test(nr_pages, &c2b->remaining))
        return;

    debug("Completed io on c2b"cep_fmt_str_nl, cep2str(c2b->cep));

    /* At least one of the bios for this c2b had an error. Handle that first. */
    if(c2b_bio_error(c2b))
    {
        clear_c2b_bio_error(c2b);
        if (!c2b_no_resubmit(c2b)) /* This c2b can be resubmitted */
            castle_resubmit_c2b(rw, c2b);
        else
        {
            /*
             * Caller has set no_resubmit on c2b and is responsible for checking the c2b for
             * I/O error via !uptodate or dirty flags.
             */
            debug("c2b %p had bio error(s) - returning error\n", c2b);
            clear_c2b_in_flight(c2b);
            c2b->end_io(c2b);
        }
        return;
    }

    /* All bios succeeded for this c2b. On reads, update the c2b, on writes clean it. */
    if(rw == READ)
        update_c2b(c2b);
    else
        clean_c2b(c2b);
    clear_c2b_in_flight(c2b);
    c2b->end_io(c2b);
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
static int c2b_multi_io_end(struct bio *bio, unsigned int completed, int err)
#else
static void c2b_multi_io_end(struct bio *bio, int err)
#endif
{
    struct bio_info     *bio_info = bio->bi_private;
    struct castle_slave *slave, *io_slave;
    c2_block_t          *c2b = bio_info->c2b;
    struct list_head    *lh;
#ifdef CASTLE_DEBUG
    unsigned long flags;

    /* In debugging mode force the end_io to complete in atomic */
    local_irq_save(flags);
#endif
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
    if (bio->bi_size)
    {
#ifdef CASTLE_DEBUG
        local_irq_restore(flags);
#endif
        return 1;
    }

    /* Check if we always complete the entire BIO. Likely yes, since
       the interface in >= 2.6.24 removes the completed variable */
    BUG_ON((!err) && (completed != C_BLK_SIZE * bio_info->nr_pages));
    BUG_ON(err && test_bit(BIO_UPTODATE, &bio->bi_flags));
#endif
    BUG_ON(atomic_read(&c2b->remaining) == 0);

    if (INJECT_ERR(SLAVE_OOS_ERR))
    {
        struct castle_slave *oos_slave = castle_slave_find_by_bdev(bio_info->bdev);
        if (oos_slave->uuid == castle_fault_arg)
        {
            castle_printk(LOG_DEVEL, "Injecting bio error on slave 0x%x\n", oos_slave->uuid);
            castle_fault = castle_fault_arg = 0;
            clear_bit(BIO_UPTODATE, &bio->bi_flags);
        }
    }

    io_slave = castle_slave_find_by_bdev(bio_info->bdev);
    BUG_ON(!io_slave);

    if (!test_bit(BIO_UPTODATE, &bio->bi_flags))
    {
        /* I/O has failed for this bio, or testing has injected fault. */
        if (!test_and_set_bit(CASTLE_SLAVE_OOS_BIT, &io_slave->flags))
        {
            /*
             * This is the first time a bio for this slave has failed. If removing this slave
             * from service would leave us with less than the minimum number of live slaves,
             * then BUG out. Otherwise, mark the slave as out-of-service and trigger a rebuild.
             * Note: We only look at non-SSD slaves here, as SSD slaves can be remapped to
             * non-SSD slaves.
             */
            if (!(io_slave->cs_superblock.pub.flags & CASTLE_SLAVE_SSD))
            {
                int nr_live_slaves=0;

                rcu_read_lock();
                list_for_each_rcu(lh, &castle_slaves.slaves)
                {
                    slave = list_entry(lh, struct castle_slave, list);
                    if (!test_bit(CASTLE_SLAVE_EVACUATE_BIT, &slave->flags) &&
                        !test_bit(CASTLE_SLAVE_OOS_BIT, &slave->flags) &&
                        !(slave->cs_superblock.pub.flags & CASTLE_SLAVE_SSD))
                        nr_live_slaves++;
                }
                rcu_read_unlock();
                BUG_ON(nr_live_slaves < MIN_LIVE_SLAVES);
            }
            castle_printk(LOG_WARN, "Disabling slave 0x%x [%s], due to IO errors.\n",
                    io_slave->uuid, io_slave->bdev_name);
            castle_extents_rebuild_wake();
        }

        /* We may need to re-submit I/O for the c2b. Mark this c2b as 'bio_error' */
        set_c2b_bio_error(((struct bio_info *)bio->bi_private)->c2b);
    }

    /* Record how many pages we've completed, potentially ending the c2b io. */
    c2b_remaining_io_sub(bio_info->rw, bio_info->nr_pages, c2b);
#ifdef CASTLE_DEBUG
    local_irq_restore(flags);
#endif
    castle_free(bio_info);
    bio_put(bio);

    /*
     * io_in_flight logic. The ordering of the dec and read of io_in_flight and the test
     * of CASTLE_SLAVE_OOS_BIT is important.
     * Decrement io_in_flight. If the slave is marked out-of-service, then check if
     * io_in_flight is zero. If it is, then we know that it cannot now be incremented
     * in submit_c2b_io because it is only incremented there if the out-of-service flag
     * is not set. It is therefore safe to queue the device for release.
     */
    atomic_dec(&io_slave->io_in_flight);

    /* If slave is out-of-service, and no I/O is outstanding, then queue up bdev release. */
    if (test_bit(CASTLE_SLAVE_OOS_BIT, &io_slave->flags) &&
        (atomic_read(&io_slave->io_in_flight) == 0))
    {
        CASTLE_INIT_WORK(&io_slave->work, castle_release_oos_slave);
        queue_work(castle_wq, &io_slave->work);
    }

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
    return 0;
#endif
}

#ifdef CASTLE_DEBUG
int chk_valid(c_disk_chk_t chk)
{
    struct castle_slave *cs = castle_slave_find_by_uuid(chk.slave_id);
    c_chk_t size;

    if (!cs)
    {
        castle_printk(LOG_DEBUG, "Couldn't find disk with uuid: %u\n", chk.slave_id);
        return 0;
    }

    BUG_ON(test_bit(CASTLE_SLAVE_GHOST_BIT, &cs->flags));
    castle_freespace_summary_get(cs, NULL, &size);
    if (chk.offset >= size)
    {
        castle_printk(LOG_DEBUG, "Unexpected chunk "disk_chk_fmt", Disk Size: 0x%x\n",
                disk_chk2str(chk), size);
        return 0;
    }

    return 1;
}
#endif

#define MAX_BIO_PAGES        128

/**
 * Handle completion for submit_direct_io bios
 *
 * @return     'err' is returned to submit_bio caller via bio_info.
 */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
static int direct_io_complete(struct bio *bio, unsigned int completed, int err)
#else
static int direct_io_complete(struct bio *bio, int err)
#endif
{
    struct bio_info     *bio_info = bio->bi_private;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
    if (bio->bi_size)
        return 1;

    /* Check if we always complete the entire BIO. Likely yes, since
       the interface in >= 2.6.24 removes the completed variable */
    BUG_ON((!err) && (completed != C_BLK_SIZE * bio_info->nr_pages));
    BUG_ON(err && test_bit(BIO_UPTODATE, &bio->bi_flags));
#endif

    /* Return the error back to caller of submit_bio. */
    bio_info->err = err;

    complete((struct completion *)&bio_info->completion);
    return 0;
}

/**
 * Read directly from disk
 * This function performs I/O using a single submit_bio, and is therefore limited to a maximum
 * of bio_get_nr_vecs(bdev) pages per call (which varies depending on the underlying block driver).
 *
 * @param rw        [in]    READ, WRITE or WRITE_BARRIER.
 * @param bdev      [in]    The block device.
 * @param sector    [in]    The sector to start at.
 * @param iopages   [in]    The pages to read/write into/from.
 * @param size      [in]    The number of pages.
 *
 * @return 0:       On success.
 * @return -EINVAL: If nr_pages > the number of pages submit_bio can handle (in one bio).
 * @return -EPERM:  If a barrier write is attempted on a device which does not support it.
 */
int submit_direct_io(int                    rw,
                     struct block_device    *bdev,
                     sector_t               sector,
                     struct page            **iopages,
                     int                    nr_pages)
{
    struct bio          *bio;
    struct bio_info     *bio_info;
    int                 i, ret;

    if (nr_pages > bio_get_nr_vecs(bdev))
        return -EINVAL;

    /* Allocate BIO and bio_info struct */
    bio = bio_alloc(GFP_KERNEL, 1);
    BUG_ON(!bio);
    bio_info = castle_alloc(sizeof(struct bio_info));
    BUG_ON(!bio_info);

    /* Init BIO and bio_info. */
    bio_info->nr_pages = nr_pages;
    bio_info->bdev     = bdev;
    init_completion(&bio_info->completion);

    for(i=0; i < nr_pages; i++)
    {
        bio->bi_io_vec[i].bv_page   = iopages[i];
        bio->bi_io_vec[i].bv_len    = PAGE_SIZE;
        bio->bi_io_vec[i].bv_offset = 0;
    }

    bio->bi_sector  = sector;
    bio->bi_bdev    = bdev;
    bio->bi_vcnt    = 1;
    bio->bi_idx     = 0;
    bio->bi_size    = nr_pages * PAGE_SIZE;
    bio->bi_end_io  = direct_io_complete;
    bio->bi_private = bio_info;

    bio_get(bio);
    /* Hand off to Linux block layer. */
    submit_bio(rw, bio);
    if(bio_flagged(bio, BIO_EOPNOTSUPP))
    {
        castle_printk(LOG_ERROR, "BIO flagged not supported.\n");
        bio_put(bio);
        castle_free(bio_info);
        return -EOPNOTSUPP;
    }

    bio_put(bio);

    wait_for_completion(&bio_info->completion);
    ret = bio_info->err;

    castle_free(bio_info);

    return ret;
}

/**
 * Allocate bio for pages & hand-off to Linux block layer.
 *
 * @param disk_chk  Chunk to be IOed to
 * @param pages     Array of pages to be used for IO
 * @param nr_pages  Size of @pages array
 *
 * @return          number of pages remaining un-submitted if slave is,
 *                  or becomes, out-of-service. Otherwise EXIT_SUCCESS.
 */
int submit_c2b_io(int           rw,
                  c2_block_t   *c2b,
                  c_ext_pos_t   cep,
                  c_disk_chk_t  disk_chk,
                  struct page **pages,
                  int           nr_pages)
{
    struct castle_slave *cs;
    sector_t sector;
    struct bio *bio;
    struct bio_info *bio_info;
    int i, j, batch;
    c_ext_type_t ext_type;

#ifdef CASTLE_DEBUG
    /* Check that we are submitting IO to the right ceps. */
    c_ext_pos_t dcep = cep;
    c2_page_t *c2p;

    /* This first one could be turned into a valid error. */
    BUG_ON(DISK_CHK_INVAL(disk_chk));
    BUG_ON(!SUPER_EXTENT(cep.ext_id) && !chk_valid(disk_chk));

    /* Only works for 1 page c2ps. */
    BUG_ON(PAGES_PER_C2P != 1);
    for(i=0; i<nr_pages; i++)
    {
        c2p = (c2_page_t *)pages[i]->lru.next;
        if(!EXT_POS_EQUAL(c2p->cep, dcep))
        {
            castle_printk(LOG_DEBUG, "Unmatching ceps "cep_fmt_str", "cep_fmt_str_nl,
                cep2str(c2p->cep), cep2str(dcep));
            BUG();
        }
        dcep.offset += PAGE_SIZE;
    }
#endif

    /* Update extent-type statistics */
    ext_type = castle_extent_type_get(cep.ext_id);
    if (ext_type != EXT_T_INVALID)
        atomic_inc(&extent_stats[ext_type].ios_cnt);

    /* Work out the slave structure. */
    cs = castle_slave_find_by_uuid(disk_chk.slave_id);
    debug("slave_id=%d, cs=%p\n", disk_chk.slave_id, cs);
    BUG_ON(!cs);
    BUG_ON(test_bit(CASTLE_SLAVE_GHOST_BIT, &cs->flags));
    /* Work out the sector on the slave. */
    sector = ((sector_t)disk_chk.offset << (C_CHK_SHIFT - 9)) +
              (BLK_IN_CHK(cep.offset) << (C_BLK_SHIFT - 9));

    BUG_ON(nr_pages > MAX_BIO_PAGES);
    j = 0;
    while (nr_pages > 0)
    {
        /*
         * io_in_flight logic. The ordering of the dec and read of io_in_flight and the test
         * of CASTLE_SLAVE_OOS_BIT is important.
         * Pre-increment io_in_flight, then check if the slave is out-of-service. If it is then
         * decrement it and request device release if required. If it is not out-of-service
         * then it remains incremented. This means that, effectively, io_in_flight is only
         * incremented if the slave is not out-of-service.
         */
        atomic_inc(&cs->io_in_flight);
        if (test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags))
        {
            /* Slave is OOS. Return true and release claimed device if no outstanding I/O. */
            if (atomic_dec_and_test(&cs->io_in_flight) &&
                (test_bit(CASTLE_SLAVE_BDCLAIMED_BIT, &cs->flags)))
                castle_release_device(cs);
            return nr_pages;
        }

        /*
         * We may have more pages than we are allowed to submit in one bio. Each time we submit
         * we re-calculate what we can send, because bio_get_nr_vecs can change dynamically.
         */
        batch = min(nr_pages, bio_get_nr_vecs(cs->bdev));

        /* Allocate BIO and bio_info struct */
        bio = bio_alloc(GFP_KERNEL, batch);
        bio_info = castle_alloc(sizeof(struct bio_info));
        BUG_ON(!bio_info);

        /* Init BIO and bio_info. */
        bio_info->rw       = rw;
        bio_info->bio      = bio;
        bio_info->c2b      = c2b;
        bio_info->nr_pages = batch;
        bio_info->bdev     = cs->bdev;
        for(i=0; i < batch; i++)
        {
            bio->bi_io_vec[i].bv_page   = pages[i + j];
            bio->bi_io_vec[i].bv_len    = PAGE_SIZE;
            bio->bi_io_vec[i].bv_offset = 0;
        }
        bio->bi_sector  = sector + (sector_t)(j * 8);
        bio->bi_bdev    = cs->bdev;
        bio->bi_vcnt    = batch;
        bio->bi_idx     = 0;
        bio->bi_size    = batch * C_BLK_SIZE;
        bio->bi_end_io  = c2b_multi_io_end;
        bio->bi_private = bio_info;

        j += batch;
        nr_pages -= batch;

        bio_get(bio);
        /* Hand off to Linux block layer. Deal with barrier writes correctly. */
        if(unlikely(c2b_barrier(c2b) &&
                    nr_pages <= 0 &&
                    test_bit(CASTLE_SLAVE_ORDERED_SUPP_BIT, &cs->flags)))
        {
            BUG_ON(rw != WRITE);
            /* Set the barrier flag, but only if that the last bio. */
            submit_bio(WRITE_BARRIER, bio);
        }
        else
            submit_bio(rw, bio);
        if(bio_flagged(bio, BIO_EOPNOTSUPP))
        {
            castle_printk(LOG_ERROR, "BIO flagged not supported.\n");
            WARN_ON(1);
        }
        bio_put(bio);
    }
    return EXIT_SUCCESS;
}

typedef struct castle_io_array {
    struct page *io_pages[MAX_BIO_PAGES];
    c_ext_pos_t start_cep;
    c_chk_t chunk;
    int next_idx;
} c_io_array_t;

/**
 * Select the next slave to read from.
 *
 * @param chunks    The chunk for which a slave is to be selected
 * @param k_factor  k_factor for the chunk
 * @param idx       Returns the index in the chunk for the slave to use
 *
 * @return          ENOENT if no slave found, EXIT_SUCCESS if found
 */
static int c_io_next_slave_get(c2_block_t *c2b, c_disk_chk_t *chunks, int k_factor, int *idx)
{
    struct castle_slave *slave;
    int i, do_second, disk_idx, min_outstanding_ios, tmp;

    /*
     * Read scheduler: select the one with minimum in-flight IOs
     *
     * At the moment, when prefetching,
     * 1. Avoid using the first copy, which may be stored on SSDs (don't waste SSD bandwidth).
     * 2. Always go to the same hd-copy in order to exploit sequentiality of prefetches.
     */
    do_second = c2b_prefetch(c2b);
    /* Loop around, searching for disks in service. */
    disk_idx = -1;
    min_outstanding_ios = 0; /* keep the compiler happy */
    for(i=0; i<k_factor; i++)
    {
        slave = castle_slave_find_by_uuid(chunks[i].slave_id);
        BUG_ON(!slave);
        if (!test_bit(CASTLE_SLAVE_OOS_BIT, &slave->flags))
        {
            if(disk_idx == -1)
            {
                disk_idx = i;
                min_outstanding_ios = atomic_read(&slave->io_in_flight);
            }
            else if(do_second && disk_idx != -1) {
                disk_idx = i;
                min_outstanding_ios = 0; /* fix on this second disk */
            }
            else
            {
                tmp = atomic_read(&slave->io_in_flight);
                if(tmp < min_outstanding_ios)
                {
                    disk_idx = i;
                    min_outstanding_ios = tmp;
                }
            }
        }
    }

    if(disk_idx >= 0)
    {
        *idx = disk_idx;
        return EXIT_SUCCESS;
    }
    BUG_ON(disk_idx != -1);
    /* Could not find a slave to read from. */
    return -ENOENT;

}

/**
 * Dispatches k copies of the I/O.
 *
 * @param rw        Reading or writing
 * @param c2b       The c2b we are performing I/O for
 * @param chunks    The disk chunks we are reading/writing from/to
 * @param k_factor  The number of disk chunks we are reading/writing from/to
 * @param io_array  The array of pages that we will actually do I/O on
 * @param ext_id    The extent we are performing I/O for
 *
 * @return          EAGAIN if none of the slaves in the disk chunks were found to be live
 *                  EXIT_SUCCESS if I/O was successfully submitted
 *
 * @see submit_c2b_io()
 */
static int c_io_array_submit(int rw,
                             c2_block_t *c2b,
                             c_disk_chk_t *chunks,
                             int k_factor,
                             c_io_array_t *array,
                             c_ext_id_t ext_id)
{
    int                  i, nr_pages, nr_pages_remaining, read_idx, found;
    struct castle_slave *slave;
    int                  ret = 0;

    nr_pages = array->next_idx;
    debug("%s::Submitting io_array of %d pages, for cep "cep_fmt_str", k_factor=%d, rw=%s\n",
        __FUNCTION__,
        nr_pages,
        cep2str(array->start_cep),
        k_factor,
        (rw == READ) ? "read" : "write");

    BUG_ON((nr_pages <= 0) || (nr_pages > MAX_BIO_PAGES));

    if (rw == READ) /* Read from one slave only */
    {
        /* Accounting */
        atomic_add(nr_pages, &castle_cache_read_stats);

retry:
        /* Call the slave scheduler to find the next slave to read from */
        ret = c_io_next_slave_get(c2b, chunks, k_factor, &read_idx);
        /*
         * If there is a read failure here (no live slaves found) then we return error.
         * Callers must check for read failure. For non-superblock extents this will be fatal.
         * For superblock extents this is non-fatal, but the caller needs to know not to use the
         * returned buffers.
         */
        if (ret)
            return ret;

        slave = castle_slave_find_by_uuid(chunks[read_idx].slave_id);
        BUG_ON(!slave);

        /* Only increment remaining count once we know we'll submit the IO. */
        atomic_add(nr_pages, &c2b->remaining);
        /* Submit the IO. */
        nr_pages_remaining = submit_c2b_io(READ, c2b, array->start_cep, chunks[read_idx],
                            array->io_pages, nr_pages);
        if (nr_pages_remaining)
        {
            /*
             * Failed to read nr_pages_remaining pages from this slave because it has gone
             * out-of-service. Retry to find another slave to read from.
             */
            atomic_sub(nr_pages_remaining, &c2b->remaining);
            goto retry;
        }

        /* Return with success. */
        return EXIT_SUCCESS;
    }

    /* Write to all slaves */
    BUG_ON(rw != WRITE);
    found = 0;
    for(i=0; i<k_factor; i++)
    {
        slave = castle_slave_find_by_uuid(chunks[i].slave_id);
        if(!slave)
            castle_printk(LOG_DEVEL, "%s::writing %d pages for cep "cep_fmt_str
                    ", no slave; chunks[%d].slave_id=%d\n",
                    __FUNCTION__, nr_pages, cep2str(array->start_cep), i, chunks[i].slave_id);
        BUG_ON(!slave);

        if (!test_bit(CASTLE_SLAVE_OOS_BIT, &slave->flags))
        {
            found = 1;
            /* Slave is not out-of-service - submit the IO */
            atomic_add(nr_pages, &castle_cache_write_stats);
            atomic_add(nr_pages, &c2b->remaining);
            nr_pages_remaining = submit_c2b_io(WRITE, c2b, array->start_cep, chunks[i],
                                               array->io_pages, nr_pages);
            if (nr_pages_remaining)
            {
                /*
                 * Failed to write nr_pages_remaining pages to this slave because it has
                 * gone out-of-service. Skip to next slave.
                 */
                atomic_sub(nr_pages_remaining, &castle_cache_write_stats);
                atomic_sub(nr_pages_remaining, &c2b->remaining);
                continue;
            }
        }
    }

    /*
     * If no live slave was found , and the extent is for a superblock then we can treat this
     * as successful because we don't care if writes fail to a to the superblock of a now-dead
     * disk. We won't have incremented c2b->remaining so doing nothing here is safe.
     * For all other extent types, if we find no live slave then return EAGAIN so the caller
     * can retry if it wants.
     */
    if (!found && !SUPER_EXTENT(ext_id))
    {
        set_c2b_eio(c2b);
        debug("Could not submit I/O. Only oos slaves specified in disk chunk\n");
        return -EAGAIN;
    }

    return EXIT_SUCCESS;
}

static inline void c_io_array_init(c_io_array_t *array)
{
    array->start_cep = INVAL_EXT_POS;
    array->chunk = INVAL_CHK;
    array->next_idx = 0;
}

/**
 * Add page to I/O array.
 */
static inline int c_io_array_page_add(c_io_array_t *array,
                                      c_ext_pos_t cep,
                                      c_chk_t logical_chunk,
                                      struct page *page)
{
    c_ext_pos_t cur_cep;

    /* We cannot accept any more pages, if we already have MAX_BIO_PAGES. */
    if(array->next_idx >= MAX_BIO_PAGES)
        return -1;
    /* If it is an established array, reject pages for different chunks, or non-sequential ceps. */
    if(array->next_idx > 0)
    {
        cur_cep = array->start_cep;
        cur_cep.offset += array->next_idx * PAGE_SIZE;
        if(logical_chunk != array->chunk)
            return -2;
        if(!EXT_POS_EQUAL(cur_cep, cep))
            return -3;
    }
    /* If it is a new array, initialise start_cep and chunk. */
    if(array->next_idx == 0)
    {
        array->start_cep = cep;
        array->chunk = logical_chunk;
        cur_cep = cep;
    }
    /* Add the page, increment the index. */
    array->io_pages[array->next_idx] = page;
    array->next_idx++;

    return EXIT_SUCCESS;
}

extern atomic_t wi_in_flight;

/**
 * Callback for synchronous c2b I/O completion.
 *
 * Wakes thread that dispatched the synchronous I/O
 *
 * @param c2b   completed c2b I/O
 */
static void castle_cache_sync_io_end(c2_block_t *c2b)
{
    struct completion *completion = c2b->private;

    complete(completion);
}

extern int rebuild_write_chunks;

/**
 * Generates asynchronous write I/O for disk block(s) associated with a remap c2b.
 * A remap c2b maps just one logical chunk.
 *
 * Iterates over passed c2b's c2ps
 * Populates array of pages from c2ps
 * Dispatches array to all disk chunks if a dirty page was found
 * Dispatches array to remap disk chunks only if a dirty page was not found
 * Continues until whole c2b has been dispatched
 *
 * @param c2b       The c2b to be written
 * @param chunks    The array of disk chunks for this logical chunk
 * @param nr_remaps The number of disk chunks that are for remaps
 *
 * @also c_io_array_init()
 * @also c_io_array_page_add()
 * @also c_io_array_submit()
 * @also submit_c2b()
 */
int submit_c2b_remap_rda(c2_block_t *c2b, c_disk_chk_t *chunks, int nr_remaps)
{
    c2_page_t           *c2p;
    c_io_array_t        *io_array;
    struct page         *page;
    int                 ret = 0;
    c_ext_pos_t         cur_cep;
    c_ext_id_t          ext_id = c2b->cep.ext_id;
    uint32_t            k_factor = castle_extent_kfactor_get(ext_id);
    int                 found_dirty_page = 0;

    /* This can only be called with chunks populated, and nr_remaps > 0 */
    BUG_ON(!chunks || !nr_remaps);

    BUG_ON(!c2b_locked(c2b));

    debug("Submitting remap write c2b "cep_fmt_str", for %s\n", __cep2str(c2b->cep));

    io_array = kmem_cache_alloc(castle_io_array_cache, GFP_KERNEL);
    if (!io_array)
        return -1;

    /* TODO: Add a check to make sure cep is within live extent range. */

    /* c2b->remaining is effectively a reference count. Get one ref before we start. */
    BUG_ON(atomic_read(&c2b->remaining) != 0);
    atomic_inc(&c2b->remaining);
    c_io_array_init(io_array);

    found_dirty_page = 0;
    /* Everything initialised, go through each page in the c2p. */
    c2b_for_each_page_start(page, c2p, cur_cep, c2b)
    {
        /* If any page is found to be dirty, the next c_io_array_submit must write to all slaves */
        if (c2p_dirty(c2p))
            found_dirty_page = 1;

        /* Add the page to the io array. */
        if(c_io_array_page_add(io_array, cur_cep, 0, page) != EXIT_SUCCESS)
        {
            /*
             * Failed to add this page to the array (see return code for reason).
             * Dispatch the current array, initialise a new one and
             * attempt to add the page to the new array.
             */
            debug("%s on c2p->cep="cep_fmt_str_nl,
                    (found_dirty_page ? "Writing to all slaves" : "Writing to remap slaves only"),
                    cep2str(c2p->cep));

            /* Submit the array. */
            ret = c_io_array_submit(WRITE, c2b, chunks, (found_dirty_page ? k_factor : nr_remaps),
                                io_array, ext_id);
            if (ret)
            {
                /*
                 * Could not submit the IO, possibly due to a slave going out-of-service. Drop
                 * our reference and return early.
                 */
                c2b_remaining_io_sub(WRITE, 1, c2b);
                goto out;
            }
            /* Reinit the array, and re-try adding the current page. This should not
               fail any more. */
            c_io_array_init(io_array);
            found_dirty_page = 0;
            BUG_ON(c_io_array_page_add(io_array, cur_cep, 0, page));
        }
    }
    c2b_for_each_page_end(page, c2p, cur_cep, c2b);

    /* IO array may contain leftover pages, submit those too. */
    if(io_array->next_idx > 0)
    {
        ret = c_io_array_submit(WRITE, c2b, chunks, (found_dirty_page ? k_factor : nr_remaps),
                                io_array, ext_id);
        if (ret)
        {
            /*
             * Could not submit the IO, possibly due to a slave going out-of-service. Drop
             * our reference and return early.
             */
            c2b_remaining_io_sub(WRITE, 1, c2b);
            goto out;
        }
    }

    if (c2b_remap(c2b))
        rebuild_write_chunks+=nr_remaps;

    /* Drop the 1 ref. */
    c2b_remaining_io_sub(WRITE, 1, c2b);

out:
    kmem_cache_free(castle_io_array_cache, io_array);
    return ret;
}

/**
 * Generates I/O for disk block(s) associated with the c2b.
 *
 * Iterates over passed c2b's c2ps (ignoring those that are clean/uptodate for WRITEs/READs)
 * Populates array of pages from c2ps
 * Dispatches array once it reaches a chunk boundary
 * Continues until whole c2b has been dispatched
 *
 * @see c_io_array_init()
 * @see c_io_array_page_add()
 * @see c_io_array_submit()
 */
int submit_c2b_rda(int rw, c2_block_t *c2b)
{
    c2_page_t    *c2p;
    c_io_array_t *io_array;
    struct page  *page;
    int           skip_c2p, ret = 0, iochunks = 0;
    c_ext_pos_t   cur_cep;
    c_chk_t       last_chk, cur_chk;
    c_ext_id_t    ext_id = c2b->cep.ext_id;
    uint32_t      k_factor = castle_extent_kfactor_get(ext_id);
    c_disk_chk_t  chunks[k_factor*2]; /* May need to handle I/O to shadow map chunks as well. */
    int           chunk;

    debug("%s::Submitting c2b "cep_fmt_str", for %s\n",
            __FUNCTION__, __cep2str(c2b->cep), (rw == READ) ? "read" : "write");

    /* TODO: Add a check to make sure cep is within live extent range. */

    io_array = kmem_cache_alloc(castle_io_array_cache, GFP_KERNEL);
    if (!io_array)
        return -1;

    /* c2b->remaining is effectively a reference count. Get one ref before we start. */
    BUG_ON(atomic_read(&c2b->remaining) != 0);
    atomic_inc(&c2b->remaining);
    last_chk = INVAL_CHK;
    cur_chk = INVAL_CHK;
    c_io_array_init(io_array);
    /* Everything initialised, go through each page in the c2p. */
    c2b_for_each_page_start(page, c2p, cur_cep, c2b)
    {
        cur_chk = CHUNK(cur_cep.offset);
        debug("Processing a c2b page, last_chk=%d, cur_chk=%d\n", last_chk, cur_chk);

        /* Do not read into uptodate pages, do not write out of clean pages. */
        skip_c2p = ((rw == READ)  && c2p_uptodate(c2p)) ||
                   ((rw == WRITE) && !c2p_dirty(c2p));
        debug("%s %s on c2p->cep="cep_fmt_str_nl,
                    (skip_c2p ? "Skipping" : "Not skipping"),
                    (rw == READ ? "read" : "write"),
                    cep2str(c2p->cep));
        /* Move to the next page, if we are not supposed to do IO on this page. */
        if(skip_c2p)
            goto next_page;

        /* If we are not skipping, add the page to io array. */
        if(c_io_array_page_add(io_array, cur_cep, cur_chk, page) != EXIT_SUCCESS)
        {
            /* Failed to add this page to the array (see return code for reason).
             * Dispatch the current array, initialise a new one and
             * attempt to add the page to the new array.
             *
             * We've got physical chunks for last_chk (logical chunk), this should
               match with the logical chunk stored in io_array. */
            BUG_ON(io_array->chunk != last_chk);
            /* Submit the array. */
            ret = c_io_array_submit(rw, c2b, chunks, iochunks, io_array, ext_id);
            if (ret)
            {
                /*
                 * Could not submit the IO, possibly due to a slave going out-of-service. Drop
                 * our reference and return early.
                 */
                c2b_remaining_io_sub(rw, 1, c2b);
                goto out;
            }
            /* Reinit the array, and re-try adding the current page. This should not
               fail any more. */
            c_io_array_init(io_array);
            BUG_ON(c_io_array_page_add(io_array, cur_cep, cur_chk, page));
        }

        /* Update chunk map when we move to a new chunk. */
        if(cur_chk != last_chk)
        {
            debug("Asking extent manager for "cep_fmt_str_nl,
                    cep2str(cur_cep));
            iochunks = castle_extent_map_get(cur_cep.ext_id,
                                        CHUNK(cur_cep.offset),
                                        chunks,
                                        rw, cur_cep.offset);
            BUG_ON((iochunks != 0) && (iochunks > k_factor*2));
            if (iochunks == 0)
            {
                /* Complete the IO by dropping our reference, return early. */
                c2b_remaining_io_sub(rw, 1, c2b);
                goto out;
            }

            /*
             * Keep track of remap c2b IOs (we're only handling writes).
             * Any chunks for non-oos slaves will (probably) result into a chunk write.
             */
            if (c2b_remap(c2b))
            {
                for (chunk=0; chunk<iochunks; chunk++)
                {
                    if (!test_bit(CASTLE_SLAVE_OOS_BIT, &chunks[chunk].slave_id))
                    rebuild_write_chunks++;
                }
            }

            debug("chunks[0]="disk_chk_fmt_nl, disk_chk2str(chunks[0]));
            last_chk = cur_chk;
        }
    }
next_page:
    c2b_for_each_page_end(page, c2p, cur_cep, c2b);

    /* IO array may contain leftover pages, submit those too. */
    if(io_array->next_idx > 0)
    {
        /* Chunks array is always initialised for last_chk. */
        BUG_ON(io_array->chunk != last_chk);
        ret = c_io_array_submit(rw, c2b, chunks, iochunks, io_array, ext_id);
        if (ret)
        {
            /*
             * Could not submit the IO, possibly due to a slave going out-of-service. Drop
             * our reference and return early.
             */
            c2b_remaining_io_sub(rw, 1, c2b);
            goto out;
        }
    }
    /* Drop the 1 ref. */
    c2b_remaining_io_sub(rw, 1, c2b);

out:
    kmem_cache_free(castle_io_array_cache, io_array);
    return ret;
}

/**
 * Submit asynchronous c2b I/O.
 *
 * Updates statistics before passing I/O to submit_c2b_rda().
 *
 * NOTE: IOs can also be submitted via submit_c2b_remap_rda().
 *
 * @also submit_c2b_rda()
 * @also submit_c2b_remap_rda()
 */
int submit_c2b(int rw, c2_block_t *c2b)
{
    BUG_ON(!c2b->end_io);
    BUG_ON(EXT_POS_INVAL(c2b->cep));
    BUG_ON(atomic_read(&c2b->remaining));
    /* If we are reading into the c2b block, we need to hold the write lock */
    BUG_ON((rw == READ) && !c2b_write_locked(c2b));
    /* If we writing out of the block, we need to hold the lock in either mode */
    BUG_ON((rw == WRITE) && !c2b_locked(c2b));
    if (unlikely(BLOCK_OFFSET(c2b->cep.offset)))
    {
        castle_printk(LOG_ERROR, "RDA %s: nr_pages - %u cep: "cep_fmt_str_nl,
                (rw == READ)?"Read":"Write", c2b->nr_pages, __cep2str(c2b->cep));
        BUG();
    }

    /* Set in-flight bit on the block. */
    set_c2b_in_flight(c2b);

    return submit_c2b_rda(rw, c2b);
}

/**
 * Unplug queues on all live slaves.
 *
 * Useful if you know that a sequence of submit_c2b()s has been completed.
 *
 * @TODO we should be more intelligent about this and unplug just those slaves
 * that need to be.
 */
static void castle_slaves_unplug(void)
{
    struct list_head *lh;

    rcu_read_lock();
    list_for_each_rcu(lh, &castle_slaves.slaves)
    {
        struct castle_slave *cs = list_entry(lh, struct castle_slave, list);
        if (!test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags))
            generic_unplug_device(bdev_get_queue(cs->bdev));
    }
    rcu_read_unlock();
}

/**
 * Submit synchronous c2b I/O.
 *
 * Dispatches cache block-I/O then blocks for completion.
 *
 * @see submit_c2b()
 */
int submit_c2b_sync(int rw, c2_block_t *c2b)
{
    struct completion completion;
    int ret;

    BUG_ON((rw == READ)  &&  c2b_uptodate(c2b));
    BUG_ON((rw == WRITE) && !c2b_dirty(c2b));
    c2b->end_io = castle_cache_sync_io_end;
    c2b->private = &completion;
    init_completion(&completion);
    if((ret = submit_c2b(rw, c2b)) != EXIT_SUCCESS)
        return ret;
    wait_for_completion(&completion);

    /* Success (ret=0) if c2b is uptodate now for READ, or dirty now for WRITE */
    if (rw == READ)
        return !c2b_uptodate(c2b);
    else
        return c2b_dirty(c2b);
}

/**
 * Submit synchronous c2b write, which is also a barrier write
 * (as per: Documentation/block/barrier.txt).
 *
 * @see submit_c2b_sync()
 */
int submit_c2b_sync_barrier(int rw, c2_block_t *c2b)
{
    int ret;

    /* Only makes sense for writes. */
    BUG_ON(rw != WRITE);

    /* Mark the c2b as a barrier c2b. */
    set_c2b_barrier(c2b);

    /* Submit the c2b as per usual. */
    ret = submit_c2b_sync(rw, c2b);

    /* Clear the bit, since c2b is write locked, no-one else will see it. */
    clear_c2b_barrier(c2b);

    return ret;
}

static inline unsigned long castle_cache_hash_idx(c_ext_pos_t cep, int nr_buckets)
{
    unsigned long hash_idx = (cep.ext_id ^ cep.offset);

    hash_idx = hash_long(hash_idx, 32);
    return (hash_idx % nr_buckets);
}

static inline void castle_cache_page_hash_idx(c_ext_pos_t cep, int *hash_idx_p, int *lock_idx_p)
{
    int hash_idx;

    hash_idx = castle_cache_hash_idx(cep, castle_cache_page_hash_buckets);

    if(hash_idx_p)
        *hash_idx_p = hash_idx;
    if(lock_idx_p)
        *lock_idx_p = hash_idx / PAGE_HASH_LOCK_PERIOD;
}

/* Must be called with the page_hash lock held */
static inline void __castle_cache_c2p_get(c2_page_t *c2p)
{
#ifdef CASTLE_DEBUG
    int lock_idx;

    castle_cache_page_hash_idx(c2p->cep, NULL, &lock_idx);
    BUG_ON(!spin_is_locked(&castle_cache_page_hash_locks[lock_idx]));
#endif
    c2p->count++;
}

static c2_page_t* castle_cache_page_hash_find(c_ext_pos_t cep)
{
    struct hlist_node *lh;
    c2_page_t *c2p;
    int idx;

    castle_cache_page_hash_idx(cep, &idx, NULL);
    debug("Idx = %d\n", idx);
    hlist_for_each_entry(c2p, lh, &castle_cache_page_hash[idx], hlist)
    {
        if(EXT_POS_EQUAL(c2p->cep, cep))
            return c2p;
    }

    return NULL;
}

static c2_page_t* castle_cache_page_hash_insert_get(c2_page_t *c2p)
{
    c2_page_t *existing_c2p;
    spinlock_t *lock;
    int idx, lock_idx;

    /* Work out the index, and the lock. */
    castle_cache_page_hash_idx(c2p->cep, &idx, &lock_idx);
    lock = castle_cache_page_hash_locks + lock_idx;

    /* Check if already in the hash */
    spin_lock_irq(lock);
    existing_c2p = castle_cache_page_hash_find(c2p->cep);
    if(existing_c2p)
    {
        __castle_cache_c2p_get(existing_c2p);
        spin_unlock_irq(lock);
        return existing_c2p;
    }
    else
    {
        __castle_cache_c2p_get(c2p);
        hlist_add_head(&c2p->hlist, &castle_cache_page_hash[idx]);
        spin_unlock_irq(lock);
        return c2p;
    }
}

#define MIN(_a, _b)     ((_a) < (_b) ? (_a) : (_b))
static inline void castle_cache_c2p_put(c2_page_t *c2p, struct list_head *accumulator)
{
    spinlock_t *lock;
    int idx, lock_idx;

    castle_cache_page_hash_idx(c2p->cep, &idx, &lock_idx);
    lock = castle_cache_page_hash_locks + lock_idx;
    spin_lock_irq(lock);

    c2p->count--;
    /* If the count reached zero, delete from the hash, add to the accumulator list,
       so that they get freed later on. */
    if(c2p->count == 0)
    {
#ifdef CASTLE_DEBUG
        char *buf, *poison="dead-page";
        int i, j, str_len;

        str_len = strlen(poison);
        for(i=0; i<PAGES_PER_C2P; i++)
        {
            buf = pfn_to_kaddr(page_to_pfn(c2p->pages[i]));
            for(j=0; j<PAGE_SIZE; j+=str_len)
                memcpy(buf+j, poison, MIN(PAGE_SIZE-j, str_len));
        }
#endif
        if (LOGICAL_EXTENT(c2p->cep.ext_id))
            atomic_sub(PAGES_PER_C2P, &castle_cache_logical_ext_pages);
        debug("Freeing c2p for cep="cep_fmt_str_nl, cep2str(c2p->cep));
        BUG_ON(c2p_dirty(c2p));
        atomic_sub(PAGES_PER_C2P, &castle_cache_clean_pages);
        hlist_del(&c2p->hlist);
        list_add(&c2p->list, accumulator);
    }
    spin_unlock_irq(lock);
}

static inline int castle_cache_block_hash_idx(c_ext_pos_t cep)
{
    return castle_cache_hash_idx(cep, castle_cache_block_hash_buckets);
}

static c2_block_t* castle_cache_block_hash_find(c_ext_pos_t cep, uint32_t nr_pages)
{
    struct hlist_node *lh;
    c2_block_t *c2b;
    int idx;

    idx = castle_cache_block_hash_idx(cep);
    debug("Idx = %d\n", idx);
    hlist_for_each_entry(c2b, lh, &castle_cache_block_hash[idx], hlist)
    {
        if(EXT_POS_EQUAL(c2b->cep, cep) && (c2b->nr_pages == nr_pages))
            return c2b;
    }

    return NULL;
}

/**
 * Give a hint that a block can be reclaimed soon
 * Caller must hold a reference to the block
 * The reference is released as part of the call
 * Caller must not be in interrupt context
 *
 */
void put_c2b_and_demote(c2_block_t *c2b)
{
    spin_lock_irq(&castle_cache_block_lru_lock);
    if(!c2b_dirty(c2b)) {
        list_move(&c2b->clean, &castle_cache_cleanlist);
    }
    spin_unlock_irq(&castle_cache_block_lru_lock);
    put_c2b(c2b);
}


/**
 * Gets c2b matching (cep, nr_pages) and adjusts its dirty/freelist position.
 *
 * @arg cep         Specifies the c2b offset and extent
 * @arg nr_pages    Specifies size of block
 * @arg promote     If set: advises LRU mechanism we will use this block
 *                  If unset: advises LRU mechanism we will free this block
 *
 * @return Matching c2b with an additional reference
 * @return NULL if no matches were found
 */
static inline c2_block_t* _castle_cache_block_hash_get(c_ext_pos_t cep,
                                                       uint32_t nr_pages,
                                                       int promote)
{
    c2_block_t *c2b = NULL;

    /* Hold the hash lock. */
    read_lock(&castle_cache_block_hash_lock);

    /* Try and get the matching block from the hash. */
    c2b = castle_cache_block_hash_find(cep, nr_pages);
    if (c2b)
    {
        /* We found a matching block. */
        get_c2b(c2b);
        /* we have a reference so drop the lock on the hash */
        read_unlock(&castle_cache_block_hash_lock);
        if(promote)
        {
            /* We are obtaining this block to be used.  We should push it to
             * the end of the LRU list indicating that it is recently used
             * and should not be freed any time soon.
             *
             * We're going to return this block to the caller so hold a
             * reference for them so it doesn't get removed. */
            spin_lock_irq(&castle_cache_block_lru_lock);
            if (!c2b_dirty(c2b))
                list_move_tail(&c2b->clean, &castle_cache_cleanlist);
            spin_unlock_irq(&castle_cache_block_lru_lock);
        }
        else
        {
            spin_lock_irq(&castle_cache_block_lru_lock);
            if (atomic_read(&c2b->count) == 0)
            {
                /* No references on this block means it's not in use.
                 * If clean: demote so it gets reused next
                 * If dirty: don't touch it - let LRU mechanism handle it */
                if (!c2b_dirty(c2b))
                    list_move(&c2b->clean, &castle_cache_cleanlist);
            }
            spin_unlock_irq(&castle_cache_block_lru_lock);
            /* demote callers do not need a reference to the block */
            put_c2b(c2b);
        }
    } /* if(c2b) */
    else
    {
        read_unlock(&castle_cache_block_hash_lock);
    }
    return c2b;
}

/**
 * Get c2b matching (cep, nr_pages).
 *
 * @arg cep     Specifies the c2b offset and extent
 * @arg nr_pages    Specifies size of block
 *
 * @return Matching c2b with an additional reference
 * @return NULL if no matches were found
 */
static inline c2_block_t* castle_cache_block_hash_get(c_ext_pos_t cep,
                               uint32_t nr_pages)
{
    return _castle_cache_block_hash_get(cep, nr_pages, 1);
}

/**
 * Find block matching (cep, nr_pages) and demote it in the clean/dirtytree.
 *
 * NOTE: does not obtain an addition reference on any block returned.  The
 * caller is responsible for obtaining this if required.
 *
 * @arg cep         Specifies the c2b offset and extent
 * @arg nr_pages    Specifies size of block
 *
 * @return 1 c2b found
 * @return 0 c2b not found
 */
static inline int castle_cache_block_hash_demote(c_ext_pos_t cep,
                                                         uint32_t nr_pages)
{
    return _castle_cache_block_hash_get(cep, nr_pages, 0) ? 1 : 0;
}

/**
 * Insert a clean block into the hash.
 *
 * - Insert the block into the hash
 * - Cleanlist accounting
 *
 * @warning The block must not be dirty.
 *
 * @return >0   on success
 * @return  0   on failure
 */
static int castle_cache_block_hash_insert(c2_block_t *c2b, int transient)
{
    int idx, success;

    write_lock(&castle_cache_block_hash_lock);

    /* Check if already in the hash */
    success = 0;
    if(castle_cache_block_hash_find(c2b->cep, c2b->nr_pages))
    {
        write_unlock(&castle_cache_block_hash_lock);
        goto out;
    }

    /* Insert */
    success = 1;
    idx = castle_cache_block_hash_idx(c2b->cep);
    hlist_add_head(&c2b->hlist, &castle_cache_block_hash[idx]);
    /* in the hash and hold a reference so drop lock */
    BUG_ON(atomic_read(&c2b->count) == 0);
    BUG_ON(c2b_dirty(c2b));
    BUG_ON(c2b_softpin(c2b));
    spin_lock_irq(&castle_cache_block_lru_lock);
    write_unlock(&castle_cache_block_hash_lock);
    if (transient)
        list_add(&c2b->clean, &castle_cache_cleanlist);
    else
        list_add_tail(&c2b->clean, &castle_cache_cleanlist);
    /* Cleanlist accounting. */
    atomic_inc(&castle_cache_cleanlist_size);
    spin_unlock_irq(&castle_cache_block_lru_lock);

out:
    return success;
}

/**
 * Add c2p to freelist or reservelist and do list accounting.
 *
 * c2p goes to the reservelist if reservelist_size is below quota.
 */
static inline void __castle_cache_page_freelist_add(c2_page_t *c2p)
{
    int size, on_reservelist = 0;

    BUG_ON(c2p->count != 0);

    size = atomic_read(&castle_cache_page_reservelist_size);

    if (unlikely(size < CASTLE_CACHE_RESERVELIST_QUOTA))
    {
        /* c2p reservelist is below quota.  Grab the lock and retest.  If it is
         * still below quota, place this c2p on reservelist. */
        spin_lock(&castle_cache_reservelist_lock);
        size = atomic_read(&castle_cache_page_reservelist_size);
        if (likely(size < CASTLE_CACHE_RESERVELIST_QUOTA))
        {
            list_add_tail(&c2p->list, &castle_cache_page_reservelist);
            atomic_inc(&castle_cache_page_reservelist_size);
            on_reservelist = 1;
        }
        spin_unlock(&castle_cache_reservelist_lock);
    }

    if (likely(!on_reservelist))
    {
        /* c2p reservelist is at its quota.  Place this c2p on freelist. */
        list_add_tail(&c2p->list, &castle_cache_page_freelist);
        castle_cache_page_freelist_size++;
    }
}

/**
 * Add block to freelist or reservelist and do list accounting.
 *
 * c2b goes to the reservelist if reservelist_size is below quota.
 */
static inline void __castle_cache_block_freelist_add(c2_block_t *c2b)
{
    int size, on_reservelist = 0;

    size = atomic_read(&castle_cache_block_reservelist_size);

    if (unlikely(size < CASTLE_CACHE_RESERVELIST_QUOTA))
    {
        /* c2b reservelist is below quota.  Grab the lock and retest.  If it is
         * still below quota, places this c2b on reservelist. */
        spin_lock(&castle_cache_reservelist_lock);
        size = atomic_read(&castle_cache_block_reservelist_size);
        if (likely(size < CASTLE_CACHE_RESERVELIST_QUOTA))
        {
            list_add_tail(&c2b->reserve, &castle_cache_block_reservelist);
            atomic_inc(&castle_cache_block_reservelist_size);
            on_reservelist = 1;
        }
        spin_unlock(&castle_cache_reservelist_lock);
    }

    if (likely(!on_reservelist))
    {
        /* c2b reservelist is at its quota.  Places this c2b on freelist. */
        list_add_tail(&c2b->free, &castle_cache_block_freelist);
        castle_cache_block_freelist_size++;
    }
}

/**
 * Get nr_pages of c2ps from the freelist.
 *
 * @also castle_cache_page_reservelist_get()
 */
static c2_page_t** castle_cache_page_freelist_get(int nr_pages)
{
    struct list_head *lh, *lt;
    c2_page_t **c2ps;
    int i, nr_c2ps;

    debug("%s::Asked for %d pages from the freelist.\n", __FUNCTION__, nr_pages);
    nr_c2ps = castle_cache_pages_to_c2ps(nr_pages);
    c2ps = castle_zalloc(nr_c2ps * sizeof(c2_page_t *));
    BUG_ON(!c2ps);
    spin_lock(&castle_cache_freelist_lock);
    /* Will only be able to satisfy the request if we have nr_pages on the list */
    if (castle_cache_page_freelist_size * PAGES_PER_C2P < nr_pages)
    {
        spin_unlock(&castle_cache_freelist_lock);
        castle_free(c2ps);
        debug("Freelist too small to allocate %d pages.\n", nr_pages);
        return NULL;
    }

    i = 0;
    list_for_each_safe(lh, lt, &castle_cache_page_freelist)
    {
        if (nr_pages <= 0)
            break;
        list_del(lh);
        castle_cache_page_freelist_size--;
        BUG_ON(i >= nr_c2ps);
        c2ps[i++] = list_entry(lh, c2_page_t, list);
        nr_pages -= PAGES_PER_C2P;
    }
    spin_unlock(&castle_cache_freelist_lock);
#ifdef CASTLE_DEBUG
    for (i--; i>=0; i--)
    {
        debug("Got c2p id=%d from freelist.\n", c2ps[i]->id);
    }
#endif
    /* Check that we _did_ succeed at allocating required number of c2ps */
    BUG_ON(nr_pages > 0);

    return c2ps;
}

/**
 * Get nr_pages of c2ps from the reservelist.
 *
 * @also castle_cache_page_freelist_get()
 */
static c2_page_t** castle_cache_page_reservelist_get(int nr_pages)
{
    struct list_head *lh, *lt;
    c2_page_t **c2ps;
    int i, nr_c2ps;

    nr_c2ps = castle_cache_pages_to_c2ps(nr_pages);
    c2ps = castle_zalloc(nr_c2ps * sizeof(c2_page_t *));
    BUG_ON(!c2ps);

    spin_lock(&castle_cache_reservelist_lock);
    if (atomic_read(&castle_cache_page_reservelist_size) * PAGES_PER_C2P < nr_pages)
    {
        spin_unlock(&castle_cache_reservelist_lock);
        castle_free(c2ps);
        debug("Reservelist too small to allocate %d pages.\n", nr_pages);
        return NULL;
    }

    i = 0;
    list_for_each_safe(lh, lt, &castle_cache_page_reservelist)
    {
        if (nr_pages <= 0)
            break;
        list_del(lh);
        atomic_dec(&castle_cache_page_reservelist_size);
        BUG_ON(i >= nr_c2ps);
        c2ps[i++] = list_entry(lh, c2_page_t, list);
        nr_pages -= PAGES_PER_C2P;
    }
    spin_unlock(&castle_cache_reservelist_lock);
#ifdef CASTLE_DEBUG
    for (i--; i >= 0; i--)
    {
        debug("Got c2p id=%d from reservelist.\n", c2ps[i]->id);
    }
#endif
    BUG_ON(nr_pages > 0); /* verify we got nr_pages of c2ps */

    castle_trace_cache(TRACE_VALUE,
                       TRACE_CACHE_RESERVE_PGS_USED_ID,
                       CASTLE_CACHE_RESERVELIST_QUOTA
                            - atomic_read(&castle_cache_page_reservelist_size), 0);

    return c2ps;
}

/**
 * Get a c2b from the freelist.
 *
 * @return c2b from freelist.
 * @return NULL if the freelist is empty.
 */
static c2_block_t* castle_cache_block_freelist_get(void)
{
    struct list_head *lh;
    c2_block_t *c2b = NULL;

    spin_lock(&castle_cache_freelist_lock);
    BUG_ON(castle_cache_block_freelist_size < 0);
    if(castle_cache_block_freelist_size > 0)
    {
        lh = castle_cache_block_freelist.next;
        list_del(lh);
        c2b = list_entry(lh, c2_block_t, free);
        castle_cache_block_freelist_size--;
    }
    spin_unlock(&castle_cache_freelist_lock);

    return c2b;
}

/**
 * Return a c2b from the reservelist if one exists.
 *
 * @return      c2b from the reservelist
 * @return NULL reservelist is empty
 */
static c2_block_t *castle_cache_block_reservelist_get(void)
{
    struct list_head *lh;
    c2_block_t *c2b = NULL;

    BUG_ON(current != castle_cache_flush_thread);

    spin_lock(&castle_cache_reservelist_lock);
    if (atomic_read(&castle_cache_block_reservelist_size) > 0)
    {
        lh = castle_cache_block_reservelist.next;
        list_del(lh);
        c2b = list_entry(lh, c2_block_t, reserve);
        atomic_dec(&castle_cache_block_reservelist_size);
    }
    spin_unlock(&castle_cache_reservelist_lock);

    castle_trace_cache(TRACE_VALUE,
                       TRACE_CACHE_RESERVE_BLKS_USED_ID,
                       CASTLE_CACHE_RESERVELIST_QUOTA
                           - atomic_read(&castle_cache_block_reservelist_size), 0);

    return c2b;
}

static void castle_cache_page_init(c_ext_pos_t cep,
                                   c2_page_t *c2p)
{
    BUG_ON(c2p->count != 0);
    c2p->cep   = cep;
    c2p->state = INIT_C2P_BITS;
}

static int castle_cache_pages_get(c_ext_pos_t cep,
                                  c2_page_t **c2ps,
                                  int nr_c2ps)
{
    struct list_head *lh, *lt;
    LIST_HEAD(freed_c2ps);
    c2_page_t *c2p;
    int i, freed_c2ps_cnt, all_uptodate;

    BUG_ON(nr_c2ps <= 0);

    all_uptodate = 1;
    freed_c2ps_cnt = 0;
    for(i=0; i<nr_c2ps; i++)
    {
        castle_cache_page_init(cep, c2ps[i]);
        debug("c2p for cep="cep_fmt_str_nl, cep2str(c2ps[i]->cep));
        c2p = castle_cache_page_hash_insert_get(c2ps[i]);
        if(c2p != c2ps[i])
        {
            debug("Found c2p in the hash\n");
            list_add(&c2ps[i]->list, &freed_c2ps);
            freed_c2ps_cnt++;
            c2ps[i] = c2p;
            BUG_ON(c2p == NULL);
        }
        else
        {
            atomic_add(PAGES_PER_C2P, &castle_cache_clean_pages);
            if (LOGICAL_EXTENT(cep.ext_id))
                atomic_add(PAGES_PER_C2P, &castle_cache_logical_ext_pages);
        }
        /* Check if this page is clean. */
        if(!c2p_uptodate(c2ps[i]))
            all_uptodate = 0;
        cep.offset += PAGES_PER_C2P * PAGE_SIZE;
    }

    /* Return all the freed_c2ps back onto the freelist */
    BUG_ON(!list_empty(&freed_c2ps) && (freed_c2ps_cnt == 0));
    BUG_ON( list_empty(&freed_c2ps) && (freed_c2ps_cnt != 0));
    /* Return early if we have nothing to free (this avoids locking). */
    if(freed_c2ps_cnt == 0)
        return all_uptodate;
    spin_lock(&castle_cache_freelist_lock);
    list_for_each_safe(lh, lt, &freed_c2ps)
    {
        list_del(lh);
        c2p = list_entry(lh, c2_page_t, list);
        __castle_cache_page_freelist_add(c2p);
    }
    spin_unlock(&castle_cache_freelist_lock);

    return all_uptodate;
}

/**
 * Initialises a c2b to meet cep, nr_pages.
 *
 * NOTE: c2b passed in could have come from the freelist so it is necessary
 * to fully initialise all fields.
 */
static void castle_cache_block_init(c2_block_t *c2b,
                                    c_ext_pos_t cep,
                                    c2_page_t **c2ps,
                                    int nr_pages)
{
    struct page *page;
    c_ext_pos_t dcep;
    c2_page_t *c2p;
    int i, uptodate;
    struct mutex *vmap_per_cpu_mutex_ptr;
    struct page ** vmap_per_cpu_pgs_ptr;

    debug("Initing c2b for cep="cep_fmt_str", nr_pages=%d\n",
            cep2str(cep), nr_pages);
    /* c2b should only be initialised if it's not used */
    BUG_ON(nr_pages > CASTLE_CACHE_VMAP_PGS);
#ifdef CASTLE_DEBUG
    /* On debug builds, unpoison the fields. */
    atomic_set(&c2b->count, 0);
    atomic_set(&c2b->lock_cnt, 0);
    c2b->state.softpin_cnt = 0;
#else
    /* On non-debug builds, those fields should all be zero. */
    BUG_ON(c2b->c2ps != NULL);
    BUG_ON(atomic_read(&c2b->count) != 0);
    BUG_ON(atomic_read(&c2b->lock_cnt) != 0);
    BUG_ON(c2b->state.softpin_cnt != 0);
#endif
    /* Init the page array (note: this may substitute some c2ps,
       if they already exist in the hash. */
    uptodate = castle_cache_pages_get(cep, c2ps, castle_cache_pages_to_c2ps(nr_pages));
    /* Initialise c2b. */
    atomic_set(&c2b->remaining, 0);
    c2b->cep = cep;
    c2b->state.bits = INIT_C2B_BITS | (uptodate ? (1 << C2B_uptodate) : 0);
    c2b->nr_pages = nr_pages;
    c2b->c2ps = c2ps;

    i = 0;
    debug("c2b->nr_pages=%d\n", nr_pages);
    vmap_per_cpu_mutex_ptr = &get_cpu_var(castle_cache_vmap_lock);
    vmap_per_cpu_pgs_ptr = (struct page **)&get_cpu_var(castle_cache_vmap_pgs);
    put_cpu_var(castle_cache_vmap_pgs);
    put_cpu_var(castle_cache_vmap_lock);
    /* we can now sleep or switch cpus even though we hold a reference
     * to a per-cpu variable
     */
    mutex_lock(vmap_per_cpu_mutex_ptr);
    c2b_for_each_page_start(page, c2p, dcep, c2b)
    {
#ifdef CASTLE_DEBUG
        debug("Adding c2p id=%d, to cep "cep_fmt_str_nl,
                c2p->id, cep2str(dcep));
#endif
        vmap_per_cpu_pgs_ptr[i++] = page;
    }
    c2b_for_each_page_end(page, c2p, dcep, c2b)
    debug("Added %d pages.\n", i);
    BUG_ON(i != nr_pages);

    if (nr_pages == 1)
        c2b->buffer = pfn_to_kaddr(page_to_pfn(vmap_per_cpu_pgs_ptr[0]));
    else if (nr_pages <= CASTLE_VMAP_PGS)
        c2b->buffer = castle_vmap_fast_map(vmap_per_cpu_pgs_ptr, i);
    else
        c2b->buffer = vmap(vmap_per_cpu_pgs_ptr, i, VM_READ|VM_WRITE, PAGE_KERNEL);

    mutex_unlock(vmap_per_cpu_mutex_ptr);
    BUG_ON(!c2b->buffer);
}

/**
 * Return clean c2b to the freelist.
 *
 * @param c2b   c2b to go to the freelist
 *
 * - Unmap buffer (linear mapping of pages)
 * - Destroy any associated prefetch window
 * - Drop reference on each c2p
 * - Place on the freelist
 *
 * NOTE: Cleanlist and softpin accounting must have already been done prior to
 * calling this function.  It is therefore safe to free the c2b with a non-zero
 * softpin_cnt.
 */
static void castle_cache_block_free(c2_block_t *c2b)
{
    struct list_head *lh, *lt;
    LIST_HEAD(freed_c2ps);
    c2_page_t *c2p, **c2ps;
    int i, nr_c2ps;

#ifdef CASTLE_DEBUG
    if(c2b_locked(c2b))
        castle_printk(LOG_DEVEL, "%s::c2b for "cep_fmt_str" locked from: %s:%d\n",
                __FUNCTION__, cep2str(c2b->cep), c2b->file, c2b->line);
    if(atomic_read(&c2b->count) != 0)
        castle_printk(LOG_DEVEL, "%s::c2b for "cep_fmt_str" refcount = %d, locked from: %s:%d\n",
                __FUNCTION__, cep2str(c2b->cep), atomic_read(&c2b->count), c2b->file, c2b->line);
#endif
    BUG_ON(c2b_locked(c2b));
    BUG_ON(atomic_read(&c2b->count) != 0);

    nr_c2ps = castle_cache_pages_to_c2ps(c2b->nr_pages);
    if (c2b->nr_pages > 1)
    {
        if (c2b->nr_pages <= CASTLE_VMAP_PGS)
            castle_vmap_fast_unmap(c2b->buffer, c2b->nr_pages);
        else
            vunmap(c2b->buffer);
    }
#ifdef CASTLE_DEBUG
    {
        c2_page_t *c2p;
        c_ext_pos_t cep_unused;

        c2b_for_each_c2p_start(c2p, cep_unused, c2b, 0)
            debug("Freeing c2p id=%d, from c2b=%p\n", c2p->id, c2b);
        c2b_for_each_c2p_end(c2p, cep_unused, c2b, 0)
    }
#endif

    /* Maintain cache statistics for number of active prefetch chunks. */
    if (c2b_prefetch(c2b))
        atomic_dec(&c2_pref_active_window_size);
    /* Call deallocator function for all prefetch window start c2bs. */
    if (c2b_windowstart(c2b))
        c2_pref_c2b_destroy(c2b);

    /* Add the pages back to the freelist */
    for(i=0; i<nr_c2ps; i++)
        castle_cache_c2p_put(c2b->c2ps[i], &freed_c2ps);
    /* Save the array of c2ps. */
    c2ps = c2b->c2ps;
    /* Poison the c2b. */
#ifdef CASTLE_DEBUG
    memset(c2b, 0x0D, sizeof(c2_block_t));
#endif
    /* Set c2ps array to NULL, BUGed_ON in _init(). */
    c2b->c2ps = NULL;
    /* Changes to freelists under freelist_lock */
    spin_lock(&castle_cache_freelist_lock);
    /* Free all the c2ps. */
    list_for_each_safe(lh, lt, &freed_c2ps)
    {
        list_del(lh);
        c2p = list_entry(lh, c2_page_t, list);
        __castle_cache_page_freelist_add(c2p);
    }
    /* Then put the block on its freelist */
    __castle_cache_block_freelist_add(c2b);
    spin_unlock(&castle_cache_freelist_lock);
    /* Free the c2ps array. By this point, we must not use c2b any more. */
    castle_free(c2ps);
}

static inline int c2b_busy(c2_block_t *c2b, int expected_count)
{
    /* If the lock can be read locked it means that lock isn't writelocked
       (which is expected when calling c2b_busy). */
    BUG_ON(read_can_lock(&castle_cache_block_hash_lock));
    /* c2b_locked() implies (c2b->count > 0) */
    return (atomic_read(&c2b->count) != expected_count) ||
          (c2b->state.bits & (1 << C2B_dirty)) ||
           c2b_locked(c2b);
}

/**
 * Pick c2bs (and associated c2ps) to move from the cleanlist to freelist.
 *
 * - Return immediately if clean blocks make up < 10% of the cache.
 * - Evict softpin blocks if softpin blocks make up 1/2 of the cleanlist.
 * - Iterate through the cleanlist looking for evictable blocks.
 * - If we weren't able to evict BATCH_FREE blocks then victimise softpin blocks
 *   and try again.
 *
 * @return 0    Victims found
 * @return 1    No victims found
 * @return 2    Cleanlist too small (caller to force flush)
 *
 * @also _castle_cache_block_get()
 * @also castle_cache_freelists_grow()
 */
static int castle_cache_block_hash_clean(void)
{
#define BATCH_FREE          200
    struct list_head *lh, *th;
    struct hlist_node *le, *te;
    HLIST_HEAD(victims);
    LIST_HEAD(unevictable);
    c2_block_t *c2b;
    int clean, dirty, softpin;
    int nr_victims, nr_pages, victimise_softpin;

    /* Initialise. */
    nr_victims = nr_pages = victimise_softpin = 0;

    /* Return immediately if the c2p cleanlist is < 10% of the cache.
     *
     * By doing this we expect the caller to wake the flush thread to write back
     * dirty c2ps to disk and placing them onto the cleanlist.
     *
     * If we are the flush thread, skip this check and instead attempt to return
     * as much as we can to the freelist so the active flush can progress. */
    if (likely(current != castle_cache_flush_thread))
    {
        clean = atomic_read(&castle_cache_clean_pages);
        dirty = atomic_read(&castle_cache_dirty_pages);
        if (clean < (clean + dirty) / 10)
            return 2;
    }

    /* Victimise softpin blocks if they make up more than half the cleanlist. */
    clean   = atomic_read(&castle_cache_cleanlist_size);
    softpin = atomic_read(&castle_cache_cleanlist_softpin_size);
    if (softpin > clean / 2)
        victimise_softpin = 1;

    /* Hunt for victim c2bs. Hold hash lock for duration. */
    /* this means we can delete victim blocks from the hash */
    /* this also means no-one can acquire new references */
    write_lock(&castle_cache_block_hash_lock);

    /* acquire the lock on the LRU list, since we are moving things around */
    spin_lock_irq(&castle_cache_block_lru_lock);

    do
    {
        list_for_each_safe(lh, th, &castle_cache_cleanlist)
        {
            c2b = list_entry(lh, c2_block_t, clean);
            nr_pages += c2b->nr_pages;

            /* Blocks that match the following criteria are evicted:
             *
             * (1) Not actively referenced by cache consumers (e.g. only non-busy blocks).
             * (2) Softpin blocks are prioritised (see comment above).
             * (3) Are marked as blocks that sit at the beginning of a prefetch window for an extent
             *     that no longer exists.  This allows us to correctly evict softpinned blocks from
             *     extents that have now been removed - by targeting the start of window block we
             *     unpin and demote those other blocks from the window.
             * (4) Must be transient or from an evictable extent (i.e. not from the super, micro or
             *     mstore extents).  @TODO longer term solution: pools. */
            if (!c2b_busy(c2b, 0) /* (1) */
                    && (victimise_softpin || !c2b_softpin(c2b) /* (2) */
                        || (c2b_windowstart(c2b) && !castle_extent_exists(c2b->cep.ext_id))) /*(3)*/
                    && (c2b_transient(c2b) || EVICTABLE_EXTENT(c2b->cep.ext_id))) /* (4) */
            {
                debug("Found a %svictim.\n", c2b_softpin(c2b) ? "softpin " : "");

                hlist_del(&c2b->hlist);
                list_del(&c2b->clean);
                hlist_add_head(&c2b->hlist, &victims);

                /* Cleanlist accounting and victimisation stats. */
                BUG_ON(atomic_read(&castle_cache_cleanlist_size) == 0);
                atomic_dec(&castle_cache_cleanlist_size);
                if (c2b_softpin(c2b))
                {
                    clearsoftpin_c2b(c2b);
                    atomic_inc(&castle_cache_softpin_block_victims);
                }
                else
                    atomic_inc(&castle_cache_block_victims);
                nr_victims++;
            }
            else
            {
                /* Remove the unevictable block from its current location, and stick it
                   at the end of the list. This will prevent the clean list accumulating
                   unevictable blocks at the start, and this function having to go
                   through them every time. */
                list_del(&c2b->clean);
                list_add(&c2b->clean, &unevictable);
            }

            if (nr_victims >= BATCH_FREE)
                break;
        }
        /* Put all the unevictable pages back on the clean list, but at the tail of the list. */
        list_splice_init(&unevictable, castle_cache_cleanlist.prev);
    }
    /* If we weren't able to clean BATCH_FREE c2bs to the freelist then begin
     * victimising softpin c2bs if we have not already done so. */
    while (!victimise_softpin && (victimise_softpin = (nr_victims < BATCH_FREE)));

    /* Hunt complete. Release locks. */
    spin_unlock_irq(&castle_cache_block_lru_lock);
    write_unlock(&castle_cache_block_hash_lock);

    /* We couldn't find any victims */
    if (hlist_empty(&victims))
    {
        if (nr_pages > castle_cache_size / 2)
            castle_printk(LOG_WARN, "Couldn't find a victim page in %d pages, cache size %d\n",
                    nr_pages, castle_cache_size);
        debug("No victims found!!\n");
        return 1;
    }

    /* Remove victims from hash and return them to the freelist. */
    hlist_for_each_entry_safe(c2b, le, te, &victims, hlist)
    {
        hlist_del(le);
        castle_cache_block_free(c2b);
    }

    return 0;
}

/**
 * Frees up the c2b specified. Only succeeds if the c2b there is precisely one
 * outstanding reference to the c2b (held by the caller), it is not dirty, and
 * it is not locked.
 * This function will put the reference to the c2b regardless of whether is
 * succeeded at destroying the block (under the assumption that the caller
 * is no longer interested in that c2b).
 *
 * @param c2b       Block to free.
 * @return 0:       Success.
 * @return -EINVAL: Failed, due to c2b not being freeable.
 */
int castle_cache_block_destroy(c2_block_t *c2b)
{
    int ret;

    /* Check whether the c2b is busy, under the hash lock so that no other references
       can be taken. */
    write_lock(&castle_cache_block_hash_lock);
    ret = c2b_busy(c2b, 1) ? -EINVAL : 0;
    if(!ret)
    {
        spin_lock_irq(&castle_cache_block_lru_lock);
        hlist_del(&c2b->hlist);
        list_del(&c2b->clean);
        /* Update bookkeeping info. */
        atomic_dec(&castle_cache_cleanlist_size);
        if (c2b_softpin(c2b))
        {
            clearsoftpin_c2b(c2b);
            atomic_inc(&castle_cache_softpin_block_victims);
        }
        else
            atomic_inc(&castle_cache_block_victims);
        spin_unlock_irq(&castle_cache_block_lru_lock);
    }
    write_unlock(&castle_cache_block_hash_lock);
    /* If the c2b was busy, exit early. */
    if(ret)
    {
        put_c2b(c2b);
        return ret;
    }
    /* Succeeded deleting the c2b from the hash, and cleanlist. Decrement the ref count. */
    put_c2b(c2b);
    BUG_ON(atomic_read(&c2b->count) != 0);
    BUG_ON(c2b_dirty(c2b));
    /* Free the block. */
    castle_cache_block_free(c2b);

    BUG_ON(ret != 0);
    return ret;
}

/**
 * Wake up the castle_cache_flush() thread.
 */
void castle_cache_flush_wakeup(void)
{
    wake_up_process(castle_cache_flush_thread);
}

/**
 * Grow the freelists until we have nr_c2bs and nr_pages free.
 *
 * If we are unable to return enough c2bs & c2ps to the freelist then wake the
 * flush thread so dirty pages get written back to disk.
 *
 * If we are the flush thread then return before waking the flush thread after
 * checking that the reservelist is capable of satisfying the request.
 *
 * @param nr_c2bs   Minimum number of c2bs we need freed up
 * @param nr_pages  Minimum number of pages we need freed up
 *
 * @also _castle_cache_block_get()
 * @also castle_cache_block_hash_clean()
 * @also castle_extent_remap()
 */
static void castle_cache_freelists_grow(int nr_c2bs, int nr_pages)
{
    int flush_seq, success;

    while (castle_cache_block_hash_clean() != EXIT_SUCCESS)
    {
        debug("Failed to clean the hash.\n");

        /* The cache is < 10% clean pages or we failed to find any clean pages.
         *
         * Another thread might have raced us in castle_cache_block_hash_clean()
         * so get the relevant lock and check whether the freelist can satisfy
         * our request. */
        flush_seq = atomic_read(&castle_cache_flush_seq);

        spin_lock(&castle_cache_freelist_lock);
        success = (castle_cache_page_freelist_size * PAGES_PER_C2P >= nr_pages)
            && (castle_cache_block_freelist_size >= nr_c2bs);
        spin_unlock(&castle_cache_freelist_lock);

        if (success)
            return;

        /* If we're the flush thread the reservelist should now be capable of
         * satisfying our request.  We raced with castle_extent_remap() if it
         * isn't - in this case, wait and then try cleaning the hash again. */
        if (unlikely(current == castle_cache_flush_thread))
        {
            int c2p_size, c2b_size;

            spin_lock(&castle_cache_reservelist_lock);
            c2p_size = atomic_read(&castle_cache_page_reservelist_size);
            c2b_size = atomic_read(&castle_cache_block_reservelist_size);
            success = (c2p_size * PAGES_PER_C2P >= nr_pages)
                && (c2b_size >= nr_c2bs);
            spin_unlock(&castle_cache_reservelist_lock);

            if (likely(success))
                return;
            else
            {
                /* Raced with castle_extent_remap().  Wait for it to complete
                 * and call castle_cache_page_block_unreserve() to release a
                 * c2b back to the reservelist.
                 * This should never be called from userspace context. But
                 * use non-interruptible msleep just to be safe. */
                msleep(500);
                continue;
            }
        }

        /* If there are still no clean c2bs then wake the flush thread so any
         * dirty c2bs get written back to disk and placed on the cleanlist. */
        debug("Could not clean the hash table. Waking flush.\n");
        castle_cache_flush_wakeup();
        /* Make sure at least one extra IO is done */
        wait_event(castle_cache_flush_wq,
                (atomic_read(&castle_cache_flush_seq) != flush_seq));
        debug("We think there is some free memory now (clean pages: %d).\n",
                atomic_read(&castle_cache_clean_pages));
    }
    debug("Grown the list.\n");
}

/**
 * Grow castle_cache_block_freelist by (a minimum of) one block.
 */
static inline void castle_cache_block_freelist_grow(void)
{
    castle_cache_freelists_grow(1, 0);
}

/**
 * Grow castle_cache_page_freelist_size by nr_pages/PAGES_PER_C2P.
 */
static inline void castle_cache_page_freelist_grow(int nr_pages)
{
    castle_cache_freelists_grow(0, nr_pages);
}

static c2_block_t* _castle_cache_block_get(c_ext_pos_t cep,
                                           int nr_pages,
                                           int transient)
{
    int grown_block_freelist = 0, grown_page_freelist = 0;
#ifdef CASTLE_PERF_DEBUG
    c_ext_type_t ext_type;
#endif
    c2_block_t *c2b;
    c2_page_t **c2ps;

    BUG_ON(BLOCK_OFFSET(cep.offset));

    castle_cache_flush_wakeup();
    might_sleep();
    for(;;)
    {
        debug("Trying to find buffer for cep="cep_fmt_str", nr_pages=%d\n",
            __cep2str(cep), nr_pages);
        /* Try to find in the hash first */
        c2b = castle_cache_block_hash_get(cep, nr_pages);
        debug("Found in hash: %p\n", c2b);
        if (c2b)
        {
            /* Make sure that the number of pages agrees */
            BUG_ON(c2b->nr_pages != nr_pages);

            goto out;
        }

        /* If we couldn't find in the hash, try allocating from the freelists. Get c2b first. */
        /* @TODO: Return NULL if extent doesn't exist any more. Make sure this
         * doesn't break any of the clients. */
#ifdef CASTLE_DEBUG
        {
            uint64_t ext_size;

            /* Check sanity of CEP. */
            ext_size = (uint64_t)castle_extent_size_get(cep.ext_id);
            BUG_ON(ext_size == 0 && cep.ext_id != RESERVE_EXT_ID);
            if (ext_size &&
                ((ext_size * C_CHK_SIZE) < (cep.offset + (nr_pages * C_BLK_SIZE))))
            {
                castle_printk(LOG_DEBUG, "Couldn't create cache page of size %d at cep: "cep_fmt_str
                       "on extent of size %llu chunks\n", nr_pages, __cep2str(cep), ext_size);
                WARN_ON(1);
                msleep(10000);
                BUG();
            }
        }
#endif

        /* c2b couldn't be found in the hash.
         *
         * Try and get c2b and c2ps from the freelists.
         *
         * If we are the flush thread and fail to get c2b/c2ps from the freelist
         * after a _freelist_grow then allocate from the reservelist. */
        do {
            c2b = castle_cache_block_freelist_get();
            if (unlikely(!c2b))
            {
                castle_cache_block_freelist_grow();

                if (unlikely(current == castle_cache_flush_thread)
                        && grown_block_freelist++)
                    c2b = castle_cache_block_reservelist_get();
            }
        } while (!c2b);
        do {
            c2ps = castle_cache_page_freelist_get(nr_pages);
            if (unlikely(!c2ps))
            {
                castle_cache_page_freelist_grow(nr_pages);

                if (unlikely(current == castle_cache_flush_thread)
                        && grown_page_freelist++)
                    c2ps = castle_cache_page_reservelist_get(nr_pages);
            }
        } while (!c2ps);

        /* Initialise the buffer */
        debug("Initialising the c2b: %p\n", c2b);
        castle_cache_block_init(c2b, cep, c2ps, nr_pages);
        get_c2b(c2b);
        /* Try to insert into the hash, can fail if it is already there */
        debug("Trying to insert\n");
        if (!castle_cache_block_hash_insert(c2b, transient))
        {
            put_c2b(c2b);
            castle_cache_block_free(c2b);
        }
        else
        {
            BUG_ON(c2b->nr_pages != nr_pages);
            /* Mark c2b as transient, if required. */
            if (transient)
                set_c2b_transient(c2b);

            goto out;
        }
    }

    BUG(); /* can't reach here */

out:
#ifdef CASTLE_PERF_DEBUG
    /* Update per-extent type cache statistics. */
    ext_type = castle_extent_type_get(c2b->cep.ext_id);
    if (ext_type != EXT_T_INVALID)
    {
        if (c2b_uptodate(c2b)) {
            atomic_add(c2b->nr_pages, &extent_stats[ext_type].hits);
            atomic_add(c2b->nr_pages, &non_merge_hits);
        }
        else {
            atomic_add(c2b->nr_pages, &extent_stats[ext_type].misses);
            atomic_add(c2b->nr_pages, &non_merge_misses);
        }
    }
#endif

    return c2b;
}

/**
 * Get block starting at cep, size nr_pages.
 *
 * @return  Block matching cep, nr_pages.
 */
c2_block_t* castle_cache_block_get(c_ext_pos_t cep, int nr_pages)
{
    return _castle_cache_block_get(cep, nr_pages, 0 /*transient*/);
}

/**
 * Release reservation on c2b and immediately place on relevant freelist.
 *
 * Private interface for castle_extent_remap() to remove a previously made c2b
 * reservation.  This is required for the c2b/c2p reservelist to always be
 * capable of satisfying demands on c2bs, even when the remap thread is making
 * changes to otherwise static metaextent pages.
 *
 * The caller should have a reservation for the duration of the time it holds
 * a metaextent c2b for writing.
 *
 * - Put reference on c2b
 * - Wake up the flush thread
 *
 * @also castle_extent_remap()
 * @also castle_cache_page_block_reserve()
 * @also castle_cache_freelists_grow()
 */
void castle_cache_page_block_unreserve(c2_block_t *c2b)
{
    BUG_ON(!EXT_ID_RESERVE(c2b->cep.ext_id));
    BUG_ON(atomic_read(&c2b->count) != 1);

    put_c2b(c2b);

    atomic_inc(&castle_cache_flush_seq);
    wake_up(&castle_cache_flush_wq);
}

/*******************************************************************************
 * PREFETCHING
 *
 * castle_cache_prefetch_window / c2_pref_window_t:
 *    See structure definition for full description of members.
 *
 *  - start_off->end_off: Range within extent ext_id that has been prefetched.
 *  - pref_pages: Number of pages from a requested offset (cep) that will be
 *    prefetched.
 *  - adv_thresh: Percentage of window size from end_off before we advance.
 *
 * Window storage:
 *    All windows are stored in a global RB tree, protected by a spinlock.
 *    When a window is being operated on (either because of a prefetch advise
 *    or when destroying the window due to the cache evicting the start c2b)
 *    the window gets removed from the tree (through atomic
 *    c2_pref_window_find_and_remove()).
 *    When (re-)inserting the window back into the tree, conflicting window
 *    may exist, in which case the window needs to be destroyed.
 *    Finally, in order to guarantee that cache eviction isn't going to be
 *    racing with window adds. Reference to the start_c2b needs to be held
 *    when inserting.
 *
 * Invocation:
 *    Consumers call castle_cache_advise().  These consumer calls could
 *    potentially race.
 *
 * Softpinning:
 *    If requested we attempt to keep prefetched c2bs within the cache by
 *    maintaining a softpin count (c2b->softpin_cnt).  Blocks with positive
 *    softpin counts are prioritised in freelist grows/cleanlist eviction
 *    (castle_cache_block_hash_clean()).
 *
 * Deprecation of windows:
 *    When inserting a window into the RB tree, the strat_c2b is marked with
 *    'windowstart' bit. That bit provides a link between a c2b in the cache
 *    and a window.
 *    When a block with the windowstart bit set is to be freed (via
 *    castle_cache_block_free()) we call into c2_pref_c2b_destroy() which finds
 *    a matching window and destroys it.
 *    During shutdown, by the time the very last c2b gets freed, all prefetch
 *    windows should be gone too (BUG_ONs in castle_cache_hashes_fini() check
 *    for that).
 *
 * Prefetch algorithm and variables:
 *    Algorithm and variables: see comments in c2_pref_window_advance().
 *    When a window is moved forward chunks that fall off the front of
 *    the window are deprecated in the LRU cache if their softpin count reaches 0.
 *
 * Debug:
 *    Many prefetcher functions take a debug argument that is propagated to the
 *    functions they call.  This should make it straightforward to debug
 *    individual prefetch requests or specific sections of code by setting the
 *    debug flag in the correct place.  PREF_DEBUG needs to be defined.
 *
 * General rules / observations:
 *
 * 1. All changes to a window (e.g. modifying start_off, end_off, state, etc.)
 *    must happen when having exclusive access to the window. This is achieved
 *    by removing window from the RB-tree.
 *
 * 2. Within the tree windows are sorted according to start_off.  The start
 *    points in the tree are unique.
 *
 * 3. Within the tree windows ranges (start_off->end_off) may overlap.
 *
 * 4. Windows are totally chunk aligned.  If a consumer makes a non-chunk-
 *    aligned request then we align to the start of the requested chunk on
 *    their behalf.
 *
 * 5. We prefetch whole chunks.
 *
 * Code flow:
 *
 *    A very rough flow of control for updating an existing prefetch window.
 *
 *      castle_cache_advise()
 *          // calls straight into:
 *      castle_cache_prefetch_advise()
 *        c2_pref_window_get()
 *            // gets existing or allocates a new window
 *      c2_pref_window_advance()
 *          // calculates the number of pages to prefetch
 *          // updates the window
 *      c2_pref_window_falloff()
 *          // handles deprecation of old chunks
 *      c2_pref_window_submit()
 *          // issues chunk-aligned I/O
 */
#define PREF_WINDOW_ADAPTIVE        (0x1)           /**< Whether this is an adaptive window.      */
#define PREF_WINDOW_SOFTPIN         (0x2)           /**< Keep c2bs in cache if possible.          */
#define PREF_PAGES                  4 *BLKS_PER_CHK /**< #pages to non-adaptive prefetch.         */
#define PREF_ADAP_INITIAL           2 *BLKS_PER_CHK /**< Initial #pages to adaptive prefetch.     */
#define PREF_ADAP_MAX               16*BLKS_PER_CHK /**< Maximum #pages to adaptive prefetch.     */
#define PREF_ADV_THRESH             25              /**< 25% from end of window before advance.   */
STATIC_BUG_ON(PREF_ADV_THRESH > 100);

/**
 * Prefetch window definition.
 *
 * start_off to end_off defines the range within ext_id that we have already
 * issued prefetching for.
 */
typedef struct castle_cache_prefetch_window {
    uint8_t         state;      /**< State of the prefetch window.                                */
    c_ext_id_t      ext_id;     /**< Extent this window describes.                                */
    c_byte_off_t    start_off;  /**< Start of range that has been prefetched.                     */
    c_byte_off_t    end_off;    /**< End of range that[P] tests for reserve list (dirty at
                                     high rates to trigger reserve list being used)
                                     has been prefetched.  Chunk aligned.                         */
    uint32_t        pref_pages; /**< Number of pages we prefetch.                                 */
    uint8_t         adv_thresh; /**< Percentage of window size from end_off before we advance.    */
    struct rb_node  rb_node;    /**< RB-node for this window.                                     */
} c2_pref_window_t;

static          DEFINE_SPINLOCK(c2_prefetch_lock);          /**< Protects c2p_rb_root.            */
static struct rb_root           c2p_rb_root = RB_ROOT;      /**< RB tree of c2_pref_windows.      */
static  DECLARE_WAIT_QUEUE_HEAD(castle_cache_prefetch_wq);  /**< _in_flight wait queue.           */
static atomic_t                 castle_cache_prefetch_in_flight = ATOMIC_INIT(0);   /**< Number of
                                                                 outstanding prefetch IOs.        */

static USED char* c2_pref_window_to_str(c2_pref_window_t *window)
{
#define PREF_WINDOW_STR_LEN     (128)
    static char win_str[PREF_WINDOW_STR_LEN];
    c_ext_pos_t cep;

    cep.ext_id = window->ext_id;
    cep.offset = window->start_off;

    snprintf(win_str, PREF_WINDOW_STR_LEN,
        "%s%s pref win: {cep="cep_fmt_str" start_off=0x%llx (%lld) "
        "end_off=0x%llx (%lld) pref_pages=%d (%lld) adv_thresh=%u%% st=0x%.2x",
        window->state & PREF_WINDOW_SOFTPIN ? "S": "",
        window->state & PREF_WINDOW_ADAPTIVE ? "A" : "",
        cep2str(cep),
        window->start_off,
        CHUNK(window->start_off),
        window->end_off,
        CHUNK(window->end_off),
        window->pref_pages,
        window->pref_pages / BLKS_PER_CHK,
        window->adv_thresh,
        window->state);
    win_str[PREF_WINDOW_STR_LEN-1] = '\0';

    return win_str;
}

/**
 * Get a c2b for use by the prefetcher setting necessary bits.
 *
 * - Get c2b
 * - Mark as prefetch
 * - Mark as softpin if window is softpin
 *
 * @return c2b
 */
static c2_block_t* c2_pref_block_chunk_get(c_ext_pos_t cep, c2_pref_window_t *window, int debug)
{
    c2_block_t *c2b;

    if ((c2b = castle_cache_block_get(cep, BLKS_PER_CHK)))
    {
        /* Set c2b status bits. */
        if (!test_set_c2b_prefetch(c2b))
            atomic_inc(&c2_pref_active_window_size);
        if (window->state & PREF_WINDOW_SOFTPIN)
            castle_cache_block_softpin(c2b);
    }

#ifdef CASTLE_PERF_DEBUG
    if (!c2b_uptodate(c2b))
    {
        c2_page_t *c2p;
        c_ext_pos_t cep_unused;
        int up2date = 1;

        c2b_for_each_c2p_start(c2p, cep_unused, c2b, 0)
        {
            if (!c2p_uptodate(c2p))
                up2date = 0;
        }
        c2b_for_each_c2p_end(c2p, cep_unused, c2b, 0)

        if (up2date)
            set_c2b_uptodate(c2b);
    }
#endif

    pref_debug(debug, "ext_id==%lld chunk %lld/%u softpin_cnt=%d\n",
            cep.ext_id, CHUNK(cep.offset), castle_extent_size_get(cep.ext_id)-1,
            atomic_read(&c2b->softpin_cnt));

    return c2b;
}

/**
 * Put a c2b used by the prefetcher, unsetting necessary bits.
 *
 * - Lookup c2b, if one exists:
 * - Clear prefetch bit
 *   - Maintain prefetch_chunks stats if the bit was previously set
 * - Handle softpin blocks
 * - Position for eviction in LRU if prefetch & softpin counts reach 0
 */
static void c2_pref_block_chunk_put(c_ext_pos_t cep, c2_pref_window_t *window, int debug)
{
    c2_block_t *c2b;
    int demote = 0;

    if ((c2b = castle_cache_block_hash_get(cep, BLKS_PER_CHK)))
    {
        /* Clear c2b status bits. */
        if (test_clear_c2b_prefetch(c2b))
        {
            atomic_dec(&c2_pref_active_window_size);
            set_c2b_prefetched(c2b);
        }
        if (window->state & PREF_WINDOW_SOFTPIN)
            demote = demote || castle_cache_block_unsoftpin(c2b);

        pref_debug(debug, "ext_id==%lld chunk %lld/%u softpin_cnt=%d\n",
                cep.ext_id, CHUNK(cep.offset), castle_extent_size_get(cep.ext_id)-1,
                atomic_read(&c2b->softpin_cnt));

        if (demote)
            put_c2b_and_demote(c2b);
        else
            put_c2b(c2b);
    }
}

/**
 * Perform operations on c2bs that fall off front of prefetch window.
 *
 * @param cep   c2bs prior to this offset will be operated on.
 * @param pages Number of pages to falloff.
 *
 * Get the prefetch c2bs we used in this window.  This covers a range from
 * start_off to the chunk that cep.offset lies within.  We're moving the
 * window forward we should let the cache know we're done with these c2bs.
 *
 * It may seem more sensible to store the prefetch c2bs within the window.
 * In fact this method would require that we either: a) hold a reference,
 * thereby preventing the c2bs from being freed under memory pressure; or
 * b) perform the same steps we do here to verify they still exist within
 * the cache.
 *
 * @also c2_pref_block_chunk_put()
 */
static void c2_pref_window_falloff(c_ext_pos_t cep, int pages, c2_pref_window_t *window, int debug)
{
    BUG_ON(CHUNK_OFFSET(cep.offset));
    BUG_ON(pages % BLKS_PER_CHK);

    while (pages)
    {
        c2_pref_block_chunk_put(cep, window, debug);

        pages -= BLKS_PER_CHK;
        cep.offset += C_CHK_SIZE;
    }
}

/**
 * Compare extent offset (cep) to a prefetch window.
 *
 * - Check the extent ID
 * - Return whether offset is prior, within or after window
 *
 * @param window    Window to check.
 * @param cep       Position to check for.
 *
 * @return <0:  cep is prior to window
 * @return  0:  cep is within the window
 * @return >0:  cep is after next window
 */
static inline int c2_pref_window_compare(c2_pref_window_t *window, c_ext_pos_t cep)
{
    /* Check if cep and this window describe the same extent. */
    if (cep.ext_id < window->ext_id)
        return -1;
    if (cep.ext_id > window->ext_id)
        return 1;

    if (cep.offset < window->start_off)
        return -1;
    if (cep.offset < window->end_off)
        return 0;

    if (cep.offset == window->start_off && cep.offset == window->end_off)
        return 0;

    return 1;
}

/**
 * Find prefetch window with furthest start_off that matches cep.
 *
 * @TODO This logic is likely broken for adaptive prefetch windows.
 * Specifically a given cep might match two overlapping windows:
 * - One with a start_off of 10 and end_off of 200
 * - Another with a start_off of 15 and end_off of 30
 * This function will return the second (smaller, but more 'advanced') for a
 * cep.offset 20.  This behaviour is not ideal but is not incorrect.
 *
 * @arg n       Starting point for search
 * @arg cep     Offset
 *
 * @return Most advanced window matching cep
 */
static inline c2_pref_window_t* c2_pref_window_closest_find(struct rb_node *n,
                                                            c_ext_pos_t cep)
{
    c2_pref_window_t *window;
    struct rb_node *p;
    int cmp;

    /* The logic below is (probably) broken for back prefetch. */
    BUG_ON(!spin_is_locked(&c2_prefetch_lock));
    BUG_ON(c2_pref_window_compare(rb_entry(n, c2_pref_window_t, rb_node), cep) != 0);

    /* Save provided window rb_node ptr.  It is guaranteed to satisfy cep. */
    p = n;

    do {
        /* Check next entry satisfies cep. */
        n = rb_next(n);
        if(!n)
            break;
        window = rb_entry(n, c2_pref_window_t, rb_node);

        cmp = c2_pref_window_compare(window, cep);
        if (cmp == 0)
            /* Greater start_off, still satisfies cep. */
            p = n;
    }
    while (cmp >= 0);

    /* n is now NULL, or in the first window that doesn't cover the cep, return
     * the window associated with p. */
    window = rb_entry(p, c2_pref_window_t, rb_node);

    return window;
}

/**
 * Find prefetch window from tree whose range encompasses cep.
 *
 * @param cep           Position to find a window for.
 * @param forward       Direction to prefetch.
 * @param exact_match   Whether a window that exactly matches cep is required.
 *                      If false, return the most advanced matching window.
 *
 * @return Valid prefetch window if found.
 * @return NULL if no matching windows were found.
 *
 * @see c2_pref_window_compare()
 * @see c2_pref_window_closest_find()
 */
static c2_pref_window_t *c2_pref_window_find_and_remove(c_ext_pos_t cep, int exact_match)
{
    struct rb_node *n;
    c2_pref_window_t *window;
    int cmp;

    pref_debug(0, "Looking for pref window cep="cep_fmt_str", exact_match=%d\n",
            cep2str(cep), exact_match);
    spin_lock(&c2_prefetch_lock);
    n = c2p_rb_root.rb_node;
    while (n)
    {
        c_ext_pos_t window_cep;

        /* Get prefetch window from tree and initialise cep. */
        window = rb_entry(n, c2_pref_window_t, rb_node);
        window_cep.ext_id = window->ext_id;
        window_cep.offset = window->start_off;

        if(exact_match)
            /* Do they have identical offsets? */
            cmp = EXT_POS_COMP(cep, window_cep);
        else
            /* Does the offset fall within the window? */
            cmp = c2_pref_window_compare(window, cep);

        if(cmp < 0)
            /* Window is prior to cep; go left. */
            n = n->rb_left;
        else if (cmp > 0)
            /* Window is after cep; go right. */
            n = n->rb_right;
        else
        {
            /* If we are not looking for an exact match, we should return the window
               that covers the cep we are looking for, but is furthest along as well.
               This prevents corner cases, where we find a window, try to advance it
               but then fail to insert into the tree, because its already there. */
            if(!exact_match)
                window = c2_pref_window_closest_find(n, cep);
            /* Get a reference to the window. Reference count should be strictly > 1.
               Otherwise the window should not be in the tree. */
            BUG_ON(!window);
            BUG_ON(c2_pref_window_compare(window, cep) != 0);

            /* Remove from the rbtree, still under the spinlock. */
            rb_erase(&window->rb_node, &c2p_rb_root);

            /* Update count of pages covered by windows in the tree. */
            c2_pref_total_window_size -=
                ((window->end_off - window->start_off) >> PAGE_SHIFT) / BLKS_PER_CHK;

            /* Tree updated, release the lock. */
            spin_unlock(&c2_prefetch_lock);

            debug("Found %s\n", c2_pref_window_to_str(window));

            return window;
        }
    }
    spin_unlock(&c2_prefetch_lock);

    pref_debug(0, "No existing prefetch window found.\n");

    return NULL;
}

/**
 * Insert prefetch window into tree.
 *
 * @param window    Window to insert.
 *
 * @also c2_pref_window_advance()
 * @also castle_cache_block_free().
 */
static int c2_pref_window_insert(c2_pref_window_t *window)
{
    struct rb_node **p, *parent = NULL;
    c2_pref_window_t *tree_window;
    c_ext_pos_t cep, tree_cep;
    c2_block_t *start_c2b;
    int cmp;

    pref_debug(0, "Asked to insert %s\n", c2_pref_window_to_str(window));

    cep.ext_id = window->ext_id;
    cep.offset = window->start_off;
    /* The c2b at the start of the window must be held when inserting into the rbtree. */
    start_c2b = castle_cache_block_get(cep, BLKS_PER_CHK);

    /* We must hold the prefetch tree lock while manipulating the tree. */
    spin_lock(&c2_prefetch_lock);

    p = &c2p_rb_root.rb_node;
    while(*p)
    {
        parent = *p;
        tree_window = rb_entry(parent, c2_pref_window_t, rb_node);
        tree_cep.ext_id = tree_window->ext_id;
        tree_cep.offset = tree_window->start_off;

        cmp = EXT_POS_COMP(cep, tree_cep);
        if(cmp < 0)
            p = &(*p)->rb_left;
        else if (cmp > 0)
            p = &(*p)->rb_right;
        else
        {
            /* We found an identical starting point.  Do not insert. */
            spin_unlock(&c2_prefetch_lock);
            pref_debug(0, "Starting point already exists.  Not inserting.\n");
            /* Release start_c2b ref. */
            put_c2b(start_c2b);

            return -EINVAL;
        }
    }

    rb_link_node(&window->rb_node, parent, p);
    rb_insert_color(&window->rb_node, &c2p_rb_root);

    /* Update count of pages covered by windows in the tree.  This window might
     * overlap an existing window but we don't account for that (@TODO?). */
    c2_pref_total_window_size +=
        ((window->end_off - window->start_off) >> PAGE_SHIFT) / BLKS_PER_CHK;

    /* Release the lock. */
    spin_unlock(&c2_prefetch_lock);

    /* Get the first chunk in the window (from start_off).  We will perform no
     * (additional) I/O on this block but we require that it is: allocated,
     * marked as windowstart, and exists within the cache.
     *
     * This semantic is required to allow prefetch windows to be freed (see
     * castle_cache_block_free() and c2_pref_c2b_destroy()).  By marking the
     * first block in the window we try to prevent holes from occurring in the
     * window during cache eviction. */
    set_c2b_windowstart(start_c2b);
    /* Release start_c2b ref. */
    put_c2b(start_c2b);

    return EXIT_SUCCESS;
}

#ifdef PREF_DEBUG
/**
 * Walk and print entries in the prefetch window RB-tree.
 *
 * For debug purposes.
 */
static void c2_pref_window_dump(void)
{
    struct rb_node **p, *parent = NULL;
    c2_pref_window_t *cur_window;
    int entries = 0;

    /* We must hold the c2_prefetch_lock while working. */
    spin_lock(&c2_prefetch_lock);

    /* Find the leftmost node. */
    p = &c2p_rb_root.rb_node;
    while(*p)
    {
        parent = *p;
        p = &(*p)->rb_left;
    }

    /* Traverse through all of the entries with rb_entry(). */
    while(parent)
    {
        cur_window = rb_entry(parent, c2_pref_window_t, rb_node);
        pref_debug(0, "%s\n", c2_pref_window_to_str(cur_window));
        parent = rb_next(parent);

        /* Record how many entries we find. */
        entries++;
    }

    pref_debug(0, "Found %d prefetch window(s).\n", entries);

    /* Release the lock. */
    spin_unlock(&c2_prefetch_lock);
}
#endif

/**
 * Allocate new prefetch window for ext_id & initialise as PREF_WINDOW_NEW.
 *
 * @return A freshly allocated & initialised prefetch window.
 * @return NULL if we could not allocate enough memory.
 */
static c2_pref_window_t * c2_pref_window_alloc(c2_pref_window_t *window,
                                               c_ext_pos_t cep,
                                               c2_advise_t advise)
{
    window = castle_alloc(sizeof(c2_pref_window_t));
    if(!window)
        return NULL;

    window->state           = 0;
    window->ext_id          = cep.ext_id;
    window->start_off       = cep.offset;
    window->end_off         = cep.offset;
    window->adv_thresh      = PREF_ADV_THRESH;

    if (advise & C2_ADV_STATIC)
        window->pref_pages  = PREF_PAGES;
    else// if (advise & C2_ADV_ADAPTIVE)
    {
        /* By default, prefetch windows are adaptive. */
        window->state      |= PREF_WINDOW_ADAPTIVE;
        window->pref_pages  = PREF_ADAP_INITIAL;
    }
    if (advise & C2_ADV_SOFTPIN)
        window->state  |= PREF_WINDOW_SOFTPIN;

    pref_debug(0, "Allocated a new window.\n");

    return window;
}

/**
 * Looks up and returns an existing prefetch window or allocates a new one.
 *
 * @param cep       Extent position to prefetch from.
 * @param forward   Whether to look for a forward fetching window.
 *
 * @also c2_pref_window_find()
 * @also c2_pref_window_alloc()
 */
static c2_pref_window_t* c2_pref_window_get(c_ext_pos_t cep, c2_advise_t advise)
{
    c2_pref_window_t *window;

    /* Look for existing prefetch window. */
    pref_debug(0, "Looking for window for cep="cep_fmt_str_nl, cep2str(cep));
    if ((window = c2_pref_window_find_and_remove(cep, 0)))
    {
        /* Found a matching prefetch window. */
        pref_debug(0, "Found %s\n", c2_pref_window_to_str(window));
        return window;
    }

    /* No matching prefetch windows exist.  Allocate one. */
    pref_debug(0, "Failed to find window for cep="cep_fmt_str_nl, cep2str(cep));
#ifdef PREF_DEBUG
    c2_pref_window_dump();
#endif

    if ((window = c2_pref_window_alloc(window, cep, advise)) == NULL)
    {
        /* Failed to allocate a new window. */
        pref_debug(0, "Failed to allocate new window.\n");
        return NULL;
    }

    /* Return the newly allocate prefetch window. */
    return window;
}

/**
 * Prefetch I/O completion callback handler.
 *
 * NOTE: Wakes up castle_cache_prefetch_wq waiters when the number of in flight
 *       prefetch IOs reaches 0.
 *
 * @param c2b   Cache block I/O has been completed on
 */
static void c2_pref_io_end(c2_block_t *c2b)
{
    pref_debug(0, "Finished prefetch io at cep="cep_fmt_str", nr_pages=%d.\n",
            cep2str(c2b->cep), c2b->nr_pages);
    write_unlock_c2b(c2b);
    put_c2b(c2b);

    /* Allow castle_cache_prefetch_fini() to complete. */
    if (atomic_dec_return(&castle_cache_prefetch_in_flight) == 0)
        wake_up(&castle_cache_prefetch_wq);
}

/**
 * Arrange to delete prefetch window. Cleans up all chunks by calling c2_pref_window_falloff
 * on all pages.
 *
 * @param window    Window to delete.
 *
 * @also c2_pref_window_falloff()
 * @also c2_pref_c2b_destroy()
 */
static void c2_pref_window_drop(c2_pref_window_t *window)
{
    c_ext_pos_t cep;
    int pages;

    pref_debug(0, "Deleting %s\n", c2_pref_window_to_str(window));

    debug("Performing falloff for to-be-deallocated prefetch window %s.\n",
            c2_pref_window_to_str(window));

    pages = (window->end_off - window->start_off) >> PAGE_SHIFT;
    /* Construct cep corresponding to window start. */
    cep.ext_id = window->ext_id;
    cep.offset = window->start_off;
    c2_pref_window_falloff(cep, pages, window, 0);

    /* Free up the window structure. */
    castle_free(window);
}

/**
 * Destroy prefetch window associated with c2b.
 *
 * Find prefetch window exactly matching c2b's offset and destroy it.
 *
 * @param c2b   Callback block to try and match against windows.
 *
 * @also c2_pref_window_remove()
 * @also c2_pref_window_drop()
 */
static void c2_pref_c2b_destroy(c2_block_t *c2b)
{
    c2_pref_window_t *window;

    BUG_ON(!c2b_windowstart(c2b));

    pref_debug(0, "Destroying a prefetch c2b->cep"cep_fmt_str", nr_pages=%d.\n",
            cep2str(c2b->cep), c2b->nr_pages);

    /* Try and find a window matching c2b. */
    if (!(window = c2_pref_window_find_and_remove(c2b->cep, 1 /*exact_match*/)))
    {
        pref_debug(0, "No window found for c2b->ceb="cep_fmt_str_nl, cep2str(c2b->cep));
        return;
    }

    /* Window found and removed from the tree. Clean up and destroy it. */
    pref_debug(0, "Found %s\n", c2_pref_window_to_str(window));

    /* Drop the window. */
    c2_pref_window_drop(window);
}

/**
 * Hard/soft pin 'chunks' chunk-sized c2bs from cep.
 *
 * @param cep       Extent and offset to pin
 * @param chunks    Number of chunks from cep to pin
 *
 * WARNING: There must be an accompanying _unpin() call for every _pin().
 *
 * @also castle_cache_prefetch_unpin()
 */
void castle_cache_prefetch_pin(c_ext_pos_t cep, int chunks, c2_advise_t advise)
{
    c2_block_t *c2b;

    BUG_ON(cep.offset % BLKS_PER_CHK != 0);

    while (chunks > 0)
    {
        /* Get block, lock it and update offset. */
        c2b = castle_cache_block_get(cep, BLKS_PER_CHK);

        if (advise & C2_ADV_PREFETCH)
        {
            get_c2b(c2b); /* will drop this in c2_pref_io_end() */
            write_lock_c2b(c2b);
            c2b->end_io = c2_pref_io_end;

            BUG_ON(submit_c2b(READ, c2b));
            atomic_inc(&castle_cache_prefetch_in_flight);
        }

        if (advise & C2_ADV_SOFTPIN)
        {
            castle_cache_block_softpin(c2b);
            put_c2b(c2b);
        }
        else if (!(advise & C2_ADV_HARDPIN))
        {
            put_c2b(c2b);
        }
        cep.offset += BLKS_PER_CHK * PAGE_SIZE;
        chunks--;
    }

    if (advise & C2_ADV_HARDPIN)
    {
        pref_debug(0, "Hardpinning for ext_id %llu\n", cep.ext_id);
    }
    else if (advise & C2_ADV_SOFTPIN)
    {
        pref_debug(0, "Softpinning for ext_id %llu\n", cep.ext_id);
    }
}

/**
 * Un-hard/soft pin 'chunks' chunk-sized c2bs from cep allowing them to be evicted.
 *
 * @param cep       Extent and offset to unpin from
 * @param chunks    Number of chunks from cep to unpin
 *
 * @warning If unhardpinning the extent must previously have
 *          been hard-pinned with castle_cache_prefetch_pin().
 *
 * @also castle_cache_prefetch_pin()
 */
static void castle_cache_prefetch_unpin(c_ext_pos_t cep, int chunks, c2_advise_t advise)
{
    c2_block_t *c2b;

    BUG_ON(cep.offset % BLKS_PER_CHK != 0);

    while (chunks > 0)
    {
        /* Get block, lock it and update offset. */
        if (advise & C2_ADV_SOFTPIN)
        {
            if ((c2b = castle_cache_block_hash_get(cep, BLKS_PER_CHK)))
                clearsoftpin_c2b(c2b);
        }
        else //if (advise & C2_ADV_HARDPIN)
        {
            c2b = castle_cache_block_get(cep, BLKS_PER_CHK);
            put_c2b(c2b); /* will cause problems if they weren't prefetch-locked. */
        }

        if (c2b)
            put_c2b(c2b);
        cep.offset += BLKS_PER_CHK * PAGE_SIZE;
        chunks--;
    }

    if (advise & C2_ADV_HARDPIN)
    {
        pref_debug(0, "Unhardpinning for ext_id %llu\n", cep.ext_id);
    }
    else if (advise & C2_ADV_SOFTPIN)
    {
        pref_debug(0, "Unsoftpinning for ext_id %llu\n", cep.ext_id);
    }
}

/**
 * Submit new chunks for read I/O.
 *
 * @param window    The window we're advancing.
 * @param cep       Position to advance from.
 * @param pages     Number of pages to advance from cep.
 *
 * - Get n chunk-sized c2bs from cep
 * - Mark them as prefetch and softpin if necessary (@also c2_pref_block_chunk_get())
 * - Dispatch c2bs if they require I/O
 *
 * @also c2_pref_io_end()
 * @also c2_pref_block_chunk_get()
 */
static void c2_pref_window_submit(c2_pref_window_t *window, c_ext_pos_t cep, int pages, int debug)
{
    c2_block_t *c2b;

    BUG_ON(CHUNK_OFFSET(cep.offset));
    BUG_ON(pages % BLKS_PER_CHK);

    while (pages && CHUNK(cep.offset) < castle_extent_size_get(cep.ext_id))
    {
        c2b = c2_pref_block_chunk_get(cep, window, debug);

        if (c2b_uptodate(c2b))
        {
            /* c2b already up-to-date, don't do anything. */
            pref_debug(debug, "ext_id==%lld chunk %lld/%u already up-to-date\n",
                    cep.ext_id, CHUNK(cep.offset), castle_extent_size_get(cep.ext_id)-1);
#ifdef CASTLE_PERF_DEBUG
            castle_extent_up2date_inc(cep.ext_id);
#endif
            put_c2b(c2b);
        }
        else
        {
            /* Submit I/O for c2b. */
            pref_debug(debug, "ext_id==%lld chunk %lld/%u submitted for I/O\n",
                    cep.ext_id, CHUNK(cep.offset), castle_extent_size_get(cep.ext_id)-1);
#ifdef CASTLE_PERF_DEBUG
            castle_extent_not_up2date_inc(cep.ext_id);
#endif

            write_lock_c2b(c2b);
            c2b->end_io = c2_pref_io_end;

            BUG_ON(submit_c2b(READ, c2b));
            atomic_inc(&castle_cache_prefetch_in_flight);
        }

        pages -= BLKS_PER_CHK;
        cep.offset += C_CHK_SIZE;
    }
    castle_slaves_unplug();
}

/*
 * Advance the window and kick off prefetch I/O if necessary.
 *
 * @param window    Window to advance
 * @param cep       User-requested offset
 * @param advise    User-specified prefetch parameters
 * @param chunks    Unused
 * @param priority  Unused
 *
 * @return 0        Window not advanced (cep already satisfied by window)
 * @return 1        Window advanced (cep now satisfied by window)
 * @return -EEXIST  Window already existed within tree, dropped
 */
static int c2_pref_window_advance(c2_pref_window_t *window,
                                  c_ext_pos_t cep,
                                  c2_advise_t advise,
                                  int chunks,
                                  int priority,
                                  int debug)
{
    int ret = EXIT_SUCCESS;
    int pages, size, adv_pos, falloff_pages;
    c_ext_pos_t submit_cep; // old window->end_off cep (prefetch pages from here)
    c_ext_pos_t start_cep;  // old window->start_off cep

    BUG_ON(cep.ext_id != window->ext_id);
    BUG_ON(CHUNK_OFFSET(cep.offset));
    BUG_ON(CHUNK_OFFSET(window->start_off));
    BUG_ON(CHUNK_OFFSET(window->end_off));

    /* Calculate number of pages beyond end_off we would need to fetch if we
     * push start_off to cep.offset. */
    pages  = (cep.offset - window->end_off) >> PAGE_SHIFT;
    pages += window->pref_pages;
    BUG_ON(pages % BLKS_PER_CHK);

    /* No more pages need to be prefetched. */
    if (!pages)
        goto dont_advance;

    /* Pages doesn't meet advance threshold. */
    size    = (window->end_off - window->start_off) >> PAGE_SHIFT;
    adv_pos = size / (100 / window->adv_thresh);
    if (size && CHUNK(cep.offset) < CHUNK(window->end_off - adv_pos * PAGE_SIZE))
        goto dont_advance;

    pref_debug(debug, "window=%p cep=%llu pages=%d size=%d end_off=%llu "
            "start_off=%llu pref_pages=%u adv_thresh=%u\n",
            window, cep.offset, pages, size, window->end_off,
            window->start_off, window->pref_pages, window->adv_thresh);
    ret = 1;

    /* We're going to slide the window forward by pages. */
    start_cep.ext_id  = window->ext_id;
    start_cep.offset  = window->start_off;
    submit_cep.ext_id = window->ext_id;
    submit_cep.offset = window->end_off;
    falloff_pages = (cep.offset - window->start_off) >> PAGE_SHIFT;

    /* Window is not in the tree, its safe to update it. */
    window->start_off = cep.offset;
    window->end_off   = window->end_off + pages * PAGE_SIZE;
    if (window->state & PREF_WINDOW_ADAPTIVE && window->pref_pages < PREF_ADAP_MAX)
    {
        /* Double the number of prefetch pages. */
#ifdef PREF_DEBUG
        uint32_t old_pref_pages = window->pref_pages;
#endif
        window->pref_pages *= 2;
        if (window->pref_pages > PREF_ADAP_MAX)
            window->pref_pages = PREF_ADAP_MAX;
        pref_debug(debug, "Window pref_pages %d->%d chunks for next advance.\n",
                old_pref_pages / BLKS_PER_CHK, window->pref_pages / BLKS_PER_CHK);
    }
    /* End of operations on window while not in tree. */
    c2_pref_window_falloff(start_cep, falloff_pages, window, debug);
    c2_pref_window_submit(window, submit_cep, pages, debug);

dont_advance:
    BUG_ON(cep.ext_id != window->ext_id);
    if (c2_pref_window_insert(window) != EXIT_SUCCESS)
    {
        /* A window covering the same range already exists.
         * This is a race but no major deal: the data for cep will already have
         * been prefetched. Drop this window. */
        castle_printk(LOG_WARN, "WARNING: %s already in the tree.\n",
                c2_pref_window_to_str(window));
        c2_pref_window_drop(window);

        return -EEXIST;
    }

    return ret;
}

/**
 * Advise prefetcher of intention to begin read.
 *
 * This is the main entry point into the prefetcher.
 *
 * All prefetching is done on chunk-sized c2bs starting from the chunk cep lies
 * within.  If cep is not chunk-aligned we make it so.
 *
 * - Get/allocate a prefetch window for cep
 * - Lock the window
 * - Ensure the window matches cep (race detect)
 * - Prefetch data if necessary
 *
 * @param cep       Requested offset within extent
 * @param advise    Hints for the prefetcher
 * @param chunks    For future use
 * @param priority  For future use
 * @param debug     Whether to print debug info
 *
 * @return ENOMEM: Failed to allocate a new prefetch window.
 * @return See c2_pref_window_advance().
 *
 * @also c2_pref_window_get()
 * @also c2_pref_window_advance()
 */
static int castle_cache_prefetch_advise(c_ext_pos_t cep,
                                        c2_advise_t advise,
                                        int chunks,
                                        int priority,
                                        int debug)
{
    c2_pref_window_t *window;

    /* Must be block aligned. */
    BUG_ON(BLOCK_OFFSET(cep.offset));

    pref_debug(debug, "Prefetch advise: "cep_fmt_str_nl, cep2str(cep));

    /* Prefetching is chunk-aligned.  Align cep to start of its chunk. */
    cep.offset = CHUNK(cep.offset) * C_CHK_SIZE;

    /*
     * Obtain a window that satisfies cep.
     * If there already exists a window containing that cep (in the rbtree) this will
     * be used. Otherwise a new one will be created.
     * Once the window is obtained, this thread has an exclusive access to it,
     * since, even if it was find in the rbtree, it'll be removed from it.
     * Once the window is updated (possibly after scheduling the IO) it is (re-)inserted
     * into the tree.
     */
    if (!(window = c2_pref_window_get(cep, advise)))
    {
        castle_printk(LOG_WARN, "WARNING: Failed to allocate prefetch window.\n");
        return -ENOMEM;
    }
    pref_debug(debug, "%sfor cep="cep_fmt_str"\n",
            c2_pref_window_to_str(window), cep2str(cep));
    /* cep must be within the window. */
    BUG_ON(c2_pref_window_compare(window, cep));

    /* Update window advice to match prefetch advice.  Do this once we know we
     * aren't racing so we don't pollute other bystanding windows. */
    if (advise & C2_ADV_SOFTPIN)
        window->state |= PREF_WINDOW_SOFTPIN;

    /* Advance the window if necessary. */
    return c2_pref_window_advance(window, cep, advise, chunks, priority, debug);
}

/**
 * Advise the cache of intention to perform specific operation on an extent.
 *
 * @param cep       Extent/offset to operate on/from
 * @param advise    Advise for the cache
 * @param chunks    For future use
 * @param priority  For future use
 * @param debug     Whether to print debug info
 *
 * - If operating on an extent (advise & C2_ADV_EXTENT) manipulate cep and
 *   chunks to span the whole extent.
 *
 * @also castle_cache_prefetch_advise()
 */
int castle_cache_advise(c_ext_pos_t cep, c2_advise_t advise, int chunks, int priority, int debug)
{
    /* Downgrade to softpin if hardpinning is disabled. */
    if (!castle_cache_allow_hardpinning && (advise & C2_ADV_HARDPIN))
    {
        advise &= ~C2_ADV_HARDPIN;
        advise |=  C2_ADV_SOFTPIN;
    }

    /* Prefetching is handled via a _prefetch_advise() call. */
    if ((advise & C2_ADV_PREFETCH) && !(advise & C2_ADV_EXTENT))
        return castle_cache_prefetch_advise(cep, advise, chunks, priority, 0);

    /* Pinning, etc. is handled via _prefetch_pin() call. */
    if (advise & C2_ADV_EXTENT)
    {
        /* We are going to operate on a whole extent.
         * Massage cep & chunks to match. */
        cep.offset = 0;
        chunks = castle_extent_size_get(cep.ext_id);
    }
    castle_cache_prefetch_pin(cep, chunks, advise);

    return EXIT_SUCCESS;
}

/**
 * Advise the cache to clear prior requests on a given extent/offset.
 *
 * @param cep       Extent/offset to operate on/from
 * @param advise    Advise for the cache
 * @param chunks    For future use
 * @param priority  For future use
 * @param debug     Whether to print debug info
 *
 * - If operating on an extent (advise & C2_ADV_EXTENT) manipulate cep and
 *   chunks to span the whole extent.
 *
 * @TODO needs to handle multiple requests at once (e.g. C2_ADV_HARDPIN & C2_ADV_SOFTPIN).
 *
 * @also castle_cache_prefetch_unpin()
 */
int castle_cache_advise_clear(c_ext_pos_t cep, c2_advise_t advise, int chunks,
                              int priority, int debug)
{
    /* Downgrade to softpin if hardpinning is disabled. */
    if (!castle_cache_allow_hardpinning && (advise & C2_ADV_HARDPIN))
    {
        advise &= ~C2_ADV_HARDPIN;
        advise |=  C2_ADV_SOFTPIN;
    }

    /* There's no such thing as 'unprefetching'. */
    if (advise & C2_ADV_PREFETCH && !(advise & C2_ADV_EXTENT))
        return -ENOSYS;

    /* Unpinning, etc. is handled via _prefetch_unpin() call. */
    if (advise & C2_ADV_EXTENT)
    {
        /* We are going to operate on a whole extent.
         * Massage cep & chunks to match. */
        cep.offset = 0;
        chunks = castle_extent_size_get(cep.ext_id);
    }
    castle_cache_prefetch_unpin(cep, chunks, advise);

    return EXIT_SUCCESS;
}

/**
 * Wait for all outstanding prefetch IOs to complete.
 */
void castle_cache_prefetches_wait(void)
{
    wait_event(castle_cache_prefetch_wq,
            atomic_read(&castle_cache_prefetch_in_flight) == 0);
}

/**
 * Wait for all outstanding prefetch IOs to complete.
 */
static void castle_cache_prefetch_fini(void)
{
    castle_cache_prefetches_wait();
}

#ifdef CASTLE_DEBUG
static int castle_cache_debug_counts = 1;
void castle_cache_debug(void)
{
    int dirty, clean, free, diff;

    if(!castle_cache_debug_counts)
        return;

    dirty = atomic_read(&castle_cache_dirty_pages);
    clean = atomic_read(&castle_cache_clean_pages);
    free  = PAGES_PER_C2P * castle_cache_page_freelist_size;

    diff = castle_cache_size - (dirty + clean + free);
    if(diff < 0) diff *= (-1);
    if(diff > castle_cache_size / 10)
    {
        castle_printk(LOG_ERROR, "ERROR: Castle cache pages do not add up:\n"
               "       #dirty_pgs=%d, #clean_pgs=%d, #freelist_pgs=%d\n",
                dirty, clean, free);
    }
    castle_cache_stats_print(1);
}

void castle_cache_debug_fini(void)
{
    castle_cache_debug_counts = 0;
}
#else
#define castle_cache_debug_fini()    ((void)0)
#endif

/**********************************************************************************************
 * Flush thread functions.
 */

/**
 * IO completion callback handler for castle_cache_extent_flush().
 *
 * Doubles as IO completion CB handler for castle_cache_flush() as this calls
 * __castle_cache_extent_flush() to do the dirty work.
 *
 * @param c2b   c2b that has been flushed to disk
 *
 * @also __castle_cache_extent_flush()
 * @also castle_cache_flush()
 */
static void castle_cache_extent_flush_endio(c2_block_t *c2b)
{
    atomic_t *in_flight = c2b->private; /* outstanding IOs count */

    /* Clear flushing bit and release read lock. */
    BUG_ON(!c2b_flushing(c2b));
    clear_c2b_flushing(c2b);
    read_unlock_c2b(c2b);
    put_c2b(c2b);

    /* Decrementing outstanding IOs count and signal waiters. */
    BUG_ON(atomic_dec_return(in_flight) < 0);
    atomic_inc(&castle_cache_flush_seq);
    wake_up(&castle_cache_flush_wq);
}

static void castle_cache_flush_endio(c2_block_t *c2b);

/**
 * Flush a batch of dirty c2bs.
 *
 * @param   c2b_batch   Array of dirty c2bs
 * @param   batch_idx   Number of dirty c2bs in c2b_batch
 * @param   in_flight_p Number of c2bs currently in-flight
 *
 * @also __castle_cache_extent_flush()
 */
static inline void __castle_cache_extent_flush_batch(c2_block_t         *c2b_batch[],
                                                     int                *batch_idx,
                                                     c2b_end_io_t        end_io,
                                                     atomic_t           *in_flight_p)
{
    int i;

    for (i = 0; i < *batch_idx; i++)
    {
        /* Handle flush thread, differently, as it needs two counters. Global inflight counter -
         * for flush  thread rate limiting. Per extent inflight counter - to release extent
         * references. */
        if (end_io == castle_cache_flush_endio)
        {
            c_ext_inflight_t *data = (c_ext_inflight_t *)in_flight_p;

            atomic_inc(data->in_flight);
            atomic_inc(&data->ext_in_flight);
        }
        else
            atomic_inc(in_flight_p);

        c2b_batch[i]->end_io  = end_io;
        c2b_batch[i]->private = (void *)in_flight_p;
        BUG_ON(submit_c2b(WRITE, c2b_batch[i]));
    }

    *batch_idx = 0;
}

/**
 * Submit async IO on max_pgs dirty pages from start of extent to end_off.
 *
 * @param dirtytree     [in]    Per-extent dirtytree to flush
 * @param end_off       [in]    Bytes to flush from start
 *                                  0 => end of extent
 * @param max_pgs       [in]    Maximum number of pages to flush from extent
 *                                  0 => no limit
 * @param in_flight_p   [both]  Number of c2bs currently in-flight
 * @param flushed_p     [out]   Number of pages flushed from extent
 * @param waitlock      [in]    True if caller wants to block on c2b readlock,
 *                              otherwise use read_trylock()
 *
 * Caller must hold an explicit reference to the dirtytree otherwise in the
 * process of submitting IOs the IO completion handlers might free the tree.
 *
 * NOTE: max_pgs is an estimate of the number of dirty pages that will be
 *       flushed due to overlapping c2bs and dirty c2bs comprised of a mixture
 *       or dirty and clean c2ps.
 *
 * NOTE: While overlapping c2bs are permitted within the cache in practice they
 *       should not occur so are BUG_ON()ed.  Indeed, if they did it could lead
 *       to potential deadlocks when waitlock is set.  See #2237 for details.
 *
 * @also castle_cache_extent_flush()
 */
static void __castle_cache_extent_flush(c_ext_dirtytree_t  *dirtytree,
                                        c_byte_off_t        start_off,
                                        c_byte_off_t        end_off,
                                        int                 max_pgs,
                                        c2b_end_io_t        end_io,
                                        atomic_t           *in_flight_p,
                                        int                *flushed_p,
                                        int                 waitlock)
{
    c2_block_t *c2b;
    struct rb_node *parent;
    c2_block_t *c2b_batch[CASTLE_CACHE_FLUSH_BATCH_SIZE];
    int batch_idx, flushed = 0;

    /* Flush from the beginning of the extent to end_off.
     * If end_off is not specified, flush the entire extent. */
    if (end_off == 0)
        end_off = -1;

    /* If max_pgs is not specified, set a huge limit. */
    if (max_pgs == 0)
        max_pgs = INT_MAX;

    debug("Extent flush: (%llu) -> %llu\n", dirtytree->ext_id, nr_pages/BLKS_PER_CHK);
    do
    {
        c_byte_off_t last_end_off;
        int dirtytree_locked;

        batch_idx = 0;

restart_traverse:
        /* Hold dirtytree lock. */
        spin_lock_irq(&dirtytree->lock);
        dirtytree_locked = 1;
        last_end_off = 0;

        /* Walk dirty c2bs until we hit end_off or flush max_pgs. */
        parent = rb_first(&dirtytree->rb_root);
        while (parent)
        {
            /* Flush the current batch if it is full. */
            if (batch_idx >= CASTLE_CACHE_FLUSH_BATCH_SIZE)
                break;

            c2b = rb_entry(parent, c2_block_t, rb_dirtytree);
            BUG_ON(c2b->dirtytree != dirtytree);

            /* Flush is complete if we reached end_off or flushed max_pgs. */
            if (c2b->cep.offset > end_off || flushed >= max_pgs)
            {
                parent = NULL; /* outer loop while clause */
                break;
            }

            /* If c2b is not in range, skip to next c2b. */
            if ((c2b->cep.offset  + (c2b->nr_pages * PAGE_SIZE) - 1) < start_off)
                goto next_c2b;

            if (test_set_c2b_flushing(c2b))
                goto next_c2b; /* already flushing, skip to next c2b */
            while (!read_trylock_c2b(c2b))
            {
                if (unlikely(waitlock))
                {
                    /* We want to block until we have a c2b readlock. */
                    if (unlikely(dirtytree_locked))
                    {
                        /* First time we've failed to lock this c2b.  Take a
                         * temporary reference before we drop the dirtytree
                         * lock.  We'll also flush the current batch of c2bs
                         * before going to sleep, to prevent deadlocks. */
                        get_c2b(c2b);
                        spin_unlock_irq(&dirtytree->lock);
                        dirtytree_locked = 0;
                        __castle_cache_extent_flush_batch(c2b_batch,
                                                          &batch_idx,
                                                          end_io,
                                                          in_flight_p);

                        /* Dirty c2bs should never overlap. */
                        BUG_ON(c2b->cep.offset < last_end_off);
#ifdef CASTLE_DEBUG
                        castle_printk(LOG_DEBUG,
                                "%s::waiting on c2b locked from: %s:%d\n",
                                __FUNCTION__, c2b->file, c2b->line);
#endif
                    }
                    msleep(1);
                }
                else
                    goto cant_lock;
            }
            if (!c2b_uptodate(c2b) || !c2b_dirty(c2b))
                goto dont_flush;

            /* This c2b will be flushed. */
            get_c2b(c2b);
            c2b_batch[batch_idx++] = c2b;
            flushed += castle_cache_c2b_to_pages(c2b);

            goto next_c2b;

dont_flush: read_unlock_c2b(c2b);
cant_lock:  clear_c2b_flushing(c2b);
next_c2b:
            if (likely(dirtytree_locked))
                parent = rb_next(parent);
            else
            {
                put_c2b(c2b); /* extra ref */
                goto restart_traverse;
            }

            /* Calculate extent offset where current c2b ends. */
            last_end_off = c2b->cep.offset
                            + castle_cache_c2b_to_pages(c2b) * PAGE_SIZE;
        }

        /* Release holds. */
        if (likely(dirtytree_locked))
            spin_unlock_irq(&dirtytree->lock);

        /* Flush batch of c2bs. */
        __castle_cache_extent_flush_batch(c2b_batch, &batch_idx, end_io, in_flight_p);
    } while (parent);

    /* Return number of pages to caller, if requested. */
    if (flushed_p)
        *flushed_p = flushed;
}

/**
 * Synchronously flush dirty pages from beginning of extent to start+size.
 * Extent must exist, checked with a BUG_ON(!dirtytree).
 *
 * NOTE: start is currently ignored; we always flush from the beginning of
 *       the extent to start+size.
 *
 * @param ext_id    Extent to flush
 * @param start     Byte offset to flush from   (legacy, ignored)
 * @param size      Bytes to flush from start   (0 => whole extent)
 * @param ratelimit Ratelimit in KB/s           (0 => unlimited)
 */
void castle_cache_extent_flush(c_ext_id_t ext_id,
                               uint64_t start,
                               uint64_t size,
                               unsigned int ratelimit)
{
    atomic_t in_flight = ATOMIC(0);
    c_ext_dirtytree_t *dirtytree;
    int batch, batch_period, io_time, flushed;
    unsigned long io_start;

    /* Get the dirtytree. */
    dirtytree = castle_extent_dirtytree_by_id_get(ext_id);
    BUG_ON(!dirtytree);

    /* Flush 8 MB at the time if there is a ratelimit. */
    batch = INT_MAX;
    batch_period = 0;
    if(ratelimit != 0)
    {
        batch = 8 * 256;
        /* Work out how long it should take to flush each batch in order
           to achieve the specified rate. In msecs. */
        batch_period = (4 * 1000 * batch) / ratelimit;
    }

    /* Continue flushing batches for as long as there are dirty blocks
       in the specified range. */
    do {
        /* Record when the flush starts. */
        io_start = jiffies;

        /* Schedule flush of up to batch pages. */
        __castle_cache_extent_flush(dirtytree,                      /* dirtytree    */
                                    start,                          /* start offset */
                                    start + size - 1,               /* end offset   */
                                    batch,                          /* max_pgs      */
                                    castle_cache_extent_flush_endio,/* callback     */
                                    &in_flight,                     /* callback data*/
                                    &flushed,                       /* flushed_p    */
                                    1);                             /* waitlock     */

        /* Wait for IO from the current batch to complete. */
        wait_event(castle_cache_flush_wq, (atomic_read(&in_flight) == 0));

        /* If there is ratelimiting, sleep for the required amount of time. */
        if((ratelimit != 0) && (flushed > 0))
        {
            io_time = jiffies_to_msecs(jiffies - io_start);
            /* Only go to sleep if IO took less time than batch_period. */
            if(batch_period > io_time)
                msleep_interruptible(batch_period - io_time);
        }

    } while(flushed > 0);

    /* Put the dirtytree. */
    castle_extent_dirtytree_put(dirtytree);

    /* There should be no IO in flight by now. */
    BUG_ON(atomic_read(&in_flight) != 0);
}

/**
 * Evict dirty blocks for specified extent from the cache.
 *
 * @TODO Make this castle_cache_advise() functionality.
 *
 * @also _castle_extent_free()
 */
void castle_cache_extent_evict(c_ext_dirtytree_t *dirtytree, c_chk_cnt_t start, c_chk_cnt_t count)
{
    atomic_t in_flight = ATOMIC(0);
    int flushed = 0;

    /* Schedule flush of up to batch pages. */
    __castle_cache_extent_flush(dirtytree,                              /* dirtytree    */
                                start * C_CHK_SIZE,                     /* start offset */
                                (start + count) * C_CHK_SIZE  - 1,      /* end offset   */
                                0,                                      /* max_pgs      */
                                castle_cache_extent_flush_endio,        /* Callback     */
                                &in_flight,                             /* Callback data*/
                                &flushed,                               /* flushed_p    */
                                1);                                     /* waitlock     */

    /* We shouldn't have scheduled any pages for I/O. */
    BUG_ON(atomic_read(&in_flight));
}

/**
 * Comparator for elements on the dirtylist, used by castle_cache_flush().
 *
 * NOTE: Return values are the reverse of what a normal comparator might be
 *       expected to return.  This is to ensure that the dirtylist is sorted
 *       in descending order.
 *
 * @return <0   l1 is greater than l2
 * @return  0   l1 is the same size as l2
 * @return >0   l2 is smaller than l1
 */
int castle_cache_dirtytree_compare(struct list_head *l1, struct list_head *l2)
{
    c_ext_dirtytree_t *dirtytree;
    int s1, s2;

    dirtytree = list_entry(l1, c_ext_dirtytree_t, list);
    s1 = castle_extent_size_get(dirtytree->ext_id);
    dirtytree = list_entry(l2, c_ext_dirtytree_t, list);
    s2 = castle_extent_size_get(dirtytree->ext_id);

    if (s1 > s2)
        return -1;
    else if (s1 < s2)
        return 1;
    else
        return 0;
}

static void castle_cache_flush_endio(c2_block_t *c2b)
{
    c_ext_inflight_t *data = c2b->private;

    /* Clear flushing bit and release read lock. */
    BUG_ON(!c2b_flushing(c2b));
    clear_c2b_flushing(c2b);
    read_unlock_c2b(c2b);
    put_c2b(c2b);

    /* Decrementing outstanding IOs count and signal waiters. */
    BUG_ON(atomic_dec_return(data->in_flight) < 0);

    /* If per extent inflight count reached 0, time to release the reference. */
    if (atomic_dec_return(&data->ext_in_flight) == 0)
    {
        castle_extent_put_all(data->mask_id);
        kmem_cache_free(castle_flush_cache, data);
    }

    atomic_inc(&castle_cache_flush_seq);
    wake_up(&castle_cache_flush_wq);
}

static inline int castle_cache_flush_nr_slaves(void)
{
    static int cache_nr_slaves;
    int tmp_nr_slaves;
    static unsigned long last_nr_slaves_check_jiffies = 0;
#define nr_slaves_sane(_cnt)  (((_cnt) >= 1) && ((_cnt) <= MAX_NR_SLAVES))

    /* Only recheck sporadically. */
    if(likely(last_nr_slaves_check_jiffies + 10 * HZ > jiffies))
        goto out;

    /* Work out how many slaves we've got. */
    tmp_nr_slaves = castle_nr_slaves_get();
    if(!nr_slaves_sane(tmp_nr_slaves))
        tmp_nr_slaves = 1;

    /* Once sanity checked, assign to the cached variable. */
    cache_nr_slaves = tmp_nr_slaves;
    /* Update the check jiffies. */
    last_nr_slaves_check_jiffies = jiffies;

out:
    BUG_ON(!nr_slaves_sane(cache_nr_slaves));
    return cache_nr_slaves;
}

/**
 * Flush dirty blocks to disk and place them on the cleanlist.
 *
 * Fundamentally this function walks castle_cache_extent_dirtylist (the global
 * list of dirty extents) and calls __castle_cache_extent_flush() on each dirty
 * extent until a suitable number of pages have been flushed.
 *
 * The unit of flush is a page, derived from c2b->nr_pages.  Dirty blocks might
 * not consist of some dirty and some clean c2ps.  Furthermore those blocks may
 * overlap.  As such the calculation in __castle_cache_extent_flush() of pages
 * that were submitted to be flushed is inaccurate (but good enough for our
 * purposes).
 *
 * - Wait for 95% of outstanding flush IOs to complete
 * - Wait until there are at least MIN_FLUSH_SIZE pages to flush (or timeout
 *   occurs)
 * - Calculate the number of pages we will try to flush this run
 * - Grab the first dirty extent from castle_cache_extent_dirtylist and take
 *   a reference to it
 * - Push held extent to the back of the list
 * - Schedule a flush via __castle_cache_extent_flush()
 * - Drop the reference
 * - Pick the next extent from the dirtylist and repeat until we have flushed
 *   enough IOs
 *
 * @also __castle_cache_extent_flush()
 */
static int castle_cache_flush(void *unused)
{
#define MIN_FLUSH_SIZE              128
#define MAX_FLUSH_SIZE              (10*256*castle_cache_flush_nr_slaves())
                                              /* 10MB/s per slave.                    */
#define MIN_EFFICIENT_DIRTYTREE     (5*256)   /* In pages, equals 5MB                 */
#define MIN_FLUSH_FREQ  5                     /* Min flush rate: 5*128pgs/s = 2.5MB/s */
    int exiting, target_dirty_pgs, dirty_pgs, to_flush, last_flush, i, prio, aggressive;
    atomic_t in_flight = ATOMIC(0);
    c_chk_cnt_t start_chk;
    c_chk_cnt_t end_chk;

    /* Try and keep 3/4 of pages in the cache dirty. */
    target_dirty_pgs = 3 * (castle_cache_size / 4);
    last_flush = 0;

    while (1)
    {
        /* If castle_cache_fini() is called, flush everything then exit. */
        exiting = kthread_should_stop();

        /* Wait for 95% of outstanding flush IOs to complete (all if exiting).
         *
         * When exiting we need to wait for all IOs to complete or we may busy
         * loop (in_flight wait_event() never sleeps). */
        wait_event(castle_cache_flush_wq,
                (exiting ? (atomic_read(&in_flight) == 0)
                         : (atomic_read(&in_flight) <= last_flush / 20)));

        /* Wait until we have a worthwhile number of pages to flush.
         * This limits us to a min of 10 MIN_BATCHES/s. */
        wait_event_interruptible_timeout(castle_cache_flush_wq,
                exiting || (atomic_read(&castle_cache_dirty_pages)
                    - target_dirty_pgs >= MIN_FLUSH_SIZE),
                HZ/MIN_FLUSH_FREQ);

        dirty_pgs = atomic_read(&castle_cache_dirty_pages);

        /* Exit if we've finished waiting for all outstanding IOs. */
        if (unlikely(exiting))
        {
            /* Exit iff all dirtylists have been drained. */
            for(i=0; i<NR_EXTENT_FLUSH_PRIOS; i++)
                if(atomic_read(&castle_cache_extent_dirtylist_sizes[i]) != 0)
                    break;
            if(i >= NR_EXTENT_FLUSH_PRIOS)
                break; /* only way out */

            /* We've not finished the flush.  Set last_flush such that it will
             * attempt to flush all dirty c2bs.  We don't use dirty_pgs here
             * due to overlapping c2bs. */
            to_flush = INT_MAX;
        }
        else
        {
            /* We're not exiting, calculate the number of pages to flush.
             *
             * Calculate the number of pages dirtied since the last iteration.
             * Flush at least MIN_FLUSH_SIZE, at most MAX_FLUSH_SIZE and not
             * more than the number of dirty pages within the cache. */
            to_flush = dirty_pgs - target_dirty_pgs;    /* ~#pgs dirtied since last iter    */
            to_flush = max(MIN_FLUSH_SIZE, to_flush);   /* at least MIN_FLUSH_SIZE pgs      */
            to_flush = min(MAX_FLUSH_SIZE, to_flush);   /* at max MAX_FLUSH_SIZE pgs        */
            to_flush = min(dirty_pgs,      to_flush);   /* and no more than are dirty.      */
        }
        last_flush = to_flush;

        /* Iterate over all dirty extents trying to find pages to flush.
           Try flushing extents from high priority (i.e. low value) dirtylists first.
           Start with 'non-aggressive' flush (i.e. when only extents that are deemed
           to be worth-while flushing are flushed), if to_flush pages aren't found,
           switch to aggressive.
         */
        aggressive = 0;
aggressive:
        for(prio = 0; prio < NR_EXTENT_FLUSH_PRIOS; prio++)
        {
            c_ext_dirtytree_t *dirtytree;
            int flushed = 0;

            /* Stop looping if we've managed to flush enough pages. */
            if(to_flush <= 0)
                break;

            /* Record the size of this list at this point in time,
               stop processing extents once we checked that many
               (more extents could be added, or some removed while
                we are doing this. What matter is that we stop eventually). */
            i = atomic_read(&castle_cache_extent_dirtylist_sizes[prio]);

            while((--i >= 0) && (to_flush > 0))
            {
                c_ext_mask_id_t mask_id = INVAL_MASK_ID;
                c_ext_inflight_t *data = NULL;

                might_resched();

                /* Get next per-extent dirtytree to flush. */
                spin_lock_irq(&castle_cache_block_lru_lock);

                /* The dirtylist might have became empty once between us reading
                   its size, and taking the lru lock. Check for that. */
                if(list_empty(&castle_cache_extent_dirtylists[prio]))
                {
                    spin_unlock_irq(&castle_cache_block_lru_lock);
                    /* Exit the loop early. */
                    i=0;
                    continue;
                }

                dirtytree = list_entry(castle_cache_extent_dirtylists[prio].next,
                        c_ext_dirtytree_t, list);
                /* Get dirtytree ref under castle_cache_block_lru_lock.  Prevents
                 * a potential race where all c2bs in tree are flushing and final
                 * c2b IO completion callback handler might free the dirtytree. */
                castle_extent_dirtytree_get(dirtytree);
                /* Move it to the end of the list. So that next time a different
                   extent will be considered next time around. */
                list_move_tail(&dirtytree->list, &castle_cache_extent_dirtylists[prio]);

                spin_unlock_irq(&castle_cache_block_lru_lock);

                mask_id = castle_extent_all_masks_get(dirtytree->ext_id);
                /* Check if extent is already dead. This shouldn't happen as before we delete
                 * the extent, we get rid off all dirty pages. It could happen only if after last
                 * link is gone. */
                if (MASK_ID_INVAL(mask_id))
                    goto err_out;

                /* On non-aggressive scan, only flush extents with plenty of dirty
                   blocks. This makes IO more efficient. */
                if(!aggressive &&
                   prio != DEAD_EXT_FLUSH_PRIO &&
                   dirtytree->nr_pages < MIN_EFFICIENT_DIRTYTREE)
                    goto err_out;

                /* We need to pass two reference counts to __castle_cache_extent_flush() one
                 * for global counting (for rate limiting) and another per extent count to
                 * release references. */
                data = kmem_cache_alloc(castle_flush_cache, GFP_KERNEL);
                if (!data)
                {
                    castle_printk(LOG_DEVEL, "Failed to allocate space for flush element.\n");
                    goto err_out;
                }
                data->in_flight = &in_flight;
                /* Give an initial reference, to handle end_io(c2b) being called before issuing all
                 * submit_c2b(). */
                atomic_set(&data->ext_in_flight, 1);

                data->mask_id = mask_id;

                /* Get the range of extent. */
                castle_extent_mask_read_all(dirtytree->ext_id, &start_chk, &end_chk);

                /* Flushed will be set to an approximation of pages flushed. */
                __castle_cache_extent_flush(dirtytree,                      /* dirtytree    */
                                            start_chk * C_CHK_SIZE,         /* start offset */
                                            (end_chk + 1) * C_CHK_SIZE - 1, /* end offset   */
                                            to_flush,                       /* max_pgs      */
                                            castle_cache_flush_endio,       /* Callback     */
                                            (atomic_t *)data,               /* Callback data*/
                                            &flushed,                       /* flushed_p    */
                                            0);                             /* waitlock     */

                to_flush -= flushed;

                /* If per extent inflight count reached 0, time to release the reference. All
                 * io's completed or failed, or nothing scheduled for flush. */
                if (!atomic_dec_return(&data->ext_in_flight))
                    goto err_out;

                castle_extent_dirtytree_put(dirtytree);

                continue;

err_out:
                castle_extent_dirtytree_put(dirtytree);
                if (!MASK_ID_INVAL(mask_id))
                    castle_extent_put_all(mask_id);
                if (data)
                    kmem_cache_free(castle_flush_cache, data);
            }
        }

        /* Check that enough pages were found, if not go through the extents more
           exhaustively. */
        if(!aggressive && (to_flush > 0))
        {
            aggressive = 1;
            goto aggressive;
        }
    }

    BUG_ON(atomic_read(&in_flight) != 0);
    /* Exiting the flush thread. We shouldn't need locks to check these lists now. */
    for (i = 0; i < NR_EXTENT_FLUSH_PRIOS; i++)
    {
        BUG_ON(atomic_read(&castle_cache_extent_dirtylist_sizes[i]) != 0);
        BUG_ON(!list_empty(&castle_cache_extent_dirtylists[i]));
    }

    return EXIT_SUCCESS;
}

/***** Init/fini functions *****/
static int castle_cache_flush_init(void)
{
    castle_cache_flush_thread = kthread_run(castle_cache_flush, NULL, "castle_flush");
    return 0;
}

static void castle_cache_flush_fini(void)
{
    kthread_stop(castle_cache_flush_thread);
}

static int castle_cache_hashes_init(void)
{
    int i;

    if(!castle_cache_page_hash || !castle_cache_page_hash_locks || !castle_cache_block_hash)
        return -ENOMEM;

    /* Init the tables. */
    for(i=0; i<castle_cache_page_hash_buckets; i++)
        INIT_HLIST_HEAD(&castle_cache_page_hash[i]);
    for(i=0; i<(castle_cache_page_hash_buckets / PAGE_HASH_LOCK_PERIOD + 1); i++)
        spin_lock_init(&castle_cache_page_hash_locks[i]);
    for(i=0; i<castle_cache_block_hash_buckets; i++)
        INIT_HLIST_HEAD(&castle_cache_block_hash[i]);

    return 0;
}

/**
 * Release all items and tear down hashes.
 *
 * - All items should have 0 reference counts (anything else indicates a leak).
 */
static void castle_cache_hashes_fini(void)
{
    struct hlist_node *l, *t;
    c2_block_t *c2b;
    int i;

    if(!castle_cache_block_hash || !castle_cache_page_hash)
    {
        castle_check_free(castle_cache_block_hash);
        castle_check_free(castle_cache_page_hash);
        castle_check_free(castle_cache_page_hash_locks);
        return;
    }

    for(i=0; i<castle_cache_block_hash_buckets; i++)
    {
        hlist_for_each_entry_safe(c2b, l, t, &castle_cache_block_hash[i], hlist)
        {
            hlist_del(l);
            /* Buffers should not be in use any more (devices do not exist) */
            if((atomic_read(&c2b->count) != 0) || c2b_locked(c2b))
            {
                castle_printk(LOG_WARN, "cep="cep_fmt_str" not dropped count=%d, locked=%d.\n",
                    cep2str(c2b->cep), atomic_read(&c2b->count), c2b_locked(c2b));
#ifdef CASTLE_DEBUG
                if(c2b_locked(c2b))
                    castle_printk(LOG_DEVEL, "Locked from: %s:%d\n", c2b->file, c2b->line);
#endif
            }
            BUG_ON(c2b_dirty(c2b));
            list_del(&c2b->clean);

            /* Cleanlist accounting. */
            atomic_dec(&castle_cache_cleanlist_size);
            if (c2b_softpin(c2b))
                atomic_dec(&castle_cache_cleanlist_softpin_size);

            castle_cache_block_free(c2b);
        }
    }

    /* Ensure cleanlist accounting is in order. */
    BUG_ON(atomic_read(&castle_cache_cleanlist_size) != 0);
    BUG_ON(atomic_read(&castle_cache_cleanlist_softpin_size) != 0);
    BUG_ON(atomic_read(&c2_pref_active_window_size) != 0);
    BUG_ON(c2_pref_total_window_size != 0);
    BUG_ON(!RB_EMPTY_ROOT(&c2p_rb_root));

#ifdef CASTLE_DEBUG
    /* All cache pages should have been removed from the hash by now (there are no c2bs left) */
    for(i=0; i<castle_cache_page_hash_buckets; i++)
    {
        c2_page_t *c2p;

        hlist_for_each_entry(c2p, l, &castle_cache_page_hash[i], hlist)
        {
            castle_printk(LOG_ERROR, "c2p->id=%d not freed, count=%d, cep="cep_fmt_str_nl,
                c2p->id, c2p->count, cep2str(c2p->cep));
            BUG();
        }
    }
#endif
}

static int castle_cache_c2p_init(c2_page_t *c2p)
{
    int j;

    c2p->count = 0;
    init_rwsem(&c2p->lock);
    /* Allocate pages for this c2p */
    for(j=0; j<PAGES_PER_C2P; j++)
    {
        struct page *page = alloc_page(GFP_KERNEL);

        if(!page)
            goto err_out;

        /* Add page to the c2p */
        c2p->pages[j] = page;
#ifdef CASTLE_DEBUG
        /* For debugging, save the c2p pointer in used lru list. */
        page->lru.next = (void *)c2p;
#endif
    }

    return 0;

err_out:
    for(j--; j>=0; j--)
        __free_page(c2p->pages[j]);

    return -ENOMEM;
}

static void castle_cache_c2b_init(c2_block_t *c2b)
{
    c2b->c2ps = NULL;
    atomic_set(&c2b->lock_cnt, 0);
    INIT_HLIST_NODE(&c2b->hlist);
    /* This effectively also does:
        INIT_LIST_HEAD(&c2b->dirty);
        INIT_LIST_HEAD(&c2b->clean);
        INIT_LIST_HEAD(&c2b->reserve); */
    INIT_LIST_HEAD(&c2b->free);
}

/**
 * Initialise freelists (handles c2bs and c2ps).
 *
 * - Zero the c2b and c2p arrays
 * - Initialise individual array elements
 * - Place CASTLE_CACHE_RESERVELIST_QUOTA c2bs/c2ps onto respective
 *   meta-extent reserve freelists
 * - Place remaining c2bs/c2ps onto respective freelists
 *
 * @also castle_cache_freelists_fini()
 */
static int castle_cache_freelists_init(void)
{
    int i;

    if (!castle_cache_blks || !castle_cache_pgs)
        return -ENOMEM;

    memset(castle_cache_blks, 0, sizeof(c2_block_t) * castle_cache_block_freelist_size);
    memset(castle_cache_pgs,  0, sizeof(c2_page_t)  * castle_cache_page_freelist_size);

    /* Initialise the c2p freelist and meta-extent reserve freelist. */
    BUG_ON(CASTLE_CACHE_RESERVELIST_QUOTA >= castle_cache_page_freelist_size);
    for (i = 0; i < castle_cache_page_freelist_size; i++)
    {
        c2_page_t *c2p = castle_cache_pgs + i;

        castle_cache_c2p_init(c2p);
#ifdef CASTLE_DEBUG
        c2p->id = i;
#endif

        /* Thread c2p onto the relevant freelist. */
        if (unlikely(i < CASTLE_CACHE_RESERVELIST_QUOTA))
            list_add(&c2p->list, &castle_cache_page_reservelist);
        else
            list_add(&c2p->list, &castle_cache_page_freelist);
    }
    /* Finish by adjusting the freelist sizes. */
    castle_cache_page_freelist_size  -= CASTLE_CACHE_RESERVELIST_QUOTA;
    atomic_set(&castle_cache_page_reservelist_size, CASTLE_CACHE_RESERVELIST_QUOTA);

    /* Initialise the c2b freelist and meta-extent reserve freelist. */
    BUG_ON(CASTLE_CACHE_RESERVELIST_QUOTA >= castle_cache_block_freelist_size);
    for (i = 0; i < castle_cache_block_freelist_size; i++)
    {
        c2_block_t *c2b = castle_cache_blks + i;

        castle_cache_c2b_init(c2b);

        /* Thread c2b onto the relevant freelist. */
        if (unlikely(i < CASTLE_CACHE_RESERVELIST_QUOTA))
        {
            list_add(&c2b->reserve, &castle_cache_block_reservelist);
            atomic_inc(&castle_cache_block_reservelist_size);
        }
        else
            list_add(&c2b->free, &castle_cache_block_freelist);
    }
    /* Finish by adjust the freelist sizes. */
    castle_cache_block_freelist_size -= CASTLE_CACHE_RESERVELIST_QUOTA;
    atomic_set(&castle_cache_block_reservelist_size, CASTLE_CACHE_RESERVELIST_QUOTA);

    return 0;
}

/**
 * Free the freelists.
 *
 * @also castle_cache_freelists_init()
 */
static void castle_cache_freelists_fini(void)
{
    struct list_head *l, *t;
    c2_page_t *c2p;
    int i;
#ifdef CASTLE_DEBUG
    c2_block_t *c2b;
#endif

    if (!castle_cache_blks || !castle_cache_pgs)
    {
        castle_check_free(castle_cache_blks);
        castle_check_free(castle_cache_pgs);
        return;
    }

    list_splice_init(&castle_cache_page_reservelist, &castle_cache_page_freelist);
    list_for_each_safe(l, t, &castle_cache_page_freelist)
    {
        list_del(l);
        c2p = list_entry(l, c2_page_t, list);
        for(i=0; i<PAGES_PER_C2P; i++)
            __free_page(c2p->pages[i]);
    }

#ifdef CASTLE_DEBUG
    list_splice_init(&castle_cache_block_reservelist, &castle_cache_block_freelist);
    list_for_each_safe(l, t, &castle_cache_block_freelist)
    {
        list_del(l);
        c2b = list_entry(l, c2_block_t, free);
        BUG_ON(c2b->c2ps != NULL);
    }
#endif
}

int castle_checkpoint_version_inc(void)
{
    struct   castle_fs_superblock *fs_sb;
    struct   castle_slave_superblock *cs_sb;
    struct   list_head *lh;
    struct   castle_slave *cs = NULL;
    uint32_t fs_version;

    /* Done with previous checkpoint. Update freespace counters now. Safe to
     * reuse them now. */
    castle_freespace_post_checkpoint();

    /* Goto next version. */
    fs_sb = castle_fs_superblocks_get();
    fs_sb->fs_version++;
    fs_version = fs_sb->fs_version;
    castle_fs_superblocks_put(fs_sb, 1);

    /* Increment version on each slave. */
    rcu_read_lock();
    list_for_each_rcu(lh, &castle_slaves.slaves)
    {
        cs = list_entry(lh, struct castle_slave, list);

        /* Do not checkpoint out-of-service slaves. */
        if (test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags))
            continue;

        cs_sb = castle_slave_superblock_get(cs);
        cs_sb->fs_version++;
        BUG_ON(fs_version != cs_sb->fs_version);
        castle_slave_superblock_put(cs, 1);
    }
    rcu_read_unlock();

    castle_printk(LOG_INFO, "Number of logical extent pages: %u\n",
            atomic_read(&castle_cache_logical_ext_pages));

    return 0;
}

void castle_checkpoint_wait(void)
{
    struct   castle_fs_superblock *fs_sb;
    uint32_t fs_version;
    int max_retries = 1000, exit;
    int castle_checkpoint_period_save;

    /* Read version in. */
    fs_sb = castle_fs_superblocks_get();
    fs_version = fs_sb->fs_version;
    castle_fs_superblocks_put(fs_sb, 0);

    exit = 0;
    castle_checkpoint_period_save = castle_checkpoint_period;
    castle_checkpoint_period = 0;
    while(!exit && max_retries-- > 0)
    {
        msleep(1000);
        fs_sb = castle_fs_superblocks_get();
        if(fs_sb->fs_version > fs_version)
            exit = 1;
        else
            exit = 0;
        castle_fs_superblocks_put(fs_sb, 0);
    }
    if(!exit)
        castle_printk(LOG_ERROR, "Waited for a checkpoint, but it never happened.\n");
    castle_checkpoint_period = castle_checkpoint_period_save;
}

/**
 * Do necessary work before mstores writeback.
 *
 * NOTE: We are not within CASTLE_TRANSACTION.
 *
 * @also castle_mstores_writeback()
 * @also castle_periodic_checkpoint()
 */
int castle_mstores_pre_writeback(uint32_t version)
{
    /* Call pre-writebacks of components. */
    castle_double_arrays_pre_writeback();

    return 0;
}

/**
 * Schedule flush for ext_id at the next checkpoint.
 *
 * - Take an extent reference so the extent persists until the flush
 *   has completed.
 *
 * @also castle_cache_extents_flush()
 */
int castle_cache_extent_flush_schedule(c_ext_id_t ext_id, uint64_t start,
                                       uint64_t count)
{
    struct castle_cache_flush_entry *entry;

    entry = castle_alloc(sizeof(struct castle_cache_flush_entry));
    BUG_ON(!entry);

    /* Take a hard reference on extent, to make sure extent wouldn't disappear during flush. */
    BUG_ON(castle_extent_link(ext_id));

    /* Get a reference on the complete extent space. Releases the reference after
     * completing the flush of the extent in castle_cache_extents_flush(). */
    BUG_ON(MASK_ID_INVAL(entry->mask_id = castle_extent_all_masks_get(ext_id)));

    entry->ext_id = ext_id;
    entry->start  = start;
    entry->count  = count;
    list_add_tail(&entry->list, &castle_cache_flush_list);

    return 0;
}

/**
 * Flush all scheduled extents.
 *
 * - Flush all extents on flush_list
 * - Drop extent reference after flush
 *
 * @param ratelimit     Ratelimit in KB/s, 0 for unlimited.
 *
 * @also castle_cache_extent_flush_schedule()
 */
void castle_cache_extents_flush(struct list_head *flush_list, unsigned int ratelimit)
{
    struct list_head *lh, *tmp;
    struct castle_cache_flush_entry *entry;

    list_for_each_safe(lh, tmp, flush_list)
    {
        entry = list_entry(lh, struct castle_cache_flush_entry, list);
        castle_cache_extent_flush(entry->ext_id, entry->start, entry->count, ratelimit);

        /* Release references. */
        castle_extent_put_all(entry->mask_id);
        castle_extent_unlink(entry->ext_id);

        list_del(lh);
        castle_free(entry);
    }

    BUG_ON(!list_empty(flush_list));
}

extern atomic_t current_rebuild_seqno;

/**
 * Mark the previous ondisk checkpoint slot as invalid on all live slaves.
 *
 * @return  -ENOMEM if out of memory, -EIO if could not flush, otherwise EXIT_SUCCESS.
 */
int castle_slaves_superblock_invalidate(void)
{
    c2_block_t                  *c2b;
    c_ext_pos_t                 cep;
    int                         slot, ret;
    int                         length = (2 * C_BLK_SIZE);
    struct castle_fs_superblock *fs_sb;
    struct castle_slave         *slave;
    struct list_head            *lh;

    fs_sb = castle_fs_superblocks_get();
    /* If current fs version is N, the slot to invalidate is for fs version N-1. */
    slot = (fs_sb->fs_version - 1) % 2;
    castle_fs_superblocks_put(fs_sb, 0);

    rcu_read_lock();
    list_for_each_rcu(lh, &castle_slaves.slaves)
    {
        struct castle_slave_superblock *superblock;

        slave = list_entry(lh, struct castle_slave, list);

        /* Do not attempt bit mod on out-of-service slaves. */
        if ((test_bit(CASTLE_SLAVE_OOS_BIT, &slave->flags)))
            continue;

        /* Calculate CEP for the slave's super extent. */
        cep.ext_id = slave->sup_ext;
        cep.offset = length * slot;

        /* Get c2b for superblock. */
        c2b = castle_cache_block_get(cep, 2);

        write_lock_c2b(c2b);
        if(!c2b_uptodate(c2b))
        {
            ret = (submit_c2b_sync(READ, c2b));
            if (ret)
            {
                /*
                 * If the read failed due to the slave now being OOS, then we don't care.
                 * We can't handle any other reason for this to fail.
                 */
                BUG_ON(!test_bit(CASTLE_SLAVE_OOS_BIT, &slave->flags));
                write_unlock_c2b(c2b);
                put_c2b(c2b);
                continue;
            }
        }

        /* The buffer is the superblock. */
        superblock = (struct castle_slave_superblock *)c2b_buffer(c2b);

        superblock->pub.flags |= CASTLE_SLAVE_SB_INVALID;
        /* Re-calculate checksum for superblock - with checksum bytes set to 0. */
        superblock->pub.checksum = 0;
        superblock->pub.checksum =
                        fletcher32((uint16_t *)superblock, sizeof(struct castle_slave_superblock));

        dirty_c2b(c2b);
        ret = submit_c2b_sync_barrier(WRITE, c2b);
        write_unlock_c2b(c2b);
        put_c2b(c2b);
        if(ret)
        {
            castle_printk(LOG_ERROR,
                          "Failed to invalidate the superblock for slave: 0x%x\n",
                          slave->uuid);
            rcu_read_unlock();
            return -EIO;
        }
    }
    rcu_read_unlock();

    return EXIT_SUCCESS;
}

/**
 * Sets checkpoint extent flushing ratelimit.
 *
 * @param ratelimit Ratelimit in KB/s
 */
void castle_checkpoint_ratelimit_set(unsigned long ratelimit)
{
    /* If ratelimit is smaller than min, ignore the request to set it. */
    if(ratelimit < CASTLE_MIN_CHECKPOINT_RATELIMIT)
    {
        castle_printk(LOG_WARN, "Trying to set checkpoint ratelimit to too small of a rate: %d, "
                                "minimum is %d. Current ratelimit is %d\n",
                                ratelimit,
                                CASTLE_MIN_CHECKPOINT_RATELIMIT,
                                castle_checkpoint_ratelimit);
        return;
    }
    castle_checkpoint_ratelimit = ratelimit;
}

/**
 * Checkpoints system state with given periodicity.
 *
 * Notes: Checkpointing maintains metadata structures of all modules in memory. And checkpoints them
 * in hierarchy, ending with superblocks on slaves. When we completed making superblocks persistent on
 * all slaves, we are done with checkpoint.
 *
 *  START
 *
 *      CHECKPOINT START
 *
 *          - Perform any necessary work prior to starting the TRANSACTION
 *
 *          Notes: During the transaction, no high level modifications can happen like
 *                  - no additions/deletions of trees from DA
 *                  - no additions/deletions of attachments
 *                  - no additions/deletions of versions
 *
 *          TRANSACTION START
 *              - Writedown all meta data structures into a new mstore
 *          TRANSACTION END
 *
 *          - Flush all data (extents belong to previous version) and mstore on to disk
 *          - Flush superblocks onto all slaves
 *
 *      CHECKPOINT END
 *
 *          - Increment version, goto next version
 *
 *  END
 */
static int castle_periodic_checkpoint(void *unused)
{
    uint32_t version = 0;
    struct castle_fs_superblock         *fs_sb;
    struct castle_extents_superblock    *castle_extents_sb;

    int      ret, i;
    struct   list_head flush_list;

    do {
        /* Wakes-up once in a second just to check whether to stop the thread.
         * After every castle_checkpoint_period seconds checkpoints the filesystem. */
        for (i=0;
            (i<MIN_CHECKPOINT_PERIOD) ||
            ((i<castle_checkpoint_period) && (i<MAX_CHECKPOINT_PERIOD));
            i++)
        {
            if (!kthread_should_stop())
                msleep_interruptible(1000);
            else
            {
                castle_last_checkpoint_ongoing = 1;
                castle_last_checkpoint_ongoing = 1;
            }
        }

        if (!castle_fs_inited)
            continue;

        castle_printk(LOG_DEVEL, "***** Checkpoint start (period %ds) *****\n",
                      castle_checkpoint_period);
        castle_trace_cache(TRACE_START, TRACE_CACHE_CHECKPOINT_ID, 0, 0);

        /* Perform any necessary work before we take the transaction lock. */
        if (castle_mstores_pre_writeback(version) != EXIT_SUCCESS)
        {
            castle_printk(LOG_WARN, "Mstore pre-writeback failed.\n");
            castle_trace_cache(TRACE_END, TRACE_CACHE_CHECKPOINT_ID, 0, 0);
            ret = -1;
            goto out;
        }

        CASTLE_TRANSACTION_BEGIN;

        fs_sb = castle_fs_superblocks_get();
        version = fs_sb->fs_version;
        /* Update rebuild superblock information. */
        castle_fs_superblock_slaves_update(fs_sb);
        castle_fs_superblocks_put(fs_sb, 1);

        castle_extent_transaction_start();
        castle_extents_sb = castle_extents_super_block_get();
        castle_extents_sb->current_rebuild_seqno = atomic_read(&current_rebuild_seqno);
        castle_extent_transaction_end();

        /* Save meta extent pool pre-checkpoint state. */
        castle_extent_meta_pool_freeze();

        if (castle_checkpoint_syncing)
        {
            atomic_set(&castle_extents_postsyncvar, 0);
            BUG_ON(atomic_read(&castle_extents_presyncvar));
            atomic_set(&castle_extents_presyncvar, 1);
            wake_up(&process_syncpoint_waitq);
            wait_event_interruptible(process_syncpoint_waitq, atomic_read(&castle_extents_presyncvar) == 0);
        }

        if (castle_mstores_writeback(version, castle_last_checkpoint_ongoing))
        {
            castle_trace_cache(TRACE_END, TRACE_CACHE_CHECKPOINT_ID, 0, 0);
            ret = -2;
            CASTLE_TRANSACTION_END;

            goto out;
        }

        list_replace(&castle_cache_flush_list, &flush_list);
        INIT_LIST_HEAD(&castle_cache_flush_list);

        CASTLE_TRANSACTION_END;

        /* Flush all marked extents from cache. */
        castle_cache_extents_flush(&flush_list,
                                   castle_last_checkpoint_ongoing ? 0 :
                                   max_t(unsigned int,
                                         castle_checkpoint_ratelimit,
                                         CASTLE_MIN_CHECKPOINT_RATELIMIT));

        FAULT(CHECKPOINT_FAULT);

        /* Writeback superblocks. */
        if (castle_superblocks_writeback(version))
        {
            castle_printk(LOG_WARN, "Superblock writeback failed\n");
            castle_trace_cache(TRACE_END, TRACE_CACHE_CHECKPOINT_ID, 0, 0);
            ret = -3;
            goto out;
        }

        if (castle_checkpoint_syncing)
        {
            BUG_ON(atomic_read(&castle_extents_postsyncvar));
            atomic_set(&castle_extents_postsyncvar, 1);
            wake_up(&process_syncpoint_waitq);
        }

        /* All meta extent pool frozen entries can now be freed. */
        castle_extent_meta_pool_free();

        /* Mark previous on-disk checkpoint as invalid. */
        if (castle_slaves_superblock_invalidate())
        {
            ret = -4;
            goto out;
        }

        castle_checkpoint_version_inc();

        castle_printk(LOG_DEVEL, "***** Completed checkpoint of version: %u *****\n", version);
        castle_trace_cache(TRACE_END, TRACE_CACHE_CHECKPOINT_ID, 0, 0);
    } while (!castle_last_checkpoint_ongoing);
    /* Clean exit, return success. */
    ret = 0;
out:
    /* Wait until the thread is explicitly collected. */
    while(!kthread_should_stop())
        msleep_interruptible(1000);

    return ret;
}

int castle_chk_disk(void)
{
    return castle_extents_restore();
}

int castle_checkpoint_init(void)
{
    checkpoint_thread = kthread_run(castle_periodic_checkpoint, NULL,
                                    "castle-checkpoint");
    return 0;
}

void castle_checkpoint_fini(void)
{
    kthread_stop(checkpoint_thread);
}

int castle_cache_init(void)
{
    unsigned long max_ram;
    struct sysinfo i;
    struct mutex* vmap_mutex_ptr;
    int ret, j, cpu_iter;

    /* Find out how much memory there is in the system. */
    si_meminfo(&i);
    max_ram = i.totalram;
    max_ram = max_ram / 2;

    /* Fail if we are trying to use too much. */
    if(castle_cache_size > max_ram)
    {
        castle_printk(LOG_WARN, "Cache size too large, asked for %d pages, "
                "maximum is %ld pages (%ld MB)\n",
                castle_cache_size,
                max_ram, max_ram >> (20 - PAGE_SHIFT));
        return -EINVAL;
    }

    if(castle_cache_size < (CASTLE_CACHE_MIN_SIZE << (20 - PAGE_SHIFT)))
    {
        castle_printk(LOG_WARN, "Cache size too small, asked for %d pages, "
                "minimum is %d pages (%d MB)\n",
                castle_cache_size,
                CASTLE_CACHE_MIN_SIZE << (20 - PAGE_SHIFT),
                CASTLE_CACHE_MIN_SIZE);
        return -EINVAL;
    }

    castle_printk(LOG_INIT, "Cache size: %d pages (%ld MB).\n",
            castle_cache_size, ((unsigned long)castle_cache_size * PAGE_SIZE) >> 20);

    /* Work out the # of c2bs and c2ps, as well as the hash sizes */
    castle_cache_page_freelist_size  = castle_cache_size / PAGES_PER_C2P;
    castle_cache_page_hash_buckets   = castle_cache_page_freelist_size / 2;
    castle_cache_block_freelist_size = castle_cache_page_freelist_size;
    castle_cache_block_hash_buckets  = castle_cache_block_freelist_size / 2;
    /* Allocate memory for c2bs, c2ps and hash tables */
    castle_cache_page_hash  = castle_alloc(castle_cache_page_hash_buckets *
                                           sizeof(struct hlist_head));
    castle_cache_page_hash_locks
        = castle_alloc((castle_cache_page_hash_buckets / PAGE_HASH_LOCK_PERIOD + 1) *
                                             sizeof(spinlock_t));
    castle_cache_block_hash = castle_alloc(castle_cache_block_hash_buckets *
                                           sizeof(struct hlist_head));
    castle_cache_blks       = castle_alloc(castle_cache_block_freelist_size *
                                           sizeof(c2_block_t));
    castle_cache_pgs        = castle_alloc(castle_cache_page_freelist_size  *
                                           sizeof(c2_page_t));
    /* Init other variables */
    for(j=0; j<NR_EXTENT_FLUSH_PRIOS; j++)
    {
        INIT_LIST_HEAD(&castle_cache_extent_dirtylists[j]);
        atomic_set(&castle_cache_extent_dirtylist_sizes[j], 0);
    }
    atomic_set(&castle_cache_dirty_pages, 0);
    atomic_set(&castle_cache_clean_pages, 0);
    atomic_set(&castle_cache_flush_seq, 0);
    atomic_set(&castle_cache_cleanlist_size, 0);
    atomic_set(&castle_cache_cleanlist_softpin_size, 0);
    atomic_set(&castle_cache_block_victims, 0);
    atomic_set(&castle_cache_softpin_block_victims, 0);
    atomic_set(&c2_pref_active_window_size, 0);
    atomic_set(&merge_misses, 0);
    atomic_set(&merge_hits, 0);
    atomic_set(&non_merge_misses, 0);
    atomic_set(&non_merge_hits, 0);
    c2_pref_total_window_size = 0;
    castle_cache_allow_hardpinning = castle_cache_size > CASTLE_CACHE_MIN_HARDPIN_SIZE << (20 - PAGE_SHIFT);
    if (!castle_cache_allow_hardpinning)
        castle_printk(LOG_INIT, "Cache size too small, hardpinning disabled.  "
                "Minimum %d MB required.\n",
                CASTLE_CACHE_MIN_HARDPIN_SIZE);

    if((ret = castle_cache_hashes_init()))    goto err_out;
    if((ret = castle_cache_freelists_init())) goto err_out;
    if((ret = castle_vmap_fast_map_init()))   goto err_out;
    if((ret = castle_cache_flush_init()))     goto err_out;

    /* Initialise per-cpu vmap mutexes */
    for(cpu_iter = 0; cpu_iter < NR_CPUS; cpu_iter++) {
        if(cpu_possible(cpu_iter)) {
            vmap_mutex_ptr = &per_cpu(castle_cache_vmap_lock, cpu_iter);
            mutex_init(vmap_mutex_ptr);
        }
    }

    /* Init kmem_cache for io_array (Structure is too big to fit in stack). */
    castle_io_array_cache = kmem_cache_create("castle_io_array",
                                               sizeof(c_io_array_t),
                                               0,   /* align */
                                               0,   /* flags */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
                                               NULL, NULL); /* ctor, dtor */
#else
                                               NULL); /* ctor */
#endif
    if (!castle_io_array_cache)
    {
        castle_printk(LOG_INIT, "Could not allocate kmem cache for castle cache io arrays.\n");
        goto err_out;
    }

    /* Init kmem_cache for in_flight counters for extent_flush. */
    castle_flush_cache = kmem_cache_create("castle_flush_inflight",
                                            sizeof(c_ext_inflight_t),
                                            0,   /* align */
                                            0,   /* flags */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
                                            NULL, NULL); /* ctor, dtor */
#else
                                            NULL); /* ctor */
#endif
    if (!castle_flush_cache)
    {
        castle_printk(LOG_INIT,
                      "Could not allocate kmem cache for castle_flush_cache.\n");
        goto err_out;
    }

    /* Always trace cache stats. */
    castle_cache_stats_timer_interval = 1;
    if (castle_cache_stats_timer_interval) castle_cache_stats_timer_tick(0);

    return 0;

err_out:
    castle_cache_fini();

    return ret;
}

/**
 * Tear down the castle cache.
 */
void castle_cache_fini(void)
{
    castle_cache_debug_fini();
    castle_cache_prefetch_fini();
    castle_cache_flush_fini();
    castle_cache_hashes_fini();
    castle_vmap_fast_map_fini();
    castle_cache_freelists_fini();

    if(castle_flush_cache)      kmem_cache_destroy(castle_flush_cache);
    if(castle_io_array_cache)   kmem_cache_destroy(castle_io_array_cache);
    if(castle_cache_stats_timer_interval) del_timer_sync(&castle_cache_stats_timer);

    castle_check_free(castle_cache_page_hash);
    castle_check_free(castle_cache_block_hash);
    castle_check_free(castle_cache_page_hash_locks);
    castle_check_free(castle_cache_blks);
    castle_check_free(castle_cache_pgs);
}

/*
 * Determine if a c2b has any clean pages.
 */
int c2b_has_clean_pages(c2_block_t *c2b)
{
    struct page         *page;
    c2_page_t           *c2p;
    c_ext_pos_t         cur_cep;

    c2b_for_each_page_start(page, c2p, cur_cep, c2b)
    {
        /* If any page is clean ... */
        if (!c2p_dirty(c2p))
            return 1;
    }
    c2b_for_each_page_end(page, c2p, cur_cep, c2b);
    return 0;
}
