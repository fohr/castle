#include <linux/sched.h>
#include <linux/bio.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/kthread.h>
#include <linux/vmalloc.h>
#include <linux/rbtree.h>
#include <linux/delay.h>

#include "castle_public.h"
#include "castle.h"
#include "castle_cache.h"
#include "castle_vmap.h"
#include "castle_debug.h"
#include "castle_utils.h"
#include "castle_btree.h"
#include "castle_extent.h"
#include "castle_freespace.h"
#include "castle_da.h"
#include "castle_ctrl.h"
#include "castle_versions.h"


//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)           ((void)0)
#define debug_mstore(_f, _a...)  ((void)0)
#else
#define PREF_DEBUG  /* ensure pref_debug* messages are printed too. */
#define debug(_f, _a...)         (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#define debug_mstore(_f, _a...)  (printk("%s:%.4d:%s " _f, __FILE__, __LINE__ , __func__, ##_a))
#endif

//#define PREF_DEBUG
#ifndef PREF_DEBUG
#define pref_debug(_f, ...)           ((void)0)
#define pref_debug_mstore(_f, _a...)  ((void)0)
#else
#define pref_debug(_f, _a...)         (printk("%s:%.4d: " _f, FLE, __LINE__ , ##_a))
#define pref_debug_mstore(_f, _a...)  (printk("%s:%.4d %s: " _f, FLE, __LINE__ , __func__, ##_a))
#endif

/**********************************************************************************************
 * Cache descriptor structures (c2b & c2p), and related accessor functions. 
 */
enum c2b_state_bits {
    C2B_uptodate,
    C2B_dirty,
    C2B_flushing,
    C2B_prefetch,
    C2B_transient,
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

#define TAS_C2B_FNS(bit, name)                                      \
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
TAS_C2B_FNS(dirty, dirty)
C2B_FNS(flushing, flushing)
TAS_C2B_FNS(flushing, flushing)
C2B_FNS(prefetch, prefetch)
C2B_FNS(transient, transient)
TAS_C2B_FNS(transient, transient)

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
        struct list_head  list;
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
    c_ext_id_t          ext_id;
    uint64_t            start;
    uint64_t            count;
    struct list_head    list;
};

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
    Similarily for iterating over pages.
    NOTE: continue in $(block of code) musn't use continue, because this
          would skip the block of code in c2b_for_each_c2p_end(). 
 */
#define c2b_for_each_c2p_start(_c2p, _cep, _c2b)                         \
{                                                                        \
    int _a, _nr_c2ps;                                                    \
    _nr_c2ps = castle_cache_pages_to_c2ps((_c2b)->nr_pages);             \
    _cep = (_c2b)->cep;                                                  \
    for(_a=0; _a<_nr_c2ps; _a++)                                         \
    {                                                                    \
        _c2p = (_c2b)->c2ps[_a]; 
 
#define c2b_for_each_c2p_end(_c2p, _cep, _c2b)                           \
        (_cep).offset += (PAGES_PER_C2P * PAGE_SIZE);                    \
    }                                                                    \
}

#define c2b_for_each_page_start(_page, _c2p, _cep, _c2b)                 \
{                                                                        \
    c_ext_pos_t __cep;                                                   \
    int _i, _cnt;                                                        \
    _cnt = 0;                                                            \
    c2b_for_each_c2p_start(_c2p, __cep, _c2b)                            \
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
    c2b_for_each_c2p_end(_c2p, __cep, _c2b)                              \
}


/**********************************************************************************************
 * Static variables. 
 */
#define               CASTLE_CACHE_MIN_SIZE   25     /* In MB */ 
static int            castle_cache_size     = 20000; /* In pages */ 

module_param(castle_cache_size, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(castle_cache_size, "Cache size");

static int                     castle_cache_stats_timer_interval = 0; /* in seconds */

module_param(castle_cache_stats_timer_interval, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(castle_cache_stats_timer_interval, "Cache stats print interval (seconds)");

static c2_block_t             *castle_cache_blks = NULL;
static c2_page_t              *castle_cache_pgs  = NULL;

static int                     castle_cache_block_hash_buckets;
static         DEFINE_SPINLOCK(castle_cache_block_hash_lock);
static struct hlist_head      *castle_cache_block_hash = NULL;

static int                     castle_cache_page_hash_buckets;
static         DEFINE_SPINLOCK(castle_cache_page_hash_lock);
static struct hlist_head      *castle_cache_page_hash = NULL;

static               LIST_HEAD(castle_cache_dirtylist);
static               LIST_HEAD(castle_cache_cleanlist);
static atomic_t                castle_cache_dirty_pages;
static atomic_t                castle_cache_clean_pages;

static         DEFINE_SPINLOCK(castle_cache_freelist_lock); /* Lock for the two freelists below */
static int                     castle_cache_page_freelist_size;
static               LIST_HEAD(castle_cache_page_freelist);
static int                     castle_cache_block_freelist_size;
static               LIST_HEAD(castle_cache_block_freelist);

#define CASTLE_CACHE_VMAP_PGS   256
static struct page            *castle_cache_vmap_pgs[CASTLE_CACHE_VMAP_PGS]; 
static           DECLARE_MUTEX(castle_cache_vmap_lock);

static struct task_struct     *castle_cache_flush_thread;
static DECLARE_WAIT_QUEUE_HEAD(castle_cache_flush_wq); 
static atomic_t                castle_cache_flush_seq;

static atomic_t                castle_cache_read_stats = ATOMIC_INIT(0);
static atomic_t                castle_cache_write_stats = ATOMIC_INIT(0);

struct timer_list              castle_cache_stats_timer;

static c_ext_fs_t              mstore_ext_fs;

static atomic_t                mstores_ref_cnt = ATOMIC_INIT(0);
static               LIST_HEAD(castle_cache_flush_list);

#define CHECKPOINT_FREQUENCY (60)        /* Checkpoint once in every 60secs. */
static struct                  task_struct  *checkpoint_thread;
/**********************************************************************************************
 * Prototypes. 
 */
static void c2_pref_c2b_destroy(c2_block_t *c2b);

/**********************************************************************************************
 * Core cache. 
 */
void castle_cache_stats_print(int verbose)
{
    int reads = atomic_read(&castle_cache_read_stats);
    int writes = atomic_read(&castle_cache_write_stats);
    atomic_sub(reads, &castle_cache_read_stats);
    atomic_sub(writes, &castle_cache_write_stats);
    
    if(verbose)
        printk("%d, %d, %d, %d, %d\n", 
            atomic_read(&castle_cache_dirty_pages), 
            atomic_read(&castle_cache_clean_pages),
            castle_cache_page_freelist_size * PAGES_PER_C2P,
            reads, writes);
    perf_value(atomic_read(&castle_cache_dirty_pages), "dirty_pgs");
    perf_value(atomic_read(&castle_cache_clean_pages), "clean_pgs");
    perf_value(castle_cache_page_freelist_size * PAGES_PER_C2P, "free_pgs");
    perf_value(reads, "reads");
    perf_value(writes, "writes");
}

EXPORT_SYMBOL(castle_cache_stats_print);

static void castle_cache_stats_timer_tick(unsigned long foo)
{
    BUG_ON(castle_cache_stats_timer_interval <= 0);

    printk("castle_cache_stats_timer_tick: ");
    castle_cache_stats_print(1);
    printk("\n");

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

static void lock_c2p(c2_page_t *c2p, int write)
{
    if(write)
        down_write(&c2p->lock);
    else
        down_read(&c2p->lock);
}

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

void __lock_c2b(c2_block_t *c2b, int write)
{
    c_ext_pos_t cep_unused;
    c2_page_t *c2p;

    c2b_for_each_c2p_start(c2p, cep_unused, c2b)
    {
        lock_c2p(c2p, write);
    }
    c2b_for_each_c2p_end(c2p, cep_unused, c2b)
    /* Make sure that c2b counter is updated */
    lock_c2b_counter(c2b, write);
}

int __trylock_c2b(c2_block_t *c2b, int write)
{
    c_ext_pos_t cep_unused;
    c2_page_t *c2p;
    int success_cnt, ret;

    success_cnt = 0;
    c2b_for_each_c2p_start(c2p, cep_unused, c2b)
    {
        ret = trylock_c2p(c2p, write);
        if(ret == 0)
            goto fail_out;
        success_cnt++;
    }
    c2b_for_each_c2p_end(c2p, cep_unused, c2b)
    
    /* Succeeded locking all c2ps. Make sure that c2b counter is updated. */
    lock_c2b_counter(c2b, write);

    return 1;

fail_out:
    c2b_for_each_c2p_start(c2p, cep_unused, c2b)
    {
        if(success_cnt == 0)
            return 0; 
        unlock_c2p(c2p, write);
        success_cnt--;
    }
    c2b_for_each_c2p_end(c2p, cep_unused, c2b)

    /* Should never get here */
    BUG();
    return 0;
}

static inline void __unlock_c2b(c2_block_t *c2b, int write)
{
    c_ext_pos_t cep_unused;
    c2_page_t *c2p;

#ifdef CASTLE_DEBUG    
    c2b->file = "none";
    c2b->line = 0;
#endif

    unlock_c2b_counter(c2b, write);
    c2b_for_each_c2p_start(c2p, cep_unused, c2b)
    {
        unlock_c2p(c2p, write);
    }
    c2b_for_each_c2p_end(c2p, cep_unused, c2b)

}

void write_unlock_c2b(c2_block_t *c2b)
{
    __unlock_c2b(c2b, 1);
}

void read_unlock_c2b(c2_block_t *c2b)
{
    __unlock_c2b(c2b, 0);
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
 * Mark c2b and associated c2ps dirty.
 */
void dirty_c2b(c2_block_t *c2b)
{
    unsigned long flags;
    int i, nr_c2ps;

    BUG_ON(!c2b_write_locked(c2b));
    /* With overlapping c2bs we cannot rely on this c2b being dirty. We have to dirty
       all c2ps. */
    nr_c2ps = castle_cache_pages_to_c2ps(c2b->nr_pages);
    for(i=0; i<nr_c2ps; i++)
        dirty_c2p(c2b->c2ps[i]);

    spin_lock_irqsave(&castle_cache_block_hash_lock, flags);
    list_move_tail(&c2b->dirty, &castle_cache_dirtylist);
    set_c2b_dirty(c2b); 
    spin_unlock_irqrestore(&castle_cache_block_hash_lock, flags);
}

static void clean_c2b(c2_block_t *c2b)
{
    unsigned long flags;
    int i, nr_c2ps;

    /* Clean all c2ps. */
    nr_c2ps = castle_cache_pages_to_c2ps(c2b->nr_pages);
    for(i=0; i<nr_c2ps; i++)
        clean_c2p(c2b->c2ps[i]);
    /* Clean the c2b. */
    spin_lock_irqsave(&castle_cache_block_hash_lock, flags);
    BUG_ON(!c2b_locked(c2b));
    BUG_ON(!c2b_dirty(c2b));
    list_move_tail(&c2b->clean, &castle_cache_cleanlist);
    clear_c2b_dirty(c2b); 
    spin_unlock_irqrestore(&castle_cache_block_hash_lock, flags);
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
    int         rw;
    struct bio *bio;
    c2_block_t *c2b;
    uint32_t    nr_pages;
};

static void c2b_remaining_io_sub(int rw, int nr_pages, c2_block_t *c2b)
{
    if (atomic_sub_and_test(nr_pages, &c2b->remaining))
    {
        debug("Completed io on c2b"cep_fmt_str_nl, cep2str(c2b->cep));
        /* On reads, update the c2b */
        if(rw == READ)
            update_c2b(c2b);
        else
            clean_c2b(c2b);
        c2b->end_io(c2b);
    }
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
static int c2b_multi_io_end(struct bio *bio, unsigned int completed, int err)
#else
static void c2b_multi_io_end(struct bio *bio, int err)
#endif
{
    struct bio_info *bio_info = bio->bi_private;
    c2_block_t *c2b = bio_info->c2b;
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
    if( (err) && (completed != 0))
    {
        printk("NOTE: you've likely run out of space on disk for sparse loopback files. "
               "If so, this is not strictly a bug and will not be fixed.!\n");
        printk("Bio error=%d, completed=%d, bio->bi_size=%d\n", err, completed, bio->bi_size);
        BUG();
    }
    BUG_ON(err && test_bit(BIO_UPTODATE, &bio->bi_flags));
#endif
    BUG_ON(atomic_read(&c2b->remaining) == 0);
    /* We cannot handle errors proprely at the moment in the clients. BUG_ON here. */
    BUG_ON(err);
    BUG_ON(!test_bit(BIO_UPTODATE, &bio->bi_flags));
    /* Record how many pages we've completed, potentially ending the c2b io. */ 
    c2b_remaining_io_sub(bio_info->rw, bio_info->nr_pages, c2b);
#ifdef CASTLE_DEBUG    
    local_irq_restore(flags);
#endif
    kfree(bio_info);
    bio_put(bio);
    
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
    return 0;
#endif
}

/**
 * Allocate bio for pages & hand-off to Linux block layer.
 *
 * @param disk_chk  Chunk to be IOed to
 * @param pages     Array of pages to be used for IO 
 * @param nr_pages  Size of @pages array
 */
void submit_c2b_io(int           rw, 
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
    int i;

#ifdef CASTLE_DEBUG    
    /* Check that we are submitting IO to the right ceps. */
    c_ext_pos_t dcep = cep;
    c2_page_t *c2p;

    /* Only works for 1 page c2ps. */
    BUG_ON(PAGES_PER_C2P != 1);
    for(i=0; i<nr_pages; i++)
    {
        c2p = (c2_page_t *)pages[i]->lru.next;
        if(!EXT_POS_EQUAL(c2p->cep, dcep))
        {
            printk("Unmatching ceps "cep_fmt_str", "cep_fmt_str_nl,
                cep2str(c2p->cep), cep2str(dcep));
            BUG();
        }
        dcep.offset += PAGE_SIZE;
    }
#endif
  
    /* Work out the slave structure. */ 
    cs = castle_slave_find_by_uuid(disk_chk.slave_id);
    debug("slave_id=%d, cs=%p\n", disk_chk.slave_id, cs);
    /* Work out the sector on the slave. */
    sector = ((sector_t)disk_chk.offset << (C_CHK_SHIFT - 9)) +
              (BLK_IN_CHK(cep.offset) << (C_BLK_SHIFT - 9));

    /* Allocate BIO and bio_info struct */
    bio = bio_alloc(GFP_KERNEL, nr_pages);
    bio_info = kmalloc(sizeof(struct bio_info), GFP_KERNEL);
    BUG_ON(!bio_info);

    /* Init BIO and bio_info */
    bio_info->rw       = rw;
    bio_info->bio      = bio;
    bio_info->c2b      = c2b;
    bio_info->nr_pages = nr_pages;
    for(i=0; i<nr_pages; i++)
    {
        bio->bi_io_vec[i].bv_page   = pages[i];
        bio->bi_io_vec[i].bv_len    = PAGE_SIZE; 
        bio->bi_io_vec[i].bv_offset = 0;
    }
    bio->bi_sector  = sector;
    bio->bi_bdev    = cs->bdev;
    bio->bi_vcnt    = nr_pages;
    bio->bi_idx     = 0;
    bio->bi_size    = nr_pages * C_BLK_SIZE;
    bio->bi_end_io  = c2b_multi_io_end;
    bio->bi_private = bio_info;
 
    /* Hand off to Linux block layer */
    submit_bio(rw, bio);
}

#ifdef CASTLE_DEBUG
int chk_valid(c_disk_chk_t chk)
{
    struct castle_slave *cs = castle_slave_find_by_uuid(chk.slave_id);
    c_chk_t size;
    
    if (!cs)
    {
        printk("Couldn't find disk with uuid: %u\n", chk.slave_id);
        return 0;
    }

    castle_freespace_summary_get(cs, NULL, &size);
    if (chk.offset >= size)
    {
        printk("Unexpected chunk "disk_chk_fmt", Disk Size: 0x%x\n",
                disk_chk2str(chk), size);
        return 0;
    }

    return 1;
}
#endif

#define MAX_BIO_PAGES        16
typedef struct castle_io_array {
    struct page *io_pages[MAX_BIO_PAGES];
    c_ext_pos_t start_cep;
    c_chk_t chunk;
    int next_idx;
} c_io_array_t;

/**
 * Dispatches k copies of the I/O.
 *
 * @see submit_c2b_io()
 */
static inline void c_io_array_submit(int rw, 
                                     c2_block_t *c2b, 
                                     c_disk_chk_t *chunks, 
                                     int k_factor,
                                     c_io_array_t *array)
{
    int i, nr_pages;

    nr_pages = array->next_idx;
    debug("Submitting io_array of %d pages, for cep "cep_fmt_str", k_factor=%d, rw=%s\n",
        nr_pages, 
        cep2str(array->start_cep), 
        k_factor, 
        (rw == READ) ? "read" : "write");
 
    BUG_ON((nr_pages <= 0) || (nr_pages > MAX_BIO_PAGES));
    /* Account. */
    if (rw == READ)
        atomic_add(nr_pages, &castle_cache_read_stats);
    else
        atomic_add(nr_pages, &castle_cache_write_stats);

    /* Submit the IO */
    for(i=0; i<(rw == WRITE ? k_factor : 1); i++)
    {
        /* Debugging checks, the first one could be turned into a vaild error. */
#ifdef CASTLE_DEBUG
        BUG_ON(DISK_CHK_INVAL(chunks[i]));
        BUG_ON(!SUPER_EXTENT(array->start_cep.ext_id) && !chk_valid(chunks[i]));
#endif
        atomic_add(nr_pages, &c2b->remaining);
        submit_c2b_io(rw, c2b, array->start_cep, chunks[i], array->io_pages, nr_pages); 
    }
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

/**
 * Generates I/O for disk block(s) associated with the c2b.
 *
 * Iterates over passed c2b's c2ps (ignoring those that are clean/uptodate for WRITEs/READs)
 * Populates array of pages from c2ps
 * Dispatches array once it reaches the a chunk boundry
 * Continues until whole c2b has been dispatched
 *
 * @see c_io_array_init()
 * @see c_io_array_page_add()
 * @see c_io_array_submit()
 *
 */
static int submit_c2b_rda(int rw, c2_block_t *c2b)
{
    c2_page_t    *c2p;
    c_io_array_t  io_array;
    struct page  *page;
    int           skip_c2p;
    c_ext_pos_t   cur_cep;
    c_chk_t       last_chk, cur_chk;
    uint32_t      k_factor = castle_extent_kfactor_get(c2b->cep.ext_id);
    c_disk_chk_t  chunks[k_factor];

    debug("Submitting c2b "cep_fmt_str", for %s\n", 
            __cep2str(c2b->cep), (rw == READ) ? "read" : "write");

    /* c2b->remaining is effectively a reference count. Get one ref before we start. */
    BUG_ON(atomic_read(&c2b->remaining) != 0);
    atomic_inc(&c2b->remaining);
    last_chk = INVAL_CHK;
    cur_chk = INVAL_CHK;
    c_io_array_init(&io_array);
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
        if(c_io_array_page_add(&io_array, cur_cep, cur_chk, page) != EXIT_SUCCESS)
        {
            /* Failed to add this page to the array (see return code for reason).
             * Dispatch the current array, initialise a new one and
             * attempt to add the page to the new array.
             *
             * We've got physical chunks for last_chk (logical chunk), this should
               match with the logical chunk stored in io_array. */ 
            BUG_ON(io_array.chunk != last_chk);
            /* Submit the array. */
            c_io_array_submit(rw, c2b, chunks, k_factor, &io_array);
            /* Reinit the array, and re-try adding the current page. This should not
               fail any more. */
            c_io_array_init(&io_array);
            BUG_ON(c_io_array_page_add(&io_array, cur_cep, cur_chk, page));
        }
         
        /* Update chunk map when we move to a new chunk. */ 
        if(cur_chk != last_chk)
        {
            int ret;
            debug("Asking extent manager for "cep_fmt_str_nl,
                    cep2str(cur_cep));
            ret = castle_extent_map_get(cur_cep.ext_id,
                                        CHUNK(cur_cep.offset),
                                        chunks);
            /* Return value is supposed to be k_factor, unless the
               extent has been deleted. */
            BUG_ON((ret != 0) && (ret != k_factor));
            if(ret == 0)
            {
                /* Complete the IO by dropping our reference, return early. */
                c2b_remaining_io_sub(rw, 1, c2b);
                return 0;
            }
            
            debug("chunks[0]="disk_chk_fmt_nl, disk_chk2str(chunks[0]));
            last_chk = cur_chk;
        }
    }
next_page:
    c2b_for_each_page_end(page, c2p, cur_cep, c2b);

    /* IO array may contain leftover pages, submit those too. */
    if(io_array.next_idx > 0)
    {
        /* Chunks array is always initialised for last_chk. */
        BUG_ON(io_array.chunk != last_chk);
        c_io_array_submit(rw, c2b, chunks, k_factor, &io_array);
    }
    /* Drop the 1 ref. */
    c2b_remaining_io_sub(rw, 1, c2b);
    
    return 0;
}

/**
 * Submit asynchronous c2b I/O.
 *
 * Updates statistics before passing I/O to submit_c2b_rda().
 *
 * @see submit_c2b_rda()
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
        printk("RDA %s: nr_pages - %u cep: "cep_fmt_str_nl, 
                (rw == READ)?"Read":"Write", c2b->nr_pages, __cep2str(c2b->cep));
        BUG();
    }

    return submit_c2b_rda(rw, c2b);
}

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

    /* Success (ret=0) if uptodate now */
    return !c2b_uptodate(c2b);
}

static inline int castle_cache_page_hash_idx(c_ext_pos_t cep)
{
    return (BLOCK(cep.offset) % castle_cache_page_hash_buckets);
}

static c2_page_t* castle_cache_page_hash_find(c_ext_pos_t cep)
{
    struct hlist_node *lh;
    c2_page_t *c2p;
    int idx;

    idx = castle_cache_page_hash_idx(cep);
    debug("Idx = %d\n", idx);
    hlist_for_each_entry(c2p, lh, &castle_cache_page_hash[idx], hlist)
    {
        if(EXT_POS_EQUAL(c2p->cep, cep))
            return c2p;
    }

    return NULL;
}

static c2_page_t* __castle_cache_page_hash_insert(c2_page_t *c2p)
{
    c2_page_t *existing_c2p;
    int idx;

    /* Check if already in the hash */
    existing_c2p = castle_cache_page_hash_find(c2p->cep);
    if(existing_c2p)
        return existing_c2p;
    
    /* Insert */
    idx = castle_cache_page_hash_idx(c2p->cep);
    hlist_add_head(&c2p->hlist, &castle_cache_page_hash[idx]);

    return c2p;
}

/* Must be called with the page_hash lock held */
static inline void __castle_cache_c2p_get(c2_page_t *c2p)
{
    BUG_ON(!spin_is_locked(&castle_cache_page_hash_lock));
    c2p->count++;
}

#define MIN(_a, _b)     ((_a) < (_b) ? (_a) : (_b)) 
/* Must be called with the page_hash lock held */
static inline void __castle_cache_c2p_put(c2_page_t *c2p, struct list_head *accumulator)
{
    BUG_ON(!spin_is_locked(&castle_cache_page_hash_lock));

    c2p->count--;
    /* If the count reached zero, delete fromt the hash, add to the accumulator list,
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
                memcpy(buf, poison, MIN(PAGE_SIZE-j, str_len));
        }
#endif
        debug("Freeing c2p for cep="cep_fmt_str_nl, cep2str(c2p->cep));
        BUG_ON(c2p_dirty(c2p));
        atomic_sub(PAGES_PER_C2P, &castle_cache_clean_pages);
        hlist_del(&c2p->hlist);
        list_add(&c2p->list, accumulator);
    }
}

static inline int castle_cache_block_hash_idx(c_ext_pos_t cep)
{
    return (BLOCK(cep.offset) % castle_cache_block_hash_buckets);
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
    spin_lock_irq(&castle_cache_block_hash_lock);

    /* Try and get the matching block from the hash. */
    c2b = castle_cache_block_hash_find(cep, nr_pages);

    if (c2b)
    {
        /* We found a matching block. */

        if (promote)
        {
            /* We are obtaining this block to be used.  We should push it to
             * the end of the LRU list indicating that it is recently used
             * and should not be freed any time soon.
             *
             * We're going to return this block to the caller so hold a
             * reference for them so it doesn't get removed. */
            get_c2b(c2b);

            /* Move to the end of the appropriate list. */
            if(c2b_dirty(c2b))
                list_move_tail(&c2b->dirty, &castle_cache_dirtylist);
            else
                list_move_tail(&c2b->clean, &castle_cache_cleanlist);
        }
        else if (atomic_read(&c2b->count) == 0)
        {
            /* No references on this block means it's not in use.
             * If clean: demote so it gets reused next
             * If dirty: don't touch it - let LRU mechanism handle it */
            if (!c2b_dirty(c2b))
                list_move(&c2b->clean, &castle_cache_cleanlist);
        }
    }

    /* Release the hash lock. */
    spin_unlock_irq(&castle_cache_block_hash_lock);

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
 * Find block matching (cep, nr_pages) and demote it in the clean/dirtylist.
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

static int castle_cache_block_hash_insert(c2_block_t *c2b, int transient)
{
    int idx, success;

    spin_lock_irq(&castle_cache_block_hash_lock);
    /* Check if already in the hash */
    success = 0;
    if(castle_cache_block_hash_find(c2b->cep, c2b->nr_pages)) goto out;
    /* Insert */
    success = 1;
    idx = castle_cache_block_hash_idx(c2b->cep);
    hlist_add_head(&c2b->hlist, &castle_cache_block_hash[idx]);
    BUG_ON(c2b_dirty(c2b));
    if (transient)
        list_add(&c2b->clean, &castle_cache_cleanlist);
    else
        list_add_tail(&c2b->clean, &castle_cache_cleanlist);
out:
    spin_unlock_irq(&castle_cache_block_hash_lock);
    return success;
}

static inline void __castle_cache_page_freelist_add(c2_page_t *c2p)
{
    BUG_ON(c2p->count != 0);
    list_add_tail(&c2p->list, &castle_cache_page_freelist);
    castle_cache_page_freelist_size++;
}

static inline void __castle_cache_block_freelist_add(c2_block_t *c2b)
{
    list_add_tail(&c2b->free, &castle_cache_block_freelist);
    castle_cache_block_freelist_size++;
}

static c2_page_t** castle_cache_page_freelist_get(int nr_pages)
{
    struct list_head *lh, *lt;
    c2_page_t **c2ps;
    int i, nr_c2ps;

    debug("Asked for %d pages from the freelist.\n", nr_pages);
    nr_c2ps = castle_cache_pages_to_c2ps(nr_pages);
    c2ps = castle_zalloc(nr_c2ps * sizeof(c2_page_t *), GFP_KERNEL);
    BUG_ON(!c2ps);
    spin_lock(&castle_cache_freelist_lock);
    /* Will only be able to satisfy the request if we have nr_pages on the list */
    if(castle_cache_page_freelist_size * PAGES_PER_C2P < nr_pages)
    {
        spin_unlock(&castle_cache_freelist_lock);
        castle_free(c2ps);
        debug("Freelist too small to allocate %d pages.\n", nr_pages);
        return NULL;
    }
    
    i = 0;
    list_for_each_safe(lh, lt, &castle_cache_page_freelist)
    {
        if(nr_pages <= 0)
            break;
        list_del(lh);
        castle_cache_page_freelist_size--;
        BUG_ON(i >= nr_c2ps);
        c2ps[i++] = list_entry(lh, c2_page_t, list);
        nr_pages -= PAGES_PER_C2P;
    }
    spin_unlock(&castle_cache_freelist_lock);
#ifdef CASTLE_DEBUG
    for(i--; i>=0; i--)
    {
        debug("Got c2p id=%d from freelist.\n", c2ps[i]->id);
    }
#endif
    /* Check that we _did_ succeed at allocating required number of c2ps */
    BUG_ON(nr_pages > 0);

    return c2ps;
}

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
    spin_lock_irq(&castle_cache_page_hash_lock);
    for(i=0; i<nr_c2ps; i++)
    {
        castle_cache_page_init(cep, c2ps[i]);
        debug("c2p for cep="cep_fmt_str_nl, cep2str(c2ps[i]->cep));
        c2p = __castle_cache_page_hash_insert(c2ps[i]);
        /* If c2p for this cep was found in the cache already, use it. Release the one 
           from c2ps array back onto the freelist. */
        if(c2p != c2ps[i])
        {
            debug("Found c2p in the hash\n");
            list_add(&c2ps[i]->list, &freed_c2ps); 
            freed_c2ps_cnt++;
            c2ps[i] = c2p;
        } else
            atomic_add(PAGES_PER_C2P, &castle_cache_clean_pages);
        /* Get the reference to the right c2p. */
        __castle_cache_c2p_get(c2ps[i]);
        /* Check if this page is clean. */
        if(!c2p_uptodate(c2ps[i]))
            all_uptodate = 0;
        cep.offset += PAGES_PER_C2P * PAGE_SIZE;
    }
    spin_unlock_irq(&castle_cache_page_hash_lock);

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

static void castle_cache_block_init(c2_block_t *c2b,
                                    c_ext_pos_t cep, 
                                    c2_page_t **c2ps,
                                    int nr_pages)
{
    struct page *page;
    c_ext_pos_t dcep;
    c2_page_t *c2p;
    int i, uptodate;

    debug("Initing c2b for cep="cep_fmt_str", nr_pages=%d\n",
            cep2str(cep), nr_pages);
    /* Init the page array (note: this may substitute some c2ps, 
       if they aleady exist in the hash. */
    uptodate = castle_cache_pages_get(cep, c2ps, castle_cache_pages_to_c2ps(nr_pages));

    /* c2b should only be initialised if it's not used */
    BUG_ON(nr_pages > CASTLE_CACHE_VMAP_PGS);
    BUG_ON(c2b->c2ps != NULL);
    BUG_ON(atomic_read(&c2b->count) != 0);
    atomic_set(&c2b->remaining, 0);
    c2b->cep = cep;
    c2b->state = INIT_C2B_BITS | (uptodate ? (1 << C2B_uptodate) : 0);
    c2b->nr_pages = nr_pages;
    c2b->c2ps = c2ps;

    i = 0;
    debug("c2b->nr_pages=%d\n", nr_pages);
    down(&castle_cache_vmap_lock);
    c2b_for_each_page_start(page, c2p, dcep, c2b) 
    {
#ifdef CASTLE_DEBUG
        debug("Adding c2p id=%d, to cep "cep_fmt_str_nl,
                c2p->id, cep2str(dcep));
#endif
        castle_cache_vmap_pgs[i++] = page; 
    }
    c2b_for_each_page_end(page, c2p, dcep, c2b) 
    debug("Added %d pages.\n", i);
    BUG_ON(i != nr_pages);

    if (nr_pages == 1)
        c2b->buffer = pfn_to_kaddr(page_to_pfn(castle_cache_vmap_pgs[0])); 
    else if (nr_pages <= CASTLE_VMAP_PGS)
            c2b->buffer = castle_vmap_fast_map(castle_cache_vmap_pgs, i);
        else
            c2b->buffer = vmap(castle_cache_vmap_pgs, i, VM_READ|VM_WRITE, PAGE_KERNEL);

    up(&castle_cache_vmap_lock);
    BUG_ON(!c2b->buffer);
}

static void castle_cache_block_free(c2_block_t *c2b)
{
    struct list_head *lh, *lt;
    LIST_HEAD(freed_c2ps);
    c2_page_t *c2p, **c2ps;
    int i, nr_c2ps;

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

        c2b_for_each_c2p_start(c2p, cep_unused, c2b)
            debug("Freeing c2p id=%d, from c2b=%p\n", c2p->id, c2b);
        c2b_for_each_c2p_end(c2p, cep_unused, c2b)
    }
#endif
    /* For prefetch c2bs call their deallocator function. */
    if(c2b_prefetch(c2b))
        c2_pref_c2b_destroy(c2b);
    /* Add the pages back to the freelist */
    spin_lock(&castle_cache_page_hash_lock);
    for(i=0; i<nr_c2ps; i++)
        __castle_cache_c2p_put(c2b->c2ps[i], &freed_c2ps);
    spin_unlock(&castle_cache_page_hash_lock);
    /* For debugging only: it will be spotted quickly if nr_pages isn't reinited properly */
    c2b->nr_pages = 0xFFFF;
    c2ps = c2b->c2ps;
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

static inline int c2b_busy(c2_block_t *c2b)
{
    /* c2b_locked() implies (c2b->count > 0) */
    return atomic_read(&c2b->count) |
          (c2b->state & (1 << C2B_dirty)) |
           c2b_locked(c2b);
}

static int castle_cache_block_hash_clean(void)
{
#define BATCH_FREE 200
    
    struct list_head *lh, *th;
    struct hlist_node *le, *te;
    HLIST_HEAD(victims);
    c2_block_t *c2b;
    int nr_victims, nr_pages;

    spin_lock_irq(&castle_cache_block_hash_lock);
    /* Find victim buffers. */ 
    nr_victims = 0;
    nr_pages = 0;
    list_for_each_safe(lh, th, &castle_cache_cleanlist)
    {
        c2b = list_entry(lh, c2_block_t, clean);
        nr_pages += c2b->nr_pages;
        /* Note: Pinning all logical extent pages in cache. Make sure cache is 
         * big enough. 
         * TODO: gm281: this is temporary solution. Introduce pools to deal with the
         * issue properly.
         */
        if(!c2b_busy(c2b) && (c2b_transient(c2b) || !LOGICAL_EXTENT(c2b->cep.ext_id))) 
        {
            debug("Found a victim.\n");
            hlist_del(&c2b->hlist);
            list_del(&c2b->clean);
            hlist_add_head(&c2b->hlist, &victims);
            nr_victims++;
        }
        
        if(nr_victims > BATCH_FREE)
            break;
    }
    spin_unlock_irq(&castle_cache_block_hash_lock);

    /* We couldn't find any victims */
    if(hlist_empty(&victims))
    {
        if(nr_pages > castle_cache_size / 2)
        {
            static atomic_t nr_allowed = ATOMIC_INIT(1000);
            
            printk("Couldn't find a victim page in %d pages, cache size %d\n",
                    nr_pages, castle_cache_size);
            if(atomic_dec_and_test(&nr_allowed)) 
                BUG();
        }
        debug("No victims found!!\n");
        return 0;
    }

    /* Add to the freelist */
    hlist_for_each_entry_safe(c2b, le, te, &victims, hlist)
    {
        hlist_del(le);
        castle_cache_block_free(c2b);
    }

    return 1;
}

static void castle_cache_freelists_grow(int nr_c2bs, int nr_pages)
{
    int flush_seq, success = 0;

    while(!castle_cache_block_hash_clean())
    {
        debug("Failed to clean the hash.\n");
        /* Someone might have freed some pages, even though we failed. 
           We need to check that, in case hash is empty, and we will never 
           manage to free anything. */
        flush_seq = atomic_read(&castle_cache_flush_seq);
        spin_lock(&castle_cache_freelist_lock);
        if((castle_cache_page_freelist_size * PAGES_PER_C2P >= nr_pages) &&
           (castle_cache_block_freelist_size >= nr_c2bs))
           success = 1; 
        spin_unlock(&castle_cache_freelist_lock);
        if(success) return;
        /* If we haven't found any !busy buffers in the clean list 
           its likely because they are dirty. Schedule a writeout. */
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

static inline void castle_cache_block_freelist_grow(void)
{
    castle_cache_freelists_grow(1, 0);
}

static inline void castle_cache_page_freelist_grow(int nr_pages)
{
    castle_cache_freelists_grow(0, nr_pages);
}

c2_block_t* _castle_cache_block_get(c_ext_pos_t cep, int nr_pages, int transient)
{
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
        if(c2b) 
        {
            /* Make sure that the number of pages agrees */
            BUG_ON(c2b->nr_pages != nr_pages);
            return c2b;
        }

        /* If we couldn't find in the hash, try allocating from the freelists. Get c2b first. */ 
        /* TODO: Return NULL if extent doesn't exist any more. Make sure this
         * doesnt break any of the clients. */
#ifdef CASTLE_DEBUG
        {
            uint64_t ext_size;

            /* Check sanity of CEP. */
            ext_size = (uint64_t)castle_extent_size_get(cep.ext_id);
            if (ext_size && 
                ((ext_size * C_CHK_SIZE) < (cep.offset + (nr_pages * C_BLK_SIZE))))
            {
                printk("Couldnt create cache page of size %d at cep: "cep_fmt_str
                       "on extent of size %llu chunks\n", nr_pages, __cep2str(cep), ext_size);
                WARN_ON(1);
                msleep(10000);
                BUG();
            }
        }
#endif
        do {
            debug("Trying to allocate c2b from freelist.\n");
            c2b = castle_cache_block_freelist_get();
            if(!c2b)
            {
                debug("Failed to allocate c2b from freelist. Growing freelist.\n");
                /* If freelist is empty, we need to recycle some buffers */
                castle_cache_block_freelist_grow(); 
            }
        } while(!c2b);
        /* Then get as many c2ps as required */
        do {
            debug("Trying to allocate c2ps from freelist.\n");
            c2ps = castle_cache_page_freelist_get(nr_pages); 
            if(!c2ps)
            {
                debug("Failed to allocate c2ps from freelist. Growing freelist.\n");
                /* If freelist is empty, we need to recycle some buffers */
                castle_cache_page_freelist_grow(nr_pages); 
            }
        } while(!c2ps);
        /* Initialise the buffer */
        debug("Initialising the c2b: %p\n", c2b);
        castle_cache_block_init(c2b, cep, c2ps, nr_pages);
        get_c2b(c2b);
        /* Try to insert into the hash, can fail if it is already there */
        debug("Trying to insert\n");
        if(!castle_cache_block_hash_insert(c2b, transient))
        {
            printk("Failed to insert c2b into hash "cep_fmt_str"\n", cep2str(cep));
            put_c2b(c2b);
            castle_cache_block_free(c2b);
        }
        else
        {
            BUG_ON(c2b->nr_pages != nr_pages);
            /* Mark c2b as transient, if required. */
            if (transient)  set_c2b_transient(c2b);
            return c2b;
        }
    }
}

c2_block_t* castle_cache_block_get(c_ext_pos_t cep, int nr_pages)
{
    return _castle_cache_block_get(cep, nr_pages, 0);
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
 *  - adv_thresh: Number of chunks from end_off we get before prefetching.
 *  - cur_c2b: c2b pointer for the range: start_off to end of start_off's chunk.
 *
 * Window storage:
 *    All windows are stored in a global RB tree, protected by a spinlock.
 *
 * Deprecation of windows:
 *    cur_c2b is recalculated, fetched and marked as a prefetch c2b whenever the
 *    window is advanced.  It provides a callback link between c2b and window.
 *    When the block is due to be freed (via a castle_cache_block_free() call)
 *    c2_pref_c2b_destroy() is called if the c2b is marked as a prefetch block.
 *    Here we look through the prefetch window tree for the window that matches
 *    cur_c2b and free it.
 *    Windows are ref counted.  When the ref drops to 0, they are deleted.  If
 *    multiple execution threads race to delete a window, we let only one
 *    through via the PREF_WINDOW_DEAD state bit.
 *
 * Invocation:
 *    Consumer's call castle_cache_block_advise().  These consumer calls could
 *    potentially race.
 *
 * Prefetch algorithm and variables:
 *    Algorithm and variables: see comments in c2_pref_window_schedule().
 *    c2b references are held only during I/O.  When the window is moved forward
 *    we inform the LRU cache to deprecate the blocks that fall off the front.
 *
 * General rules / observations:
 *
 * 1. All changes to a window state (e.g. modifying start_off, end_off, state,
 *    etc.) must happen with window->lock held.
 *
 * 2. Windows must not be in the tree while modifying start_off/end_off as this
 *    breaks tree walks.
 *
 * 3. Within the tree windows are sorted according to start_off.  The start
 *    points in the tree are unique.
 *
 * 4. Within the tree windows ranges (start_off->end_off) may overlap.
 *
 * 5. If the requested cep.offset is not chunk-aligned then we prefetch to the
 *    end of the chunk it lies within.
 *
 * 6. We prefetch whole chunks (with the exception of the start_off chunk).
 *
 * Code flow:
 *
 *    A very rough flow of control for updating an existing prefetch window.
 *
 *      castle_cache_block_advise()
 *          // calls straight into:
 *      castle_cache_prefetch_advise()
 *        c2_pref_window_get()
 *            // gets existing or allocates a new window
 *      c2_pref_window_schedule()
 *          // determines whether the window needs to be advanced
 *      c2_pref_window_advance()
 *          // calculates the number of pages to prefetch
 *          // updates the window (including cur_c2b)
 *      c2_pref_submit()
 *          // issues chunk-aligned I/O
 */
#define PREF_WINDOW_NEW             (0x01)            /* Window is new, no IO has been sched yet. */ 
#define PREF_WINDOW_DEAD            (0x02)            /* Set when the alloc ref is dropped.       */
#define PREF_WINDOW_FORWARD         (0x04)            /* Prefetching forwards or backwards.       */
#define PREF_WINDOW_INSERTED        (0x08)            /* Is the window inserted into the rbtree.  */
#define PREF_WINDOW_ADAPTIVE        (0x10)            /* Whether this is an adaptive window.      */
#define PREF_ADAPTIVE                                 /* Enable adaptive prefetching.             */
#define PREF_CHUNKS                 4                 /* #chunks to non-adaptive prefetch.        */
#define PREF_ADAP_INITIAL_CHUNKS    1                 /* Initial #chunks to adaptive prefetch.    */
#define PREF_ADAP_MAX_CHUNKS        16                /* Maximum #chunks to adaptive prefetch.    */
#define PREF_ADVANCE_THRESHOLD      4                 /* #chunks from end before we prefetch.     */
#define PREF_ADAP_MAX_PAGES         PREF_ADAP_MAX_CHUNKS * BLKS_PER_CHK
#define PREF_ADAP_INITIAL_PAGES     PREF_ADAP_INITIAL_CHUNKS * BLKS_PER_CHK
#define PREF_PAGES                  PREF_CHUNKS * BLKS_PER_CHK

/**
 * Prefetch window definition.
 *
 * start_off to end_off defines the range within ext_id that we have already
 * issued prefetching for.
 */
typedef struct castle_cache_prefetch_window {
    uint8_t         state;      /**< State of the prefetch window.                          */
    c2_block_t      *cur_c2b;   /**< Allows c2b free mechanism to identify this window when
                                     it wants to free blocks and associated pref windows.   */
    c_ext_id_t      ext_id;     /**< Extent this window describes.                          */
    c_byte_off_t    start_off;  /**< Start of range that has been prefetched.               */
    c_byte_off_t    end_off;    /**< End of range that has been prefetched.  Chunk aligned. */
    uint32_t        pref_pages; /**< Number of pages we prefetch.                           */
    uint8_t         adv_thresh; /**< #Chunks from end_off before we prefetch.               */
    struct rb_node  rb_node;    /**< RB-node for this window.                               */
    atomic_t        count;      /**< Reference count.                                       */
    struct mutex    lock;       /**< Hold while changing start_off, end_off, pref_pages.    */
} c2_pref_window_t;

static DEFINE_SPINLOCK(c2_prefetch_lock);
static struct rb_root c2p_rb_root = RB_ROOT; 
    
static USED char* c2_pref_window_to_str(c2_pref_window_t *window)
{
#define PREF_WINDOW_STR_LEN     (128)
    static char win_str[PREF_WINDOW_STR_LEN];
    c_ext_pos_t cep;
    
    cep.ext_id = window->ext_id;
    cep.offset = window->start_off;

    snprintf(win_str, PREF_WINDOW_STR_LEN, 
        "%spref win: {cep="cep_fmt_str", start_off=%lld (%lld), end_off=%lld (%lld), pref_pages=%d (%d), st=0x%.2x, cnt=%d",
         window->state & PREF_WINDOW_ADAPTIVE ? "adaptive " : "",
             cep2str(cep), 
             window->start_off, 
             CHUNK(window->start_off),
             window->end_off, 
             CHUNK(window->end_off),
             window->pref_pages, 
             window->pref_pages / 256,
             window->state, 
             atomic_read(&window->count));
    win_str[PREF_WINDOW_STR_LEN-1] = '\0';

    return win_str;
} 

/**
 * Decrement reference counter on prefetch window.
 *
 * Frees the window if the counter reaches 0.
 */
static void c2_pref_window_put(c2_pref_window_t *window)
{
    int cnt;

    debug("Putting %s\n", c2_pref_window_to_str(window));
    cnt = atomic_dec_return(&window->count);
    BUG_ON(cnt < 0);
    if(cnt == 0)
    {
        BUG_ON(!(window->state & PREF_WINDOW_DEAD));
        BUG_ON(window->state & PREF_WINDOW_INSERTED);
        debug("Deallocating the prefetch window.\n");
        castle_free(window);
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
static inline int c2_pref_window_compare(c2_pref_window_t *window, c_ext_pos_t cep, int forward)
{
    BUG_ON(!forward);

    /* Check if cep and this window describe the same extent. */
    if (cep.ext_id < window->ext_id)
        return -1;
    if (cep.ext_id > window->ext_id)
        return 1;

    if (cep.offset < window->start_off)
        return -1;

    else if (cep.offset < window->end_off)
        return 0;

    else
        return 1;
}

/**
 * Find prefetch window with furthest start_off that matches cep.
 *
 * @FIXME This logic is likely broken for adaptive prefetch windows.
 * Specifically a given cep might match two overlapping windows:
 * - One with a start_off of 10 and end_off of 200
 * - Another with a start_off of 15 and end_off of 30
 * This function will return the second (smaller, but more 'advanced') for a
 * cep.offset 20.  This behaviour is not ideal but is not incorrect.
 *
 * @arg n       Starting point for search
 * @arg cep     Offset
 * @arg forward Direction to prefetch
 *
 * @return Most advanced window matching cep
 */
static inline c2_pref_window_t* c2_pref_window_closest_find(struct rb_node *n,
                                                            c_ext_pos_t cep,
                                                            int forward)
{
    c2_pref_window_t *window;
    struct rb_node *p;
    int cmp;

    /* The logic below is (probably) broken for back prefetch. */
    BUG_ON(!forward);
    BUG_ON(!spin_is_locked(&c2_prefetch_lock));
    BUG_ON(c2_pref_window_compare(rb_entry(n, c2_pref_window_t, rb_node), cep, forward) != 0);

    /* Save provided window rb_node ptr.  It is guaranteed to satisfy cep. */
    p = n;

    do { 
        /* Check next entry satisfies cep. */
        n = rb_next(n);
        if(!n)
            break;
        window = rb_entry(n, c2_pref_window_t, rb_node);

        cmp = c2_pref_window_compare(window, cep, forward);
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
static c2_pref_window_t *c2_pref_window_find(c_ext_pos_t cep, int forward, int exact_match)
{
    struct rb_node *n;
    c2_pref_window_t *window;
    int cmp;

    pref_debug_mstore("Looking for pref window cep="cep_fmt_str", forward=%d, exact_match=%d\n",
            cep2str(cep), forward, exact_match);
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
            cmp = c2_pref_window_compare(window, cep, forward);

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
                window = c2_pref_window_closest_find(n, cep, forward); 
            /* Get a reference to the window. Reference count should be strictly > 1. 
               Otherwise the window should not be in the tree. */
            BUG_ON(!window);
            BUG_ON(c2_pref_window_compare(window, cep, forward) != 0);
            BUG_ON(atomic_inc_return(&window->count) <= 1);
            BUG_ON(!(window->state & PREF_WINDOW_INSERTED));
            spin_unlock(&c2_prefetch_lock);
            debug("Found %s\n", c2_pref_window_to_str(window));

            return window;
        }
    }
    spin_unlock(&c2_prefetch_lock);

    pref_debug_mstore("No existing prefetch window found.\n");

    return NULL;
}

/**
 * Remove prefetch window from tree.
 *
 * @param window    Window to remove
 */
static void c2_pref_window_remove(c2_pref_window_t *window)
{
    pref_debug_mstore("Asked to remove %s\n", c2_pref_window_to_str(window));
    BUG_ON(!mutex_is_locked(&window->lock));

    if(!(window->state & PREF_WINDOW_INSERTED))
        return;

    pref_debug_mstore("Window in the tree, removing.\n");

    spin_lock(&c2_prefetch_lock);
    rb_erase(&window->rb_node, &c2p_rb_root);
    window->state &= ~PREF_WINDOW_INSERTED;
    spin_unlock(&c2_prefetch_lock);
}

/**
 * Insert prefetch window into tree.
 *
 * @param new_window    Window to insert.
 * @param cur_c2b       c2b that identifies the window.
 *
 * @also c2_pref_window_advance() for cur_c2b initialisation.
 * @also castle_cache_block_free().
 */
static int c2_pref_window_insert(c2_pref_window_t *new_window, c2_block_t *cur_c2b)
{
    struct rb_node **p, *parent = NULL;
    c2_pref_window_t *cur_window;
    c_ext_pos_t cur_cep, new_cep;
    int cmp;

    pref_debug_mstore("Asked to insert %s\n", c2_pref_window_to_str(new_window));
    BUG_ON(!mutex_is_locked(&new_window->lock));
    BUG_ON(new_window->state & PREF_WINDOW_DEAD);
    if(new_window->state & PREF_WINDOW_INSERTED)
    {
        if(cur_c2b)
            put_c2b(cur_c2b);
        return 0;
    }

    /* If the window hasn't been inserted yet, we MUST have a ref to cur_c2b, 
       in order to stop c2b destruction racing with insert. */
    BUG_ON(!cur_c2b);
    pref_debug_mstore("Not in the tree. Inserting.\n");
    new_cep.ext_id = new_window->ext_id;
    new_cep.offset = new_window->start_off;

    spin_lock(&c2_prefetch_lock);
    p = &c2p_rb_root.rb_node;
    while(*p)
    {
        parent = *p;
        cur_window = rb_entry(parent, c2_pref_window_t, rb_node);
        cur_cep.ext_id = cur_window->ext_id;
        cur_cep.offset = cur_window->start_off;

        cmp = EXT_POS_COMP(new_cep, cur_cep);
        if(cmp < 0)
            p = &(*p)->rb_left;
        else if (cmp > 0)
            p = &(*p)->rb_right;
        else 
        {
            /* We found precisely the same starting point. We require these to
             * be unique.  Do not insert.  Return error. */
            spin_unlock(&c2_prefetch_lock);
            pref_debug_mstore("Found the same starting point in the tree."
           "Not inserting.\n");
            new_window->cur_c2b = NULL;
            put_c2b(cur_c2b);
            return -EINVAL;                  
        }
    }                     

    new_window->state |= PREF_WINDOW_INSERTED;
    rb_link_node(&new_window->rb_node, parent, p);
    rb_insert_color(&new_window->rb_node, &c2p_rb_root);
    spin_unlock(&c2_prefetch_lock);
    new_window->cur_c2b = cur_c2b;
    put_c2b(cur_c2b);

    return 0;
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
        pref_debug_mstore("%s\n", c2_pref_window_to_str(cur_window));
        parent = rb_next(parent);

        /* Record how many entries we find. */
        entries++;
    }

    pref_debug_mstore("Found %d prefetch window(s).\n", entries);

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
                                               c_ext_id_t ext_id, 
                                               int forward)
{
    window = castle_malloc(sizeof(c2_pref_window_t), GFP_KERNEL);
    if(!window)
        return NULL;

    window->state       = PREF_WINDOW_NEW | (forward ? PREF_WINDOW_FORWARD : 0);
    window->cur_c2b     = NULL;
    window->ext_id      = ext_id;
    window->start_off   = 0;
    window->end_off     = 0;
#ifdef PREF_ADAPTIVE
    window->pref_pages  = PREF_ADAP_INITIAL_PAGES;
    window->state      |= PREF_WINDOW_ADAPTIVE;
#else
    window->pref_pages  = PREF_PAGES;
#endif
    window->adv_thresh  = PREF_ADVANCE_THRESHOLD;
    mutex_init(&window->lock);
    atomic_set(&window->count, 2); /* Window gets destroyed when the refcount reaches 0,
                                      therefore count=1 means allocated. Here we explicitly
                                      take a single reference too. */

    pref_debug_mstore ("Allocated a new window.\n");

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
static c2_pref_window_t* c2_pref_window_get(c_ext_pos_t cep, int forward)
{
    c2_pref_window_t *window;
    
    /* Look for existing prefetch window. */
    pref_debug_mstore("Looking for window for cep="cep_fmt_str_nl, cep2str(cep));
    if ((window = c2_pref_window_find(cep, forward, 0)))
    {
        /* Found a matching prefetch window. */
        pref_debug_mstore("Found %s\n", c2_pref_window_to_str(window));
        return window;
    }

    /* No matching prefetch windows exist.  Allocate one. */
    pref_debug_mstore("Failed to find window for cep="cep_fmt_str_nl, cep2str(cep));
#ifdef PREF_DEBUG
    c2_pref_window_dump();
#endif

    if ((window = c2_pref_window_alloc(window, cep.ext_id, forward)) == NULL)
    {
        /* Failed to allocate a new window. */
        pref_debug_mstore("Failed to allocate new window.\n");
        return NULL;
    }

    /* Return the newly allocate prefetch window. */ 
    return window;
}

/**
 * Prefetch I/O completion callback handler.
 *
 * @param c2b   Cache block I/O has been completed on
 */
static void c2_pref_io_end(c2_block_t *c2b)
{
    pref_debug_mstore("Finished prefetch io at cep="cep_fmt_str", nr_pages=%d.\n",
            cep2str(c2b->cep), c2b->nr_pages);
    write_unlock_c2b(c2b);
    put_c2b(c2b);
}

/**
 * Issue c2b I/O to prefetch requested chunks.
 *
 * - Prefetches to the end of the current chunk for new windows.
 * - For existing windows prefetches new chunks beyond end_off that lie within
 *   the range specified by end_off to start_off+pref_pages.
 *
 * @param window    Window to prefetch
 * @param pages     Number of additional pages to prefetch
 *
 * @return ENOSPC: End of extent reached.  Cannot prefetch further.
 */
static int c2_pref_submit(c2_pref_window_t *window, int pages)
{
    c2_block_t *c2b;
    c_ext_pos_t cep;
    int nr_pages;

    BUG_ON(!mutex_is_locked(&window->lock));
    BUG_ON(window->state & PREF_WINDOW_INSERTED);

    pref_debug_mstore("Prefetching %d pages from %s\n",
        pages, c2_pref_window_to_str(window));

    cep.ext_id = window->ext_id;
    cep.offset = window->end_off;

    pref_debug_mstore("Pushing end_off from %d to %d\n",
        (int)window->end_off, (int)(window->end_off + (pages * PAGE_SIZE)));
    /* Update the window to reflect where we (will below) prefetch to. */
    window->end_off += pages * PAGE_SIZE;

    /* Prefetch the required range. */
    while (pages > 0)
    {
        pref_debug_mstore("while loop pages = %d\n", pages);
        /* Stay chunk aligned. */
        if (pages >= BLKS_PER_CHK)
            nr_pages = BLKS_PER_CHK;
        else
        {
            /* should only be chunk misaligned for new windows */
            BUG_ON(!window->state & PREF_WINDOW_NEW);
            nr_pages = pages;
        }

        pages -= nr_pages;
        BUG_ON(pages < 0);

        /* We want cur/next window to be contained within one chunk. */
        BUG_ON(CHUNK(cep.offset) != CHUNK(cep.offset + nr_pages * PAGE_SIZE - 1));
        /* Check that this chunk exists. */
        if(castle_extent_size_get(cep.ext_id) <= CHUNK(cep.offset))
        {
            pref_debug_mstore("Extent too small: %s\n",
                c2_pref_window_to_str(window));
            pref_debug_mstore("Extent too small: extent %d chunks big, just requested chunk %d\n",
                (int)castle_extent_size_get(cep.ext_id), (int)CHUNK(cep.offset));
            return -ENOSPC;
        }
        /* We'll succeed now, get c2b, and submit. */
        c2b = castle_cache_block_get(cep, nr_pages);
        set_c2b_prefetch(c2b);

        /* Update the offset of the next block. */
        cep.offset += nr_pages * PAGE_SIZE;

        /* If already up-to-date, we don't need to do anything. */
        if(c2b_uptodate(c2b))
        {
            pref_debug_mstore("c2b already up-to-date for chunk %d of %d from extent %d\n",
            (int)CHUNK(cep.offset), (int)castle_extent_size_get(cep.ext_id), (int)cep.ext_id);
            put_c2b(c2b);
            continue;
        }
        pref_debug_mstore("Scheduling read for chunk %d (of %d) from extent %d\n",
            (int)CHUNK(cep.offset), (int)castle_extent_size_get(cep.ext_id), (int)cep.ext_id);
        write_lock_c2b(c2b);
        c2b->end_io = c2_pref_io_end;
        BUG_ON(submit_c2b(READ, c2b));
    }

    pref_debug_mstore("Window now %s\n", c2_pref_window_to_str(window));

    return 0;
}

/**
 * Delete prefetch window.
 *
 * @param window    Window to delete.
 */
static void c2_pref_window_drop(c2_pref_window_t *window)
{
    debug("Deleting %s\n", c2_pref_window_to_str(window));
    /* Window must not be in the tree, and it must be alive. */
    BUG_ON(window->state & PREF_WINDOW_INSERTED);
    /* Must be locked. */
    BUG_ON(!mutex_is_locked(&window->lock));
    /* Set dead bit, release the lock, add put references down.
     * Only put the second reference, if we are the first ones to set the dead bit.
     */
    if(!(window->state & PREF_WINDOW_DEAD))
        c2_pref_window_put(window);
    window->state |= PREF_WINDOW_DEAD;
    mutex_unlock(&window->lock);
    c2_pref_window_put(window);
}

/**
 * Destroy prefetch window associated with c2b (if it exists).
 *
 * - Find prefetch window exactly matching c2b's offset
 * - Compare against window's cur_c2b pointer
 * - Destroy window if it matches
 *
 * @param c2b   Callback block to try and match against windows.
 *
 * @also c2_pref_window_remove()
 * @also c2_pref_window_drop()
 */
static void c2_pref_c2b_destroy(c2_block_t *c2b)
{
    c2_pref_window_t *window;
    c_ext_pos_t cur_cep;

    pref_debug_mstore("Destroying a prefetch c2b->cep"cep_fmt_str", nr_pages=%d.\n",
            cep2str(c2b->cep), c2b->nr_pages);
    /* Try to get reference to the window, for which this c2b corresponds to cur window. */ 
    window = c2_pref_window_find(c2b->cep, -1, 1);
    /* Exit if it's not there. */
    if(!window)
    {
        pref_debug_mstore("Didn't find a window for this c2b.\n");
        return;
    }
    mutex_lock(&window->lock);
    pref_debug_mstore("Found %s\n", c2_pref_window_to_str(window));
    /* Check that cur window matches c2b under lock. */
    cur_cep.ext_id = window->ext_id;
    cur_cep.offset = window->start_off;
    if(window->cur_c2b != c2b)
    {
        pref_debug_mstore("WARNING: prefetch window delete was racing an advance, or new c2b created.\n"
               "c2b->cep="cep_fmt_str", window start cep="cep_fmt_str_nl,
               cep2str(c2b->cep), cep2str(cur_cep));
        mutex_unlock(&window->lock);
        c2_pref_window_put(window);
        return;
    }
    BUG_ON(!(window->state & PREF_WINDOW_INSERTED));
    /* If cur_c2b is the same as c2b, ceps must agree too. */
    BUG_ON(EXT_POS_COMP(cur_cep, c2b->cep) != 0);
    window->cur_c2b = NULL;
    pref_debug_mstore("Destroying the window.\n");
    /* Remove it from the tree first. */
    c2_pref_window_remove(window);
    /* Drop the window. */
    c2_pref_window_drop(window);
}

/**
 * Demote c2bs between the start of the window and cep.
 *
 * @param window    Prefetch window whose c2bs to demote.
 * @param cep       c2bs prior to this offset to demote.
 *
 * Get the prefetch c2bs we used in this window.  This covers a range from
 * start_off to the chunk that cep.offset lies within.  We're moving the
 * window forward we should let the cache know we're done with these c2bs.
 * cur_c2b may no longer be allocated, but we can check that it existed.
 *
 * It may seem more sensible to store the prefetch c2bs within the window.
 * In fact this method would require that we either: a) hold a reference,
 * thereby preventing the c2bs from being freed under memory pressure; or
 * b) perform the same steps we do here to verify they still exist within
 * the cache.
 */
static void c2_pref_window_demote(c2_pref_window_t *window, c_ext_pos_t cep)
{
    c_ext_pos_t get_cep;
    int i;
    uint64_t pages;

    if (window->cur_c2b)
    {
        pref_debug_mstore("Window CHUNK(start_off) = %lld, CHUNK(end_off) = %lld, "
                "CHUNK(cep.offset) = %lld\n", CHUNK(window->start_off),
                CHUNK(window->end_off), CHUNK(cep.offset));
        get_cep.ext_id = cep.ext_id;
        get_cep.offset = window->start_off;
        pages = (C_CHK_SIZE - CHUNK_OFFSET(window->start_off)) >> PAGE_SHIFT;
        if (castle_cache_block_hash_demote(get_cep, pages))
            pref_debug_mstore("Demoted cur_c2b chunk %lld\n", CHUNK(get_cep.offset));
        else
            pref_debug_mstore("Unable to demote cur_c2b chunk %lld (not found)\n",
                    CHUNK(get_cep.offset));

        for (i = CHUNK(window->start_off) + 1; i < CHUNK(cep.offset); i++)
        {
            get_cep.offset = i * C_CHK_SIZE;
            castle_cache_block_hash_demote(get_cep, 256);
            if (castle_cache_block_hash_demote(get_cep, pages))
                pref_debug_mstore("Demoted chunk %lld\n",
                        CHUNK(get_cep.offset));
            else
                pref_debug_mstore("Unable to demote chunk %lld (not found)\n",
                        CHUNK(get_cep.offset));
        }
    }
}

/**
 * Advance the window and kick off prefetch I/O.
 *
 * - Inform cache that old prefetch blocks are no longer needed
 * - Update current window's start_off
 * - Calculate the number of additional pages to be prefetched
 * - Ensure c2b exists in the cache for the updated window
 * - Submit the new window for I/O
 *
 * NOTE: the window must not be in the tree when this function is called.
 *
 * @param window    The prefetch window to be advanced.
 * @param cep       Requested offset.
 * @param c2b_p     Returns c2b that identifies the window.
 *
 * @return See c2_pref_submit()
 *
 * @also c2_pref_window_remove()
 * @also set_c2b_prefetch()
 * @also c2_pref_submit()
 */
static int c2_pref_window_advance(c2_pref_window_t *window, c_ext_pos_t cep, c2_block_t **c2b_p)
{
    c2_block_t *c2b;
    c_ext_pos_t get_cep;
    uint64_t pages;

    BUG_ON(!mutex_is_locked(&window->lock));
    BUG_ON(cep.ext_id != window->ext_id);
    BUG_ON(window->state & PREF_WINDOW_INSERTED);
    BUG_ON(CHUNK_OFFSET(window->end_off) != 0); /* should be chunk aligned */
    pref_debug_mstore("Advancing %s\n", c2_pref_window_to_str(window));

    /* Demote c2bs that will fall off the front when we advance the window. */
    c2_pref_window_demote(window, cep);

    /* Update the window's start offset and calculate number of pages
     * to prefetch. */
    window->start_off = cep.offset;
    pages = window->start_off + window->pref_pages * PAGE_SIZE;
    pages = CHUNK(pages) - (CHUNK(window->end_off) - 1);
    pages = pages * BLKS_PER_CHK;

    pref_debug_mstore("Will prefetch %lld pages from %lld\n", pages, window->end_off);

    /* pages should be a whole chunk. */
    BUG_ON(pages % 256 != 0);

    /* Increase the adaptive prefetch if necessary. */
    if ((window->state & PREF_WINDOW_ADAPTIVE) && (window->pref_pages < PREF_ADAP_MAX_PAGES))
    {
        /* Double the number of pages to prefetch. */
        pref_debug_mstore("Next prefetch will be increased from %d to %d chunks.\n",
            window->pref_pages / BLKS_PER_CHK, window->pref_pages * 2 / BLKS_PER_CHK);
        window->pref_pages *= 2;
        if (window->pref_pages > PREF_ADAP_MAX_PAGES)
            window->pref_pages = PREF_ADAP_MAX_PAGES;
    }

    /* Get the first c2b we prefetched in this window.  This covers a range
     * from start_off to the end of the chunk it lies within.
     * We will perform no I/O on this block but we require it is: allocated,
     * marked as a prefetch block, and exists within the cache.
     *
     * This semantic is required so that prefetch windows are freed (see
     * castle_cache_block_free() and c2_pref_c2b_destroy()). */
    get_cep.ext_id = window->ext_id;
    get_cep.offset = window->start_off;
    c2b = castle_cache_block_get(get_cep,
            (C_CHK_SIZE - CHUNK_OFFSET(window->start_off)) >> PAGE_SHIFT);
    set_c2b_prefetch(c2b);
    *c2b_p = c2b;

    /* Start the prefetch. */
    return c2_pref_submit(window, pages);
}

/**
 * Determine whether we need to issue a prefetch based on cep and window.
 *
 * - Determine whether to advance the window
 * - Schedule prefetch if the window was advanced
 *
 * NOTE: when any modifications are made to (start_off, end_off, pref_pages) the
 * window MUST NOT be in the tree (this would break tree walks).
 *
 * @return EINVAL: failed to prefetch.
 * @return EAGAIN: cep not within the window.
 * @return EEXIST: we failed to reinsert after advancing window.
 * @return EXIT_SUCCESS: window scheduled.
 *
 * @also c2_pref_submit()
 * @also c2_pref_window_advance()
 * @also c2_pref_new_window_schedule()
 */
static int c2_pref_window_schedule(c2_pref_window_t *window, c_ext_pos_t cep)
{
    c2_block_t *cur_c2b;
    int size;

    /* Hold the window lock to prevent a race. */
    mutex_lock(&window->lock);

    pref_debug_mstore("Determining whether to prefetch more for cep="cep_fmt_str", in %s\n", 
            cep2str(cep), c2_pref_window_to_str(window));
    BUG_ON(window->ext_id != cep.ext_id);

    /* If the window isn't new it could have changed since we found it in the
     * tree.  To verify that it hasn't (or that we still have a valid window)
     * we compare cep to the window. */
    if (window->state & PREF_WINDOW_DEAD ||
            c2_pref_window_compare(window, cep, (window->state & PREF_WINDOW_FORWARD ? 1 : 0)))
    {
        printk("WARNING: it seems we have raced to access prefetch window, dead=%d.\n",
                !!(window->state & PREF_WINDOW_DEAD));
        mutex_unlock(&window->lock);
        c2_pref_window_put(window);

        return -EAGAIN;
    }

    /* The point at which we advance the prefetch window depends on the prefetch
     * behaviour we require.  When we do call c2_pref_window_advance() we always
     * fetch enough blocks from end_off so that there are pref_pages available
     * from the requested cep.offset.
     *
     * We have the following behaviours:
     *
     * 1. No ganging of chunks.  Advance as soon as requested cep.offset exceeds
     *    start_off.
     *    This generally results in one chunk being fetched at a time.
     *
     * 2. Ganging of chunks but the window size (end_off-start_off) is not yet
     *    large enough to use the advance threshold (adv_thresh) that dictates
     *    how far cep.offset must be from end_off before we prefetch again.
     *    Fall back to behaviour (1).
     *
     * 3. Ganging of chunks and we have a large enough window size.  Advance the
     *    window when cep.offset is adv_thresh from end_off.
     *    This generally results in multiple chunks being fetched at a time,
     *    hopefully reducing the need for multiple seeks as required for (1).
     */
    size = CHUNK(window->end_off) - CHUNK(window->start_off);   /* of window */
    if (((!window->adv_thresh || size <= window->adv_thresh)    /* (1) & (2) */
                && CHUNK(cep.offset) > CHUNK(window->start_off))
            || ((size > window->adv_thresh)                     /* (3) */
                && CHUNK(cep.offset) > CHUNK(window->end_off) - window->adv_thresh))
    {
        int ret;    /* for debugging porpoises. */

        pref_debug_mstore("Prefetching for %s\n", c2_pref_window_to_str(window));

        /* Slide the window forward & kick off prefetch.
         * The window cannot be in the tree while we are making changes as this
         * breaks walks. */
        c2_pref_window_remove(window);
        if (c2_pref_window_advance(window, cep, &cur_c2b) != EXIT_SUCCESS)
        {
            /* Probably an extent overrun and nothing to worry about. */
            pref_debug_mstore("Failed to advance %s\n",
                c2_pref_window_to_str(window));

            BUG_ON(window->state & PREF_WINDOW_INSERTED);
        }
        if ((ret = c2_pref_window_insert(window, cur_c2b)) != EXIT_SUCCESS)
        { 
            BUG_ON(ret != -EINVAL);
            BUG_ON(window->state & PREF_WINDOW_INSERTED);
            /* We failed to insert, because there already is a window at that
             * location.  Deallocate the window. */
            printk("WARNING: window %s already exists in the tree.\n",
                c2_pref_window_to_str(window));
            c2_pref_window_drop(window);

            return -EEXIST; 
        }
    }

    /* cep is now guaranteed to be within current window. */
    BUG_ON(c2_pref_window_compare(window, cep, (window->state & PREF_WINDOW_FORWARD ? 1 : 0)));

    /* We succeeded doing everything.  Release the lock.  Put the window. */
    pref_debug_mstore("Releasing window lock, putting the reference down.\n");
    mutex_unlock(&window->lock);
    c2_pref_window_put(window);

    return EXIT_SUCCESS;
}

/**
 * Initialise and schedule a new prefetch window.
 *
 * Schedules I/O to the end of the window's first chunk, ensuring that end_off
 * is chunk-aligned.  At this point we have a valid window that needs advancing.
 *
 * - Initialise the window
 * - Prefetch to the end of the first chunk
 * - Advance the window
 * - Insert into the tree
 *
 * NOTE: c2_pref_window_schedule() code duplication for readability.
 *
 * @return EINVAL: failed to prefetch.
 * @return EAGAIN: cep not within the window.
 * @return EEXIST: we failed to reinsert after advancing window.
 * @return EXIT_SUCCESS: window scheduled.
 *
 * @also c2_pref_submit()
 * @also c2_pref_window_schedule()
 */
static int c2_pref_new_window_schedule(c2_pref_window_t *window, c_ext_pos_t cep)
{
    int pages, ret;
    c2_block_t *cur_c2b;

    /* Hold the window lock as called functions require it.  There's no chance
     * of a race as this is a new window (not in the tree) hence we have can
     * have the only reference. */
    mutex_lock(&window->lock);

    BUG_ON(!window->state & PREF_WINDOW_NEW);
    BUG_ON(window->state & PREF_WINDOW_INSERTED);
    BUG_ON(!mutex_is_locked(&window->lock));
    BUG_ON(window->ext_id != cep.ext_id);

    /* This is a new window and cep.offset may not be chunk aligned.
     * We'll fetch to the end of the block that cep.offset lies within. */
    window->state &= ~PREF_WINDOW_NEW;
    window->start_off = cep.offset;
    window->end_off = cep.offset;
    pages = (C_CHK_SIZE - CHUNK_OFFSET(window->start_off)) >> PAGE_SHIFT;

    pref_debug_mstore("Initialised %s\n", c2_pref_window_to_str(window));
    pref_debug_mstore("%d pages to end of chunk.\n", pages);

    /* Pass off for the initial chunk to be prefetched. */
    if (c2_pref_submit(window, pages) != EXIT_SUCCESS)
    {
        pref_debug_mstore("Failed to submit %s\n",
            c2_pref_window_to_str(window));
        c2_pref_window_drop(window);
        return -EINVAL;
    }
    pref_debug_mstore("Completed prefetch of initial chunk.\n");

    /* Slide the window forward & kick off prefetch.
     * The window cannot be in the tree while we are making changes as this
     * breaks walks. */
    if (c2_pref_window_advance(window, cep, &cur_c2b) != EXIT_SUCCESS)
    {
        /* Probably an extent overrun and nothing to worry about. */
        pref_debug_mstore("Failed to advance %s\n",
            c2_pref_window_to_str(window));

        BUG_ON(window->state & PREF_WINDOW_INSERTED);
    }
    if ((ret = c2_pref_window_insert(window, cur_c2b)) != EXIT_SUCCESS)
    { 
        BUG_ON(ret != -EINVAL);
        BUG_ON(window->state & PREF_WINDOW_INSERTED);
        /* We failed to insert, because there already is a window at that
         * location.  Deallocate the window. */
        printk("WARNING: window %s already exists in the tree.\n",
            c2_pref_window_to_str(window));
        c2_pref_window_drop(window);

        return -EEXIST; 
    }

    /* cep is now guaranteed to be within current window. */
    BUG_ON(c2_pref_window_compare(window, cep, (window->state & PREF_WINDOW_FORWARD ? 1 : 0)));

    /* We succeeded doing everything.  Release the lock.  Put the window. */
    pref_debug_mstore("Releasing window lock, putting the reference down.\n");
    mutex_unlock(&window->lock);
    c2_pref_window_put(window);

    return EXIT_SUCCESS;
}

/**
 * Advise prefetcher of intention to begin read.
 *
 * This is the main entry point into the prefetcher.
 *
 * - Get prefetch window for c2b->cep
 * - Schedules prefetch via c2_pref_window_schedule()
 *
 * @param c2b       c2b to start prefetching.
 * @param forward   Whether we are prefetching forwards.
 *
 * @return ENOMEM: Failed to allocate a new prefetch window.
 * @return See c2_pref_window_schedule()
 *
 * @see c2_pref_window_get()
 * @see c2_pref_window_schedule()
 */
static int castle_cache_prefetch_advise(c2_block_t *c2b, int forward)
{
    c2_pref_window_t *window;
    c_ext_pos_t cep;

    /* Back prefetch not implemented yet. */
    BUG_ON(!forward);

    cep = c2b->cep;
    BUG_ON(BLOCK_OFFSET(cep.offset));
    pref_debug_mstore("\n\n");
    pref_debug_mstore("Asking to prefetch frwd cep: "cep_fmt_str_nl, __cep2str(cep));

    /* Find the prefetch window for this c2b */
    window = c2_pref_window_get(cep, forward);
    if(!window)
    {
        pref_debug_mstore("Warning: failed to allocate prefetch window.\n");
        return -ENOMEM;
    }

    /* Hand off the real work. */
    if (window->state & PREF_WINDOW_NEW)
        return c2_pref_new_window_schedule(window, cep);
    else
        return c2_pref_window_schedule(window, cep);
}

/**
 * Advise the cache of intention to perform specific operation on a block.
 */
int castle_cache_block_advise(c2_block_t *c2b, c2b_advise_t advise) 
{
    switch(advise)
    {
        case C2B_PREFETCH_FRWD:
            return castle_cache_prefetch_advise(c2b, 1);
        default:
            return -ENOSYS;
    }
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
        printk("ERROR: Castle cache pages do not add up:\n"
               "       #dirty_pgs=%d, #clean_pgs=%d, #freelist_pgs=%d\n",
                dirty, clean, free);
    }
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
static void castle_cache_flush_endio(c2_block_t *c2b)
{
    atomic_t *count = c2b->private;

    BUG_ON(!c2b_flushing(c2b));
    clear_c2b_flushing(c2b);
    read_unlock_c2b(c2b);
    put_c2b(c2b);
    BUG_ON(atomic_read(count) == 0);
    atomic_dec(count);
    atomic_inc(&castle_cache_flush_seq);
    wake_up(&castle_cache_flush_wq);
}

static int castle_cache_flush(void *unused)
{
    int target_dirty_pgs, to_flush, flush_size, dirty_pgs, batch_idx, exiting, i;
    struct list_head *l, *t;
    c2_block_t *c2b;
#define MIN_FLUSH_SIZE     128
#define MAX_FLUSH_SIZE     (4*1024)
#define MIN_FLUSH_FREQ     5        /* Min flush rate: 5*128 pgs/s = 2.5 MB/s. */

#define FLUSH_BATCH        64
    c2_block_t *c2b_batch[FLUSH_BATCH];
    atomic_t in_flight;

    /* We'll try to maintain # dirty pages at this */
    target_dirty_pgs = 3 * (castle_cache_size / 4);
    atomic_set(&in_flight, 0);
    flush_size = 0;

    for(;;)
    {
        /* We know that we should flush everything out, and exit when cache_fini()
           asked us to stop. */ 
        exiting = kthread_should_stop();
        /* Wait for 95% of IOs to complete (or all of them if we are exiting). 
           When exiting, we need to wait for all the IO, because otherwise we may
           end up busy looping (because wait_event below never sleeps). */
        debug("====> Waiting for 95%% of outstanding IOs to complete.\n");
        wait_event_interruptible(castle_cache_flush_wq, 
               (exiting ? (atomic_read(&in_flight) == 0)
                        : (atomic_read(&in_flight) <= flush_size / 20)));

        /* Wait until enough pages have been dirtied to make it worth while
         * this will rate limit us to a min of 10 MIN_BATCHes a second */
        debug("====> Waiting completed, now waiting for big enough flush.\n");
        wait_event_interruptible_timeout(
            castle_cache_flush_wq, 
            exiting ||
            (atomic_read(&castle_cache_dirty_pages) - target_dirty_pgs > MIN_FLUSH_SIZE),
            HZ/MIN_FLUSH_FREQ);
        
        dirty_pgs = atomic_read(&castle_cache_dirty_pages);  

        /* Check if we should still continue. NOTE: we know that there is no outstanding IO,
           because we've waited for all of it to complete in the first wait_event. */
        if(exiting && (dirty_pgs == 0))
            break;
 
        /* 
         * Work out how many pages to flush.
         * Note that (dirty_pgs - target_dirty_pages) approximates the number of pages that
         * got dirtied since the last time around the loop (modulo MIN & MAX).
         */
        flush_size = dirty_pgs - target_dirty_pgs;
        flush_size = max(MIN_FLUSH_SIZE, flush_size);
        flush_size = min(MAX_FLUSH_SIZE, flush_size);
        /* If we are removing the module, we need to flush all pages */
        if(exiting || (flush_size > dirty_pgs))
            flush_size = dirty_pgs;

        /* Submit the IOs in batches of at most FLUSH_BATCH */ 
        to_flush = flush_size;
        debug("====> Flushing: %d pages out of %d dirty.\n", to_flush, dirty_pgs);
next_batch:        
        batch_idx = 0;
        spin_lock_irq(&castle_cache_block_hash_lock);
        list_for_each_safe(l, t, &castle_cache_dirtylist)
        {
            if(to_flush <= 0)
                break;
            c2b = list_entry(l, c2_block_t, dirty);
            if(!read_trylock_c2b(c2b))
            {
                BUG_ON(exiting);
                continue;
            }
            /* In current design, it is possible to try to flush same c2b twice.
             * We need a bit(C2B_flushing) to know whether a page is already in
             * flush process. */
            if (test_set_c2b_flushing(c2b))
            {
                read_unlock_c2b(c2b);
                continue;
            }
            /* This is slightly dangerous, but should be fine */
            list_move_tail(l, &castle_cache_dirtylist);
            get_c2b(c2b);
            /* It's possible that not all the pages in the c2b are dirty.
               So we may actually flush less than we wanted to, but this only affects the
               effective batch size. */ 
               to_flush -= castle_cache_c2b_to_pages(c2b);
            c2b_batch[batch_idx++] = c2b;
            if(batch_idx >= FLUSH_BATCH)
                break;
        }
        spin_unlock_irq(&castle_cache_block_hash_lock);
        
        debug("====>  Batch of: %d pages.\n", batch_idx);
        /* We've dropped the hash lock, submit all the write requests now */
        for(i=0; i<batch_idx; i++)
        {
            atomic_inc(&in_flight);
            c2b_batch[i]->end_io = castle_cache_flush_endio; 
            c2b_batch[i]->private = &in_flight;
            BUG_ON(submit_c2b(WRITE, c2b_batch[i]));
        }

        /* We may have to flush more than one batch */
        if(to_flush > 0)
        {
            if(batch_idx == FLUSH_BATCH)
                goto next_batch; 
            /* If we still have buffers to flush, but we could not lock 
               enough dirty buffers print a warning message, and stop.
               Warn if the # of dirty pages is greater than a constant.
               If it is not, the pages are likely write locked. */
            if(dirty_pgs > 100)
                printk("WARNING: Could not find enough dirty pages to flush\n"
                       "  Stats: dirty=%d, clean=%d, free=%d, in_flight=%d\n"
                       "         target=%d, to_flush=%d, blocks=%d\n",
                    atomic_read(&castle_cache_dirty_pages), 
                    atomic_read(&castle_cache_clean_pages),
                    castle_cache_page_freelist_size * PAGES_PER_C2P,
                    atomic_read(&in_flight),
                    target_dirty_pgs, to_flush, batch_idx); 
        }
        
    }

    BUG_ON(atomic_read(&in_flight) != 0);
    debug("====> Castle cache flush loop EXITING.\n");

    return 0;
}

void castle_cache_flush_wakeup(void)
{
    wake_up_process(castle_cache_flush_thread);
}

static void castle_cache_extent_flush_endio(c2_block_t *c2b)
{
    atomic_t *outst_pgs = c2b->private;
    
    clear_c2b_flushing(c2b);
    read_unlock_c2b(c2b);
    put_c2b(c2b);
    if (atomic_dec_and_test(outst_pgs))
        wake_up(&castle_cache_flush_wq);
}

int castle_cache_extent_flush(c_ext_id_t ext_id, uint64_t start, uint64_t size)
{
    c2_block_t *c2b;
    c_ext_pos_t cep;
    atomic_t    outst_pgs = ATOMIC(0);
    uint64_t    i, first_pg, nr_pages, dirty_pgs = 0;
    c_chk_cnt_t ext_size;
    
    ext_size = castle_extent_size_get(ext_id);
    if (!ext_size)
        return -EINVAL;

    /* Flush complete extent, if size is 0. */
    if (size == 0)
    {
        size  = ext_size * C_CHK_SIZE;
        start = 0;
    }

    cep.ext_id = ext_id;
    first_pg   = (start >> C_BLK_SHIFT);
    nr_pages   = (size - 1) / C_BLK_SIZE + 1;
    BUG_ON((first_pg + nr_pages) > (ext_size * BLKS_PER_CHK));

    debug("Extent flush: (%llu) -> %llu\n", ext_id, nr_pages/BLKS_PER_CHK);
    for (i=first_pg; i<nr_pages; i++)
    {
        cep.offset = i * C_BLK_SIZE;
        c2b = _castle_cache_block_get(cep, 1, 1);
        BUG_ON(!c2b);
        /* c2b_flushing bit makes sure that flush thread doesnt submit parallel
         * writes. */
        read_lock_c2b(c2b);
        if (test_set_c2b_flushing(c2b))
            goto skip_page;
        if (!c2b_uptodate(c2b) || !c2b_dirty(c2b))
        {
            clear_c2b_flushing(c2b);
            goto skip_page;
        }
        c2b->end_io  = castle_cache_extent_flush_endio;
        c2b->private = (void *)&outst_pgs;
        atomic_inc(&outst_pgs);
        dirty_pgs++;
        BUG_ON(submit_c2b(WRITE, c2b));
        continue;
skip_page:
        read_unlock_c2b(c2b);
        put_c2b(c2b);
    }

    wait_event(castle_cache_flush_wq, (atomic_read(&outst_pgs) == 0));

    debug("Extent flush completed: (%llu) -> %llu/%llu\n", 
           ext_id, dirty_pgs, nr_pages);

    return 0;
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

    if(!castle_cache_page_hash || !castle_cache_block_hash)
        return -ENOMEM;
    
    /* Init the tables. */
    for(i=0; i<castle_cache_page_hash_buckets; i++)
        INIT_HLIST_HEAD(&castle_cache_page_hash[i]);
    for(i=0; i<castle_cache_block_hash_buckets; i++)
        INIT_HLIST_HEAD(&castle_cache_block_hash[i]);

    return 0;
}

static void castle_cache_hashes_fini(void)
{
    struct hlist_node *l, *t;
    c2_block_t *c2b;
    int i;

    if(!castle_cache_block_hash || !castle_cache_page_hash) 
    {
        if(castle_cache_block_hash)
            castle_vfree(castle_cache_block_hash);
        if(castle_cache_page_hash)
            castle_vfree(castle_cache_page_hash);
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
                printk("cep="cep_fmt_str"not dropped count=%d, locked=%d.\n",
                    cep2str(c2b->cep), atomic_read(&c2b->count), c2b_locked(c2b));
#ifdef CASTLE_DEBUG
                if(c2b_locked(c2b))
                    printk("Locked from: %s:%d\n", c2b->file, c2b->line);
#endif
            }

            BUG_ON(c2b_locked(c2b));
            BUG_ON(atomic_read(&c2b->count) != 0);
            castle_cache_block_free(c2b);
        }
    }

#ifdef CASTLE_DEBUG
    /* All cache pages should have been removed from the hash by now (there are no c2bs left) */
    for(i=0; i<castle_cache_page_hash_buckets; i++)
    {
        c2_page_t *c2p;

        hlist_for_each_entry(c2p, l, &castle_cache_page_hash[i], hlist)
        {
            printk("c2p->id=%d not freed, count=%d, cep="cep_fmt_str_nl,
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
        /* For debugging, save the c2p pointer in usude lru list. */
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
        INIT_LIST_HEAD(&c2b->clean); */
    INIT_LIST_HEAD(&c2b->free);
}

static int castle_cache_freelists_init(void)
{
    int i;

    if(!castle_cache_blks || !castle_cache_pgs)
        return -ENOMEM;

    memset(castle_cache_blks, 0, sizeof(c2_block_t) * castle_cache_block_freelist_size);
    memset(castle_cache_pgs,  0, sizeof(c2_page_t)  * castle_cache_page_freelist_size);
    /* Init the c2p freelist */
    for(i=0; i<castle_cache_page_freelist_size; i++)
    {
        c2_page_t *c2p = castle_cache_pgs + i;

        castle_cache_c2p_init(c2p);
#ifdef CASTLE_DEBUG
        c2p->id = i;
#endif
        /* Add c2p to page_freelist */
        list_add(&c2p->list, &castle_cache_page_freelist);
    }
    /* Init the c2b freelist */
    for(i=0; i<castle_cache_block_freelist_size; i++)
    {
        c2_block_t *c2b = castle_cache_blks + i; 

        castle_cache_c2b_init(c2b);
        /* Add c2b to block_freelist */
        list_add(&c2b->free, &castle_cache_block_freelist);
    }

    return 0;
}

static void castle_cache_freelists_fini(void)
{
    struct list_head *l, *t;
    c2_page_t *c2p;
    int i;
#ifdef CASTLE_DEBUG     
    c2_block_t *c2b;
#endif    

    if(!castle_cache_blks || !castle_cache_pgs)
    {
        if(castle_cache_blks)
            castle_vfree(castle_cache_blks);
        if(castle_cache_pgs)
            castle_vfree(castle_cache_pgs);
        return;
    }

    list_for_each_safe(l, t, &castle_cache_page_freelist)
    {
        list_del(l);
        c2p = list_entry(l, c2_page_t, list);
        for(i=0; i<PAGES_PER_C2P; i++)
            __free_page(c2p->pages[i]);
    }

#ifdef CASTLE_DEBUG     
    list_for_each_safe(l, t, &castle_cache_block_freelist)
    {
        list_del(l);
        c2b = list_entry(l, c2_block_t, free);
        BUG_ON(c2b->c2ps != NULL);
    }
#endif
}

/**********************************************************************************************
 * Generic storage functionality for (usually small) persisted data (e.g. versions in 
 * version tree, double arrays).
 */
#define CASTLE_MSTORE_ENTRY_DELETED     (1<<1)
struct castle_mstore_entry {
    uint8_t flags;
    char payload[0];
} PACKED;

static inline struct castle_mstore_entry* castle_mstore_entry_get(struct castle_mstore *mstore,
                                                                  struct castle_mlist_node *node,
                                                                  int idx)
/* Works out where a given entry is in an mstore */
{
    return (struct castle_mstore_entry *)(node->payload + mstore->entry_size * idx); 
}

static inline char* castle_mstore_entry_payload_get(struct castle_mstore *mstore,
                                                    struct castle_mlist_node *node,
                                                    int idx)
{
    struct castle_mstore_entry *entry = castle_mstore_entry_get(mstore, node, idx);

    return entry->payload;
}

static inline size_t castle_mstore_payload_size(struct castle_mstore *mstore)
{
    return mstore->entry_size - sizeof(struct castle_mstore_entry);
}

static void castle_mstore_iterator_validate(struct castle_mstore_iter *iter)
{
    struct castle_mlist_node *node = c2b_buffer(iter->node_c2b);

    if((node->magic != MLIST_NODE_MAGIC) || 
       (node->used  >  node->capacity))
    {
        printk("Trying to iterate over non-mlist node or over-full node.\n");
        write_unlock_c2b(iter->node_c2b);
        put_c2b(iter->node_c2b);
        iter->node_c2b = NULL;
    }
    debug_mstore("Succeeded at validating the iterator.\n");
}

static void castle_mstore_iterator_advance(struct castle_mstore_iter *iter)
{
    struct castle_mlist_node *node;
    struct castle_mstore_entry *mentry;
    c2_block_t *c2b;
    int ret;

again: 
    c2b = NULL;
    debug_mstore("Advancing the iterator.\n");

    /* Ignore attemts to advance completed iterator */
    if(!iter->node_c2b)
        return;
    iter->node_idx++;
    node = c2b_buffer(iter->node_c2b);
    debug_mstore("node_idx=%d, node->used=%d.\n", iter->node_idx, node->used);
    /* Check if we need to advance to the next node */
    BUG_ON(iter->node_idx > node->used);
    if(iter->node_idx == node->used)
    {
        debug_mstore("Next node.\n");
        /* Update the node_c2 field appropriately */
        if(!EXT_POS_INVAL(node->next))
        {
            debug_mstore("Node exists.\n");
            /* If next block exist, make sure the current one is full */
            BUG_ON(node->used != node->capacity);
            c2b = castle_cache_page_block_get(node->next);
            write_lock_c2b(c2b);
            if(!c2b_uptodate(c2b)) 
            {
                debug_mstore("Scheduling a read.\n");
                ret = submit_c2b_sync(READ, c2b);
                BUG_ON(ret);
            }
        } else
        /* For the sole benefit of initialising the store */
        {
            down(&iter->store->mutex);
            iter->store->last_node_cep    = iter->node_c2b->cep;
            iter->store->last_node_unused = node->capacity - node->used;
            up(&iter->store->mutex);
            debug_mstore("End of the list, last_node_unused=%d.\n", 
                    iter->store->last_node_unused);
        }
        debug_mstore("Unlocking prev node.\n");
        write_unlock_c2b(iter->node_c2b); 
        put_c2b(iter->node_c2b);
        iter->node_c2b = c2b;
        iter->node_idx = -1;
        debug_mstore("Advancing again.\n");
        goto again;
    }
    /* We've found an entry (may be a deleted one) */
    debug_mstore("Entry found.\n");
    mentry = castle_mstore_entry_get(iter->store, node, iter->node_idx);
    if(mentry->flags & CASTLE_MSTORE_ENTRY_DELETED)
    {
        debug_mstore("The entry has been deleted. Advancing.");
        goto again;
    }
    debug_mstore("Exiting advance.\n");
}

int castle_mstore_iterator_has_next(struct castle_mstore_iter *iter)
{
    debug_mstore("Iterator %s.\n", iter->node_c2b ? "has next" : "doesn't have next");
    return iter->node_c2b ? 1 : 0;
}

void castle_mstore_iterator_next(struct castle_mstore_iter *iter,
                                 void *entry,
                                 c_mstore_key_t *key)
{
    struct castle_mlist_node *node;

    debug_mstore("Iterator next.\n");
    BUG_ON(!castle_mstore_iterator_has_next(iter));
    node = c2b_buffer(iter->node_c2b);
    if(entry)
    {
        debug_mstore("Copying entry.\n");
        memcpy(entry,
               castle_mstore_entry_payload_get(iter->store, node, iter->node_idx),
               castle_mstore_payload_size(iter->store));
    }
    if(key)
    {
        key->cep = iter->node_c2b->cep;
        key->idx = iter->node_idx;
        debug_mstore("Key: cep="cep_fmt_str", idx=%d.\n", 
                cep2str(key->cep), key->idx);
    }
    debug_mstore("Advancing the iterator.\n"); 
    castle_mstore_iterator_advance(iter);
}

void castle_mstore_iterator_destroy(struct castle_mstore_iter *iter)
{
    debug_mstore("Destroying the iterator.\n"); 
    if(iter->node_c2b)
    {
        debug_mstore("Unlocking the node.\n"); 
        write_unlock_c2b(iter->node_c2b);
        put_c2b(iter->node_c2b);
    }
    debug_mstore("Freeing.\n"); 
    castle_free(iter);
}

struct castle_mstore_iter* castle_mstore_iterate(struct castle_mstore *store)
{
    struct castle_fs_superblock *fs_sb;
    struct castle_mstore_iter *iter;
    c_ext_pos_t  list_cep;

    debug_mstore("Creating the iterator.\n"); 
    iter = castle_zalloc(sizeof(struct castle_mstore_iter), GFP_KERNEL);
    if(!iter)
        return NULL;

    iter->store = store;
    fs_sb = castle_fs_superblocks_get(); 
    list_cep = fs_sb->mstore[store->store_id];
    castle_fs_superblocks_put(fs_sb, 0); 
    debug_mstore("Read first list node for mstore %d, got "cep_fmt_str_nl,
                    store->store_id, cep2str(list_cep));
    if(EXT_POS_INVAL(list_cep))
        return NULL;
    iter->node_c2b = castle_cache_page_block_get(list_cep);
    iter->node_idx = -1;
    debug_mstore("Locknig the first node "cep_fmt_str_nl,
            cep2str(iter->node_c2b->cep));
    write_lock_c2b(iter->node_c2b);
    if(!c2b_uptodate(iter->node_c2b)) 
        BUG_ON(submit_c2b_sync(READ, iter->node_c2b));
    debug_mstore("Node uptodate\n");
    castle_mstore_iterator_validate(iter);
    castle_mstore_iterator_advance(iter);
    debug_mstore("Iterator ready.\n");

    return iter;
}

static void castle_mstore_node_add(struct castle_mstore *store)
/* Needs to be called with store mutex locked. Otherwise two/more racing node_adds may 
   be generated due to the lock-free period between last_node_unused check, and 
   node_add. */
{
    struct castle_mlist_node *node, *prev_node;
    struct castle_fs_superblock *fs_sb;
    c2_block_t *c2b, *prev_c2b;
    c_ext_pos_t  cep;
    
    debug_mstore("Adding a node.\n");
    /* Check if mutex is locked */
    BUG_ON(down_trylock(&store->mutex) == 0);

    /* Prepare the node first */
    BUG_ON(castle_ext_fs_get(&mstore_ext_fs,
                             C_BLK_SIZE,
                             0,
                             &cep) < 0);
    c2b = castle_cache_page_block_get(cep);
    debug_mstore("Allocated "cep_fmt_str_nl, cep2str(cep));
    write_lock_c2b(c2b);
    set_c2b_uptodate(c2b);
    debug_mstore("Locked.\n");

    /* Init the node correctly */
    node = c2b_buffer(c2b);
    node->magic     = MLIST_NODE_MAGIC;
    node->capacity  = (PAGE_SIZE - sizeof(struct castle_mlist_node)) / store->entry_size;
    node->used      = 0;
    node->next      = INVAL_EXT_POS;
    dirty_c2b(c2b);
    debug_mstore("Inited the node.\n");
    /* Update relevant pointers to point to us (either FS superblock, or prev node) */
    if(EXT_POS_INVAL(store->last_node_cep))
    {
        debug_mstore("Linking into the superblock.\n");
        fs_sb = castle_fs_superblocks_get(); 
        BUG_ON(!EXT_POS_INVAL(fs_sb->mstore[store->store_id]));
        fs_sb->mstore[store->store_id] = cep;
        castle_fs_superblocks_put(fs_sb, 1); 
    } else
    {
        prev_c2b = castle_cache_page_block_get(store->last_node_cep);
        debug_mstore("Linking into the prev node "cep_fmt_str_nl, 
                cep2str(prev_c2b->cep));
        write_lock_c2b(prev_c2b);
        if(!c2b_uptodate(prev_c2b))
            BUG_ON(submit_c2b_sync(READ, prev_c2b));
        debug_mstore("Read prev node.\n"); 
        prev_node = c2b_buffer(prev_c2b);
        prev_node->next = cep;
        dirty_c2b(prev_c2b);
        write_unlock_c2b(prev_c2b);
        put_c2b(prev_c2b);
    }
    debug_mstore("Updating the saved last node.\n"); 
    /* Finally, save this node as the last node */
    store->last_node_cep    = cep;
    store->last_node_unused = node->capacity; 
    write_unlock_c2b(c2b);
    put_c2b(c2b);
}

static void castle_mstore_entry_mod(struct castle_mstore *store,
                                    c_mstore_key_t key,
                                    void *entry)
{
    struct castle_mlist_node *node;
    struct castle_mstore_entry *mentry;
    c2_block_t *node_c2b;
    
    debug_mstore("Modifying an entry in "cep_fmt_str", idx=%d, %s.\n",
            cep2str(key.cep), key.idx, entry ? "updating" : "deleting"); 
    node_c2b = castle_cache_page_block_get(key.cep);
    write_lock_c2b(node_c2b);
    if(!c2b_uptodate(node_c2b))
        BUG_ON(submit_c2b_sync(READ, node_c2b));
    debug_mstore("Read the block.\n");
    node = c2b_buffer(node_c2b);
    mentry = castle_mstore_entry_get(store, node, key.idx);
    if(entry == NULL)
    {
        mentry->flags |= CASTLE_MSTORE_ENTRY_DELETED;
    } else
    {
        if(mentry->flags & CASTLE_MSTORE_ENTRY_DELETED)
        {
            printk("WARNING: updating removed mstore entry for mstore=%d, key=("cep_fmt_str", %d)\n",
                    store->store_id, cep2str(key.cep), key.idx);
            mentry->flags &= ~CASTLE_MSTORE_ENTRY_DELETED;
        }
        memcpy(mentry->payload,
               entry,
               castle_mstore_payload_size(store));
    }
    dirty_c2b(node_c2b);
    write_unlock_c2b(node_c2b); 
    put_c2b(node_c2b);
}

void castle_mstore_entry_update(struct castle_mstore *store,
                                c_mstore_key_t key,
                                void *entry)
{
    BUG_ON(!entry);
    castle_mstore_entry_mod(store, key, entry);
}

void castle_mstore_entry_delete(struct castle_mstore *store,
                                c_mstore_key_t key)
{
    castle_mstore_entry_mod(store, key, NULL);
}

c_mstore_key_t castle_mstore_entry_insert(struct castle_mstore *store,
                                          void *entry)
{
    struct castle_mlist_node *node;
    struct castle_mstore_entry *mentry;
    c_mstore_key_t key;
    c2_block_t *c2b;

    debug_mstore("Inserting a new entry.\n");
    down(&store->mutex);
    /* We should always have at least one more entry left in the last node */
    BUG_ON(store->last_node_unused <= 0);
    /* Write the entry to the last node */
    debug_mstore("Reading last node "cep_fmt_str_nl,
            cep2str(store->last_node_cep));
    c2b = castle_cache_page_block_get(store->last_node_cep);
    write_lock_c2b(c2b);
    if(!c2b_uptodate(c2b))
        BUG_ON(submit_c2b_sync(READ, c2b));
    node = c2b_buffer(c2b);
    key.cep = c2b->cep;
    key.idx = node->used;
    debug_mstore("Writing out under idx=%d.\n", key.idx);
    mentry = castle_mstore_entry_get(store, node, key.idx);
    mentry->flags = 0;
    memcpy(mentry->payload,
           entry,
           castle_mstore_payload_size(store));
    node->used++;
    store->last_node_unused--;
    dirty_c2b(c2b);
    write_unlock_c2b(c2b); 
    put_c2b(c2b);
 
    /* Add a new node if we've run out */
    if(store->last_node_unused == 0)
    {
        debug_mstore("Adding a new node to the list.\n");
        castle_mstore_node_add(store);
    }
    up(&store->mutex);

    return key;
}

static struct castle_mstore *castle_mstore_alloc(c_mstore_id_t store_id, size_t entry_size)
{
    struct castle_mstore *store;

    debug_mstore("Allocating mstore id=%d.\n", store_id);
    store = castle_zalloc(sizeof(struct castle_mstore), GFP_KERNEL);
    if(!store)
        return NULL;

    store->store_id         = store_id;
    store->entry_size       = entry_size + sizeof(struct castle_mstore_entry);
    init_MUTEX(&store->mutex);
    store->last_node_cep    = INVAL_EXT_POS; 
    store->last_node_unused = -1;
    debug_mstore("Done.\n");

    return store;
}

struct castle_mstore* castle_mstore_open(c_mstore_id_t store_id, size_t entry_size)
{
    struct castle_fs_superblock *fs_sb;
    struct castle_mstore *store;
    struct castle_mstore_iter *iterator;

    debug_mstore("Opening mstore.\n");
    /* Sanity check, to see if store_id isn't too large. */
    if(store_id >= sizeof(fs_sb->mstore) / sizeof(c_ext_pos_t ))
    {
        printk("Asked for mstore id=%d, this is too large.\n", store_id);
        return NULL;
    }

    store = castle_mstore_alloc(store_id, entry_size);
    if(!store)
        return NULL;
    /* Inefficient, because we read all the data to get to the last node,
       but mstores are expected to be small.
       The iterator will initialise last_node_{cep,unused} */
    debug_mstore("Iterating to find last node.\n");
    iterator = castle_mstore_iterate(store);
    if(!iterator)
    {
        castle_free(store);
        return NULL;
    }
    while(castle_mstore_iterator_has_next(iterator))
        castle_mstore_iterator_next(iterator, NULL, NULL);
    debug_mstore("Destroying iterator and exiting.\n");
    castle_mstore_iterator_destroy(iterator);
    
    atomic_inc(&mstores_ref_cnt);
    
    return store;
}

struct castle_mstore* castle_mstore_init(c_mstore_id_t store_id, size_t entry_size)
{
    struct castle_fs_superblock *fs_sb;
    struct castle_mstore *store;

    debug_mstore("Opening mstore id=%d.\n", store_id);
    /* Sanity check, to see if store_id isn't too large. */
    if(store_id >= sizeof(fs_sb->mstore) / sizeof(c_ext_pos_t))
    {
        printk("Asked for mstore id=%d, this is too large.\n", store_id);
        return NULL;
    }

    store = castle_mstore_alloc(store_id, entry_size);
    if(!store)
        return NULL;
    debug_mstore("Initialising first list node.\n");
    down(&store->mutex);
    castle_mstore_node_add(store);
    up(&store->mutex);
     
    atomic_inc(&mstores_ref_cnt);

    return store;
}

void castle_mstore_fini(struct castle_mstore *store)
{
    debug_mstore("Closing mstore id=%d.\n", store->store_id);
    castle_free(store);

    atomic_dec(&mstores_ref_cnt);
}

int castle_checkpoint_version_inc(void)
{
    struct   castle_fs_superblock *fs_sb;
    struct   castle_slave_superblock *cs_sb;
    struct   list_head *lh;
    struct   castle_slave *cs = NULL;
    uint32_t fs_version;

    /* Goto next version. */
    fs_sb = castle_fs_superblocks_get();
    fs_sb->fs_version++;
    fs_version = fs_sb->fs_version;
    castle_fs_superblocks_put(fs_sb, 1);

    /* Makes sure no parallel freespace operations happening. */
    (void) castle_extents_super_block_get();

    list_for_each(lh, &castle_slaves.slaves)
    {
        cs = list_entry(lh, struct castle_slave, list);
        cs_sb = castle_slave_superblock_get(cs); 
        cs_sb->fs_version++;
        if (fs_version != cs_sb->fs_version)
        {
            printk("%x:%x\n", fs_version, cs_sb->fs_version);
            BUG();
        }

        /* As the flushed version is consistent now on disk, It is okay to
         * overwrite the previous version now. Change freespace producer
         * accordingly. */
        cs->prev_prod = cs->frozen_prod;
        castle_slave_superblock_put(cs, 1);
    }

    /* We must have created some freespace, unfreeze DAs. */
    castle_double_arrays_unfreeze();

    castle_extents_super_block_put(0);

    return 0;
}

int castle_mstores_writeback(uint32_t version)
{
    struct castle_fs_superblock *fs_sb;
    int    i;
    int    slot = version % 2;

    if (!castle_fs_inited)
        return 0;

    BUG_ON(atomic_read(&mstores_ref_cnt));

    /* Setup mstore for writeback. */
    fs_sb = castle_fs_superblocks_get();
    for(i=0; i<sizeof(fs_sb->mstore) / sizeof(c_ext_pos_t ); i++)
        fs_sb->mstore[i] = INVAL_EXT_POS;
    castle_fs_superblocks_put(fs_sb, 1);

    _castle_ext_fs_init(&mstore_ext_fs, 0, 0,
                        C_BLK_SIZE, MSTORE_EXT_ID + slot);
    /* Call writebacks of components. */
    castle_attachments_writeback();
    castle_double_arrays_writeback();
    
    FAULT(CHECKPOINT_FAULT);

    castle_versions_writeback();
    castle_extents_writeback();

    BUG_ON(!castle_ext_fs_consistent(&mstore_ext_fs));
    castle_cache_extent_flush_schedule(MSTORE_EXT_ID + slot, 0, 
                                       atomic64_read(&mstore_ext_fs.used));

    return 0;
}

int castle_cache_extent_flush_schedule(c_ext_id_t ext_id, uint64_t start, 
                                       uint64_t count)
{
    struct castle_cache_flush_entry *entry;

    entry = castle_malloc(sizeof(struct castle_cache_flush_entry), GFP_KERNEL);
    if (!entry)
        return -1;

    entry->ext_id = ext_id;
    entry->start  = start;
    entry->count  = count;
    list_add_tail(&entry->list, &castle_cache_flush_list);

    return 0;
}

int castle_cache_extents_flush(struct list_head *flush_list)
{
    struct list_head *lh, *tmp;
    struct castle_cache_flush_entry *entry;

    list_for_each_safe(lh, tmp, flush_list)
    {
        entry = list_entry(lh, struct castle_cache_flush_entry, list);
        castle_cache_extent_flush(entry->ext_id, entry->start, entry->count);

        list_del(lh);
        castle_free(entry);
    }

    BUG_ON(!list_empty(flush_list));

    return 0;
}

static int castle_periodic_checkpoint(void *unused)
{
    uint32_t version = 0;
    struct   castle_fs_superblock *fs_sb;
    int      i; 
    int      exit_loop = 0;
    struct   list_head flush_list;

    do {
        /* Wakes-up once in a second just to check whether to stop the thread.
         * After every 10 seconds checkpoints the filesystem. */
        for (i=0; i<CHECKPOINT_FREQUENCY; i++)
        {
            if (!kthread_should_stop())
                msleep(1000);
            else
                exit_loop = 1;
        }

        if (!castle_fs_inited)
            continue;

        printk("*****Checkpoint start**********\n");
        CASTLE_TRANSACTION_BEGIN;
 
        fs_sb = castle_fs_superblocks_get();
        version = fs_sb->fs_version;
        castle_fs_superblocks_put(fs_sb, 1);
 
        if (castle_mstores_writeback(version))
        {
            printk("Mstore writeback failed\n");
            return -1;
        }

        list_replace(&castle_cache_flush_list, &flush_list);
        INIT_LIST_HEAD(&castle_cache_flush_list);

        CASTLE_TRANSACTION_END;

        /* Flush all marked extents from cache. */
        castle_cache_extents_flush(&flush_list);

        FAULT(CHECKPOINT_FAULT);

        /* Writeback superblocks. */
        if (castle_superblocks_writeback(version))
        {
            printk("Superblock writeback failed\n");
            return -1;
        }
        castle_checkpoint_version_inc();
        
        printk("*****Completed checkpoint of version: %u*****\n", version);
    } while (!exit_loop);

    return 0;
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
    int ret;

    /* Find out how much memory there is in the system. */
    si_meminfo(&i);
    max_ram = i.totalram;
    max_ram = max_ram / 2;

    /* Fail if we are trying to use too much. */
    if(castle_cache_size > max_ram) 
    {
        printk("Cache size too large, configured with %d pages, maximum is %ld pages (%ld MB)\n",
                castle_cache_size,
                max_ram,
                max_ram >> (20 - PAGE_SHIFT));
        return -EINVAL;
    }

    if(castle_cache_size < (CASTLE_CACHE_MIN_SIZE << (20 - PAGE_SHIFT)))
    {
        printk("Cache size too small, configured with %d pages, minimum is %d pages (%d MB)\n",
                castle_cache_size,
                CASTLE_CACHE_MIN_SIZE << (20 - PAGE_SHIFT),
                CASTLE_CACHE_MIN_SIZE);
        return -EINVAL;
    }

    printk("Cache size: %d pages (%ld MB).\n", 
            castle_cache_size, 
            ((unsigned long)castle_cache_size * PAGE_SIZE) >> 20);

    /* Work out the # of c2bs and c2ps, as well as the hash sizes */
    castle_cache_page_freelist_size  = castle_cache_size / PAGES_PER_C2P;
    castle_cache_page_hash_buckets   = castle_cache_page_freelist_size / 2;
    castle_cache_block_freelist_size = castle_cache_page_freelist_size;
    castle_cache_block_hash_buckets  = castle_cache_block_freelist_size / 2; 
    /* Allocate memory for c2bs, c2ps and hash tables */
    castle_cache_page_hash  = castle_vmalloc(castle_cache_page_hash_buckets  * 
                                             sizeof(struct hlist_head));
    castle_cache_block_hash = castle_vmalloc(castle_cache_block_hash_buckets * 
                                             sizeof(struct hlist_head));
    castle_cache_blks       = castle_vmalloc(castle_cache_block_freelist_size * 
                                             sizeof(c2_block_t));
    castle_cache_pgs        = castle_vmalloc(castle_cache_page_freelist_size  * 
                                             sizeof(c2_page_t));
    /* Init other variables */
    atomic_set(&castle_cache_dirty_pages, 0);
    atomic_set(&castle_cache_clean_pages, 0);
    atomic_set(&castle_cache_flush_seq, 0);

    if((ret = castle_cache_hashes_init()))    goto err_out;
    if((ret = castle_cache_freelists_init())) goto err_out; 
    if((ret = castle_vmap_fast_map_init()))   goto err_out;
    if((ret = castle_cache_flush_init()))     goto err_out;
#ifdef CASTLE_PERF_DEBUG
    castle_cache_stats_timer_interval = 1;
#endif
    if(castle_cache_stats_timer_interval) castle_cache_stats_timer_tick(0);

    return 0;

err_out:
    castle_cache_fini();

    return ret;
}

void castle_cache_fini(void)
{
    castle_cache_debug_fini();
    castle_cache_flush_fini();
    castle_cache_hashes_fini();
    castle_vmap_fast_map_fini();
    castle_cache_freelists_fini();

    if(castle_cache_stats_timer_interval) del_timer(&castle_cache_stats_timer);

    if(castle_cache_page_hash)  castle_vfree(castle_cache_page_hash);
    if(castle_cache_block_hash) castle_vfree(castle_cache_block_hash);
    if(castle_cache_blks)       castle_vfree(castle_cache_blks);
    if(castle_cache_pgs)        castle_vfree(castle_cache_pgs);
}

