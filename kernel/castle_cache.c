#include <linux/sched.h>
#include <linux/bio.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/kthread.h>
#include <linux/vmalloc.h>
#include <linux/rbtree.h>

#include "castle_public.h"
#include "castle.h"
#include "castle_cache.h"
#include "castle_debug.h"
#include "castle_utils.h"
#include "castle_btree.h"
#include "castle_extent.h"
#include "castle_freespace.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)           ((void)0)
#define debug_mstore(_f, _a...)  ((void)0)
#else
#define debug(_f, _a...)         (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#define debug_mstore(_f, _a...)  (printk("%s:%.4d:%s " _f, __FILE__, __LINE__ , __func__, ##_a))
#endif

/**********************************************************************************************
 * Cache descriptor structures (c2b & c2p), and related accessor functions. 
 */
enum c2b_state_bits {
    C2B_uptodate,
    C2B_dirty,
    C2B_flushing,
};

#define INIT_C2B_BITS (0)
#define C2B_FNS(bit, name)					                        \
inline void set_c2b_##name(c2_block_t *c2b)		                    \
{									                                \
	set_bit(C2B_##bit, &(c2b)->state);				                \
}									                                \
inline void clear_c2b_##name(c2_block_t *c2b)		                \
{									                                \
	clear_bit(C2B_##bit, &(c2b)->state);				            \
}									                                \
inline int c2b_##name(c2_block_t *c2b)		                        \
{									                                \
	return test_bit(C2B_##bit, &(c2b)->state);			            \
}

#define TAS_C2B_FNS(bit, name)					                    \
inline int test_set_c2b_##name(c2_block_t *c2b)	                    \
{									                                \
	return test_and_set_bit(C2B_##bit, &(c2b)->state);		        \
}									                                \
inline int test_clear_c2b_##name(c2_block_t *c2b)	                \
{									                                \
	return test_and_clear_bit(C2B_##bit, &(c2b)->state);		    \
}

C2B_FNS(uptodate, uptodate)
C2B_FNS(dirty, dirty)
TAS_C2B_FNS(dirty, dirty)
C2B_FNS(flushing, flushing)
TAS_C2B_FNS(flushing, flushing)

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

#define INIT_C2P_BITS (0)
#define C2P_FNS(bit, name)					                        \
inline void set_c2p_##name(c2_page_t *c2p)		                    \
{									                                \
	set_bit(C2P_##bit, &(c2p)->state);				                \
}									                                \
inline void clear_c2p_##name(c2_page_t *c2p)		                \
{									                                \
	clear_bit(C2P_##bit, &(c2p)->state);				            \
}									                                \
inline int c2p_##name(c2_page_t *c2p)		                        \
{									                                \
	return test_bit(C2P_##bit, &(c2p)->state);			            \
}

#define TAS_C2P_FNS(bit, name)					                    \
inline int test_set_c2p_##name(c2_page_t *c2p)	                    \
{									                                \
	return test_and_set_bit(C2P_##bit, &(c2p)->state);		        \
}									                                \
inline int test_clear_c2p_##name(c2_page_t *c2p)	                \
{									                                \
	return test_and_clear_bit(C2P_##bit, &(c2p)->state);		    \
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
static int                     castle_cache_size = 20000; /* In pages */ 

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
static int                     castle_cache_fast_vmap_c2bs;
static uint32_t               *castle_cache_fast_vmap_freelist;
static void                   *castle_cache_fast_vmap_vstart;
#ifdef CASTLE_DEBUG
static void                   *castle_cache_fast_vmap_vend;
#endif
static struct page            *castle_cache_vmap_pgs[CASTLE_CACHE_VMAP_PGS]; 
static           DECLARE_MUTEX(castle_cache_vmap_lock);

static struct task_struct     *castle_cache_flush_thread;
static DECLARE_WAIT_QUEUE_HEAD(castle_cache_flush_wq); 
static atomic_t                castle_cache_flush_seq;

static atomic_t                castle_cache_read_stats = ATOMIC_INIT(0);
static atomic_t                castle_cache_write_stats = ATOMIC_INIT(0);

struct timer_list              castle_cache_stats_timer;

/**********************************************************************************************
 * Core cache. 
 */
void castle_cache_stats_print(void)
{
    int reads = atomic_read(&castle_cache_read_stats);
    int writes = atomic_read(&castle_cache_write_stats);
    atomic_sub(reads, &castle_cache_read_stats);
    atomic_sub(writes, &castle_cache_write_stats);
    
    printk("%d, %d, %d, %d, %d", 
        atomic_read(&castle_cache_dirty_pages), 
        atomic_read(&castle_cache_clean_pages),
        castle_cache_page_freelist_size * PAGES_PER_C2P,
        reads, writes);
}

EXPORT_SYMBOL(castle_cache_stats_print);

static void castle_cache_stats_timer_tick(unsigned long foo)
{
    BUG_ON(castle_cache_stats_timer_interval <= 0);

    printk("castle_cache_stats_timer_tick: ");
    castle_cache_stats_print();
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

static int c2p_read_locked(c2_page_t *c2p)
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
#ifdef CASTLE_DEBUG
    BUG_ON(!c2p_read_locked(c2p));
#endif
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
 
    /* Submit. */
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

static inline void submit_c2b_io_array(int rw, 
                                       c2_block_t *c2b, 
                                       c_ext_pos_t cep, 
                                       c_disk_chk_t *chunks, 
                                       int k_factor,
                                       struct page **io_pages,
                                       int nr_pages)
{
    int i;

    debug("Submitting io_array of %d pages, for cep "cep_fmt_str", k_factor=%d, rw=%s\n",
        nr_pages, __cep2str(cep), k_factor, (rw == READ) ? "read" : "write");

    if(nr_pages <= 0)
        return;
    /* Submit the IO */
    for(i=0; i<(rw == WRITE ? k_factor : 1); i++)
    {
        /* Debugging checks, the first one could be turned into a vaild error. */
#ifdef CASTLE_DEBUG
        BUG_ON(DISK_CHK_INVAL(chunks[i]));
        BUG_ON(!SUPER_EXTENT(cep.ext_id) && !chk_valid(chunks[i]));
#endif
        atomic_add(nr_pages, &c2b->remaining);
        submit_c2b_io(rw, c2b, cep, chunks[i], io_pages, nr_pages); 
    }
}

static int submit_c2b_rda(int rw, c2_block_t *c2b)
{
#define MAX_BIO_PAGES        16
    c2_page_t            *c2p;
    struct page          *io_pages[MAX_BIO_PAGES], *page;
    int                   io_pages_idx, skip_c2p;
    c_ext_pos_t           cur_cep, cep = c2b->cep;
    c_chk_t               last_chk, cur_chk;
    uint32_t              k_factor = castle_extent_kfactor_get(cep.ext_id);
    c_disk_chk_t          chunks[k_factor];

    debug("Submitting c2b "cep_fmt_str", for %s\n", 
            __cep2str(c2b->cep), (rw == READ) ? "read" : "write");
    /* c2b->remaining is effectively a reference count. Get one ref before we start. */
    BUG_ON(atomic_read(&c2b->remaining) != 0);
    atomic_inc(&c2b->remaining);
    last_chk = INVAL_CHK; 
    io_pages_idx = 0;
    c2b_for_each_page_start(page, c2p, cur_cep, c2b)
    {
        cur_chk = CHUNK(cur_cep.offset);
        debug("Processing a c2b page, io_pages_idx=%d, last_chk=%d, cur_chk=%d\n",
                io_pages_idx, last_chk, cur_chk);
        /* Do not read into uptodate pages, do not write out of clean pages. */
        skip_c2p = ((rw == READ)  && c2p_uptodate(c2p)) ||
                   ((rw == WRITE) && !c2p_dirty(c2p));
        debug("%s %s on c2p->cep="cep_fmt_str_nl,
                    (skip_c2p ? "Skipping" : "Not skipping"),
                    (rw == READ ? "read" : "write"), 
                    cep2str(c2p->cep));
        /* Continue collecting pages into io_pages array for as long as there
           is space in it, and we continue looking at the same chunk */
        if((!skip_c2p) && (io_pages_idx < MAX_BIO_PAGES) && (cur_chk == last_chk))
        {
            io_pages[io_pages_idx] = page;
            io_pages_idx++;
            goto cont;
        } 

        /* We have to submit the IO here if last_chk is valid (either because we 
           moved chunks, or because we've run out of space in the io_array). */
            
        /* Update chunk map as soon as we move to a new chunk. */ 
        if(cur_chk != last_chk)
        {
            debug("Asking extent manager for "cep_fmt_str_nl,
                    cep2str(cur_cep));
            BUG_ON(castle_extent_map_get(cur_cep.ext_id,
                                         CHUNK(cur_cep.offset),
                                         1,
                                         chunks) != k_factor);
            debug("chunks[0]="disk_chk_fmt_nl, disk_chk2str(chunks[0]));
        }
        submit_c2b_io_array(rw, c2b, cep, chunks, k_factor, io_pages, io_pages_idx);

        /* The current page hasn't been saved in the io_pages array yet, do that, and
           reset all the other vars. */ 
        io_pages_idx = 0;
        if(!skip_c2p)
        {
            cep = cur_cep; 
            last_chk = cur_chk;
            io_pages[0] = page;
            io_pages_idx = 1;
        }
    }
cont:        
    c2b_for_each_page_end(page, c2p, cur_cep, c2b);
    /* Chunk map must be up-to-date, because we either exited after a continue above (which 
       implies that (cur_chk == last_chk), or fell through the bottom of the loop above,
       which again implies that (cur_chk == last_chk) */ 
    BUG_ON((io_pages_idx > 0) && (CHK_INVAL(last_chk) || (cur_chk != last_chk)));
    submit_c2b_io_array(rw, c2b, cep, chunks, k_factor, io_pages, io_pages_idx);
    /* Drop the 1 ref. */
    c2b_remaining_io_sub(rw, 1, c2b);

    return 0;
}

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
 
    if (rw == READ)
        atomic_inc(&castle_cache_read_stats);
    else
        atomic_inc(&castle_cache_write_stats);
    
    return submit_c2b_rda(rw, c2b);
}

static void castle_cache_sync_io_end(c2_block_t *c2b)
{
    struct completion *completion = c2b->private;
    
    if(c2b_uptodate(c2b) && c2b_dirty(c2b)) 
        clean_c2b(c2b);
    complete(completion);
}

int submit_c2b_sync(int rw, c2_block_t *c2b)
{
    struct completion completion;
    int ret;

	BUG_ON((rw == READ)  &&  c2b_uptodate(c2b));
	BUG_ON((rw == WRITE) && !c2b_dirty(c2b));
    c2b->end_io = castle_cache_sync_io_end;
    c2b->private = &completion;
    init_completion(&completion);
    if((ret = submit_c2b(rw, c2b)))
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

/* Must be called with the page_hash lock held */
static inline void __castle_cache_c2p_put(c2_page_t *c2p, struct list_head *accumulator)
{
    BUG_ON(!spin_is_locked(&castle_cache_page_hash_lock));

    c2p->count--;
    /* If the count reached zero, delete fromt the hash, add to the accumulator list,
       so that they get freed later on. */
    if(c2p->count == 0)
    {
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

static c2_block_t* castle_cache_block_hash_get(c_ext_pos_t cep, uint32_t nr_pages)
{
    c2_block_t *c2b = NULL;

    spin_lock_irq(&castle_cache_block_hash_lock);
    /* Try to find in the hash first */
    c2b = castle_cache_block_hash_find(cep, nr_pages);
    /* If found, get a reference to make sure c2b doesn't get removed.
       Move to the tail of dirty/clean list to get LRU(-like) behaviour. */
    if(c2b) 
    {
        get_c2b(c2b);
        /* Move to the end of the apprapriate list */
        if(c2b_dirty(c2b))
            list_move_tail(&c2b->dirty, &castle_cache_dirtylist);
        else
            list_move_tail(&c2b->clean, &castle_cache_cleanlist);

    }
    /* If not found, drop the lock, we need to get ourselves a c2b first */
    spin_unlock_irq(&castle_cache_block_hash_lock);

    return c2b;
}

static int castle_cache_block_hash_insert(c2_block_t *c2b)
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
    }
    castle_cache_block_freelist_size--;
    spin_unlock(&castle_cache_freelist_lock);

    return c2b;
}

static void castle_cache_fast_vmap_freelist_add(uint32_t id)
{
    /* The slot should be free */
    BUG_ON(castle_cache_fast_vmap_freelist[id+1] != 0xFAFAFAFA);
    castle_cache_fast_vmap_freelist[id+1] = castle_cache_fast_vmap_freelist[0]; 
    castle_cache_fast_vmap_freelist[0]    = id; 
}

static uint32_t castle_cache_fast_vmap_freelist_get(void)
{
    uint32_t id;
#ifdef CASTLE_DEBUG
    int nr_vmap_slots = castle_cache_size / (PAGES_PER_C2P * castle_cache_fast_vmap_c2bs);
#endif
   
    id = castle_cache_fast_vmap_freelist[0];
    castle_cache_fast_vmap_freelist[0] = castle_cache_fast_vmap_freelist[id+1]; 
    /* Invalidate the slot we've just allocated, so that we can test for double frees */ 
    castle_cache_fast_vmap_freelist[id+1] = 0xFAFAFAFA;
#ifdef CASTLE_DEBUG
    /* Make sure we didn't run out of entries in the freelist (we'd get id == (uint32_t)-1). */
    BUG_ON(id >= nr_vmap_slots);
#endif

    return id;
}

/* This should be called _with_ the vmap_lock */
static inline void* castle_cache_fast_vmap(struct page **pgs, int nr_pages)
{
    uint32_t vmap_slot;
    void *vaddr;

    BUG_ON(down_trylock(&castle_cache_vmap_lock) == 0);
    vmap_slot = castle_cache_fast_vmap_freelist_get();
    debug("Fast vmapping in slot: %d\n", vmap_slot);
    /* Make sure that nr_pages matches the vmap slot size */
    BUG_ON(castle_cache_pages_to_c2ps(nr_pages) != castle_cache_fast_vmap_c2bs);
    vaddr = castle_cache_fast_vmap_vstart + 
            vmap_slot * PAGES_PER_C2P * PAGE_SIZE * castle_cache_fast_vmap_c2bs;
#ifdef CASTLE_DEBUG    
    BUG_ON((unsigned long)vaddr <  (unsigned long)castle_cache_fast_vmap_vstart);
    BUG_ON((unsigned long)vaddr >= (unsigned long)castle_cache_fast_vmap_vend);
#endif
    if(castle_map_vm_area(vaddr, pgs, nr_pages, PAGE_KERNEL))
    {
        debug("ERROR: failed to vmap!\n");
        castle_cache_fast_vmap_freelist_add(vmap_slot);
        return NULL;
    }

    return vaddr;
}

/* This should be called _without_ the vmap_lock */
static inline void castle_cache_fast_vunmap(void *vaddr, int nr_pages)
{
    uint32_t vmap_slot;

    BUG_ON(castle_cache_pages_to_c2ps(nr_pages) != castle_cache_fast_vmap_c2bs);
    castle_unmap_vm_area(vaddr, nr_pages);
    vmap_slot = (vaddr - castle_cache_fast_vmap_vstart) / 
                (castle_cache_fast_vmap_c2bs * PAGES_PER_C2P * PAGE_SIZE);
    down(&castle_cache_vmap_lock);
    debug("Releasing fast vmap slot: %d\n", vmap_slot);
    castle_cache_fast_vmap_freelist_add(vmap_slot);
    up(&castle_cache_vmap_lock);
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
    c2b->state = INIT_C2B_BITS | (uptodate ? C2B_uptodate : 0);
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

    if(castle_cache_pages_to_c2ps(nr_pages) == castle_cache_fast_vmap_c2bs)
        c2b->buffer = castle_cache_fast_vmap(castle_cache_vmap_pgs, i);
    else
    if(nr_pages > 1)
        c2b->buffer = vmap(castle_cache_vmap_pgs, i, VM_READ|VM_WRITE, PAGE_KERNEL);
    else
        c2b->buffer = pfn_to_kaddr(page_to_pfn(castle_cache_vmap_pgs[0])); 

    up(&castle_cache_vmap_lock);
    BUG_ON(!c2b->buffer);
}

static void castle_cache_block_free(c2_block_t *c2b)
{
    struct list_head *lh, *lt;
    LIST_HEAD(freed_c2ps);
    c2_page_t *c2p;
    int i, c2ps;

    c2ps = castle_cache_pages_to_c2ps(c2b->nr_pages);
    if(c2ps == castle_cache_fast_vmap_c2bs)
        castle_cache_fast_vunmap(c2b->buffer, PAGES_PER_C2P * c2ps);
    else
    if(c2b->nr_pages > 1)
        vunmap(c2b->buffer);
#ifdef CASTLE_DEBUG
    {
        c2_page_t *c2p;
        c_ext_pos_t cep_unused;

        c2b_for_each_c2p_start(c2p, cep_unused, c2b)
            debug("Freeing c2p id=%d, from c2b=%p\n", c2p->id, c2b);
        c2b_for_each_c2p_end(c2p, cep_unused, c2b)
    }
#endif
    /* Add the pages back to the freelist */
    spin_lock(&castle_cache_page_hash_lock);
    for(i=0; i<c2ps; i++)
        __castle_cache_c2p_put(c2b->c2ps[i], &freed_c2ps);
    spin_unlock(&castle_cache_page_hash_lock);
    /* For debugging only: it will be spotted quickly if nr_pages isn't reinited properly */
    c2b->nr_pages = 0xFFFF;
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
    /* Free the c2ps array */
    castle_free(c2b->c2ps);
    c2b->c2ps = NULL;
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
    int nr_victims;

    spin_lock_irq(&castle_cache_block_hash_lock);
    /* Find victim buffers. */ 
    nr_victims = 0;
    list_for_each_safe(lh, th, &castle_cache_cleanlist)
    {
        c2b = list_entry(lh, c2_block_t, clean);
        /* FIXME: Pinning all logical extent pages in cache. Make sure cache is
         * big enough. 
         * TODO: gm281: this is temporary solution. Introduce pools to deal with the
         * issue properly.
         */
        if(!c2b_busy(c2b) && !LOGICAL_EXTENT(c2b->cep.ext_id)) 
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

c2_block_t* castle_cache_block_get(c_ext_pos_t cep, int nr_pages)
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
        if(!castle_cache_block_hash_insert(c2b))
        {
            printk("Failed to insert c2b into hash\n");
            put_c2b(c2b);
            castle_cache_block_free(c2b);
        }
        else
        {
            BUG_ON(c2b->nr_pages != nr_pages);
            return c2b;
        }
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

/***** Flush thread functions *****/
static void castle_cache_flush_endio(c2_block_t *c2b)
{
    atomic_t *count = c2b->private;
    if(!c2b_uptodate(c2b))
        printk("Could not write out a page!\n");

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
    int target_dirty_pgs, to_flush, flush_size, dirty_pgs, batch_idx, i;
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
        /* Wait for 95% of IOs to complete */
        debug("====> Waiting for 95%% of outstanding IOs to complete.\n");
        wait_event(castle_cache_flush_wq, (atomic_read(&in_flight) <= flush_size / 20));

        /* Wait until enough pages have been dirtied to make it worth while
         * this will rate limit us to a min of 10 MIN_BATCHes a second */
        debug("====> Waiting completed, now waiting for big enough flush.\n");
        wait_event_timeout(
            castle_cache_flush_wq, 
            kthread_should_stop() ||
            (atomic_read(&castle_cache_dirty_pages) - target_dirty_pgs > MIN_FLUSH_SIZE),
            HZ/MIN_FLUSH_FREQ);
 
        dirty_pgs = atomic_read(&castle_cache_dirty_pages);  

        /* 
         * Work out how many pages to flush.
         * Note that (dirty_pgs - target_dirty_pages) approximates the number of pages that
         * got dirtied since the last time around the loop (modulo MIN & MAX).
         */
        flush_size = dirty_pgs - target_dirty_pgs;
        flush_size = max(MIN_FLUSH_SIZE, flush_size);
        flush_size = min(MAX_FLUSH_SIZE, flush_size);
        /* If we are removing the module, we need to flush all pages */
        if(kthread_should_stop() || (flush_size > dirty_pgs))
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
                continue;
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
               enough dirty buffers print a warning message, and stop */
            printk("WARNING: Could not find enough dirty pages to flush\n"
                   "  Stats: dirty=%d, clean=%d, free=%d\n"
                   "         target=%d, to_flush=%d, blocks=%d\n",
                atomic_read(&castle_cache_dirty_pages), 
                atomic_read(&castle_cache_clean_pages),
                castle_cache_page_freelist_size * PAGES_PER_C2P,
                target_dirty_pgs, to_flush, batch_idx); 
        }
        
        /* Finally check if we should still continue */
        if(kthread_should_stop() && (atomic_read(&castle_cache_dirty_pages) == 0))
            break;
    }

    BUG_ON(atomic_read(&in_flight) != 0);
    debug("====> Castle cache flush loop EXITING.\n");

    return 0;
}

void castle_cache_flush_wakeup(void)
{
    wake_up_process(castle_cache_flush_thread);
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
            vfree(castle_cache_block_hash);
        if(castle_cache_page_hash)
            vfree(castle_cache_page_hash);
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
            vfree(castle_cache_blks);
        if(castle_cache_pgs)
            vfree(castle_cache_pgs);
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

static int castle_cache_fast_vmap_init(void)
{
    struct page **pgs_array;
    struct list_head *l;
    c2_page_t *c2p;
    int i, j, nr_fast_vmap_slots;

    /* Work out the fast vmap unit size in # of c2ps. Make sure that VLBA tree nodes can
       handled. */
    castle_cache_fast_vmap_c2bs = castle_cache_pages_to_c2ps(
                                        castle_btree_type_get(VLBA_TREE_TYPE)->node_size);
    /* We need cache_castle_size / 512 for this array, if that's too big, we
       could use the cache pages themselves */
    pgs_array = vmalloc(PAGES_PER_C2P * castle_cache_page_freelist_size * sizeof(struct page *));
    if(!pgs_array)
        return -ENOMEM;

    nr_fast_vmap_slots = castle_cache_page_freelist_size / castle_cache_fast_vmap_c2bs;
    castle_cache_fast_vmap_freelist = vmalloc((nr_fast_vmap_slots + 1) * sizeof(uint32_t)); 
    if(!castle_cache_fast_vmap_freelist)
    {
        vfree(pgs_array);
        return -ENOMEM;
    }
    memset(castle_cache_fast_vmap_freelist, 0xFA, (nr_fast_vmap_slots + 1) * sizeof(uint32_t));

    /* Assemble array of all pages from the freelist. Vmap them all. */
    i = 0;
    list_for_each(l, &castle_cache_page_freelist)
    {
        c2p = list_entry(l, c2_page_t, list);
        for(j=0; j<PAGES_PER_C2P; j++) 
            pgs_array[i++] = c2p->pages[j];
    }

    castle_cache_fast_vmap_vstart = vmap(pgs_array, 
                                         PAGES_PER_C2P * castle_cache_page_freelist_size, 
                                         VM_READ|VM_WRITE, 
                                         PAGE_KERNEL);
#ifdef CASTLE_DEBUG
    castle_cache_fast_vmap_vend = castle_cache_fast_vmap_vstart + 
                                  castle_cache_page_freelist_size * PAGES_PER_C2P * PAGE_SIZE;
#endif
    /* This gives as an area in virtual memory in which we'll keep mapping multi-page c2bs.
       In order for this to work we need to unmap all the pages, but tricking the vmalloc.c
       into not deallocating the vm_area_struct describing our virtual memory region.
       Use castle_unmap_vm_area for that.
     */
    BUG_ON(!castle_cache_fast_vmap_vstart);
    castle_unmap_vm_area(castle_cache_fast_vmap_vstart, 
                         PAGES_PER_C2P * castle_cache_page_freelist_size);
    /* Init the freelist. The freelist needs to contain ids which will always put us within
       the vmap area created above. */
    for(i=0; i<nr_fast_vmap_slots; i++)
        castle_cache_fast_vmap_freelist_add(i);

    return 0;
}

static void castle_cache_fast_vmap_fini(void)
{
    int i, nr_slots;

    /* If the freelist didn't get allocated, there is nothing to fini. */
    if(!castle_cache_fast_vmap_freelist)
        return;

    /* Because we've done hash_fini(), there should be nothing mapped in the fast vmap area. 
       When in debug mode, verify that the freelist contains castle_cache_size items. Then,
       map all the cache pages, and let the vmalloc.c destroy vm_area_struct by vmunmping it.
     */ 
   nr_slots = castle_cache_size / (PAGES_PER_C2P * castle_cache_fast_vmap_c2bs);
#ifdef CASTLE_DEBUG
   i = 0;
   while(castle_cache_fast_vmap_freelist[0] < nr_slots)
   {
       castle_cache_fast_vmap_freelist_get();
       i++;
   }
   BUG_ON(i != nr_slots);
#endif 
   vunmap(castle_cache_fast_vmap_vstart);
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

    // FIXME: bhaskar
    /* Prepare the node first */
    cep.ext_id  = castle_extent_alloc(DEFAULT, 0, 1);
    cep.offset = 0;
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
     
    return store;
}

void castle_mstore_fini(struct castle_mstore *store)
{
    debug_mstore("Closing mstore id=%d.\n", store->store_id);
    castle_free(store);
}

int castle_cache_init(void)
{
    int ret;

    debug("Castle cache init, #c2ps=%d, pages per c2p=%d, #pages=%d\n", 
           castle_cache_size, PAGES_PER_C2P, castle_cache_size * PAGES_PER_C2P);

    /* Work out the # of c2bs and c2ps, as well as the hash sizes */
    castle_cache_page_freelist_size  = castle_cache_size / PAGES_PER_C2P;
    castle_cache_page_hash_buckets   = castle_cache_page_freelist_size / 2;
    castle_cache_block_freelist_size = castle_cache_page_freelist_size;
    castle_cache_block_hash_buckets  = castle_cache_block_freelist_size / 2; 
    /* Allocate memory for c2bs, c2ps and hash tables */
    castle_cache_page_hash  = vmalloc(castle_cache_page_hash_buckets  * sizeof(struct hlist_head));
    castle_cache_block_hash = vmalloc(castle_cache_block_hash_buckets * sizeof(struct hlist_head));
    castle_cache_blks       = vmalloc(castle_cache_block_freelist_size * sizeof(c2_block_t));
    castle_cache_pgs        = vmalloc(castle_cache_page_freelist_size  * sizeof(c2_page_t));
    /* Init other variables */
    castle_cache_fast_vmap_freelist = NULL;
    castle_cache_fast_vmap_vstart   = NULL;
    atomic_set(&castle_cache_dirty_pages, 0);
    atomic_set(&castle_cache_clean_pages, 0);
    atomic_set(&castle_cache_flush_seq, 0);

    if((ret = castle_cache_hashes_init()))    goto err_out;
    if((ret = castle_cache_freelists_init())) goto err_out; 
    if((ret = castle_cache_fast_vmap_init())) goto err_out;
    if((ret = castle_cache_flush_init()))     goto err_out;

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
    castle_cache_fast_vmap_fini();
    castle_cache_freelists_fini();

    if(castle_cache_stats_timer_interval) del_timer(&castle_cache_stats_timer);

    if(castle_cache_page_hash)  vfree(castle_cache_page_hash);
    if(castle_cache_block_hash) vfree(castle_cache_block_hash);
    if(castle_cache_blks)       vfree(castle_cache_blks);
}

