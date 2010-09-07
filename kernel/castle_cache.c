#include <linux/sched.h>
#include <linux/bio.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/kthread.h>
#include <linux/vmalloc.h>

#include "castle_public.h"
#include "castle.h"
#include "castle_cache.h"
#include "castle_freespace.h"
#include "castle_utils.h"
#include "castle_btree.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)           ((void)0)
#define debug_mstore(_f, _a...)  ((void)0)
#else
#define debug(_f, _a...)         (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#define debug_mstore(_f, _a...)  (printk("%s:%.4d:%s " _f, __FILE__, __LINE__ , __func__, ##_a))
#endif

static int                     castle_cache_size = 1000; /* in pages */

module_param(castle_cache_size, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(castle_cache_size, "Cache size");

static int                     castle_cache_stats_timer_interval = 0; /* in seconds */

module_param(castle_cache_stats_timer_interval, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(castle_cache_stats_timer_interval, "Cache stats print interval (seconds)");

static c2_block_t             *castle_cache_blks = NULL;

static int                     castle_cache_hash_buckets;
static         DEFINE_SPINLOCK(castle_cache_hash_lock);
static struct list_head       *castle_cache_hash = NULL;
static atomic_t                castle_cache_flush_seq;

static atomic_t                castle_cache_dirtylist_size;
static               LIST_HEAD(castle_cache_dirtylist);
static atomic_t                castle_cache_cleanlist_size;
static               LIST_HEAD(castle_cache_cleanlist);

static         DEFINE_SPINLOCK(castle_cache_freelist_lock); /* Lock for the two freelists below */
static int                     castle_cache_page_freelist_size;
static               LIST_HEAD(castle_cache_page_freelist);
static               LIST_HEAD(castle_cache_block_freelist);

#define CASTLE_CACHE_VMAP_PGS   256
static int                     castle_cache_fast_vmap_pages;
static uint32_t               *castle_cache_fast_vmap_freelist;
static void                   *castle_cache_fast_vmap_vstart;
static struct page            *castle_cache_vmap_pgs[CASTLE_CACHE_VMAP_PGS]; 
static           DECLARE_MUTEX(castle_cache_vmap_lock);

static struct task_struct     *castle_cache_flush_thread;
static DECLARE_WAIT_QUEUE_HEAD(castle_cache_flush_wq); 

static atomic_t                castle_cache_read_stats = ATOMIC_INIT(0);
static atomic_t                castle_cache_write_stats = ATOMIC_INIT(0);

struct timer_list              castle_cache_stats_timer;

void castle_cache_print_stats(void)
{
    int reads = atomic_read(&castle_cache_read_stats);
    int writes = atomic_read(&castle_cache_write_stats);
    atomic_sub(reads, &castle_cache_read_stats);
    atomic_sub(writes, &castle_cache_write_stats);
    
    printk("%d, %d, %d, %d, %d", 
        atomic_read(&castle_cache_dirtylist_size), 
        atomic_read(&castle_cache_cleanlist_size),
        castle_cache_page_freelist_size,
        reads, writes);
}

EXPORT_SYMBOL(castle_cache_print_stats);

static void castle_cache_stats_timer_tick(unsigned long foo)
{
    BUG_ON(castle_cache_stats_timer_interval <= 0);

    printk("castle_cache_stats_timer_tick: ");
    castle_cache_print_stats();
    printk("\n");

    setup_timer(&castle_cache_stats_timer, castle_cache_stats_timer_tick, 0);
    mod_timer(&castle_cache_stats_timer, jiffies + (HZ * castle_cache_stats_timer_interval));
}

void __lock_c2b(c2_block_t *c2b, int write)
{
    if(write)
        down_write(&c2b->lock);
    else
        down_read(&c2b->lock);
}

static int inline trylock_c2b(c2_block_t *c2b)
{
    return down_write_trylock(&c2b->lock);
}

static inline void __unlock_c2b(c2_block_t *c2b, int write)
{
#ifdef CASTLE_DEBUG    
    c2b->file = "none";
    c2b->line = 0;
#endif
    if(write)
        up_write(&c2b->lock);
    else
        up_read(&c2b->lock);
}

void unlock_c2b(c2_block_t *c2b)
{
    __unlock_c2b(c2b, 1);
}

void unlock_c2b_read(c2_block_t *c2b)
{
    __unlock_c2b(c2b, 0);
}

int c2b_locked(c2_block_t *c2b)
{
    return rwsem_is_locked(&c2b->lock); 
}

void dirty_c2b(c2_block_t *c2b)
{
    unsigned long flags;

    spin_lock_irqsave(&castle_cache_hash_lock, flags);
    BUG_ON(!c2b_locked(c2b));
    if(c2b_dirty(c2b)) goto out;
    list_move_tail(&c2b->dirty_or_clean, &castle_cache_dirtylist);
    set_c2b_dirty(c2b); 
    atomic_sub(c2b->nr_pages, &castle_cache_cleanlist_size);
    atomic_add(c2b->nr_pages, &castle_cache_dirtylist_size);
out:        
    spin_unlock_irqrestore(&castle_cache_hash_lock, flags);
}

static void clean_c2b(c2_block_t *c2b)
{
    unsigned long flags;

    spin_lock_irqsave(&castle_cache_hash_lock, flags);
    BUG_ON(!c2b_locked(c2b));
    BUG_ON(!c2b_dirty(c2b));
    list_move_tail(&c2b->dirty_or_clean, &castle_cache_cleanlist);
    clear_c2b_dirty(c2b); 
    atomic_sub(c2b->nr_pages, &castle_cache_dirtylist_size);
    atomic_add(c2b->nr_pages, &castle_cache_cleanlist_size);
    spin_unlock_irqrestore(&castle_cache_hash_lock, flags);
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
static int c2b_io_end(struct bio *bio, unsigned int completed, int err)
#else
static void c2b_io_end(struct bio *bio, int err)
#endif
{
	c2_block_t *c2b = bio->bi_private;
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
    BUG_ON((!err) && (completed != C_BLK_SIZE * c2b->nr_pages));
    if( (err) && (completed != 0))
    {
        printk("Bio error=%d, completed=%d, bio->bi_size=%d\n", err, completed, bio->bi_size);
        BUG();
    }
    BUG_ON(err && test_bit(BIO_UPTODATE, &bio->bi_flags));
#endif
    /* End the IO by calling the client's end_io function */ 
	c2b->end_io(c2b, test_bit(BIO_UPTODATE, &bio->bi_flags));
#ifdef CASTLE_DEBUG    
    local_irq_restore(flags);
#endif
	bio_put(bio);
	
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
    return 0;
#endif
}

int submit_c2b(int rw, c2_block_t *c2b)
{
    struct castle_slave *cs;
    struct list_head *l;
	struct bio *bio;
    struct page *pg;
    int i;

	BUG_ON(!c2b_locked(c2b));
	BUG_ON(!c2b->end_io);
    BUG_ON(DISK_BLK_INVAL(c2b->cdb));
    
    if (rw == READ)
        atomic_inc(&castle_cache_read_stats);
    else if (rw == WRITE)
        atomic_inc(&castle_cache_write_stats);
    
    cs = castle_slave_find_by_block(c2b->cdb);
    if(!cs) return -ENODEV;

    i = 0;
	bio = bio_alloc(GFP_NOIO, c2b->nr_pages);
    list_for_each(l, &c2b->pages)
    {
        pg = list_entry(l, struct page, lru);
        BUG_ON(i > c2b->nr_pages);
	    bio->bi_io_vec[i].bv_page   = pg; 
	    bio->bi_io_vec[i].bv_len    = C_BLK_SIZE; 
	    bio->bi_io_vec[i].bv_offset = 0;
        i++;
    }

	bio->bi_sector = (sector_t)(c2b->cdb.block * (C_BLK_SIZE >> 9));
	bio->bi_bdev = cs->bdev;
	bio->bi_vcnt = c2b->nr_pages;
	bio->bi_idx = 0;
	bio->bi_size = c2b->nr_pages * C_BLK_SIZE;
	bio->bi_end_io = c2b_io_end;
	bio->bi_private = c2b;

	submit_bio(rw, bio);
	
    return 0;
}

static void castle_cache_sync_io_end(c2_block_t *c2b, int uptodate)
{
    struct completion *completion = c2b->private;
    
    if(uptodate) 
    {
        set_c2b_uptodate(c2b);
        if(c2b_dirty(c2b)) clean_c2b(c2b);
    }
    complete(completion);
}

int submit_c2b_sync(int rw, c2_block_t *c2b)
{
    struct completion completion;
    int ret;

	BUG_ON(!c2b_locked(c2b));
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

static inline int castle_cache_hash_idx(c_disk_blk_t cdb)
{
    return (cdb.block % castle_cache_hash_buckets);
}

static c2_block_t* castle_cache_hash_find(c_disk_blk_t cdb)
{
    struct list_head *lh;
    c2_block_t *c2b;
    int idx;

    idx = castle_cache_hash_idx(cdb);
    debug("Idx = %d\n", idx);
    list_for_each(lh, &castle_cache_hash[idx])
    {
        debug("Checking list element.\n");
        c2b = list_entry(lh, c2_block_t, list);
        if(DISK_BLK_EQUAL(c2b->cdb, cdb))
            return c2b;
    }

    return NULL;
}

static c2_block_t* castle_cache_hash_get(c_disk_blk_t cdb)
{
    c2_block_t *c2b = NULL;

    spin_lock_irq(&castle_cache_hash_lock);
    /* Try to find in the hash first */
    c2b = castle_cache_hash_find(cdb);
    /* If found, get a reference to make sure c2b doesn't get removed.
       Move to the tail of dirty/clean list to get LRU(-like) behaviour. */
    if(c2b) 
    {
        get_c2b(c2b);
        list_move_tail(&c2b->dirty_or_clean, 
                        c2b_dirty(c2b) ? &castle_cache_dirtylist : 
                                         &castle_cache_cleanlist);
    }
    /* If not found, drop the lock, we need to get ourselves a c2b first */
    spin_unlock_irq(&castle_cache_hash_lock);

    return c2b;
}

static int castle_cache_hash_insert(c2_block_t *c2b)
{
    int idx, success;

    spin_lock_irq(&castle_cache_hash_lock);
    /* Check if already in the hash */
    success = 0;
    if(castle_cache_hash_find(c2b->cdb)) goto out;
    /* Insert */
    success = 1;
    idx = castle_cache_hash_idx(c2b->cdb);
    list_add(&c2b->list, &castle_cache_hash[idx]);
    if(c2b_dirty(c2b))
    {
        list_add_tail(&c2b->dirty_or_clean, &castle_cache_dirtylist);
        atomic_add(c2b->nr_pages, &castle_cache_dirtylist_size);
    } else
    {
        list_add_tail(&c2b->dirty_or_clean, &castle_cache_cleanlist);
        atomic_add(c2b->nr_pages, &castle_cache_cleanlist_size);
    }
out:
    spin_unlock_irq(&castle_cache_hash_lock);
    return success;
}

static c2_block_t* castle_cache_block_freelist_get(void)
{
    struct list_head *lh;
    c2_block_t *c2b = NULL;

    spin_lock(&castle_cache_freelist_lock);
    /* We should never run out of blocks, we will run out of pages first */
    BUG_ON(list_empty(&castle_cache_block_freelist));
    lh = castle_cache_block_freelist.next;
    list_del(lh);
    c2b = list_entry(lh, c2_block_t, list);
    spin_unlock(&castle_cache_freelist_lock);

    return c2b;
}

static inline void __castle_cache_block_freelist_add(c2_block_t *c2b)
{
    list_add_tail(&c2b->list, &castle_cache_block_freelist);
}

static inline void castle_cache_block_freelist_add(c2_block_t *c2b)
{
    spin_lock(&castle_cache_freelist_lock);
    __castle_cache_block_freelist_add(c2b);
    spin_unlock(&castle_cache_freelist_lock);
}

static void castle_cache_page_freelist_get(int nr_pages, struct list_head *pages)
{
    struct list_head *lh, *lt;
    struct page *pg;

    spin_lock(&castle_cache_freelist_lock);
    /* Will only be able to satisfy the request if we have nr_pages on the list */
    if(castle_cache_page_freelist_size < nr_pages)
    {
        spin_unlock(&castle_cache_freelist_lock);
        return;
    }
    
    list_for_each_safe(lh, lt, &castle_cache_page_freelist)
    {
        if(nr_pages-- <= 0)
            break;
        list_del(lh);
        castle_cache_page_freelist_size--;
        pg = list_entry(lh, struct page, lru);
        list_add(&pg->lru, pages);
    }
    spin_unlock(&castle_cache_freelist_lock);
}

static void castle_cache_fast_vmap_freelist_add(uint32_t id)
{
    castle_cache_fast_vmap_freelist[id+1] = castle_cache_fast_vmap_freelist[0]; 
    castle_cache_fast_vmap_freelist[0]    = id; 
}

static uint32_t castle_cache_fast_vmap_freelist_get(void)
{
    uint32_t id;
   
    id = castle_cache_fast_vmap_freelist[0];
    castle_cache_fast_vmap_freelist[0] = castle_cache_fast_vmap_freelist[id+1]; 
    /* Make sure we didn't run out of entries in the freelist (we'd get id == (uint32_t)-1). */
    BUG_ON(id >= castle_cache_size);

    return id;
}

static void castle_cache_block_init(c2_block_t *c2b,
                                    c_disk_blk_t cdb, 
                                    struct list_head *pages,
                                    int nr_pages)
{
    struct list_head *lh;
    int i;

    /* c2b should only be initialised if it's not used */
    BUG_ON(nr_pages > CASTLE_CACHE_VMAP_PGS);
    BUG_ON(list_empty(&c2b->list)); 
    BUG_ON(!list_empty(&c2b->pages));
    BUG_ON(atomic_read(&c2b->count) != 0);
    c2b->cdb = cdb;
    c2b->state = INIT_C2B_BITS;
    c2b->nr_pages = nr_pages;
    list_splice(pages, &c2b->pages);

    i = 0;
    down(&castle_cache_vmap_lock);
    list_for_each(lh, &c2b->pages)
        castle_cache_vmap_pgs[i++] = list_entry(lh, struct page, lru);

    if(nr_pages == castle_cache_fast_vmap_pages)
    {
        uint32_t vmap_slot;

        vmap_slot = castle_cache_fast_vmap_freelist_get();
        c2b->buffer = castle_cache_fast_vmap_vstart + vmap_slot * nr_pages * PAGE_SIZE;
        if(castle_map_vm_area(c2b->buffer, castle_cache_vmap_pgs, nr_pages, PAGE_KERNEL))
            c2b->buffer = NULL;
    }
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
    if(c2b->nr_pages == castle_cache_fast_vmap_pages)
    {
        uint32_t vmap_slot;

        castle_unmap_vm_area(c2b->buffer, c2b->nr_pages);
        vmap_slot = (c2b->buffer - castle_cache_fast_vmap_vstart) / (c2b->nr_pages * PAGE_SIZE);
        down(&castle_cache_vmap_lock);
        castle_cache_fast_vmap_freelist_add(vmap_slot);
        up(&castle_cache_vmap_lock);
    }
    else
    if(c2b->nr_pages > 1)
        vunmap(c2b->buffer);
    /* Changes to freelists under freelist_lock */
    spin_lock(&castle_cache_freelist_lock);
    /* Add the pages back to the freelist */
    list_splice_init(&c2b->pages, &castle_cache_page_freelist);
    castle_cache_page_freelist_size += c2b->nr_pages;
    /* For debugging only: it will be spotted quickly if nr_pages isn't reinited properly */
    c2b->nr_pages = 0xFFFF;
    /* Then put the block on its freelist */
    __castle_cache_block_freelist_add(c2b);
    spin_unlock(&castle_cache_freelist_lock);
}

static inline int c2b_busy(c2_block_t *c2b)
{
	return atomic_read(&c2b->count) |
		  (c2b->state & (1 << C2B_dirty)) |
           rwsem_is_locked(&c2b->lock);
}

static int castle_cache_hash_clean(void)
{
#define BATCH_FREE 200
    
    struct list_head *lh, *t;
    LIST_HEAD(victims);
    c2_block_t *c2b;
    int nr_victims;

    spin_lock_irq(&castle_cache_hash_lock);
    /* Find victim buffers. */ 
    nr_victims = 0;
    list_for_each_safe(lh, t, &castle_cache_cleanlist)
    {
        c2b = list_entry(lh, c2_block_t, dirty_or_clean);
        if(!c2b_busy(c2b)) 
        {
            debug("Found a victim.\n");
            list_del(&c2b->list);
            list_del(&c2b->dirty_or_clean);
            atomic_sub(c2b->nr_pages, &castle_cache_cleanlist_size);
            list_add(&c2b->list, &victims);
            nr_victims++;
        }
        
        if(nr_victims > BATCH_FREE)
            break;
    }
    spin_unlock_irq(&castle_cache_hash_lock);

    /* We couldn't find any victims */
    if(list_empty(&victims))
    {
        debug("No victims found!!\n");
        return 0;
    }

    /* Add to the freelist */
    list_for_each_safe(lh, t, &victims)
    {
        list_del(lh);
        c2b = list_entry(lh, c2_block_t, list);
        castle_cache_block_free(c2b);
    }

    return 1;
}

static void castle_cache_page_freelist_grow(int nr_pages)
{
    int flush_seq, success = 0;

    while(!castle_cache_hash_clean())
    {
        debug("Failed to clean the hash.\n");
        /* Someone might have freed some pages, even though we failed. 
           We need to check that, in case hash is empty, and we will never 
           manage to free anything. */
        flush_seq = atomic_read(&castle_cache_flush_seq);
        spin_lock(&castle_cache_freelist_lock);
        if(castle_cache_page_freelist_size >= nr_pages)
           success = 1; 
        spin_unlock(&castle_cache_freelist_lock);
        if(success) return;
        /* If we haven't found any !busy buffers in the cleanlist 
           its likely because they are dirty. 
           Schedule a writeout. */
        debug("=> Could not clean the hash table. Waking flush.\n");
        castle_cache_flush_wakeup();
        debug("=> Woken.\n");
        /* Make sure at least one extra IO is done */
        wait_event(castle_cache_flush_wq, 
                (atomic_read(&castle_cache_flush_seq) != flush_seq));
        debug("=> We think there is some free memory now (cleanlist size: %d).\n",
                atomic_read(&castle_cache_cleanlist_size));
    }
    debug("Grown the list.\n");
}

c2_block_t* castle_cache_block_get(c_disk_blk_t cdb, int nr_pages)
{
    c2_block_t *c2b;
    struct list_head pages;

    castle_cache_flush_wakeup();
    might_sleep();
    for(;;)
    {
        debug("Trying to find buffer for cdb=(0x%x, 0x%x)\n",
            cdb.disk, cdb.block);
        /* Try to find in the hash first */
        c2b = castle_cache_hash_get(cdb); 
        debug("Found in hash: %p\n", c2b);
        if(c2b) 
        {
            /* Make sure that the number of pages agrees */
            BUG_ON(c2b->nr_pages != nr_pages);
            return c2b;
        }

        /* If we couldn't find in the hash, 
           try allocating from the freelist */ 
        INIT_LIST_HEAD(&pages);
        do {
            debug("Trying to allocate from freelist.\n");
            castle_cache_page_freelist_get(nr_pages, &pages); 
            if(list_empty(&pages))
            {
                debug("Failed to allocate from freelist. Growing freelist.\n");
                /* If freelist is empty, we need to recycle some buffers */
                castle_cache_page_freelist_grow(nr_pages); 
            }
        } while(list_empty(&pages));
        /* Initialise the buffer */
        c2b = castle_cache_block_freelist_get();
        debug("Initialisng the c2b: %p\n", c2b);
        castle_cache_block_init(c2b, cdb, &pages, nr_pages);
        get_c2b(c2b);
        /* Try to insert into the hash, can fail if it is already there */
        debug("Trying to insert\n");
        if(!castle_cache_hash_insert(c2b))
        {
            debug("Failed\n");
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

    dirty = atomic_read(&castle_cache_dirtylist_size);
    clean = atomic_read(&castle_cache_cleanlist_size);
    free  = castle_cache_page_freelist_size;

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
static void castle_cache_flush_endio(c2_block_t *c2b, int uptodate)
{
    atomic_t *count = c2b->private;
    if(!uptodate)
        printk("Could not write out a page!\n");
    else
        clean_c2b(c2b);

    unlock_c2b(c2b);
    put_c2b(c2b);
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
#define MAX_FLUSH_SIZE     1024
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
        debug("====> Waiting for 95\% of outstanding IOs to complete.\n");
        wait_event(castle_cache_flush_wq, atomic_read(&in_flight) <= flush_size / 20);

        /* Wait until enough pages have been dirtied to make it worth while
         * this will rate limit us to a min of 10 MIN_BATCHes a second */
        debug("====> Waiting completed, now waiting for big enough flush.\n");
        wait_event_timeout(
            castle_cache_flush_wq, 
            kthread_should_stop() ||
            (atomic_read(&castle_cache_dirtylist_size) - target_dirty_pgs > MIN_FLUSH_SIZE),
            HZ/MIN_FLUSH_FREQ);
 
        dirty_pgs = atomic_read(&castle_cache_dirtylist_size);  

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
        spin_lock_irq(&castle_cache_hash_lock);
        list_for_each_safe(l, t, &castle_cache_dirtylist)
        {
            if(to_flush <= 0)
                break;
            c2b = list_entry(l, c2_block_t, dirty_or_clean);
            if(!trylock_c2b(c2b))
                continue;
            /* This is slightly dangerous, but should be fine */
            list_move_tail(l, &castle_cache_dirtylist);
            get_c2b(c2b);
            to_flush -= c2b->nr_pages;
            c2b_batch[batch_idx++] = c2b;
            if(batch_idx >= FLUSH_BATCH)
                break;
        }
        spin_unlock_irq(&castle_cache_hash_lock);
        
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
                atomic_read(&castle_cache_dirtylist_size), 
                atomic_read(&castle_cache_cleanlist_size),
                castle_cache_page_freelist_size,
                target_dirty_pgs, to_flush, batch_idx); 
        }
        
        /* Finally check if we should still continue */
        if(kthread_should_stop())
            break;
    }

    /* When exitig wait for _all_ (and not 95%) of IO to complete */
    wait_event(castle_cache_flush_wq, atomic_read(&in_flight) == 0);
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

static int castle_cache_hash_init(void)
{
    int i;

    if(!castle_cache_hash)
        return -ENOMEM;
    
    for(i=0; i<castle_cache_hash_buckets; i++)
        INIT_LIST_HEAD(&castle_cache_hash[i]);

    atomic_set(&castle_cache_dirtylist_size, 0);
    atomic_set(&castle_cache_cleanlist_size, 0);

    return 0;
}

static void castle_cache_hash_fini(void)
{
    struct list_head *l, *t;
    c2_block_t *c2b;
    int i;

    if(!castle_cache_hash) 
        return;

    for(i=0; i<castle_cache_hash_buckets; i++)
    {
        list_for_each_safe(l, t, &castle_cache_hash[i])
        {
            list_del(l);
            c2b = list_entry(l, c2_block_t, list);
            /* Buffers should not be in use any more (devices do not exist) */
            if((atomic_read(&c2b->count) != 0) || c2b_locked(c2b))
            {
                printk("(disk,block)=(0x%x, 0x%x) not dropped count=%d, locked=%d.\n",
                    c2b->cdb.disk, c2b->cdb.block, atomic_read(&c2b->count), c2b_locked(c2b));
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
}

static int castle_cache_freelists_init(void)
{
    int i;

    if(!castle_cache_blks)
        return -ENOMEM;

    memset(castle_cache_blks, 0, sizeof(c2_block_t) * castle_cache_size);
    for(i=0; i<castle_cache_size; i++)
    {
        struct page *page = alloc_page(GFP_KERNEL); 
        c2_block_t  *c2b  = castle_cache_blks + i; 

        if(!page)
            return -ENOMEM;
        /* Add page to page_freelist */
        list_add(&page->lru, &castle_cache_page_freelist);

        /* Add c2b to block_freelist */
        INIT_LIST_HEAD(&c2b->pages);
        INIT_LIST_HEAD(&c2b->list);
        INIT_LIST_HEAD(&c2b->dirty_or_clean);
        init_rwsem(&c2b->lock);
        list_add(&c2b->list, &castle_cache_block_freelist);
    }
    castle_cache_page_freelist_size = castle_cache_size;

    return 0;
}

static void castle_cache_freelists_fini(void)
{
    struct list_head *l, *t;
    struct page *pg;
#ifdef CASTLE_DEBUG     
    c2_block_t *c2b;
#endif    

    if(!castle_cache_blks)
        return;

    list_for_each_safe(l, t, &castle_cache_page_freelist)
    {
        list_del(l);
        pg = list_entry(l, struct page, lru);
        __free_page(pg);
    }

#ifdef CASTLE_DEBUG     
    list_for_each_safe(l, t, &castle_cache_block_freelist)
    {
        list_del(l);
        c2b = list_entry(l, c2_block_t, list);
        BUG_ON(!list_empty(&c2b->pages));
    }
#endif    
}

static int castle_cache_fast_vmap_init(void)
{
    struct page **pgs_array;
    struct list_head *l;
    int i;

    castle_cache_fast_vmap_pages = castle_btree_type_get(VLBA_TREE_TYPE)->node_size;
    /* We need cache_castle_size / 512 for this array, if that's too big, we
       could use the cache pages themselves */
    pgs_array = vmalloc(castle_cache_size * sizeof(struct page *));
    if(!pgs_array)
        return -ENOMEM;

    castle_cache_fast_vmap_freelist = vmalloc((castle_cache_size + 1) * sizeof(uint32_t)); 
    if(!castle_cache_fast_vmap_freelist)
    {
        vfree(pgs_array);
        return -ENOMEM;
    }

    /* Assemble array of all pages from the freelist. Vmap them all. */
    i = 0;
    list_for_each(l, &castle_cache_page_freelist)
        pgs_array[i++] = list_entry(l, struct page, lru);

    castle_cache_fast_vmap_vstart = vmap(pgs_array, 
                                         castle_cache_size, 
                                         VM_READ|VM_WRITE, 
                                         PAGE_KERNEL);
    /* This gives as an area in virtual memory in which we'll keep mapping multi-page c2bs.
       In order for this to work we need to unmap all the pages, but tricking the vmalloc.c
       into not deallocating the vm_area_struct describing our virtual memory region.
       Use castle_unmap_vm_area for that.
     */
    BUG_ON(!castle_cache_fast_vmap_vstart);
    castle_unmap_vm_area(castle_cache_fast_vmap_vstart, castle_cache_size);
    /* Init the freelist */
    castle_cache_fast_vmap_freelist[0] = (uint32_t)-1;
    for(i=0; i<castle_cache_size; i++)
        castle_cache_fast_vmap_freelist_add(i);

    return 0;
}

static void castle_cache_fast_vmap_fini(void)
{
    int i;

    /* If the freelist didn't get allocated, there is nothing to fini. */
    if(!castle_cache_fast_vmap_freelist)
        return;

    /* Because we've done hash_fini(), there should be nothing mapped in the fast vmap area. 
       When in debug mode, verify that the freelist contains castle_cache_size items. Then,
       map all the cache pages, and let the vmalloc.c destroy vm_area_struct by vmunmping it.
     */ 
#ifdef CASTLE_DEBUG
   i = 0;
   while(castle_cache_fast_vmap_freelist[0] < castle_cache_size)
   {
       castle_cache_fast_vmap_freelist_get(); 
       i++;
   }
   BUG_ON(i != castle_cache_size);
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
        unlock_c2b(iter->node_c2b);
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
        if(!DISK_BLK_INVAL(node->next))
        {
            debug_mstore("Node exists.\n");
            /* If next block exist, make sure the current one is full */
            BUG_ON(node->used != node->capacity);
            c2b = castle_cache_page_block_get(node->next);
            lock_c2b(c2b);
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
            iter->store->last_node_cdb    = iter->node_c2b->cdb;
            iter->store->last_node_unused = node->capacity - node->used;
            up(&iter->store->mutex);
            debug_mstore("End of the list, last_node_unused=%d.\n", 
                    iter->store->last_node_unused);
        }
        debug_mstore("Unlocking prev node.\n");
        unlock_c2b(iter->node_c2b); 
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
        key->cdb = iter->node_c2b->cdb;
        key->idx = iter->node_idx;
        debug_mstore("Key: cdb=(0x%x, 0x%x), idx=%d.\n", 
                key->cdb.disk, key->cdb.block, key->idx);
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
        unlock_c2b(iter->node_c2b);
        put_c2b(iter->node_c2b);
    }
    debug_mstore("Freeing.\n"); 
    kfree(iter);
}

struct castle_mstore_iter* castle_mstore_iterate(struct castle_mstore *store)
{
    struct castle_fs_superblock *fs_sb;
    struct castle_mstore_iter *iter;
    c_disk_blk_t list_cdb;

    debug_mstore("Creating the iterator.\n"); 
    iter = kzalloc(sizeof(struct castle_mstore_iter), GFP_KERNEL);
    if(!iter)
        return NULL;

    iter->store = store;
    fs_sb = castle_fs_superblocks_get(); 
    list_cdb = fs_sb->mstore[store->store_id];
    castle_fs_superblocks_put(fs_sb, 0); 
    debug_mstore("Read first list node for mstore %d, got (0x%x, 0x%x)\n",
                    store->store_id, list_cdb.disk, list_cdb.block);
    if(DISK_BLK_INVAL(list_cdb))
        return NULL;
    iter->node_c2b = castle_cache_page_block_get(list_cdb);
    iter->node_idx = -1;
    debug_mstore("Locknig the first node (0x%x, 0x%x)\n",
            iter->node_c2b->cdb.disk, iter->node_c2b->cdb.block);
    lock_c2b(iter->node_c2b);
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
    c_disk_blk_t cdb;
    
    debug_mstore("Adding a node.\n");
    /* Check if mutex is locked */
    BUG_ON(down_trylock(&store->mutex) == 0);

    /* Prepare the node first */
    cdb = castle_freespace_block_get(0, 1);
    c2b = castle_cache_page_block_get(cdb);
    debug_mstore("Allocated (0x%x, 0x%x).\n", cdb.disk, cdb.block);
    lock_c2b(c2b);
    set_c2b_uptodate(c2b);
    debug_mstore("Locked.\n");

    /* Init the node correctly */
    node = c2b_buffer(c2b);
    node->magic     = MLIST_NODE_MAGIC;
    node->capacity  = (PAGE_SIZE - sizeof(struct castle_mlist_node)) / store->entry_size;
    node->used      = 0;
    node->next      = INVAL_DISK_BLK;
    dirty_c2b(c2b);
    debug_mstore("Inited the node.\n");
    /* Update relevant pointers to point to us (either FS superblock, or prev node) */
    if(DISK_BLK_INVAL(store->last_node_cdb))
    {
        debug_mstore("Linking into the superblock.\n");
        fs_sb = castle_fs_superblocks_get(); 
        BUG_ON(!DISK_BLK_INVAL(fs_sb->mstore[store->store_id]));
        fs_sb->mstore[store->store_id] = cdb;
        castle_fs_superblocks_put(fs_sb, 1); 
    } else
    {
        prev_c2b = castle_cache_page_block_get(store->last_node_cdb);
        debug_mstore("Linking into the prev node (0x%x, 0x%x).\n", 
                prev_c2b->cdb.disk, prev_c2b->cdb.block);
        lock_c2b(prev_c2b);
        if(!c2b_uptodate(prev_c2b))
            BUG_ON(submit_c2b_sync(READ, prev_c2b));
        debug_mstore("Read prev node.\n"); 
        prev_node = c2b_buffer(prev_c2b);
        prev_node->next = cdb;
        dirty_c2b(prev_c2b);
        unlock_c2b(prev_c2b);
        put_c2b(prev_c2b);
    }
    debug_mstore("Updating the saved last node.\n"); 
    /* Finally, save this node as the last node */
    store->last_node_cdb    = cdb;
    store->last_node_unused = node->capacity; 
    unlock_c2b(c2b);
    put_c2b(c2b);
}

static void castle_mstore_entry_mod(struct castle_mstore *store,
                                    c_mstore_key_t key,
                                    void *entry)
{
    struct castle_mlist_node *node;
    struct castle_mstore_entry *mentry;
    c2_block_t *node_c2b;
    
    debug_mstore("Modifying an entry in (0x%x, 0x%x), idx=%d, %s.\n",
            key.cdb.disk, key.cdb.block, key.idx, entry ? "updating" : "deleting"); 
    node_c2b = castle_cache_page_block_get(key.cdb);
    lock_c2b(node_c2b);
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
            printk("WARNING: updating removed mstore entry for mstore=%d, key=((0x%x, 0x%x), %d)\n",
                    store->store_id, key.cdb.disk, key.cdb.block, key.idx);
            mentry->flags &= ~CASTLE_MSTORE_ENTRY_DELETED;
        }
        memcpy(mentry->payload,
               entry,
               castle_mstore_payload_size(store));
    }
    dirty_c2b(node_c2b);
    unlock_c2b(node_c2b); 
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
    debug_mstore("Reading last node (0x%x, 0x%x).\n",
            store->last_node_cdb.disk, store->last_node_cdb.block);
    c2b = castle_cache_page_block_get(store->last_node_cdb);
    lock_c2b(c2b);
    if(!c2b_uptodate(c2b))
        BUG_ON(submit_c2b_sync(READ, c2b));
    node = c2b_buffer(c2b);
    key.cdb = c2b->cdb;
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
    unlock_c2b(c2b); 
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
    store = kzalloc(sizeof(struct castle_mstore), GFP_KERNEL);
    if(!store)
        return NULL;

    store->store_id         = store_id;
    store->entry_size       = entry_size + sizeof(struct castle_mstore_entry);
    init_MUTEX(&store->mutex);
    store->last_node_cdb    = INVAL_DISK_BLK; 
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
    if(store_id >= sizeof(fs_sb->mstore) / sizeof(c_disk_blk_t))
    {
        printk("Asked for mstore id=%d, this is too large.\n", store_id);
        return NULL;
    }

    store = castle_mstore_alloc(store_id, entry_size);
    if(!store)
        return NULL;
    /* Inefficient, because we read all the data to get to the last node,
       but mstores are expected to be small.
       The iterator will initialise last_node_{cdb,unused} */
    debug_mstore("Iterating to find last node.\n");
    iterator = castle_mstore_iterate(store);
    if(!iterator)
    {
        kfree(store);
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
    if(store_id >= sizeof(fs_sb->mstore) / sizeof(c_disk_blk_t))
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

int castle_cache_init(void)
{
    int ret;

    printk("Castle cache init, size=%d\n", castle_cache_size);

    castle_cache_hash_buckets = castle_cache_size >> 3; 
    castle_cache_hash = vmalloc(castle_cache_hash_buckets * sizeof(struct list_head));
    castle_cache_blks = vmalloc(castle_cache_size * sizeof(c2_block_t));
    castle_cache_fast_vmap_freelist = NULL;
    castle_cache_fast_vmap_vstart = NULL;
    atomic_set(&castle_cache_flush_seq, 0);

    if((ret = castle_cache_hash_init()))      goto err_out;
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
    castle_cache_hash_fini();
    castle_cache_fast_vmap_fini();
    castle_cache_freelists_fini();

    if(castle_cache_stats_timer_interval) del_timer(&castle_cache_stats_timer);

    if(castle_cache_hash) vfree(castle_cache_hash);
    if(castle_cache_blks) vfree(castle_cache_blks);
}

