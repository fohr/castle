#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/bio.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/kthread.h>

#include "castle_public.h"
#include "castle.h"
#include "castle_cache.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)  ((void)0)
#else
#define debug(_f, _a...)  (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

static int                     castle_cache_size = 1000; /* in pages */
static c2_block_t             *castle_cache_blks = NULL;

static int                     castle_cache_hash_buckets;
static         DEFINE_SPINLOCK(castle_cache_hash_lock);
static struct list_head       *castle_cache_hash = NULL;

static atomic_t                castle_cache_dirtylist_size;
static               LIST_HEAD(castle_cache_dirtylist);
static atomic_t                castle_cache_cleanlist_size;
static               LIST_HEAD(castle_cache_cleanlist);

static         DEFINE_SPINLOCK(castle_cache_freelist_lock); /* Lock for the two freelists below */
static int                     castle_cache_page_freelist_size;
static               LIST_HEAD(castle_cache_page_freelist);
static               LIST_HEAD(castle_cache_block_freelist);


static struct task_struct     *castle_cache_flush_thread;
static DECLARE_WAIT_QUEUE_HEAD(castle_cache_flush_wq); 

static int sync_c2b(void *word)
{
	/* If you need to use the c2b, here is how you work it out;
       c2_block_t *c2b = container_of(word, c2_block_t, state); */

	smp_mb();
    debug("In sync_c2b. Yielding\n");
	io_schedule();

	return 0;
}

void fastcall __lock_c2b(c2_block_t *c2b)
{
	wait_on_bit_lock(&c2b->state, C2B_lock, sync_c2b, TASK_UNINTERRUPTIBLE);
}

static int inline trylock_c2b(c2_block_t *c2b)
{
    /* We succeed at locking if the previous value of the lock bit was 0 */
    return (test_set_c2b_locked(c2b) == 0);
}

void fastcall unlock_c2b(c2_block_t *c2b)
{
#ifdef CASTLE_DEBUG    
    c2b->file = "none";
    c2b->line = 0;
#endif
	smp_mb__before_clear_bit();
	clear_c2b_locked(c2b);
	smp_mb__after_clear_bit();
	wake_up_bit(&c2b->state, C2B_lock);
}

void fastcall dirty_c2b(c2_block_t *c2b)
{
    unsigned long flags;

    spin_lock_irqsave(&castle_cache_hash_lock, flags);
    BUG_ON(!c2b_locked(c2b));
    if(c2b_dirty(c2b)) goto out;
    list_move(&c2b->dirty, &castle_cache_dirtylist);
    set_c2b_dirty(c2b); 
    atomic_dec(&castle_cache_cleanlist_size);
    atomic_inc(&castle_cache_dirtylist_size);
out:        
    spin_unlock_irqrestore(&castle_cache_hash_lock, flags);
}

static void fastcall clean_c2b(c2_block_t *c2b)
{
    unsigned long flags;

    spin_lock_irqsave(&castle_cache_hash_lock, flags);
    BUG_ON(!c2b_locked(c2b));
    BUG_ON(!c2b_dirty(c2b));
    list_move(&c2b->dirty, &castle_cache_cleanlist);
    clear_c2b_dirty(c2b); 
    atomic_dec(&castle_cache_dirtylist_size);
    atomic_inc(&castle_cache_cleanlist_size);
    spin_unlock_irqrestore(&castle_cache_hash_lock, flags);
}

static void c2b_io_end(struct bio *bio, int err)
{
	c2_block_t *c2b = bio->bi_private;
#ifdef CASTLE_DEBUG    
    unsigned long flags;
    
    local_irq_save(flags);
#endif
	c2b->end_io(c2b, test_bit(BIO_UPTODATE, &bio->bi_flags));
#ifdef CASTLE_DEBUG    
    local_irq_restore(flags);
#endif
	bio_put(bio);
}

int submit_c2b(int rw, c2_block_t *c2b)
{
    struct castle_slave *cs;
	struct bio *bio;

	BUG_ON(!c2b_locked(c2b));
	BUG_ON(!c2b->end_io);
    BUG_ON(DISK_BLK_INVAL(c2b->cdb));
    
    cs = castle_slave_find_by_block(c2b->cdb);
    if(!cs) return -ENODEV;

	bio = bio_alloc(GFP_NOIO, 1);
/* Temporarily we assume a single page to c2_block_t */
BUG_ON(c2b->pages.next       == &c2b->pages);
BUG_ON(c2b->pages.next->next != &c2b->pages);

	bio->bi_sector = (sector_t)(c2b->cdb.block * (C_BLK_SIZE >> 9));
	bio->bi_bdev = cs->bdev;
	bio->bi_io_vec[0].bv_page = (struct page *)list_entry(c2b->pages.next, struct page, lru);
	bio->bi_io_vec[0].bv_len  = C_BLK_SIZE; 
	bio->bi_io_vec[0].bv_offset = 0;

	bio->bi_vcnt = 1;
	bio->bi_idx = 0;
	bio->bi_size = C_BLK_SIZE;

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
    /* If found, get a reference to make sure c2b doesn't get removed */
    if(c2b) get_c2b(c2b);
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
        list_add_tail(&c2b->dirty, &castle_cache_dirtylist);
        atomic_inc(&castle_cache_dirtylist_size);
    } else
    {
        list_add_tail(&c2b->dirty, &castle_cache_cleanlist);
        atomic_inc(&castle_cache_cleanlist_size);
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

static struct page* castle_cache_page_freelist_get(void)
{
    struct list_head *lh;
    struct page *pg = NULL;

    spin_lock(&castle_cache_freelist_lock);
    if(!list_empty(&castle_cache_page_freelist)) 
    {
        lh = castle_cache_page_freelist.next;
        castle_cache_page_freelist_size--;
        list_del(lh);
        pg = list_entry(lh, struct page, lru);
    }
    spin_unlock(&castle_cache_freelist_lock);

    return pg;
}

static inline void __castle_cache_page_freelist_add(struct page *pg)
{
    list_add_tail(&pg->lru, &castle_cache_page_freelist);
    castle_cache_page_freelist_size++;
}

static inline void castle_cache_page_freelist_add(struct page *pg)
{
    spin_lock(&castle_cache_freelist_lock);
    __castle_cache_page_freelist_add(pg);
    spin_unlock(&castle_cache_freelist_lock);
}

static void castle_cache_block_init(c2_block_t *c2b, c_disk_blk_t cdb, struct page *pg)
{
    /* c2b should only be initialised if it's not used */
    BUG_ON(list_empty(&c2b->list)); 
    BUG_ON(!list_empty(&c2b->pages));
    BUG_ON(atomic_read(&c2b->count) != 0);
    c2b->cdb = cdb;
    c2b->state = INIT_C2B_BITS;
    list_add(&pg->lru, &c2b->pages);
}

/* Must be called with freelist lock held */
static void castle_cache_block_free(c2_block_t *c2b)
{
    /* Add the pages back to the freelist */
    list_splice_init(&c2b->pages, &castle_cache_page_freelist);
    /* Then put the block on its freelist */
    __castle_cache_block_freelist_add(c2b);
}

static inline int c2b_busy(c2_block_t *c2b)
{
	return atomic_read(&c2b->count) |
		(c2b->state & ((1 << C2B_dirty) | (1 << C2B_lock)));
}

static int castle_cache_hash_clean(void)
{
    struct list_head *lh, *t;
    LIST_HEAD(victims);
    c2_block_t *c2b;
    int nr_victims;

    spin_lock_irq(&castle_cache_hash_lock);
    /* Find victim buffers. */ 
    nr_victims = 0;
    list_for_each_safe(lh, t, &castle_cache_cleanlist)
    {
        c2b = list_entry(lh, c2_block_t, dirty);
        if(!c2b_busy(c2b)) 
        {
            debug("Found a victim.\n");
            list_del(&c2b->list);
            list_del(&c2b->dirty);
            atomic_dec(&castle_cache_cleanlist_size);
            list_add(&c2b->list, &victims);
            nr_victims++;
        }
        if(nr_victims > 20)
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
    spin_lock(&castle_cache_freelist_lock);
    list_for_each_safe(lh, t, &victims)
    {
        list_del(lh);
        c2b = list_entry(lh, c2_block_t, list);
        castle_cache_block_free(c2b);
    }
    spin_unlock(&castle_cache_freelist_lock);

    return 1;
}

static void castle_cache_page_freelist_grow(void)
{
    int success = 0;

    while(!castle_cache_hash_clean())
    {
        debug("Failed to clean the hash.\n");
        /* Someone might have freed some pages, even though we failed. 
           We need to check that, in case hash is empty, and we will never 
           manage to free anything. */
        spin_lock(&castle_cache_freelist_lock);
        if(!list_empty(&castle_cache_page_freelist))
           success = 1; 
        spin_unlock(&castle_cache_freelist_lock);
        if(success) return;
        /* If we haven't found any !busy buffers in the cleanlist 
           its likely because they are dirty. 
           Schedule a writeout. */
        debug("=> Could not clean the hash table. Waking flush.\n");
        castle_cache_flush_wakeup();
        debug("=> Woken.\n");
        sleep_on_timeout(&castle_cache_flush_wq, HZ / 25);
        debug("=> We think there is some free memory now (cleanlist size: %d).\n",
                atomic_read(&castle_cache_cleanlist_size));
    }
    debug("Grown the list.\n");
}

c2_block_t* castle_cache_block_get(c_disk_blk_t cdb)
{
    c2_block_t *c2b;
    struct page *pg;

    castle_cache_flush_wakeup();
    might_sleep();
    for(;;)
    {
        debug("Trying to find buffer for cdb=(0x%x, 0x%x)\n",
            cdb.disk, cdb.block);
        /* Try to find in the hash first */
        c2b = castle_cache_hash_get(cdb); 
        debug("Found in hash: %p\n", c2b);
        if(c2b) return c2b;

        /* If we couldn't find in the hash, 
           try allocating from the freelist */ 
        do {
            debug("Trying to allocate from freelist.\n");
            pg = castle_cache_page_freelist_get(); 
            if(!c2b)
            {
                debug("Failed to allocate from freelist. Growing freelist.\n");
                /* If freelist is empty, we need to recycle some buffers */
                castle_cache_page_freelist_grow(); 
            }
        } while(!pg);
        /* Initialise the buffer */
        c2b = castle_cache_block_freelist_get();
        debug("Initialisng the c2b: %p\n", c2b);
        castle_cache_block_init(c2b, cdb, pg);
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
            return c2b;
    }
}

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
    wake_up(&castle_cache_flush_wq);
}

static int castle_cache_flush(void *unused)
{
    int high_water_mark, low_water_mark, to_flush, dirty_pgs, batch_idx, i;
    struct list_head *l, *t;
    c2_block_t *c2b;
#define FLUSH_BATCH     512    
    c2_block_t *c2b_batch[FLUSH_BATCH];
    atomic_t in_flight;

    high_water_mark = castle_cache_size >> 1;
    low_water_mark = high_water_mark - (castle_cache_size >> 3) - 1;
    for(;;)
    {
        dirty_pgs = atomic_read(&castle_cache_dirtylist_size);  
        /* Go to sleep if < high_water_mark pages dirty.
           As long as we've not been asked to flush everything and exit. */
        debug("====> Castle cache flush loop.\n");
        if((dirty_pgs < high_water_mark) && !kthread_should_stop())
        {
            debug("====> Going to sleep.\n");
            set_current_state(TASK_INTERRUPTIBLE);
            schedule();
            continue;
        }
        to_flush = dirty_pgs - low_water_mark;
        if(kthread_should_stop())
            to_flush = dirty_pgs;
        atomic_set(&in_flight, 0);
        debug("====> Flushing: %d pages out of %d dirty.\n", to_flush, dirty_pgs);
next_batch:        
        batch_idx = 0;
        spin_lock_irq(&castle_cache_hash_lock);
        list_for_each_safe(l, t, &castle_cache_dirtylist)
        {
            if(to_flush == 0)
                break;
            c2b = list_entry(l, c2_block_t, dirty);
            if(!trylock_c2b(c2b))
                continue;
            /* This is slightly dangerous, but should be fine */
            list_move_tail(l, &castle_cache_dirtylist);
            get_c2b(c2b);
            to_flush--;
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
        if(to_flush != 0)
        {
            if(batch_idx == FLUSH_BATCH)
                goto next_batch; 
            /* If we still have buffers to flush, but we could not lock 
               enough dirty buffers print a warning message, and stop */
            printk("Could not find enough dirty pages to flush!\n");
        }
        
        debug("====> Waiting for all IOs to complete.\n");
        /* Wait for all the IOs to complete */
        wait_event(castle_cache_flush_wq, atomic_read(&in_flight) == 0);
        debug("====> Waiting completed.\n");
        
        /* Finally check if we should still continue */
        if(kthread_should_stop())
            break;
    }
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
            BUG_ON(c2b_locked(c2b));
            if(atomic_read(&c2b->count) != 0)
                printk("(disk,block)=(0x%x, 0x%x) not dropped.\n",
                    c2b->cdb.disk, c2b->cdb.block);

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
        INIT_LIST_HEAD(&c2b->dirty);
        list_add(&c2b->list, &castle_cache_block_freelist);
    }
    castle_cache_page_freelist_size = castle_cache_size;

    return 0;
}

static void castle_cache_freelists_fini(void)
{
    struct list_head *l, *t;
    c2_block_t *c2b;
    struct page *pg;

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

int castle_cache_init(void)
{
    int ret;

    castle_cache_hash_buckets = castle_cache_size >> 3; 
    castle_cache_hash = 
         kzalloc(castle_cache_hash_buckets * sizeof(struct list_head), GFP_KERNEL);
    castle_cache_blks  = kzalloc(castle_cache_size * sizeof(c2_block_t), GFP_KERNEL);

    if((ret = castle_cache_hash_init()))      goto err_out;
    if((ret = castle_cache_freelists_init())) goto err_out; 
    if((ret = castle_cache_flush_init()))     goto err_out;

    return 0;

err_out:
    castle_cache_fini();

    return ret;
}

void castle_cache_fini(void)
{
    castle_cache_flush_fini();
    castle_cache_hash_fini();
    castle_cache_freelists_fini();

    if(castle_cache_hash) kfree(castle_cache_hash);
    if(castle_cache_blks) kfree(castle_cache_blks);
}

