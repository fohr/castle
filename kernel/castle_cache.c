#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/bio.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/kthread.h>

#include "castle.h"
#include "castle_cache.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)  ((void)0)
#else
#define debug(_f, _a...)  (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

static int                     castle_cache_size = 100; /* in pages */
static c2_page_t              *castle_cache_pgs  = NULL;

static int                     castle_cache_hash_buckets;
static         DEFINE_SPINLOCK(castle_cache_hash_lock);
static struct list_head       *castle_cache_hash = NULL;

static atomic_t                castle_cache_dirtylist_size;
static               LIST_HEAD(castle_cache_dirtylist);
static atomic_t                castle_cache_cleanlist_size;
static               LIST_HEAD(castle_cache_cleanlist);

static int                     castle_cache_freelist_last;
static int                     castle_cache_freelist_size;
static         DEFINE_SPINLOCK(castle_cache_freelist_lock);
static               LIST_HEAD(castle_cache_freelist);


static struct task_struct     *castle_cache_flush_thread;
static DECLARE_WAIT_QUEUE_HEAD(castle_cache_flush_wq); 
// TODO: This isn't used any more. Review, remove.
static DECLARE_WAIT_QUEUE_HEAD(castle_cache_flush_all_wq); 

static int sync_c2p(void *word)
{
	c2_page_t *c2p
		= container_of(word, c2_page_t, state);

	smp_mb();
    debug("In sync_c2p. Yielding\n");
	io_schedule();

	return 0;
}

void fastcall __lock_c2p(c2_page_t *c2p)
{
	wait_on_bit_lock(&c2p->state, C2P_lock, sync_c2p, TASK_UNINTERRUPTIBLE);
}

static int inline trylock_c2p(c2_page_t *c2p)
{
    /* We succeed at locking if the previous value of the lock bit was 0 */
    return (test_set_c2p_locked(c2p) == 0);
}

void fastcall unlock_c2p(c2_page_t *c2p)
{
	smp_mb__before_clear_bit();
	clear_c2p_locked(c2p);
	smp_mb__after_clear_bit();
	wake_up_bit(&c2p->state, C2P_lock);
}

void fastcall dirty_c2p(c2_page_t *c2p)
{
    unsigned long flags;

    spin_lock_irqsave(&castle_cache_hash_lock, flags);
    BUG_ON(!c2p_locked(c2p));
    if(c2p_dirty(c2p)) goto out;
    list_move(&c2p->dirty, &castle_cache_dirtylist);
    set_c2p_dirty(c2p); 
    atomic_dec(&castle_cache_cleanlist_size);
    atomic_inc(&castle_cache_dirtylist_size);
out:        
    spin_unlock_irqrestore(&castle_cache_hash_lock, flags);
}

static void fastcall clean_c2p(c2_page_t *c2p)
{
    unsigned long flags;

    spin_lock_irqsave(&castle_cache_hash_lock, flags);
    BUG_ON(!c2p_locked(c2p));
    BUG_ON(!c2p_dirty(c2p));
    list_move(&c2p->dirty, &castle_cache_cleanlist);
    clear_c2p_dirty(c2p); 
    atomic_dec(&castle_cache_dirtylist_size);
    atomic_inc(&castle_cache_cleanlist_size);
    spin_unlock_irqrestore(&castle_cache_hash_lock, flags);
}

static void c2p_io_end(struct bio *bio, int err)
{
	c2_page_t *c2p = bio->bi_private;

	c2p->end_io(c2p, test_bit(BIO_UPTODATE, &bio->bi_flags));
	bio_put(bio);
}

int submit_c2p(int rw, c2_page_t *c2p)
{
    struct castle_slave *cs;
	struct bio *bio;
	int ret = 0;

	BUG_ON(!c2p_locked(c2p));
	BUG_ON(!c2p->end_io);
    BUG_ON(DISK_BLK_INVAL(c2p->cdb));
    
    cs = castle_slave_find_by_block(c2p->cdb);
    if(!cs) return -ENODEV;

	bio = bio_alloc(GFP_NOIO, 1);

	bio->bi_sector = c2p->cdb.block * (C_BLK_SIZE >> 9);
	bio->bi_bdev = cs->bdev;
	bio->bi_io_vec[0].bv_page = c2p->page;
	bio->bi_io_vec[0].bv_len  = C_BLK_SIZE; 
	bio->bi_io_vec[0].bv_offset = 0;

	bio->bi_vcnt = 1;
	bio->bi_idx = 0;
	bio->bi_size = C_BLK_SIZE;

	bio->bi_end_io = c2p_io_end;
	bio->bi_private = c2p;

	submit_bio(rw, bio);
	
    return ret;
}

static void castle_cache_sync_io_end(c2_page_t *c2p, int uptodate)
{
    struct completion *completion = c2p->private;
    
    if(uptodate) set_c2p_uptodate(c2p);
    complete(completion);
}

int submit_c2p_sync(int rw, c2_page_t *c2p)
{
    struct completion completion;

	BUG_ON(!c2p_locked(c2p));
	BUG_ON(c2p_uptodate(c2p));
    c2p->end_io = castle_cache_sync_io_end;
    c2p->private = &completion;
    init_completion(&completion);
    submit_c2p(rw, c2p);
    wait_for_completion(&completion);

    /* Success (ret=0) if uptodate now */
    return !c2p_uptodate(c2p);
}

static inline int castle_cache_hash_idx(c_disk_blk_t cdb)
{
    return (cdb.block % castle_cache_hash_buckets);
}

static c2_page_t* castle_cache_hash_find(c_disk_blk_t cdb)
{
    struct list_head *lh;
    c2_page_t *c2p;
    int idx;

    idx = castle_cache_hash_idx(cdb);
    debug("Idx = %d\n", idx);
    list_for_each(lh, &castle_cache_hash[idx])
    {
        debug("Checking list element.\n");
        c2p = list_entry(lh, c2_page_t, list);
        if(DISK_BLK_EQUAL(c2p->cdb, cdb))
            return c2p;
    }

    return NULL;
}

static c2_page_t* castle_cache_hash_get(c_disk_blk_t cdb)
{
    c2_page_t *c2p = NULL;

    spin_lock_irq(&castle_cache_hash_lock);
    /* Try to find in the hash first */
    c2p = castle_cache_hash_find(cdb);
    /* If found, get a reference to make sure c2p doesn't get removed */
    if(c2p) get_c2p(c2p);
    /* If not found, drop the lock, we need to get ourselves a c2p first */
    spin_unlock_irq(&castle_cache_hash_lock);

    return c2p;
}

static int castle_cache_hash_insert(c2_page_t *c2p)
{
    int idx, success;

    spin_lock_irq(&castle_cache_hash_lock);
    /* Check if already in the hash */
    success = 0;
    if(castle_cache_hash_find(c2p->cdb)) goto out;
    /* Insert */
    success = 1;
    idx = castle_cache_hash_idx(c2p->cdb);
    list_add(&c2p->list, &castle_cache_hash[idx]);
    if(c2p_dirty(c2p))
    {
        list_add_tail(&c2p->dirty, &castle_cache_dirtylist);
        atomic_inc(&castle_cache_dirtylist_size);
    } else
    {
        list_add_tail(&c2p->dirty, &castle_cache_cleanlist);
        atomic_inc(&castle_cache_cleanlist_size);
    }
out:
    spin_unlock_irq(&castle_cache_hash_lock);
    return success;
}

static c2_page_t* castle_cache_freelist_get(void)
{
    struct list_head *lh;
    c2_page_t *c2p = NULL;

    spin_lock(&castle_cache_freelist_lock);
    if(!list_empty(&castle_cache_freelist)) 
    {
        lh = castle_cache_freelist.next;
        castle_cache_freelist_size--;
        list_del(lh);
        c2p = list_entry(lh, c2_page_t, list);
    }
    spin_unlock(&castle_cache_freelist_lock);

    return c2p;
}

static inline void __castle_cache_freelist_add(c2_page_t *c2p)
{
    list_add_tail(&c2p->list, &castle_cache_freelist);
    castle_cache_freelist_size++;
}

static inline void castle_cache_freelist_add(c2_page_t *c2p)
{
    spin_lock(&castle_cache_freelist_lock);
    __castle_cache_freelist_add(c2p);
    spin_unlock(&castle_cache_freelist_lock);
}

static inline int c2p_busy(c2_page_t *c2p)
{
	return atomic_read(&c2p->count) |
		(c2p->state & ((1 << C2P_dirty) | (1 << C2P_lock)));
}

static int castle_cache_hash_clean(void)
{
    int idx;
    struct list_head *lh, *t;
    LIST_HEAD(victims);
    c2_page_t *c2p;

    spin_lock_irq(&castle_cache_hash_lock);
    /* Find victim buffers, greater than the last one (if one exists) */ 
    idx = castle_cache_freelist_last;
    do {
        idx = (idx + 1) % castle_cache_hash_buckets;
        debug("Trying to find victims in bucket %d\n", idx);
        list_for_each_safe(lh, t, &castle_cache_hash[idx])
        {
            c2p = list_entry(lh, c2_page_t, list);
            if(!c2p_busy(c2p)) 
            {
                debug("Found a victim.\n");
                list_del(&c2p->list);
                list_del(&c2p->dirty);
                atomic_dec(&castle_cache_cleanlist_size);
                list_add(&c2p->list, &victims);
            }
        }
    } while(list_empty(&victims) && (idx != castle_cache_freelist_last));
    castle_cache_freelist_last = idx;
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
        c2p = list_entry(lh, c2_page_t, list);
        list_del(lh);
        __castle_cache_freelist_add(c2p);
    }
    spin_unlock(&castle_cache_freelist_lock);

    return 1;
}

static void castle_cache_freelist_grow(void)
{
    int success = 0;

    while(!castle_cache_hash_clean())
    {
        debug("Failed to clean the hash.\n");
        /* Someone might have freed some pages, even though we failed. 
           We need to check that, in case hash is empty, and we will never 
           manage to free anything. */
        spin_lock(&castle_cache_freelist_lock);
        if(!list_empty(&castle_cache_freelist))
           success = 1; 
        spin_unlock(&castle_cache_freelist_lock);
        if(success) return;
        /* If we haven't found any !busy buffers in the hash
           its likely because they are dirty. 
           Schedule a writeout. */
        printk("=> Could not clean the hash table. Waking flush.\n");
        castle_cache_flush_wakeup();
        printk("=> Woken.\n");
        wait_event(castle_cache_flush_wq, 
                   atomic_read(&castle_cache_cleanlist_size) > 0);
        printk("=> We think there is some free memory now.\n");
    }
    debug("Grown the list.\n");
}

static void castle_cache_page_init(c2_page_t *c2p, c_disk_blk_t cdb)
{
    /* c2p should only be initialised if it's not used */
    BUG_ON(list_empty(&c2p->list)); 
    BUG_ON(atomic_read(&c2p->count) != 0);
    c2p->cdb = cdb;
    c2p->state = INIT_C2P_BITS;
}

c2_page_t* castle_cache_page_get(c_disk_blk_t cdb)
{
    c2_page_t *c2p;

    castle_cache_flush_wakeup();
    might_sleep();
    for(;;)
    {
        debug("Trying to find buffer for cdb=(0x%x, 0x%x)\n",
            cdb.disk, cdb.block);
        /* Try to find in the hash first */
        c2p = castle_cache_hash_get(cdb); 
        debug("Found in hash: %p\n", c2p);
        if(c2p) return c2p;

        /* If we couldn't find in the hash, 
           try allocating from the freelist */ 
        do {
            debug("Trying to allocate from freelist.\n");
            c2p = castle_cache_freelist_get(); 
            if(!c2p)
            {
                debug("Failed to allocate from freelist. Growing freelist.\n");
                /* If freelist is empty, we need to recycle some buffers */
                castle_cache_freelist_grow(); 
            }
        } while(!c2p);
        /* Initialise the buffer */
        debug("Initialisng the c2p\n");
        castle_cache_page_init(c2p, cdb);
        get_c2p(c2p);
        /* Try to insert into the hash, can fail if it is already there */
        debug("Trying to insert\n");
        if(!castle_cache_hash_insert(c2p))
        {
            debug("Failed\n");
            put_c2p(c2p);
            castle_cache_freelist_add(c2p);
        }
        else
            return c2p;
    }
}

/***** Flush thread functions *****/
static void castle_cache_flush_endio(c2_page_t *c2p, int uptodate)
{
    atomic_t *count = c2p->private;
    if(!uptodate)
        printk("Could not write out a page!\n");
    else
        clean_c2p(c2p);

    unlock_c2p(c2p);
    put_c2p(c2p);
    atomic_dec(count);
    if(atomic_read(count) == 0)
        wake_up(&castle_cache_flush_all_wq);
    wake_up(&castle_cache_flush_wq);
}

static int castle_cache_flush(void *unused)
{
    int high_water_mark, low_water_mark, to_flush, dirty_pgs, batch_idx, i;
    struct list_head *l, *t;
    c2_page_t *c2p;
#define FLUSH_BATCH     512    
    c2_page_t *c2p_batch[FLUSH_BATCH];
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
            c2p = list_entry(l, c2_page_t, dirty);
            if(!trylock_c2p(c2p))
                continue;
            /* This is slightly dangerous, but should be fine */
            list_move_tail(l, &castle_cache_dirtylist);
            get_c2p(c2p);
            to_flush--;
            c2p_batch[batch_idx++] = c2p;
            if(batch_idx >= FLUSH_BATCH)
                break;
        }
        spin_unlock_irq(&castle_cache_hash_lock);
        
        debug("====>  Batch of: %d pages.\n", batch_idx);
        /* We've dropped the hash lock, submit all the write requests now */
        for(i=0; i<batch_idx; i++)
        {
            atomic_inc(&in_flight);
            c2p_batch[i]->end_io = castle_cache_flush_endio; 
            c2p_batch[i]->private = &in_flight;
            submit_c2p(WRITE, c2p_batch[i]);
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
    c2_page_t *c2p;
    int i;

    if(!castle_cache_hash) 
        return;

    for(i=0; i<castle_cache_hash_buckets; i++)
    {
        list_for_each_safe(l, t, &castle_cache_hash[i])
        {
            c2p = list_entry(l, c2_page_t, list);
            /* Buffers should not be in use any more (devices do not exist) */
            BUG_ON(c2p_locked(c2p));
            BUG_ON(atomic_read(&c2p->count) != 0);
            __free_page(c2p->page);
        }
    }
}

static int castle_cache_freelist_init(void)
{
    int i;

    if(!castle_cache_pgs)
        return -ENOMEM;

    for(i=0; i<castle_cache_size; i++)
    {
        struct page *page = alloc_page(GFP_KERNEL); 
        c2_page_t   *c2p  = castle_cache_pgs + i; 

        if(!page)
            return -ENOMEM;
        c2p->page = page; 
        list_add(&c2p->list, &castle_cache_freelist);
        INIT_LIST_HEAD(&c2p->dirty);
    }
    castle_cache_freelist_size = castle_cache_size;
    castle_cache_freelist_last = 0;

    return 0;
}

static void castle_cache_freelist_fini(void)
{
    struct list_head *l, *t;
    c2_page_t *c2p;

    if(!castle_cache_pgs)
        return;

    list_for_each_safe(l, t, &castle_cache_freelist)
    {
        list_del(l);
        c2p = list_entry(l, c2_page_t, list);
        __free_page(c2p->page);
    }
}

int castle_cache_init(void)
{
    int ret;

    castle_cache_hash_buckets = castle_cache_size >> 3; 
    castle_cache_hash = 
         kzalloc(castle_cache_hash_buckets * sizeof(struct list_head), GFP_KERNEL);
    castle_cache_pgs  = kzalloc(castle_cache_size * sizeof(c2_page_t), GFP_KERNEL);

    if((ret = castle_cache_hash_init()))     goto err_out;
    if((ret = castle_cache_freelist_init())) goto err_out; 
    if((ret = castle_cache_flush_init()))    goto err_out;

    return 0;

err_out:
    castle_cache_fini();

    return ret;
}

void castle_cache_fini(void)
{
    castle_cache_flush_fini();
    castle_cache_hash_fini();
    castle_cache_freelist_fini();

    if(castle_cache_hash) kfree(castle_cache_hash);
    if(castle_cache_pgs)  kfree(castle_cache_pgs);
}

