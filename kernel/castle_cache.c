#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/bio.h>
#include <linux/spinlock.h>

#include "castle.h"
#include "castle_cache.h"

/* In pages */
static int castle_cache_size = 1000;

static int               castle_cache_hash_size;
static   DEFINE_SPINLOCK(castle_cache_hash_lock);
static struct list_head *castle_cache_hash = NULL;
static c2_page_t        *castle_cache_pgs  = NULL;
static int               castle_cache_freelist_last;
static   DEFINE_SPINLOCK(castle_cache_freelist_lock);
static         LIST_HEAD(castle_cache_freelist);

static int sync_c2p(void *word)
{
    printk("In sync_c2p. Not doing anything!\n");
	return 0;
}

void fastcall __lock_c2p(c2_page_t *c2p)
{
	wait_on_bit_lock(&c2p->state, C2P_lock, sync_c2p, TASK_UNINTERRUPTIBLE);
}

void fastcall unlock_c2p(c2_page_t *c2p)
{
	smp_mb__before_clear_bit();
	clear_c2p_locked(c2p);
	smp_mb__after_clear_bit();
	wake_up_bit(&c2p->state, C2P_lock);
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

static inline int castle_cache_hash_idx(c_disk_blk_t cdb)
{
    return (cdb.block % castle_cache_hash_size);
}

static c2_page_t* castle_cache_hash_find(c_disk_blk_t cdb)
{
    struct list_head *lh;
    c2_page_t *c2p;
    int idx;

    idx = castle_cache_hash_idx(cdb);
    list_for_each(lh, &castle_cache_hash[idx])
    {
        c2p = list_entry(lh, c2_page_t, list);
        if(DISK_BLK_EQUAL(c2p->cdb, cdb))
            return c2p;
    }

    return NULL;
}

static c2_page_t* castle_cache_hash_get(c_disk_blk_t cdb)
{
    c2_page_t *c2p = NULL;

    spin_lock(&castle_cache_hash_lock);
    /* Try to find in the hash first */
    c2p = castle_cache_hash_find(cdb);
    /* If found, get a reference to make sure c2p doesn't get removed */
    if(c2p) get_c2p(c2p);
    /* If not found, drop the lock, we need to get ourselves a c2p first */
    spin_unlock(&castle_cache_hash_lock);
}

static int castle_cache_hash_insert(c2_page_t *c2p)
{
    int idx, success;

    spin_lock(&castle_cache_hash_lock);
    /* Check if already in the hash */
    success = 0;
    if(castle_cache_hash_find(c2p->cdb)) goto out;
    /* Insert */
    success = 1;
    idx = castle_cache_hash_idx(c2p->cdb);
    list_add(&c2p->list, &castle_cache_hash[idx]);
out:
    spin_unlock(&castle_cache_hash_lock);
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
        list_del(lh);
        c2p = list_entry(lh, c2_page_t, list);
    }
    spin_unlock(&castle_cache_freelist_lock);

    return c2p;
}

static void castle_cache_freelist_add(c2_page_t *c2p)
{
    spin_lock(&castle_cache_freelist_lock);
    list_add(&c2p->list, &castle_cache_freelist);
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

    spin_lock(&castle_cache_hash_lock);
    /* Find victim buffers, greater than the last one (if one exists) */ 
    idx = castle_cache_freelist_last;
    do {
        idx = (idx + 1) % castle_cache_hash_size;
        list_for_each(lh, &castle_cache_hash[idx])
        {
            c2p = list_entry(lh, c2_page_t, list);
            if(!c2p_busy(c2p)) list_add(&c2p->list, &victims);
        }
    } while(list_empty(&victims) && (idx != castle_cache_freelist_last));
    spin_unlock(&castle_cache_hash_lock);

    /* We couldn't find any victims */
    if(list_empty(&victims))
        return 0;

    /* Add to the freelist */
    spin_lock(&castle_cache_freelist_lock);
    list_for_each_safe(lh, t, &victims)
    {
        list_del(lh);
        list_add_tail(lh, &castle_cache_freelist);
    }
    spin_unlock(&castle_cache_freelist_lock);

    return 1;
}

static void castle_cache_writeout(void)
{
    /* TODO: not implemented yet */
    BUG(); 
}

static void castle_cache_freelist_grow(void)
{
    int success = 0;

    while(!castle_cache_hash_clean())
    {
        /* Someone might have freed some pages, even though we failed. 
           We need to check that, in case hash is empty, and we will never 
           manage to free anything. */
        spin_lock(&castle_cache_freelist_lock);
        if(!list_empty(&castle_cache_freelist))
           success = 1; 
        spin_unlock(&castle_cache_freelist_lock);
        if(success) return;
        /* If we haven't found any !busy buffers in the hash
           its likely because some of them are dirty. 
           Schedule a writeout. */
        castle_cache_writeout(); 
    }
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

    for(;;)
    {
        /* Try to find in the hash first */
        c2p = castle_cache_hash_get(cdb); 
        if(c2p) return c2p;

        /* If we couldn't find in the hash, 
           try allocating from the freelist */ 
        do {
            c2p = castle_cache_freelist_get(); 
            if(!c2p)
            {
                /* If freelist is empty, we need to recycle some buffers */
                castle_cache_freelist_grow(); 
            }
        } while(!c2p);
        /* Initialise the buffer */
        castle_cache_page_init(c2p, cdb);
        get_c2p(c2p);
        /* Try to insert into the hash, can fail if it is already there */
        if(!castle_cache_hash_insert(c2p))
        {
            put_c2p(c2p);
            castle_cache_freelist_add(c2p);
        }
        else
            return c2p;
    }
}

#if 0
struct 

void castle_cache_uptodate_page_get(c_disk_blk_t cdb,
                                    void (*callback)(void *arg, c2_page_t *c2p),
                                    void *arg)
{
    c2_page_t *c2p;

    c2p = castle_cache_page_get(cdb);
    lock_c2p(c2p);
    if(!c2p_uptodate(c2p))
    {
        c2p->private = 
        c2p->end_io(>>>);
        submit_c2p(READ, c2p);
    }
}
#endif

int castle_cache_init(void)
{
    int i;

    castle_cache_hash_size = castle_cache_size >> 4; 
    castle_cache_hash = kzalloc(castle_cache_hash_size * sizeof(struct list_head), GFP_KERNEL);
    castle_cache_pgs  = kzalloc(castle_cache_size * sizeof(c2_page_t), GFP_KERNEL);
    if(!castle_cache_hash || ! castle_cache_pgs)
        goto no_mem;

    for(i=0; i<castle_cache_size; i++)
    {
        struct page *page = alloc_page(GFP_KERNEL); 
        c2_page_t   *c2p  = castle_cache_pgs + i; 

        if(!page) goto no_mem;
        c2p->page = page; 
        list_add(&c2p->list, &castle_cache_freelist);
    }

    castle_cache_freelist_last = 0;

    return 0;

no_mem:
    castle_cache_fini();

    return -ENOMEM;
}

void castle_cache_fini(void)
{
    struct list_head *l, *t;
    c2_page_t *c2p;
    
    /* TODO needs to free all buffers in the hash! */
    list_for_each_safe(l, t, &castle_cache_freelist)
    {
        list_del(l);
        c2p = list_entry(l, c2_page_t, list);
        __free_page(c2p->page);
    }
    if(castle_cache_hash) kfree(castle_cache_hash);
    if(castle_cache_pgs)  kfree(castle_cache_pgs);
}
















