#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/bio.h>

#include "castle.h"
#include "castle_cache.h"

/* In pages */
static int castle_cache_size = 1000;

static int               castle_cache_hash_size;
static struct list_head *castle_cache_hash = NULL;
static c2_page_t        *castle_cache_pgs  = NULL;
static         LIST_HEAD(castle_cache_freelist);

static int sync_c2p(void *word)
{
    printk("In sync_c2p. Not doing anything!\n");
	return 0;
}

void fastcall __lock_c2p(c2_page_t *c2p)
{
	wait_on_bit_lock(&c2p->state, c2p_lock, sync_c2p, TASK_UNINTERRUPTIBLE);
}

void fastcall unlock_c2p(c2_page_t *c2p)
{
	smp_mb__before_clear_bit();
	clear_c2p_locked(c2p);
	smp_mb__after_clear_bit();
	wake_up_bit(&c2p->state, c2p_lock);
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

    return 0;

no_mem:
    castle_cache_fini();

    return -ENOMEM;
}

void castle_cache_fini(void)
{
    struct list_head *l, *t;
    c2_page_t *c2p;
    
    list_for_each_safe(l, t, &castle_cache_freelist)
    {
        list_del(l);
        c2p = list_entry(l, c2_page_t, list);
        __free_page(c2p->page);
    }
    if(castle_cache_hash) kfree(castle_cache_hash);
    if(castle_cache_pgs)  kfree(castle_cache_pgs);
}
















