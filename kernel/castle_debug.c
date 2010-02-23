#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/fs.h>
#include <linux/bio.h>

#include "castle.h"
#include "castle_debug.h"

typedef struct castle_debug_watch {
    uint32_t block;
    uint32_t version;
} cd_watch_t;


static spinlock_t           bio_list_spinlock = SPIN_LOCK_UNLOCKED;
static int                  bio_id = 0;
static            LIST_HEAD(bio_list);
static struct task_struct  *debug_thread;
static cd_watch_t           watches[] = {{0x41, 0x3}};
static int                  nr_watches = 1;
static struct page        **watched_data;

static void castle_debug_buffer_init(struct page *pg)
{
    uint8_t *buffer = pfn_to_kaddr(page_to_pfn(pg));
    int i;

    for(i=0; i<PAGE_SIZE; i++)
        buffer[i] = (uint8_t)i;
}

static int castle_debug_buffer_sector_written(struct page *pg, sector_t sector)
{
    uint8_t *buffer = pfn_to_kaddr(page_to_pfn(pg));
    int i;
     
    for(i=(sector << 9); 
        i<((sector+1) << 9);
        i++)
    {
        if(buffer[i] != (uint8_t)i)
            return 1;
    }
    return 0;
}

void castle_debug_bvec_update(c_bvec_t *c_bvec, unsigned long state_flag)
{
    c_bvec->c_bio->stuck = 0;
    c_bvec->state |= state_flag;
}

void castle_debug_bvec_btree_walk(c_bvec_t *c_bvec)
{
    c_bvec->btree_depth++;
    c_bvec->state &= (~C_BVEC_BTREE_MASK);
}

static void castle_debug_watches_print(void)
{
    uint8_t *buffer;
    sector_t sector;
    int i, j;

    if(!watched_data) return;

    printk("\n");
    for(i=0; i<nr_watches; i++)
    {
        printk("Data for watched (b,v)=(0x%x, 0x%x)\n",
            watches[i].block, watches[i].version);
        buffer = pfn_to_kaddr(page_to_pfn(watched_data[i]));
        for(sector=0; sector<8; sector++)
        {
            if(castle_debug_buffer_sector_written(watched_data[i], sector))
            {
                for(j=(sector << 9); 
                    j<((sector+1) << 9);
                    j++)
                {
                    if(j % 8 == 0) printk(" ");
                    if(j % 16 == 0) printk("\n[0x%.3x] ", j);
                    printk("%.2x ", buffer[j]);
                }
            } else
            {
                printk("[0x%.3lx - 0x%.3lx] not written\n", 
                   (sector << 9), (((sector+1)<<9) -1));
            }
        }
        printk("\n\n");
    }
}

static void castle_debug_watch_update(int id, struct bio_vec *bvec)
{
    memcpy(pfn_to_kaddr(page_to_pfn(watched_data[id])) + bvec->bv_offset,
           pfn_to_kaddr(page_to_pfn(bvec->bv_page))    + bvec->bv_offset,
           bvec->bv_len);
}

static void castle_debug_watches_update(struct bio *bio, uint32_t version)
{
    struct bio_vec *bvec;
    sector_t sector;
    int i, j;

    sector = bio->bi_sector;
    bio_for_each_segment(bvec, bio, i)
    {
        for(j=0; j<nr_watches; j++)
        { 
            cd_watch_t *watch = &watches[j];

            if((sector >> (C_BLK_SHIFT - 9) == watch->block) &&
               (version == watch->version) )
            {
                printk("Watched block (b,v)=(0x%x, 0x%x) accessed.\n",
                    watch->block, watch->version);
                if(bio_data_dir(bio) == WRITE)
                {
                    printk("It's a write\n");
                    castle_debug_watch_update(j, bvec);
                }
            }
            sector += (bvec->bv_len >> 9);
        } 
    }
}

void castle_debug_bio_add(c_bio_t *c_bio, uint32_t version)
{
    unsigned long flags;

    c_bio->nr_bvecs = atomic_read(&c_bio->remaining);
    spin_lock_irqsave(&bio_list_spinlock, flags);
    c_bio->id = bio_id++;
    c_bio->stuck = 0;
    list_add(&c_bio->list, &bio_list);
    castle_debug_watches_update(c_bio->bio, version);
    spin_unlock_irqrestore(&bio_list_spinlock, flags);
}

void castle_debug_bio_del(c_bio_t *c_bio)
{
    unsigned long flags;
         
    spin_lock_irqsave(&bio_list_spinlock, flags);
    list_del(&c_bio->list);
    spin_unlock_irqrestore(&bio_list_spinlock, flags);
}

static int castle_debug_run(void *unused)
{
    c_bio_t *c_bio;
    struct list_head *l;
    int i, j;
    unsigned long flags;

    printk("Castle debugging thread starting.\n");
    do {
        msleep_interruptible(1000);
        i=0;
        spin_lock_irqsave(&bio_list_spinlock, flags);
        list_for_each(l, &bio_list)
        {
            c_bio = list_entry(l, c_bio_t, list); 
            if(!c_bio->stuck)
            {
                c_bio->stuck = 1;
                continue;
            }
            printk("Found an oustanding Castle BIO, id=%d\n", c_bio->id);
            for(j=0; j<c_bio->nr_bvecs; j++)
            {
                c_bvec_t *c_bvec = &c_bio->c_bvecs[j];
                printk(" c_bvecs[%d], "
                       "(b,v)=(0x%lx, 0x%x), "
                       "btree_depth=%d, "
                       "state=0x%lx\n",
                    j,
                    c_bvec->block, c_bvec->version,
                    c_bvec->btree_depth,
                    c_bvec->state);
            }
            i++;
        }
        spin_unlock_irqrestore(&bio_list_spinlock, flags);
        if(i > 0) printk("Number of outstanding requests: %d\n", i);
    } while(!kthread_should_stop());

    return 0;
}

static void castle_debug_watches_free(void)
{
    int i;
    
    if(watched_data)
    {
        for(i=0; i<nr_watches; i++)
            if(watched_data[i] != NULL)
                __free_page(watched_data[i]);
        kfree(watched_data);
    }
}

void castle_debug_init(void)
{
    int i;

    debug_thread = kthread_run(castle_debug_run, NULL, "castle-debug");
   
    /* Try to allocate buffers for watched pages */
    watched_data = kzalloc(sizeof(struct page*) * nr_watches, GFP_KERNEL); 
    if(!watched_data) goto alloc_failed;
    for(i=0; i<nr_watches; i++)
    {
        watched_data[i] = alloc_page(GFP_KERNEL);
        if(!watched_data[i]) goto alloc_failed;
        castle_debug_buffer_init(watched_data[i]);
    }
    return;

alloc_failed:    
    printk("Failed to allocate buffers for debug watches.\n");
    castle_debug_watches_free();
}

void castle_debug_fini(void)
{
    kthread_stop(debug_thread);
    castle_debug_watches_print();
    castle_debug_watches_free();
}
