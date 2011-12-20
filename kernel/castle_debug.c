#include <linux/kthread.h>
#include <linux/bio.h>

#include "castle_public.h"
#include "castle.h"
#include "castle_debug.h"
#include "castle_cache.h"
#include "castle_utils.h"

typedef struct castle_debug_watch {
    uint32_t block;
    uint32_t version;
} cd_watch_t;

struct castle_malloc_debug {
    uint32_t cannary1;
    struct list_head list;
    uint32_t size;
    char *file;
    int vmalloced;
    int line;
    uint32_t cannary2;
};

static spinlock_t           malloc_list_spinlock = SPIN_LOCK_UNLOCKED;
static            LIST_HEAD(malloc_list);
static spinlock_t           bio_list_spinlock = SPIN_LOCK_UNLOCKED;
static int                  bio_id = 0;
static            LIST_HEAD(bio_list);
struct task_struct  *debug_thread;
static cd_watch_t           watches[] = {{0x41, 0x3}};
static int                  nr_watches = 0;
static struct page        **watched_data;

#define CANNARY1 0xabcd0123
#define CANNARY2 0x456789ab
static void __castle_debug_dobj_add(struct castle_malloc_debug *dobj,
                                    size_t size,
                                    char *file,
                                    int line,
                                    int vmalloced)
{
    /* Init all fields */
    INIT_LIST_HEAD(&dobj->list);
    dobj->cannary1 = CANNARY1;
    dobj->file = file;
    dobj->line = line;
    dobj->size = size;
    dobj->vmalloced = vmalloced;
    dobj->cannary2 = CANNARY2;

    /* Add ourselves to the list under lock */
    spin_lock_irq(&malloc_list_spinlock);
    list_add(&dobj->list, &malloc_list);
    spin_unlock_irq(&malloc_list_spinlock);
}

/**
 * Allocate bytes using castle_debug_malloc(), falling back to castle_debug_vmalloc) as appropriate.
 */
void* castle_debug_alloc_func(size_t size, char *file, int line)
{
    void *buf;

    if (likely(size <= MAX_KMALLOC_SIZE))
    {
        buf = castle_debug_malloc(size, GFP_KERNEL, file, line);
        if (buf)
            return buf;
    }

    return castle_debug_vmalloc(size, file, line);
}

void* castle_debug_zalloc_func(size_t size, char *file, int line)
{
    void *buf;

    if (likely(size <= MAX_KMALLOC_SIZE))
    {
        buf = castle_debug_zalloc(size, GFP_KERNEL, file, line);
        if (buf)
            return buf;
    }

    buf = castle_debug_vmalloc(size, file, line);
    if (buf)
        memset(buf, 0, size);

    return buf;
}

/**
 * Deallocate buffer previously allocated via castle_debug_alloc_func().
 */
void castle_debug_free_func(void *ptr)
{
    unsigned long addr = (unsigned long) ptr;

    if (likely(addr >= VMALLOC_START && addr < VMALLOC_END))
        castle_debug_vfree(ptr);
    else
        castle_debug_free(ptr);
}

/**
 * Allocate a buffer, unless a suitable one is provided by the caller.
 * @see castle_alloc_maybe_func()
 */
void *castle_debug_alloc_maybe_func(size_t len, void *dst, size_t *dst_len, char *file, int line)
{
    if (!dst)
        return castle_debug_alloc_func(len, file, line);
    else if (dst_len && *dst_len >= len)
        return *dst_len = len, dst;
    else
        return NULL;
}

/**
 * Copy a buffer, either to a freshly allocated buffer, or to one supplied by the caller.
 * @see castle_dup_or_copy_func()
 */
void *castle_debug_dup_or_copy_func(const void *src, size_t src_len, void *dst, size_t *dst_len,
                                    char *file, int line)
{
    if ((dst = castle_debug_alloc_maybe_func(src_len, dst, dst_len, file, line)))
        memcpy(dst, src, src_len);
    return dst;
}

void* castle_debug_malloc(size_t size, gfp_t flags, char *file, int line)
{
    struct castle_malloc_debug *dobj;

    BUG_ON((flags != GFP_ATOMIC) && in_atomic());

    size += sizeof(struct castle_malloc_debug);
    /* Alloc the object */
    dobj = kmalloc(size, flags);
    if(!dobj)
        return NULL;
    /* Init and add the object to the list. */
    __castle_debug_dobj_add(dobj, size, file, line, 0);

    return (char *)dobj + sizeof(struct castle_malloc_debug);
}
EXPORT_SYMBOL(castle_debug_malloc);

void* castle_debug_zalloc(size_t size, gfp_t flags, char *file, int line)
{
    char *obj;

    obj = castle_debug_malloc(size, flags, file, line);
    if(obj)
        memset(obj, 0, size);

    return obj;
}
EXPORT_SYMBOL(castle_debug_zalloc);

void castle_debug_free(void *obj)
{
    struct castle_malloc_debug *dobj;
    unsigned long flags;

    dobj = obj;
    dobj--;

    if((dobj->cannary1 != CANNARY1) || (dobj->cannary2 != CANNARY2))
    {
        castle_printk(LOG_ERROR, "Cannaries dead, for %p, double free?\n", dobj);
        BUG();
    }
    /* Remove from list */
    spin_lock_irqsave(&malloc_list_spinlock, flags);
    list_del(&dobj->list);
    spin_unlock_irqrestore(&malloc_list_spinlock, flags);

   if(dobj->vmalloced)
    {
        castle_printk(LOG_ERROR, "Trying to kfree() vmalloced object.\n");
        BUG();
    }
    memset(dobj, 0xf5, sizeof(struct castle_malloc_debug));
    kfree(dobj);
}
EXPORT_SYMBOL(castle_debug_free);

void* castle_debug_vmalloc(unsigned long size, char *file, int line)
{
    struct castle_malloc_debug *dobj;

    BUG_ON(in_atomic());

    size += PAGE_SIZE;
    /* Alloc the object */
    dobj = vmalloc(size);
    if(!dobj)
        return NULL;

    BUG_ON(((unsigned long)dobj < VMALLOC_START) || ((unsigned long)dobj >= VMALLOC_END));
    /* Init and add the object to the list. */
    __castle_debug_dobj_add(dobj, size, file, line, 1);

    return (char *)dobj + PAGE_SIZE;
}
EXPORT_SYMBOL(castle_debug_vmalloc);

void castle_debug_vfree(void *obj)
{
    struct castle_malloc_debug *dobj;
    unsigned long flags;

    dobj = (struct castle_malloc_debug *)((char *)obj - PAGE_SIZE);

    if((dobj->cannary1 != CANNARY1) || (dobj->cannary2 != CANNARY2))
    {
        castle_printk(LOG_ERROR, "Cannaries dead, for %p, double free?\n", dobj);
        BUG();
    }
     /* Remove from list */
    spin_lock_irqsave(&malloc_list_spinlock, flags);
    list_del(&dobj->list);
    spin_unlock_irqrestore(&malloc_list_spinlock, flags);

    if(!dobj->vmalloced)
    {
        castle_printk(LOG_ERROR, "Trying to vfree() kmalloced object.\n");
        BUG();
    }
    memset(dobj, 0xf6, sizeof(struct castle_malloc_debug));
    vfree(dobj);
}
EXPORT_SYMBOL(castle_debug_vfree);

static void castle_debug_malloc_fini(void)
{
    struct castle_malloc_debug *dobj;
    struct list_head *l;
    uint32_t sum = 0;
    uint32_t i = 0;

    list_for_each(l, &malloc_list)
    {
        dobj = list_entry(l, struct castle_malloc_debug, list);
        castle_printk(LOG_ERROR, "%s of %u bytes from %s:%d hasn't been deallocated.\n",
                dobj->vmalloced ? "vmalloc" : "kmalloc/kzalloc",
                dobj->size,
                dobj->file,
                dobj->line);
        sum += dobj->size;
        i++;
    }
    castle_printk(LOG_ERROR, "******** Memory Leak: %u bytes / %u objects *********\n", sum, i);
}

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
    c_bvec->state &= (~C_BVEC_BTREE_MASK);
}

static void castle_debug_watches_print(void)
{
    uint8_t *buffer;
    sector_t sector;
    int i, j;

    if(!watched_data) return;

    castle_printk(LOG_DEBUG, "\n");
    for(i=0; i<nr_watches; i++)
    {
        castle_printk(LOG_DEBUG, "Data for watched (b,v)=(0x%x, 0x%x)\n",
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
                    if(j % 8 == 0) castle_printk(LOG_DEBUG, " ");
                    if(j % 16 == 0) castle_printk(LOG_DEBUG, "\n[0x%.3x] ", j);
                    castle_printk(LOG_DEBUG, "%.2x ", buffer[j]);
                }
            }
        }
        castle_printk(LOG_DEBUG, "\n\n");
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
                castle_printk(LOG_DEBUG, "Watched block (b,v)=(0x%x, 0x%x) accessed.\n",
                    watch->block, watch->version);
                if(bio_data_dir(bio) == WRITE)
                {
                    castle_printk(LOG_DEBUG, "It's a write\n");
                    castle_debug_watch_update(j, bvec);
                }
            }
            sector += (bvec->bv_len >> 9);
        }
    }
}

void castle_debug_bio_register(c_bio_t *c_bio, uint32_t version, int nr_bvecs)
{
    unsigned long flags;
    int i;

    c_bio->nr_bvecs = nr_bvecs;
    spin_lock_irqsave(&bio_list_spinlock, flags);
    c_bio->id = bio_id++;
    c_bio->stuck = 0;
    for(i=0; i<nr_bvecs; i++)
        c_bio->c_bvecs[i].state = 0;
    /* One extra reference (on top of the bvec refs)
       taken to c_bio when bio_add is called */
    list_add(&c_bio->list, &bio_list);
    castle_debug_watches_update(c_bio->bio, version);
    spin_unlock_irqrestore(&bio_list_spinlock, flags);
}

void castle_debug_bio_deregister(c_bio_t *c_bio)
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
    int something_printed, j, nr_bios;
    unsigned long flags, states_printed;
    int sleep_time = 2;

    do {
        spin_lock_irqsave(&bio_list_spinlock, flags);
        states_printed = 0;
        something_printed = 0;
        nr_bios = 0;
        list_for_each(l, &bio_list)
        {
            c_bio = list_entry(l, c_bio_t, list);
            if(!c_bio->stuck)
            {
                c_bio->stuck = 1;
                continue;
            }
                c_bio->stuck++;

            nr_bios++;
            for(j=0; j<c_bio->nr_bvecs; j++)
            {
                c_bvec_t *c_bvec = &c_bio->c_bvecs[j];
                int locking = ((c_bvec->state & C_BVEC_BTREE_GOT_NODE) &&
                              !(c_bvec->state & C_BVEC_BTREE_LOCKED_NODE)) ||
                              ((c_bvec->state & C_BVEC_DATA_C2B_GOT) &&
                              !(c_bvec->state & C_BVEC_DATA_C2B_LOCKED));
                int print = (states_printed & c_bvec->state) != c_bvec->state;

                /* Save that we've already printed this particular state */
                states_printed |= c_bvec->state;

                if(!something_printed)
                {
                    castle_printk(LOG_DEBUG, "Found an outstanding Castle BIOs\n");
                    something_printed = 1;
                }

                /* Print info about first 10 stuck BIO + all in locking state */
                if(print || locking)
                    castle_printk(LOG_DEBUG, " c_bio->id=%d, c_bvecs[%d], "
                           "(k,v)=(%p, 0x%x), "
                           "btree_depth=%d, "
                           "state=0x%lx\n",
                        c_bio->id, j,
                        c_bvec->key, c_bvec->version,
                        c_bvec->btree_depth,
                        c_bvec->state);
                /* For locking BIOs print what lock are they blocked on. */
                if(locking)
                {
                    c2_block_t *c2b = c_bvec->locking;

                    castle_printk(LOG_DEBUG, "Blocked on locking c2b for "cep_fmt_str_nl,
                        cep2str(c2b->cep));
                    if(c2b->file != NULL)
                        castle_printk(LOG_DEBUG, "c2b last write locked from: %s:%d\n",
                                c2b->file, c2b->line);
                    else
                        castle_printk(LOG_DEBUG, "has never been write locked before?\n");
                }
            }
        }
        spin_unlock_irqrestore(&bio_list_spinlock, flags);
        if(something_printed)
        {
            castle_printk(LOG_DEBUG, "...\nTotal number of stuck bios=%d\n\n", nr_bios);
            sleep_time += 1;
        }
        castle_cache_stats_print(something_printed);

        set_task_state(current, TASK_INTERRUPTIBLE);
        schedule_timeout(sleep_time * HZ);
        castle_cache_debug();
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
        castle_free(watched_data);
    }
}

int castle_debug_init(void)
{
    int i;

    debug_thread = kthread_run(castle_debug_run, NULL, "castle-debug");
    if(!debug_thread)
        return -ENOMEM;

    /* Try to allocate buffers for watched pages */
    watched_data = castle_zalloc(sizeof(struct page*) * nr_watches);
    if(!watched_data) goto alloc_failed;
    for(i=0; i<nr_watches; i++)
    {
        watched_data[i] = alloc_page(GFP_KERNEL);
        if(!watched_data[i]) goto alloc_failed;
        castle_debug_buffer_init(watched_data[i]);
    }
    return 0;

alloc_failed:
    castle_printk(LOG_INIT, "Failed to allocate buffers for debug watches.\n");
    castle_debug_watches_free();

    return -ENOMEM;
}

void castle_debug_fini(void)
{
    kthread_stop(debug_thread);
    castle_debug_watches_print();
    castle_debug_watches_free();
    castle_debug_malloc_fini();
}
