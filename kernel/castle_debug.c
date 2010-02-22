#include <linux/module.h>
#include <linux/kthread.h>

#include "castle.h"
#include "castle_debug.h"

static spinlock_t           bio_list_spinlock = SPIN_LOCK_UNLOCKED;
static int                  bio_id = 0;
static            LIST_HEAD(bio_list);
static struct task_struct  *debug_thread;


void castle_debug_bvec_update(c_bvec_t *c_bvec, unsigned long state_flag)
{
    c_bvec->state |= state_flag;
}

void castle_debug_bvec_btree_walk(c_bvec_t *c_bvec)
{
    c_bvec->btree_depth++;
    c_bvec->state &= (~C_BVEC_BTREE_MASK);
}

void castle_debug_bio_add(c_bio_t *c_bio)
{
    unsigned long flags;

    c_bio->nr_bvecs = atomic_read(&c_bio->remaining);
    spin_lock_irqsave(&bio_list_spinlock, flags);
    c_bio->id = bio_id++;
    list_add(&c_bio->list, &bio_list);
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

void castle_debug_init(void)
{
    debug_thread = kthread_run(castle_debug_run, NULL, "castle-debug");
}

void castle_debug_fini(void)
{
    kthread_stop(debug_thread); 
}
