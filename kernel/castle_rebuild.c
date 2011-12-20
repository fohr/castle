#include "castle.h"
#include "castle_utils.h"
#include "castle_debug.h"
#include "castle_extent.h"
#include "castle_cache.h"
#include "castle_rebuild.h"
#include <linux/kthread.h>
#include <linux/bio.h>

#ifdef DEBUG
#define debug(_f, _a...)        (castle_printk(LOG_DEBUG, _f, ##_a))
#else
#define debug(_f, ...)          ((void)0)
#endif

/* The elements of the resubmit list */
struct resubmit_c2b {
    struct list_head    list;
    c2_block_t          *c2b;
    int                 rw;
};

static struct list_head resubmit_list;

DEFINE_SPINLOCK         (resubmit_list_lock);

wait_queue_head_t       resubmit_wq;

/**
 * Add a c2b to the resubmit list.
 *
 * @param rw    Read or write the block
 * @param c2b   Block to resubmit
 */
void castle_resubmit_c2b(int rw, c2_block_t * c2b)
{
    struct resubmit_c2b *rc2b;
    unsigned long flags;

    rc2b = castle_alloc_atomic(sizeof(struct resubmit_c2b));
    BUG_ON(!rc2b);

    spin_lock_irqsave(&resubmit_list_lock, flags);
    rc2b->c2b = c2b;
    rc2b->rw = rw;
    list_add_tail(&rc2b->list, &resubmit_list);
    spin_unlock_irqrestore(&resubmit_list_lock, flags);
    wake_up(&resubmit_wq);
}

struct task_struct   *resubmit_thread;

/**
 * Check if there are blocks on the resubmit list.
 *
 * @return      True if there are blocks on the resubmit list
 */
static int c2bs_to_resubmit(void)
{
    int ret;

    BUG_ON(in_irq());
    spin_lock_irq(&resubmit_list_lock);
    ret = (!list_empty(&resubmit_list));
    spin_unlock_irq(&resubmit_list_lock);
    return ret;
}

/**
 * Main block resubmit kthread loop. Walks resubmit list and resubmits blocks.
 *
 * @return      True when kthread has been stopped successfully.
 */
static int castle_resubmit_run(void *unused)
{
    debug("Starting resubmit thread ...\n");
    do {
        struct resubmit_c2b *rc2b;
        c2_block_t          *c2b;

        wait_event_interruptible(resubmit_wq, c2bs_to_resubmit() || kthread_should_stop());

        spin_lock_irq(&resubmit_list_lock);
        if (kthread_should_stop())
        {
            BUG_ON(!list_empty(&resubmit_list));
            spin_unlock_irq(&resubmit_list_lock);
            return EXIT_SUCCESS;
        }
        while (!list_empty(&resubmit_list))
        {
            rc2b = list_first_entry(&resubmit_list, struct resubmit_c2b, list);
            list_del(&rc2b->list);
            spin_unlock_irq(&resubmit_list_lock);
            c2b = rc2b->c2b;
            /*
             * It is possible that I/O has been submitted for the chunk mapping for this
             * c2b. If that I/O is bound for a now dead slave then that I/O will be
             * resubmitted. However, it may be inserted after this c2b in the resubmit list
             * in which case we could deadlock. To avoid this, we'll check that the c2b
             * is up to date in the cache, and submit our own I/O for the chunk mapping
             * if it is not.
             */
            BUG_ON(atomic_read(&c2b->remaining));
            debug("Resubmitting c2b %p\n", rc2b->c2b);
            BUG_ON(submit_c2b(rc2b->rw, rc2b->c2b));
            castle_free(rc2b);
            spin_lock_irq(&resubmit_list_lock);
        }
        spin_unlock_irq(&resubmit_list_lock);

    } while (1);

    return EXIT_SUCCESS;
}

/**
 * Start resubmit kthread.
 *
 * @return      True if kthread has been started successfully.
 */
int castle_resubmit_init(void)
{
    init_waitqueue_head(&resubmit_wq);
    /* Initialise the resubmit list. */
    INIT_LIST_HEAD(&resubmit_list);

    resubmit_thread = kthread_run(castle_resubmit_run, NULL, "castle-resubmit");
    if(!resubmit_thread)
        return -ENOMEM;

    return EXIT_SUCCESS;
}

/**
 * Stop resubmit kthread.
 *
 */
void castle_resubmit_fini(void)
{
    kthread_stop(resubmit_thread);
}
