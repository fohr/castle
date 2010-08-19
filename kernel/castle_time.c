#include <linux/kthread.h>

#include "castle_public.h"
#include "castle.h"
#include "castle_time.h"

static       DEFINE_SPINLOCK(castle_timelines_list_lock);
static             LIST_HEAD(castle_timelines_list);
static             LIST_HEAD(castle_dead_timelines_list);
static int                   castle_checkpoint_collisions_print;
static uint32_t              castle_checkpoint_seq;
static struct task_struct   *time_thread;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
/* Copied from the kernel code, because not EXPORTed until ~2.6.24 */
/**
 * set_normalized_timespec - set timespec sec and nsec parts and normalize
 *
 * @ts:     pointer to timespec variable to be set
 * @sec:    seconds to set
 * @nsec:   nanoseconds to set
 *
 * Set seconds and nanoseconds field of a timespec variable and
 * normalize to the timespec storage format
 *
 * Note: The tv_nsec part is always in the range of
 *  0 <= tv_nsec < NSEC_PER_SEC
 * For negative values only the tv_sec field is negative !
 */
void set_normalized_timespec(struct timespec *ts, time_t sec, long nsec)
{
    while (nsec >= NSEC_PER_SEC) {
        nsec -= NSEC_PER_SEC;
        ++sec;
    }
    while (nsec < 0) {
        nsec += NSEC_PER_SEC;
        --sec;
    }
    ts->tv_sec = sec;
    ts->tv_nsec = nsec;
}

/**
 * ns_to_timespec - Convert nanoseconds to timespec
 * @nsec:       the nanoseconds value to be converted
 *
 * Returns the timespec representation of the nsec parameter.
 */
struct timespec ns_to_timespec(const s64 nsec)
{
    struct timespec ts;
                       
    if (!nsec)
        return (struct timespec) {0, 0};

    ts.tv_sec = div_long_long_rem_signed(nsec, NSEC_PER_SEC, &ts.tv_nsec);
    if (unlikely(nsec < 0))
        set_normalized_timespec(&ts, ts.tv_sec, ts.tv_nsec);

    return ts;
}
#endif

static void castle_request_timeline_add(c_req_time_t *timeline)
{
    spin_lock(&castle_timelines_list_lock);
    timeline->seq = castle_checkpoint_seq++;
    list_add(&timeline->list, &castle_timelines_list);
    spin_unlock(&castle_timelines_list_lock);
}

static void castle_request_timeline_del(c_req_time_t *timeline)
{
    spin_lock(&castle_timelines_list_lock);
    list_del(&timeline->list);
    spin_unlock(&castle_timelines_list_lock);
}

static int castle_request_chekpoint_get(c_req_time_t *timeline, char *file, int line)
{
    struct castle_checkpoint *checkpoint;
    int checkpoint_idx;

    /* This may be collision prone, fine for now */
    checkpoint_idx = line % MAX_CHECK_POINTS; 
    checkpoint = &timeline->checkpoints[checkpoint_idx]; 
    /* Check if that's a new checkpoint */
    if(checkpoint->file == NULL)
    {
        checkpoint->file = file;
        checkpoint->line = line;

        return checkpoint_idx;
    }
    /* Check if the checkpoints are the same */
    if((checkpoint->line == line) &&
       (strcmp(checkpoint->file, file) == 0))
    {
        return checkpoint_idx;
    }
    /* Collision! */
    if(castle_checkpoint_collisions_print)
        printk("Checkpoints collided: %s:%d & %s:%d\n", 
                checkpoint->file,
                checkpoint->line,
                file,
                line);
    return -1;
}

c_req_time_t* _castle_request_timeline_create(void)
{
    c_req_time_t* timeline;

    timeline = kmalloc(sizeof(c_req_time_t), GFP_KERNEL);
    if(!timeline)
        return NULL;
    timeline->active_checkpoint = -1;
    INIT_LIST_HEAD(&timeline->list);
    castle_request_timeline_add(timeline);
    getnstimeofday(&timeline->create_tm);

    return timeline;
}

/* Records the start of operation, called from file:line */
void _castle_request_timeline_checkpoint_start(c_req_time_t *timeline,
                                               char *file,
                                               int line)
{
    struct castle_checkpoint *checkpoint;
    int checkpoint_idx;
    
    /* Stop should have been called first */
    BUG_ON(timeline->active_checkpoint >= 0);

    checkpoint_idx = castle_request_chekpoint_get(timeline, file, line);
    if(checkpoint_idx < 0)
        return;
    checkpoint = &timeline->checkpoints[checkpoint_idx];    
    /* We checked that we are not in checkpoint ATM, so this should not be active */
    BUG_ON(checkpoint->active);
    checkpoint->active = 1;
    checkpoint->cnts++;
    getnstimeofday(&checkpoint->start_tm);
    timeline->active_checkpoint = checkpoint_idx;
}

/* Records the end of sleep called from a particular place */
void castle_request_timeline_checkpoint_stop(c_req_time_t *timeline)
{
    struct castle_checkpoint *checkpoint;
    struct timespec end_tm;
    s64 aggr;

    BUG_ON(timeline->active_checkpoint < 0); 
    checkpoint = &timeline->checkpoints[timeline->active_checkpoint];
    BUG_ON(!checkpoint->active);
    getnstimeofday(&end_tm);
    aggr = timespec_to_ns(&end_tm); 
    aggr += timespec_to_ns(&checkpoint->aggregate_tm);
    checkpoint->aggregate_tm = ns_to_timespec(aggr);
    checkpoint->active = 0;
    timeline->active_checkpoint = -1;
}

void castle_request_timeline_destroy(c_req_time_t *timeline)
{
    /* Record the time, and move to the dead list */
    getnstimeofday(&timeline->destroy_tm);
    castle_request_timeline_del(timeline);
    spin_lock(&castle_timelines_list_lock);
    list_add(&timeline->list, &castle_dead_timelines_list);
    spin_unlock(&castle_timelines_list_lock);
    wake_up_process(time_thread);    
}
        
static void castle_request_timeline_process(c_req_time_t *timeline)
{
    /* Empty for the time being */
}

static int castle_time_run(void *unused)
{
    c_req_time_t *timeline;

    while(1)
    {
        timeline = NULL;
        spin_lock(&castle_timelines_list_lock);
        if(!list_empty(&castle_dead_timelines_list))
        {
            timeline = list_entry(castle_dead_timelines_list.next, c_req_time_t, list);
            list_del(&timeline->list);
        }
        spin_unlock(&castle_timelines_list_lock);
        
        if(!timeline)
            goto no_timelines;

        /* Process the timeline */
        castle_request_timeline_process(timeline);
        kfree(timeline);

        /* Go to the next timeline */
        continue;

no_timelines:
        /* Go to sleep or exit the thread */
        if(!kthread_should_stop())
        {
            set_task_state(current, TASK_INTERRUPTIBLE);
            schedule();
        } else
            return 0;
    }
}

void castle_time_init(void)
{
    time_thread = kthread_run(castle_time_run, NULL, "castle-perf-debug");
    BUG_ON(!time_thread);
    castle_checkpoint_collisions_print = 1;
    castle_checkpoint_seq = 0;
}

void castle_time_fini(void)
{
    kthread_stop(time_thread);
    spin_lock(&castle_timelines_list_lock);
    if(!list_empty(&castle_timelines_list))
        printk("WARNING: Haven't destroyed all the timelines before exiting.\n");
    spin_unlock(&castle_timelines_list_lock);
}


