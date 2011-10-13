#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <asm/signal.h>

#include "castle_public.h"
#include "castle_defines.h"
#include "castle.h"
#include "castle_events.h"


enum {
    CTRL_PROG_NOT_PRESENT,      /**< Ctrl prog not registered.               */
    CTRL_PROG_PRESENT,          /**< Ctrl prog registered, and heartbeating. */
    CTRL_PROG_SHUTDOWN,         /**< Ctrl prog may exist, but the shutdown
                                     is imminent, no need to start a new
                                     nugget.                                 */
    CTRL_PROG_INVAL
};

static unsigned long castle_ctrl_prog_timeouts[CTRL_PROG_INVAL]
                        = {[CTRL_PROG_NOT_PRESENT] =  10 * HZ,
                           [CTRL_PROG_PRESENT]     =   3 * HZ,
                           [CTRL_PROG_SHUTDOWN]    = 120 * HZ };

static struct timer_list castle_ctrl_prog_heartbeat_timer;
static int               castle_ctrl_prog_state             = CTRL_PROG_NOT_PRESENT;
static pid_t             castle_ctrl_prog_pid;
static long              castle_ctrl_prog_last_jiffies      = 0;


static void castle_ctrl_prog_touch(void)
{
    castle_ctrl_prog_last_jiffies = jiffies;
}

static int castle_ctrl_prog_timed_out(void)
{
    return (castle_ctrl_prog_last_jiffies +
            castle_ctrl_prog_timeouts[castle_ctrl_prog_state] < jiffies);
}


int castle_ctrl_prog_ioctl(cctrl_ioctl_t *ioctl)
{
    switch(ioctl->cmd)
    {
        case CASTLE_CTRL_PROG_REGISTER:
            printk("Registering, from pid=%d\n", current->pid);
            if(castle_ctrl_prog_state != CTRL_PROG_NOT_PRESENT)
            {
                ioctl->ctrl_prog_register.ret = -EEXIST;
                break;
            }
            castle_ctrl_prog_pid = current->pid;
            castle_ctrl_prog_state = CTRL_PROG_PRESENT;
            castle_ctrl_prog_touch();

            ioctl->ctrl_prog_register.ret = 0;
            break;

        case CASTLE_CTRL_PROG_DEREGISTER:
            printk("Deregistering, from pid=%d\n", current->pid);
            if(ioctl->ctrl_prog_deregister.shutdown)
            {
                if(castle_ctrl_prog_state == CTRL_PROG_PRESENT)
                {
                    struct task_struct *p;

                    ioctl->ctrl_prog_deregister.pid = castle_ctrl_prog_pid;
                    read_lock(&tasklist_lock);
                    p = find_task_by_pid(castle_ctrl_prog_pid);
                    if(p)
                        send_sig(SIGKILL, p, 1);
                    read_unlock(&tasklist_lock);
                    castle_ctrl_prog_pid = 0;
                    castle_ctrl_prog_state = CTRL_PROG_SHUTDOWN;
                }
                else
                {
                    ioctl->ctrl_prog_deregister.pid = 0;
                    castle_ctrl_prog_pid = 0;
                    castle_ctrl_prog_state = CTRL_PROG_NOT_PRESENT;
                }
            }
            ioctl->ctrl_prog_deregister.ret = 0;
            break;

        case CASTLE_CTRL_PROG_HEARTBEAT:
            printk("Heartbeat, from pid=%d\n", current->pid);
            if(castle_ctrl_prog_state != CTRL_PROG_PRESENT)
            {
                ioctl->ctrl_prog_register.ret = -EEXIST;
                break;
            }
            if(current->pid != castle_ctrl_prog_pid)
            {
                ioctl->ctrl_prog_register.ret = -ECHILD;
                break;
            }
            castle_ctrl_prog_touch();

            ioctl->ctrl_prog_heartbeat.ret = 0;
            break;

        default:
            return 0;
    }

    return 1;
}

static void castle_ctrl_prog_work_do(void *unused)
{
    switch(castle_ctrl_prog_state)
    {
        case CTRL_PROG_NOT_PRESENT:
            printk("Startup ctrl prog.\n");
            castle_ctrl_prog_touch();
            castle_uevent1(CASTLE_CTRL_PROG_REGISTER, 0);
            break;
        case CTRL_PROG_PRESENT:
            printk("No heartbeat from ctrl prog.\n");
            castle_ctrl_prog_state = CTRL_PROG_NOT_PRESENT;
            break;
        case CTRL_PROG_SHUTDOWN:
            printk("Expected shutdown didn't happen.\n");
            castle_ctrl_prog_state = CTRL_PROG_NOT_PRESENT;
            break;
    }
}

static DECLARE_WORK(castle_ctrl_prog_work, castle_ctrl_prog_work_do, 0);

static void castle_ctrl_prog_timer(unsigned long unused)
{
    printk("Heartbeat timer.\n");
    if(castle_ctrl_prog_timed_out())
        schedule_work(&castle_ctrl_prog_work);
    mod_timer(&castle_ctrl_prog_heartbeat_timer, jiffies + HZ);
}

int castle_ctrl_prog_init(void)
{
    setup_timer(&castle_ctrl_prog_heartbeat_timer, castle_ctrl_prog_timer, 0);
    mod_timer(&castle_ctrl_prog_heartbeat_timer, jiffies + HZ);

    return 0;
}

void castle_ctrl_prog_fini(void)
{
    del_timer_sync(&castle_ctrl_prog_heartbeat_timer);
}
