#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/sched.h>

#include "castle_public.h"
#include "castle.h"
#include "castle_events.h"
#include "castle_utils.h"
#include "castle_debug.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)          ((void)0)
#else
#define debug(_f, _a...)        (castle_printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
/* rhel backported these, will not work on vanilla 2.6.18. */
#define add_uevent_var(_env, _fmt, _a...) add_uevent_var_env(_env, _fmt, ##_a)
#else
#define add_uevent_var(_env, _fmt, _a...) add_uevent_var(_env, _fmt, ##_a)
#endif

void castle_uevent4(uint16_t cmd, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4)
{
    int err = 0;
    struct kobj_uevent_env *env;

    env = castle_zalloc(sizeof(struct kobj_uevent_env), GFP_NOIO);
    if(!env)
    {
        castle_printk("No memory\n");
        return;
    }
    err = add_uevent_var(env, "NOTIFY=%s",  "false");
    if (err) debug("Error adding event var NOTIFY err=%d\n", err);
    
    err = add_uevent_var(env, "CMD=%d",  cmd);
    if (err) debug("Error adding event var CMD err=%d\n", err);
    
    err = add_uevent_var(env, "ARG1=0x%llx", arg1);
    if (err) debug("Error adding event var ARG1 err=%d\n", err);
        
    err = add_uevent_var(env, "ARG2=0x%llx", arg2);
    if (err) debug("Error adding event var ARG2 err=%d\n", err);
    
    err = add_uevent_var(env, "ARG3=0x%llx", arg3);
    if (err) debug("Error adding event var ARG3 err=%d\n", err);
    
    err = add_uevent_var(env, "ARG4=0x%llx", arg4);    
    if (err) debug("Error adding event var ARG4 err=%d\n", err);
    
    debug("Sending the event. CMD=%d ARG1=0x%Lx ARG2=0x%Lx ARG3=0x%Lx ARG4=0x%Lx\n", cmd, arg1, arg2, arg3, arg4);
    
    err = kobject_uevent_env(&castle.kobj, KOBJ_CHANGE, env->envp);
    if (err) debug("Error sending event err=%d\n", err);
    
    castle_free(env);
}

void castle_uevent3(uint16_t cmd, uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
    castle_uevent4(cmd, arg1, arg2, arg3, 0);
}

void castle_uevent2(uint16_t cmd, uint64_t arg1, uint64_t arg2)
{
    castle_uevent4(cmd, arg1, arg2, 0, 0);
}

void castle_uevent1(uint16_t cmd, uint64_t arg1)
{
    castle_uevent4(cmd, arg1, 0, 0, 0);
}
