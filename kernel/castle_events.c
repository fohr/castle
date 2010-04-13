#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/sched.h>
#include <asm/semaphore.h>

#include "castle_public.h"
#include "castle.h"
#include "castle_events.h"

void castle_uevent4(uint16_t cmd, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4)
{
    struct kobj_uevent_env *env;

    env = kzalloc(sizeof(struct kobj_uevent_env), GFP_NOIO);
    if(!env)
    {
        printk("No memory\n");
        return;
    }
    add_uevent_var(env, "NOTIFY=%s",  "false");
    add_uevent_var(env, "CMD=%d",  cmd);
    add_uevent_var(env, "ARG1=0x%llx", arg1);
    add_uevent_var(env, "ARG2=0x%llx", arg2);
    add_uevent_var(env, "ARG3=0x%llx", arg3);
    add_uevent_var(env, "ARG4=0x%llx", arg4);    
    printk("Sending the event. CMD=%d ARG1=0x%Lx ARG2=0x%Lx ARG3=0x%Lx ARG4=0x%Lx\n", cmd, arg1, arg2, arg3, arg4);
    kobject_uevent_env(&castle.kobj, KOBJ_CHANGE, env->envp);
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
