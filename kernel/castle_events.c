#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/sched.h>
#include <linux/netlink.h>
#include <net/genetlink.h>

#include "castle_public.h"
#include "castle.h"
#include "castle_events.h"
#include "castle_utils.h"
#include "castle_debug.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)          ((void)0)
#else
#define debug(_f, _a...)        (castle_printk(LOG_DEBUG, "%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
/* rhel backported these, will not work on vanilla 2.6.18. */
#define add_uevent_var(_env, _fmt, _a...) add_uevent_var_env(_env, _fmt, ##_a)
#else
#define add_uevent_var(_env, _fmt, _a...) add_uevent_var(_env, _fmt, ##_a)
#endif

extern atomic_t current_rebuild_seqno;

/**
 * Notifies the userspace about any disks which are being rebuilt at the moment.
 * If called multiple disks are being rebuilt, it may notify about the same disk multiple times
 * because no information about which notifications have already been sent out is stored.
 */
static void castle_events_slave_rebuild_handle(void *unused)
{
    struct castle_slave *cs;
    struct list_head *lh;
    int seqno;

    /* Read the sequence number before notification starts. */
    seqno = atomic_read(&current_rebuild_seqno);
    rcu_read_lock();
    list_for_each_rcu(lh, &castle_slaves.slaves)
    {
        cs = list_entry(lh, struct castle_slave, list);
        /* Notify about any slaves which have the EVACUATE or OOS bit set, but
           don't have the REMAPPED bit set yet. */
        if((test_bit(CASTLE_SLAVE_EVACUATE_BIT, &cs->flags) ||
            test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags)) &&
           (!test_bit(CASTLE_SLAVE_REMAPPED_BIT, &cs->flags)))
            castle_events_slave_rebuild(cs->uuid);
    }
    rcu_read_unlock();
    /* If the sequence number changed, re-notify. */
    if(seqno != atomic_read(&current_rebuild_seqno))
        castle_events_slave_rebuild_notify();
}

static DECLARE_WORK(castle_events_slave_rebuild_work, castle_events_slave_rebuild_handle, NULL);
/**
 * Schedules notifications about disks being rebuilt.
 * Safe to be called from atomic contexts.
 */
void castle_events_slave_rebuild_notify(void)
{
    schedule_work(&castle_events_slave_rebuild_work);
}

/* Attributes (data types) supported by castle uevent family */
enum {
    CASTLE_ATTR_UNSPEC,
    CASTLE_ATTR_UEVENT,
    __CASTLE_ATTR_MAX,
};
#define CASTLE_ATTR_MAX (__CASTLE_ATTR_MAX - 1)

/*
 * Attribute policy:
 * For each attribute defined above, map this to an attribute type (see net/netlink.h
 */
static struct nla_policy castle_uevent_genl_policy[CASTLE_ATTR_MAX + 1] = {
    [CASTLE_ATTR_UEVENT] = { .type = NLA_NUL_STRING }, /* A null-terminated string. */
};

/* commands supported by castle uevent family */
enum {
    CASTLE_CMD_UNSPEC,
    CASTLE_CMD_UEVENT_INIT, /* 1. Initialisation request from userland, and castle's ACK. */
    CASTLE_CMD_UEVENT_SEND, /* 2. Send a message to userland. */
    __CASTLE_CMD_MAX,
};
#define CASTLE_CMD_MAX (__CASTLE_CMD_MAX - 1)

/*
 * Definition of the castle uevent family of commands. */
static struct genl_family castle_uevent_family = {
    .id = GENL_ID_GENERATE,
    .name = "castle", /* This token is used by the userland process to find and connect to us. */
    .version = 1,
    .maxattr = CASTLE_CMD_MAX
};

/*
 * For unicast messages, the pid of the userland process defines the message target.
 */
static uint32_t castle_uevent_pid = 0;

int castle_uevent_netlink_up = 0;

/* (Asynchronously) receive and process a CASTLE_CMD_UEVENT_INIT cmd from userland. */
int castle_uevent_init(struct sk_buff *unused, struct genl_info *info)
{
    struct sk_buff  *skb;
    int             ret=0;
    void            *msg_head;

    if (info == NULL)
        goto errout;

    castle_uevent_pid = info->snd_pid;

    castle_printk(LOG_DEVEL, "Received castle uevent initialisation request (PID: %u)\n",
                  castle_uevent_pid);

    /*
     * 'ACK' the init message. If 'NAK' is also needed, will have to add an attribute
     * to send back the result.
     */

    /* allocate some memory, since the size is not yet known use NLMSG_GOODSIZE */
    skb = nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (skb == NULL)
        goto errout;

    /* create the message header */
    msg_head = genlmsg_put(skb, 0, 0,
                 castle_uevent_family.id, 0, 0,
                 CASTLE_CMD_UEVENT_INIT,
                 castle_uevent_family.version);
    if (msg_head == NULL)
    {
        ret = -ENOMEM;
        goto errout_dealloc;
    }

    /* finalise the message */
    genlmsg_end(skb, msg_head);

    /* Send the 'ACK' message back */
    ret = genlmsg_unicast(skb, castle_uevent_pid);
    if (ret != 0)
        goto errout_dealloc;

    castle_uevent_netlink_up = 1;

    return EXIT_SUCCESS;

errout_dealloc:
    nlmsg_free(skb);
errout:
    castle_printk(LOG_ERROR, "Failed to correctly initialise castle uevent netlink: %d\n", ret);
    return ret;
}

/* Map between the command and the function it will call */
struct genl_ops castle_uevent_gnl_ops_init =
{
    .cmd = CASTLE_CMD_UEVENT_INIT,  /* If we get a CASTLE_CMD_UEVENT_INIT ... */
    .flags = 0,
    .policy = castle_uevent_genl_policy,
    .doit = castle_uevent_init,     /* ... then call this function. */
    .dumpit = NULL,
};

/**
 * castle_netlink_init
 *      registers castle_uevent_family
 *      registers castle_uevent_init function
 *
 * @return  0 if the castle_uevent_family is successfully registered
 *          with netlink, error otherwise
 */
int castle_netlink_init(void)
{
    int result;

    result = genl_register_family(&castle_uevent_family);

    if (result)
        return result;

    result = genl_register_ops(&castle_uevent_family, &castle_uevent_gnl_ops_init);
    if (result != 0)
    {
        printk("register ops: %i\n",result);
        genl_unregister_family(&castle_uevent_family);
        return result;
    }

    castle_printk(LOG_USERINFO, "Castle fs has registered NETLINK GENERIC group: %d\n",
             castle_uevent_family.id);

    return result;
}

/*
 * castle_netlink_release - unregisters castle_uevent_family
 */
void castle_netlink_fini(void)
{
    genl_unregister_family(&castle_uevent_family);
}

/**
 * castle_uevent - sends event msg to user space application
 * @data: pointer to data to send
 * @size: size of data (in bytes) type
 *
 * Return value:
 *  0 if success, error value in case of any failure.
 */
int castle_uevent(struct kobj_uevent_env *env)
{
    struct sk_buff *skb;
    void *msg_header;
    int total_size;
    int result;

    if (castle_uevent_netlink_up == 0)
    {
        /* Userland is not ready to receive messages. */
        castle_printk(LOG_WARN, "Attempt to send netlink message denied.\n");
        return -EIO;
    }

    total_size = nla_total_size(env->buflen);
    skb = nlmsg_new(total_size, GFP_ATOMIC);

    if (!skb)
    {
        castle_printk(LOG_ERROR, "castle uevent failed to allocate data SKB of size: 0x%x\n",
                 total_size);
        return -ENOMEM;
    }

    /* Add the genetlink message header */
    msg_header = genlmsg_put(skb, 0, 0,
                 castle_uevent_family.id, 0, 0,
                 CASTLE_CMD_UEVENT_SEND,
                 castle_uevent_family.version);
    if (!msg_header)
    {
        castle_printk(LOG_ERROR, "castle uevent failed to copy command details\n");
        nlmsg_free(skb);
        return -ENOMEM;
    }
    result = nla_put(skb, CASTLE_ATTR_UEVENT, env->buflen, env->buf);

    if (result)
    {
        castle_printk(LOG_ERROR, "castle uevent failed to put data \n");
        nlmsg_free(skb);
        return -EINVAL;
    }

    /* Send genetlink multicast message to notify applications */
    result = genlmsg_end(skb, msg_header);

    if (result < 0)
    {
        castle_printk(LOG_ERROR, "castle uevent genlmsg_end failed\n");
        nlmsg_free(skb);
        return result;
    }

    result = genlmsg_unicast(skb, castle_uevent_pid);

    /*
     * If there are no listeners, genlmsg_multicast may return non-zero
     * value.
     */
    if (result)
        castle_printk(LOG_ERROR, "Castle netlink event failed: %d\n", result);

    return result;
}

void castle_uevent6(uint16_t cmd, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4,
                    uint64_t arg5, uint64_t arg6)
{
    int err = 0;
    struct kobj_uevent_env *env;

    env = castle_zalloc(sizeof(struct kobj_uevent_env));
    if(!env)
    {
        castle_printk(LOG_WARN, "No memory\n");
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

    err = add_uevent_var(env, "ARG5=0x%llx", arg5);
    if (err) debug("Error adding event var ARG5 err=%d\n", err);

    err = add_uevent_var(env, "ARG6=0x%llx", arg6);
    if (err) debug("Error adding event var ARG6 err=%d\n", err);

    debug("Sending the event. CMD=%d ARG1=0x%Lx ARG2=0x%Lx ARG3=0x%Lx ARG4=0x%Lx ARG5=0x%Lx ARG6=0x%Lx\n",
            cmd, arg1, arg2, arg3, arg4, arg5, arg6);

    if((cmd >= CASTLE_CTRL_PROG_EVENT_RANGE_START) &&
       (cmd <= CASTLE_CTRL_PROG_EVENT_RANGE_END))
        err = castle_uevent(env);
    else
        err = kobject_uevent_env(&castle.kobj, KOBJ_CHANGE, env->envp);

    if (err) debug("Error sending event err=%d\n", err);

    castle_free(env);
}

void castle_uevent5(uint16_t cmd, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4,
                    uint64_t arg5)
{
    castle_uevent6(cmd, arg1, arg2, arg3, arg4, arg5, 0);
}

void castle_uevent4(uint16_t cmd, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4)
{
    castle_uevent6(cmd, arg1, arg2, arg3, arg4, 0, 0);
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
