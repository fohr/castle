#include <linux/module.h>
#include <linux/bio.h>
#include <linux/kobject.h>
#include <linux/device-mapper.h>
#include <linux/miscdevice.h>
#include <linux/blkdev.h>
#include <asm/semaphore.h>

#include "castle_public.h"
#include "castle.h"
#include "castle_sysfs.h"

struct castle         castle;
struct castle_volumes castle_volumes;
struct castle_disks   castle_disks;

/* HACK! */
DECLARE_MUTEX(in_ioctl);
static cctrl_ioctl_t ioctl_ret;
int ret_ready = 0;


static int castle_claim(uint32_t new_dev, struct castle_disk *cd)
{
    dev_t dev;
    struct block_device *bdev;
    int err;
    char b[BDEVNAME_SIZE];

    dev = new_decode_dev(new_dev);
    bdev = open_by_devnum(dev, FMODE_READ|FMODE_WRITE);
    if (IS_ERR(bdev)) {
        printk("Could not open %s.\n", __bdevname(dev, b));
        return PTR_ERR(bdev);
    }
    err = bd_claim(bdev, &castle);
    if (err) {
        printk("Could not bd_claim %s.\n", bdevname(bdev, b));
        blkdev_put(bdev);
        return err;
    }
    cd->bdev = bdev;
    return 0;
}

static void castle_release(struct castle_disk *cd)
{
    bd_release(cd->bdev);
    blkdev_put(cd->bdev);
}


static void castle_uevent(uint16_t cmd, uint64_t main_arg)
{
    struct kobj_uevent_env *env;

    env = kzalloc(sizeof(struct kobj_uevent_env), GFP_NOIO);
    if(!env)
    {
        printk("No memory\n");
        return;
    }
    add_uevent_var(env, "CMD=%d",  cmd);
    add_uevent_var(env, "ARG=0x%llx", main_arg);
    printk("Sending the event.\n");
    kobject_uevent_env(&castle.kobj, KOBJ_CHANGE, env->envp);
}


static int castle_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
    int i, ma, mi, ret;
    struct castle_disk *cd;

    cd = kzalloc(sizeof(struct castle_disk), GFP_KERNEL);
    if(!cd)
    {
        printk("Could not alloc castle_disk.\n");
        return -ENOMEM;
    }
    
    printk("Castle DM ctr\n");
    for(i=0; i<argc; i++)
        printk("argv[%d]=%s\n", i, argv[i]);
    ma=simple_strtol(argv[0], NULL, 10);
    mi=simple_strtol(argv[1], NULL, 10);
    
    ret = castle_claim(new_encode_dev(MKDEV(ma,mi)), cd); 
    if(ret)
    {
        printk("Could not claim (%d,%d)\n", ma, mi);
        return ret;
    }
    cd->ma = ma;
    cd->mi = mi;
    ti->private = cd;
    return 0;
}

static void castle_dtr(struct dm_target *ti)
{
    struct castle_disk *cd = (struct castle_disk *)ti->private;

    printk("Castle DM dtr\n");
    castle_release(cd);
    kfree(cd);
}

static int castle_map(struct dm_target *ti, struct bio *bio,
                      union map_info *map_context)
{
    struct castle_disk *cd = (struct castle_disk *)ti->private;

    printk("Castle DM map forwarded to: (%d, %d)\n", cd->ma, cd->mi);
    bio->bi_bdev = cd->bdev;
	generic_make_request(bio);

    return 0;
}

static int castle_ioctl(struct dm_target *ti,
                        struct inode *inode,
                        struct file *flip,
                        unsigned int cmd,
                        unsigned long arg)
{
    printk("Castle DM ioctl, cmd=%d, arg=0x%lx\n", cmd, arg);
    return 0;
}

static struct target_type castle_target = {
    .name    = "castle",
    .version = {1, 0, 0},
    .module  = THIS_MODULE,
    .ctr     = castle_ctr,
    .dtr     = castle_dtr,
    .map     = castle_map,
    .ioctl   = castle_ioctl,
};

static int castle_control_ioctl(struct inode *inode, struct file *filp,
                                unsigned int cmd, unsigned long arg)
{
    void __user *udata = (void __user *) arg;
    cctrl_ioctl_t ioctl;
    uint64_t main_arg;

    int ret_ioctl = 0;

    if(cmd != CASTLE_CTRL_IOCTL)
    {
        printk("Unknown IOCTL: %d\n", cmd);
        return -EINVAL;
    }

    if (copy_from_user(&ioctl, udata, sizeof(cctrl_ioctl_t)))
        return -EFAULT;

    printk("Got IOCTL command %d.\n", ioctl.cmd);
    switch(ioctl.cmd)
    {
        case CASTLE_CTRL_CMD_CLAIM:
            main_arg = ioctl.claim.dev;
            //castle_claim(ioctl.claim.dev);
            break;
        case CASTLE_CTRL_CMD_RELEASE:
            main_arg = ioctl.release.dev;
            break;
        case CASTLE_CTRL_CMD_ATTACH:
            main_arg = ioctl.attach.snap;
            break;
        case CASTLE_CTRL_CMD_DETACH:
            main_arg = ioctl.detach.dev;
            break;
        case CASTLE_CTRL_CMD_CREATE:
            main_arg = ioctl.create.size;
            break;
        case CASTLE_CTRL_CMD_CLONE:
            main_arg = ioctl.clone.snap;
            break;
        case CASTLE_CTRL_CMD_SNAPSHOT:
            main_arg = ioctl.snapshot.dev;
            break;
        case CASTLE_CTRL_CMD_INIT:
            main_arg = -1; 
            break;

        case CASTLE_CTRL_CMD_RET:
            ret_ioctl = 1;
            break;
        default:
            return -EINVAL;
    }

    /* Only allow one ioctl at the time. */
    if(!ret_ioctl)
    {
        down(&in_ioctl);
        ret_ready = 0;
        /* Signal to userspace */
        castle_uevent(ioctl.cmd, main_arg);
        while(!ret_ready) msleep(1);
        /* We've got the response */
        printk("Got response, ret val=%lld.\n", ioctl_ret.ret.ret_val);
        switch(ioctl.cmd)
        {
            case CASTLE_CTRL_CMD_CLAIM:
                ioctl.claim.ret = (int)ioctl_ret.ret.ret_val;
                break;
            case CASTLE_CTRL_CMD_RELEASE:
                ioctl.release.ret = (int)ioctl_ret.ret.ret_val;
                break;
            case CASTLE_CTRL_CMD_ATTACH:
                ioctl.attach.dev = (uint32_t)ioctl_ret.ret.ret_val;
                /* Attach always succeeds at the moment ... */
                ioctl.attach.ret = 0;
                break;
            case CASTLE_CTRL_CMD_DETACH:
                ioctl.detach.ret = (int)ioctl_ret.ret.ret_val;
                break;
            case CASTLE_CTRL_CMD_CREATE:
                ioctl.create.id = (snap_id_t)ioctl_ret.ret.ret_val;
                break;
            case CASTLE_CTRL_CMD_CLONE:
                ioctl.clone.clone = (snap_id_t)ioctl_ret.ret.ret_val;
                break;
            case CASTLE_CTRL_CMD_SNAPSHOT:
                ioctl.snapshot.snap_id = (snap_id_t)ioctl_ret.ret.ret_val;
                break;
            case CASTLE_CTRL_CMD_INIT:
                ioctl.init.ret = (int)ioctl_ret.ret.ret_val;
                break;
            default:
                BUG();
        }
        up(&in_ioctl);
    } else
    {
        memcpy(&ioctl_ret, &ioctl, sizeof(cctrl_ioctl_t));
        ret_ready = 1;
    }

    /* Copy the results back */
    if(copy_to_user(udata, &ioctl, sizeof(cctrl_ioctl_t)))
        return -EFAULT;

    return 0;
}

static struct file_operations castle_control_fops = {
    .owner   = THIS_MODULE,
    .ioctl   = castle_control_ioctl,
};


static struct miscdevice castle_control = {
    .minor   = MISC_DYNAMIC_MINOR,
    .name    = "castle-control",
    .fops    = &castle_control_fops,
};

static int __init castle_init(void)
{
    int ret;

    printk("Castle init\n");

    ret = castle_kobjs_init();
    if(ret < 0)
    {
        printk("Could not register kobj\n");
        return ret;
    }

    ret = dm_register_target(&castle_target);
    if(ret < 0)
    {
        printk("Castle DM target registration failed\n");
        return ret;
    }

    ret = misc_register(&castle_control);
    if (ret)
    {
        printk("Castle control node could not be register.\n");
        return ret;
    }

    return 0;
}

static void __exit castle_exit(void)
{
    printk("Castle exit\n");
    if(dm_unregister_target(&castle_target) < 0)
        printk("Could not unregister castle DM target.\n");

    if (misc_deregister(&castle_control) < 0)
        printk("Could not unregister castle control node.\n");

    castle_kobjs_exit();
}

module_init(castle_init);
module_exit(castle_exit);

MODULE_LICENSE("GPL");
