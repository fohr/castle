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
struct castle_slaves  castle_slaves;
struct castle_devices castle_devices;

/* HACK! */
DECLARE_MUTEX(in_ioctl);
static cctrl_ioctl_t ioctl_ret;
int ret_ready = 0;


static struct castle_slave* castle_claim(uint32_t new_dev)
{
    dev_t dev;
    struct block_device *bdev;
    int err;
    char b[BDEVNAME_SIZE];
    struct castle_slave *cs;
    static int slave_id = 0;

    cs = kmalloc(sizeof(struct castle_slave), GFP_KERNEL); 
    if(!cs)
        return NULL;
    cs->id = slave_id++;

    dev = new_decode_dev(new_dev);
    bdev = open_by_devnum(dev, FMODE_READ|FMODE_WRITE);
    if (IS_ERR(bdev)) {
        printk("Could not open %s.\n", __bdevname(dev, b));
        goto err_out;
    }
    err = bd_claim(bdev, &castle);
    if (err) {
        printk("Could not bd_claim %s.\n", bdevname(bdev, b));
        blkdev_put(bdev);
        goto err_out;
    }
    cs->bdev = bdev;
    list_add(&cs->list, &castle_slaves.slaves);
    castle_sysfs_slave_add(cs);

    return cs;
err_out:
    kfree(cs);
    return NULL;    
}

static struct castle_slave* castle_slave_find_by_id(uint32_t id)
{
    struct list_head *lh;
    struct castle_slave *slave;

    list_for_each(lh, &castle_slaves.slaves)
    {
        slave = list_entry(lh, struct castle_slave, list);
        if(slave->id == id)
            return slave;
    }

    return NULL;
}

static void castle_release(struct castle_slave *cs)
{
    printk("Releasing slave %x.\n", 
            MKDEV(cs->bdev->bd_disk->major, 
                  cs->bdev->bd_disk->first_minor));
    castle_sysfs_slave_del(cs);
    bd_release(cs->bdev);
    blkdev_put(cs->bdev);
    list_del(&cs->list);
    kfree(cs);
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
    add_uevent_var(env, "NOTIFY=%s",  "false");
    add_uevent_var(env, "CMD=%d",  cmd);
    add_uevent_var(env, "ARG=0x%llx", main_arg);
    printk("Sending the event.\n");
    kobject_uevent_env(&castle.kobj, KOBJ_CHANGE, env->envp);
}

static void castle_notify(uint16_t cmd, 
                          uint64_t arg1, 
                          uint64_t arg2,
                          uint64_t arg3)
{
    struct kobj_uevent_env *env;

    env = kzalloc(sizeof(struct kobj_uevent_env), GFP_NOIO);
    if(!env)
    {
        printk("No memory\n");
        return;
    }
    add_uevent_var(env, "NOTIFY=%s",  "true");
    add_uevent_var(env, "CMD=%d",  cmd);
    add_uevent_var(env, "ARG1=0x%llx", arg1);
    add_uevent_var(env, "ARG2=0x%llx", arg2);
    add_uevent_var(env, "ARG3=0x%llx", arg3);
    printk("Sending the event.\n");
    kobject_uevent_env(&castle.kobj, KOBJ_CHANGE, env->envp);
}

static int castle_open(struct inode *inode, struct file *filp)
{
	struct castle_device *dev = inode->i_bdev->bd_disk->private_data;

	filp->private_data = dev;
	spin_lock(&dev->lock);
	if (! dev->users) 
		check_disk_change(inode->i_bdev);
	dev->users++;
	spin_unlock(&dev->lock);
	return 0;
}

static int castle_close(struct inode *inode, struct file *filp)
{
	struct castle_device *dev = inode->i_bdev->bd_disk->private_data;

	spin_lock(&dev->lock);
	dev->users--;
	spin_unlock(&dev->lock);

	return 0;
}

static struct block_device_operations castle_bd_ops = {
	.owner           = THIS_MODULE,
	.open 	         = castle_open,
	.release 	     = castle_close,
	.media_changed   = NULL,
	.revalidate_disk = NULL,
};

static struct block_device* castle_basedisk_claim(dev_t base_dev)
{
    struct block_device *bdev;
    int err;
    char b[BDEVNAME_SIZE];

    bdev = open_by_devnum(base_dev, FMODE_READ|FMODE_WRITE);
    if (IS_ERR(bdev)) {
        printk("Could not open %s.\n", __bdevname(base_dev, b));
        return NULL;
    }
    err = bd_claim(bdev, &castle);
    if (err) {
        printk("Could not bd_claim %s.\n", bdevname(bdev, b));
        blkdev_put(bdev);
        return NULL;
    }

    return bdev;
}

static int castle_device_make_request(struct request_queue *rq, struct bio *bio)
{ 
    struct castle_device *dev = rq->queuedata;

    bio->bi_bdev = dev->bdev;
	generic_make_request(bio);
    return 0;
}

static struct castle_device* castle_dev_mirror(dev_t base_dev)
{
    struct castle_device *dev;
    struct request_queue *rq;
    struct gendisk *gd;
    static int minor = 0;

    struct block_device *bdev;

    dev = kmalloc(sizeof(struct castle_device), GFP_KERNEL); 
    if(!dev)
        goto error_out;
    dev->bdev = castle_basedisk_claim(base_dev);
    if(!dev->bdev)
        goto error_out;
	spin_lock_init(&dev->lock);
        
    gd = alloc_disk(1);
    if(!gd)
        goto error_out;

    sprintf(gd->disk_name, "castle%d", minor);
    gd->major        = castle_devices.major;
    gd->first_minor  = minor++;
	gd->fops         = &castle_bd_ops;
    gd->private_data = dev;

	rq = blk_alloc_queue(GFP_KERNEL);
    if (!rq)
        goto error_out;
	blk_queue_make_request(rq, castle_device_make_request);
	rq->queuedata    = dev;
    gd->queue        = rq;


    list_add(&dev->list, &castle_devices.devices);
    dev->gd = gd;
    set_capacity(gd, get_capacity(dev->bdev->bd_disk));
    add_disk(gd);

    bdev = bdget(MKDEV(gd->major, gd->first_minor));

    return dev;

error_out:
    printk("Failed to mirror device.\n");
    return NULL;    
}

static int castle_devices_init(void)
{
    int major;

    memset(&castle_devices, 0, sizeof(struct castle_devices));
    INIT_LIST_HEAD(&castle_devices.devices);
    /* Dynamically allocate a major for this device */
    major = register_blkdev(0, "castle");
    if (major < 0) 
    {
        printk("Couldn't register castle device\n");
        return -ENOMEM;
    }

    castle_devices.major = major;
    printk("blktap device major %d\n", major);

    return 0;
}

static int castle_slaves_init(void)
{
    memset(&castle_slaves, 0, sizeof(struct castle_slaves));
    INIT_LIST_HEAD(&castle_slaves.slaves);

    return 0;
}

static void castle_device_free(struct castle_device *cd)
{
    bd_release(cd->bdev);
    blkdev_put(cd->bdev);
    del_gendisk(cd->gd);
    put_disk(cd->gd);
    list_del(&cd->list);
    kfree(cd);
}

static void castle_devices_free(void)                                                                 
{                                                                                        
    struct list_head *lh, *th;
    struct castle_device *dev;

    list_for_each_safe(lh, th, &castle_devices.devices)
    {
        dev = list_entry(lh, struct castle_device, list); 
        castle_device_free(dev);
    }

    if (castle_devices.major)
        unregister_blkdev(castle_devices.major, "castle");
}

static void castle_slaves_free(void)                                                                 
{                                                                                        
    struct list_head *lh, *th;
    struct castle_slave *slave;

    list_for_each_safe(lh, th, &castle_slaves.slaves)
    {
        slave = list_entry(lh, struct castle_slave, list); 
        castle_release(slave);
    }
}
static int castle_control_ioctl(struct inode *inode, struct file *filp,
                                unsigned int cmd, unsigned long arg)
{
    void __user *udata = (void __user *) arg;
    cctrl_ioctl_t ioctl;
    uint64_t main_arg;
    uint64_t ret1, ret2, ret3;

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
            break;
        case CASTLE_CTRL_CMD_RELEASE:
        {
            struct castle_slave *slave =
                castle_slave_find_by_id(ioctl.release.id);
            BUG_ON(slave == NULL);
            main_arg = slave->uuid; 
            break;
        }
        case CASTLE_CTRL_CMD_ATTACH:
            main_arg = ioctl.attach.snap;
            break;
        case CASTLE_CTRL_CMD_DETACH:
        {
            struct list_head *lh, *ls;
            dev_t dev = new_decode_dev(ioctl.detach.dev);

            
            list_for_each_safe(lh, ls, &castle_devices.devices)
            {
                dev_t cd_dev;
                struct castle_device *cd;

                cd     = list_entry(lh, struct castle_device, list);
                cd_dev = MKDEV(cd->gd->major, cd->gd->first_minor);

                if(cd_dev == dev)
                {
                    dev = MKDEV(cd->bdev->bd_disk->major, 
                                cd->bdev->bd_disk->first_minor);
                    castle_device_free(cd);
                    goto cd_found;
                }
            }
            /* XXX: Could not find the device, fail for now */
            BUG();
cd_found:
            main_arg = new_encode_dev(dev);
            break;
        }
        case CASTLE_CTRL_CMD_CREATE:
            main_arg = ioctl.create.size;
            break;
        case CASTLE_CTRL_CMD_CLONE:
            main_arg = ioctl.clone.snap;
            break;
        case CASTLE_CTRL_CMD_SNAPSHOT:
        {
            dev_t idev = ioctl.snapshot.dev;
            struct block_device *bdev = 
                open_by_devnum(new_decode_dev(idev), FMODE_READ);
            struct castle_device *cdev;

            printk("==> Asked for snapshot on: %x\n", idev);
            if(!bdev)
            {
                printk("=====> Could not find dev: %x\n", idev);
                ioctl.snapshot.snap_id = 0;
                goto out;
            }
            // XXX should really check if bdev is _castle_ bdev, but 
            // this code is going to go away eventually anyway
            cdev = bdev->bd_disk->private_data;
            blkdev_put(bdev);
            main_arg = new_encode_dev(
                       MKDEV(cdev->bdev->bd_disk->major, 
                             cdev->bdev->bd_disk->first_minor));
            printk("==> Will snapshot: %llx\n", main_arg);
            break;
        }
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
        ret1 = ret2 = ret3 = 0;
        switch(ioctl.cmd)
        {
            case CASTLE_CTRL_CMD_CLAIM:
            {
                struct castle_slave *slave;

                slave = castle_claim(ioctl.claim.dev);
                slave->uuid = (uint32_t)ioctl_ret.ret.ret_val;
                ioctl.claim.ret = (ioctl_ret.ret.ret_val != 0 ? 0 : -EINVAL);
                ioctl.claim.id = (uint32_t)ioctl_ret.ret.ret_val;
                /* event: return_code, disk_id */
                ret1 = ioctl.claim.ret;
                ret2 = ioctl.claim.id;
                break;
            }
            case CASTLE_CTRL_CMD_RELEASE:
            {
                struct castle_slave *slave =
                    castle_slave_find_by_id(ioctl.release.id);
                uint32_t id;

                BUG_ON(slave == NULL);
                id = slave->id;
                castle_release(slave);
                ioctl.release.ret = (int)ioctl_ret.ret.ret_val;
                ret1 = ioctl.release.ret;
                ret2 = id;
                break;
            }
            case CASTLE_CTRL_CMD_ATTACH:
            {
                struct castle_device *cdev;
                dev_t userspace_dev;

                userspace_dev = (uint32_t)ioctl_ret.ret.ret_val;
                cdev = castle_dev_mirror(new_decode_dev(userspace_dev));
                if(cdev)
                {
                    ioctl.attach.ret = 0;
                    ioctl.attach.dev = new_encode_dev( 
                        MKDEV(cdev->gd->major, cdev->gd->first_minor));
                    printk("===> Attached to (%d,%d) instead.\n",
                            cdev->gd->major, cdev->gd->first_minor);
                    ret1 = 0;
                    ret2 = ioctl.attach.dev;
                    ret3 = ioctl.attach.snap;
                } else
                {
                    ioctl.attach.ret = -EINVAL;
                    ioctl.attach.dev = 0; 
                    ret1 = -1;
                    ret2 = ioctl.attach.dev;
                }
                break;
            }
            case CASTLE_CTRL_CMD_DETACH:
                ioctl.detach.ret = (int)ioctl_ret.ret.ret_val;
                ret1 = ioctl.detach.ret;
                ret2 = ioctl.detach.dev;
                break;
            case CASTLE_CTRL_CMD_CREATE:
                ioctl.create.ret = (ioctl_ret.ret.ret_val != 0 ? 0 : -EINVAL); 
                ioctl.create.id  = (snap_id_t)ioctl_ret.ret.ret_val;
                ret1 = ioctl.create.ret;
                ret2 = ioctl.create.id;
                break;
            case CASTLE_CTRL_CMD_CLONE:
                ioctl.clone.ret   = (ioctl_ret.ret.ret_val != 0 ? 0 : -EINVAL);
                ioctl.clone.clone = (snap_id_t)ioctl_ret.ret.ret_val;
                ret1 = ioctl.clone.ret;
                ret2 = ioctl.clone.clone;
                break;
            case CASTLE_CTRL_CMD_SNAPSHOT:
                ioctl.snapshot.ret     = (ioctl_ret.ret.ret_val != 0 ? 0 : -EINVAL);
                ioctl.snapshot.snap_id = (snap_id_t)ioctl_ret.ret.ret_val;
                ret1 = ioctl.snapshot.ret;
                ret2 = ioctl.snapshot.snap_id;
                ret3 = ioctl.snapshot.dev;
                break;
            case CASTLE_CTRL_CMD_INIT:
                ioctl.init.ret = (int)ioctl_ret.ret.ret_val;
                ret1 = ioctl.init.ret;
                break;
            default:
                BUG();
        }
        castle_notify(ioctl.cmd, ret1, ret2, ret3);
        up(&in_ioctl);
    } else
    {
        memcpy(&ioctl_ret, &ioctl, sizeof(cctrl_ioctl_t));
        ret_ready = 1;
    }
out:
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

    /* XXX: Handle failures properly! */
    printk("Castle init\n");

    ret = castle_devices_init();
    if(ret < 0)
    {
        printk("Could not initialise castle device\n");
        return ret;
    }

    ret = castle_slaves_init();
    if(ret < 0)
    {
        printk("Could not initialise castle slaves\n");
        return ret;
    }

    ret = misc_register(&castle_control);
    if (ret)
    {
        printk("Castle control node could not be register.\n");
        return ret;
    }

    ret = castle_sysfs_init();
    if(ret < 0)
    {
        printk("Could not register sysfs\n");
        return ret;
    }


    return 0;
}

static void __exit castle_exit(void)
{
    castle_sysfs_exit();
    castle_slaves_free();
    castle_devices_free();

    if (misc_deregister(&castle_control) < 0)
        printk("Could not unregister castle control node.\n");

}

module_init(castle_init);
module_exit(castle_exit);

MODULE_LICENSE("GPL");
