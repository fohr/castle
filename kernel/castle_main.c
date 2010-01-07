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
struct castle_devices castle_devices;

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

static struct castle_device* castle_dev_mirror(uint32_t base_dev)
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

static void castle_devices_free(void)                                                                 
{                                                                                        
    struct list_head *lh, *th;
    struct castle_device *dev;

    list_for_each_safe(lh, th, &castle_devices.devices)
    {
        dev = list_entry(lh, struct castle_device, list); 
        bd_release(dev->bdev);
        blkdev_put(dev->bdev);
        del_gendisk(dev->gd);
        put_disk(dev->gd);
        list_del(&dev->list);
        kfree(dev);
    }

    if (castle_devices.major)
        unregister_blkdev(castle_devices.major, "castle");
}

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
        {
            dev_t idev = ioctl.snapshot.dev;
            struct block_device *bdev = open_by_devnum(idev, FMODE_READ);
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
            main_arg = MKDEV(cdev->bdev->bd_disk->major, 
                             cdev->bdev->bd_disk->first_minor);
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
        switch(ioctl.cmd)
        {
            case CASTLE_CTRL_CMD_CLAIM:
                ioctl.claim.ret = (int)ioctl_ret.ret.ret_val;
                break;
            case CASTLE_CTRL_CMD_RELEASE:
                ioctl.release.ret = (int)ioctl_ret.ret.ret_val;
                break;
            case CASTLE_CTRL_CMD_ATTACH:
            {
                struct castle_device *cdev;
                dev_t userspace_dev;

                userspace_dev = (uint32_t)ioctl_ret.ret.ret_val;
                cdev = castle_dev_mirror(userspace_dev);
                if(cdev)
                {
                    ioctl.attach.dev = 
                        MKDEV(cdev->gd->major, cdev->gd->first_minor);
                    printk("===> Attached to (%d,%d) instead.\n",
                            cdev->gd->major, cdev->gd->first_minor);
                    ioctl.attach.ret = 0;
                } else
                {
                    ioctl.attach.dev = 0; 
                    ioctl.attach.ret = -EINVAL;
                }
                break;
            }
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

    ret = castle_kobjs_init();
    if(ret < 0)
    {
        printk("Could not register kobj\n");
        return ret;
    }

    ret = castle_devices_init();
    if(ret < 0)
    {
        printk("Could not initialise castle device\n");
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

    castle_devices_free();

    if (misc_deregister(&castle_control) < 0)
        printk("Could not unregister castle control node.\n");

    castle_kobjs_exit();
}

module_init(castle_init);
module_exit(castle_exit);

MODULE_LICENSE("GPL");
