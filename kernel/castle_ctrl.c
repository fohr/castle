#include <linux/module.h>
#include <linux/fs.h>
#include <linux/genhd.h>
#include <linux/miscdevice.h>
#include <asm/uaccess.h>

#include "castle_public.h"
#include "castle.h"
#include "castle_cache.h"
#include "castle_btree.h"
#include "castle_versions.h"
#include "castle_transfer.h"

static DECLARE_MUTEX(castle_control_lock);

static void castle_control_claim(cctrl_cmd_claim_t *ioctl)
{
    struct castle_slave *cs;

    if((cs = castle_claim(ioctl->dev)))
    {
        ioctl->id  = cs->id;
        ioctl->ret = 0;
    }
    else
    {
        ioctl->id  = (uint32_t)-1;
        ioctl->ret = -EINVAL;
    }
}

static void castle_control_release(cctrl_cmd_release_t *ioctl)
{
    printk("==> Release NOT IMPLEMENTED YET\n");
    ioctl->ret = -ENOSYS;
}

static void castle_control_attach(cctrl_cmd_attach_t *ioctl)
{
    struct castle_device* dev;
    // TODO all version numbers should be uint32_t/version_t (snap_id_t -> uint32_t)
    version_t version = (version_t)ioctl->snap;
  
    ioctl->dev = 0;
    dev = castle_device_init(version);
    if(!dev)
    {
        ioctl->ret = -EINVAL; 
        return;
    }
    ioctl->dev = new_encode_dev(MKDEV(dev->gd->major, dev->gd->first_minor));
    ioctl->ret = 0;
}

static void castle_control_detach(cctrl_cmd_detach_t *ioctl)
{
    dev_t dev = new_decode_dev(ioctl->dev);
    struct castle_device *cd = castle_device_find(dev);

    if(cd) castle_device_free(cd);
    ioctl->ret = (cd ? 0 : -ENODEV);
}

static void castle_control_create(cctrl_cmd_create_t *ioctl)
{
    version_t version;

    version = castle_version_new(0, /* clone */ 
                                 0, /* root version */
                                 ioctl->size);
    if(VERSION_INVAL(version))
    {
        ioctl->id  = -1;
        ioctl->ret = -EINVAL;
    } else
    {
        ioctl->id  = version;
        ioctl->ret = 0;
    }
}

static void castle_control_clone(cctrl_cmd_clone_t *ioctl)
{
    version_t version = ioctl->snap;

    if(version == 0)
    {
        printk("Do not clone version 0. Create a new volume.\n");
        ioctl->clone = 0;
        ioctl->ret   = -EINVAL;
        return;
    }
    
    /* Try to create a new version in the version tree */
    version = castle_version_new(0,       /* clone */ 
                                 version, 
                                 0);      /* size: take parent's */
    if(VERSION_INVAL(version))
    {
        ioctl->clone = 0;
        ioctl->ret = -EINVAL;
    } else
    {
        ioctl->clone = version;
        ioctl->ret = 0;
    }
}

static void castle_control_snapshot(cctrl_cmd_snapshot_t *ioctl)
{
    dev_t dev = new_decode_dev(ioctl->dev);
    struct castle_device *cd = castle_device_find(dev);
    version_t version, old_version;

    if(!cd)
    {   
        ioctl->snap_id = -1;
        ioctl->ret     = -ENOENT;
        return;
    }
    down_write(&cd->lock);
    old_version  = cd->version;
    version = castle_version_new(1,            /* snapshot */
                                 cd->version,
                                 0);           /* take size from the parent */ 
    if(VERSION_INVAL(version))
    {
        ioctl->snap_id = -1;
        ioctl->ret     = -EINVAL;
    }
    else
    {
        /* Attach the new version */
        castle_version_snap_get(version, NULL, NULL, NULL);
        /* Change the version associated with the device */
        cd->version    = version;
        /* Release the old version */
        castle_version_snap_put(old_version);
        ioctl->snap_id = version;
        ioctl->ret     = 0;
    }
    up_write(&cd->lock);
}
 
static void castle_control_fs_init(cctrl_cmd_init_t *ioctl)
{
    ioctl->ret = castle_fs_init();
}

static void castle_control_region_create(cctrl_cmd_region_create_t *ioctl)
{
    struct castle_region *region;

    if(!(region = castle_region_create(ioctl->slave, ioctl->snapshot, ioctl->start, ioctl->length)))
        goto err_out;

    ioctl->id  = region->id;
    ioctl->ret = 0;
    
    return;
        
err_out:
    ioctl->id  = (uint32_t)-1;
    ioctl->ret = -EINVAL;
}

static void castle_control_region_destroy(cctrl_cmd_region_destroy_t *ioctl)
{
    struct castle_region *region;
    
    if(!(region = castle_region_find(ioctl->id)))
    {
        ioctl->ret = -EINVAL;
    }
    else
    {
        castle_region_destroy(region);
        ioctl->ret = 0;
    }
}

static void castle_control_transfer_create(cctrl_cmd_transfer_create_t *ioctl)
{
    struct castle_transfer *transfer;

    if(!(transfer = castle_transfer_create(ioctl->snapshot, ioctl->direction)))
        goto err_out;

    ioctl->id  = transfer->id;
    ioctl->ret = 0;

    return;

err_out:
    ioctl->id  = (uint32_t)-1;
    ioctl->ret = -EINVAL;
}

static void castle_control_transfer_destroy(cctrl_cmd_transfer_destroy_t *ioctl)
{
    struct castle_transfer *transfer;
    
    if(!(transfer = castle_transfer_find(ioctl->id)))
    {
        ioctl->ret = -EINVAL;
    }
    else
    {
        castle_transfer_destroy(transfer);
        ioctl->ret = 0;
    }
}

int castle_control_ioctl(struct inode *inode, struct file *filp,
                         unsigned int cmd, unsigned long arg)
{
    void __user *udata = (void __user *) arg;
    cctrl_ioctl_t ioctl;

    if(cmd != CASTLE_CTRL_IOCTL)
    {
        printk("Unknown IOCTL: %d\n", cmd);
        return -EINVAL;
    }

    if (copy_from_user(&ioctl, udata, sizeof(cctrl_ioctl_t)))
        return -EFAULT;

    down(&castle_control_lock);
    //printk("Got IOCTL command %d.\n", ioctl.cmd);
    switch(ioctl.cmd)
    {
        case CASTLE_CTRL_CMD_CLAIM:
            castle_control_claim(&ioctl.claim);
            break;
        case CASTLE_CTRL_CMD_RELEASE:
            castle_control_release(&ioctl.release);
            break;
        case CASTLE_CTRL_CMD_ATTACH:
            castle_control_attach(&ioctl.attach);
            break;
        case CASTLE_CTRL_CMD_DETACH:
            castle_control_detach(&ioctl.detach);
            break;
        case CASTLE_CTRL_CMD_CREATE:
            castle_control_create(&ioctl.create);
            break;
        case CASTLE_CTRL_CMD_CLONE:
            castle_control_clone(&ioctl.clone);
            break;
        case CASTLE_CTRL_CMD_SNAPSHOT:
            castle_control_snapshot(&ioctl.snapshot);
            break;
        case CASTLE_CTRL_CMD_INIT:
            castle_control_fs_init(&ioctl.init);
            break;
        case CASTLE_CTRL_CMD_REGION_CREATE:
            castle_control_region_create(&ioctl.region_create);
            break;        
        case CASTLE_CTRL_CMD_REGION_DESTROY:
            castle_control_region_destroy(&ioctl.region_destroy);
            break;
        case CASTLE_CTRL_CMD_TRANSFER_CREATE:
            castle_control_transfer_create(&ioctl.transfer_create);
            break;
        case CASTLE_CTRL_CMD_TRANSFER_DESTROY:
            castle_control_transfer_destroy(&ioctl.transfer_destroy);
            break;
        default:
            up(&castle_control_lock);
            return -EINVAL;
    }
    up(&castle_control_lock);

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
    .name    = "castle-fs-control",
    .fops    = &castle_control_fops,
};

int castle_control_init(void)
{
    int ret;
    
    if((ret = misc_register(&castle_control)))
        printk("Castle control device could not be registered (%d).", ret);

    return ret;
}

void castle_control_fini(void)
{
    int ret;

    if((ret = misc_deregister(&castle_control))) 
        printk("Could not unregister castle control node (%d).\n", ret);
}
