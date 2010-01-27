#include <linux/module.h>
#include <linux/fs.h>
#include <linux/genhd.h>
#include <linux/miscdevice.h>
#include <asm/uaccess.h>

#include "castle_public.h"
#include "castle.h"
#include "castle_btree.h"

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
    struct castle_vtree_leaf_slot *version;
  
    printk("Asked to attach version: %llx\n", ioctl->snap); 
    ioctl->dev = 0;
    // TODO all version numbers should be uint32_t (snap_id_t -> uint32_t)
    version = castle_version_find(castle_vtree_root, (uint32_t)ioctl->snap);
    if(!version)
    {
        ioctl->ret = -EINVAL;
        return;
    }
    dev = castle_device_init(version);
    if(!dev)
    {
        ioctl->ret = -ENOMEM; 
        return;
    }
    ioctl->dev = new_encode_dev(MKDEV(dev->gd->major, dev->gd->first_minor));
    ioctl->ret = 0;
}

static void castle_control_detach(cctrl_cmd_detach_t *ioctl)
{
    printk("==> Detach NOT IMPLEMENTED YET\n");
    ioctl->ret = -ENOSYS;
}

static void castle_control_create(cctrl_cmd_create_t *ioctl)
{
    printk("==> Create NOT IMPLEMENTED YET\n");
    ioctl->id = -1;
    ioctl->ret = -ENOSYS;
}

static void castle_control_clone(cctrl_cmd_clone_t *ioctl)
{
    printk("==> Clone NOT IMPLEMENTED YET\n");
    ioctl->clone = 0;
    ioctl->ret = -ENOSYS;
}

static void castle_control_snapshot(cctrl_cmd_snapshot_t *ioctl)
{
    printk("==> Snapshot NOT IMPLEMENTED YET\n");
    ioctl->snap_id = 0;
    ioctl->ret = -ENOSYS;
}
 
static void castle_control_fs_init(cctrl_cmd_init_t *ioctl)
{
    ioctl->ret = castle_fs_init();
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

    printk("Got IOCTL command %d.\n", ioctl.cmd);
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

        default:
            return -EINVAL;
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
