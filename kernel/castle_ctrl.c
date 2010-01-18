#include <linux/module.h>
#include <linux/fs.h>
#include <linux/genhd.h>
#include <asm/uaccess.h>

#include "castle_public.h"
#include "castle.h"

int castle_control_ioctl(struct inode *inode, struct file *filp,
                         unsigned int cmd, unsigned long arg)
{
    void __user *udata = (void __user *) arg;
    cctrl_ioctl_t ioctl;
    uint64_t main_arg;
    uint64_t ret1, ret2, ret3;

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

        default:
            return -EINVAL;
    }

    switch(ioctl.cmd)
    {
        case CASTLE_CTRL_CMD_CLAIM:
        {
            struct castle_slave *slave;

            slave = castle_claim(ioctl.claim.dev);
            //slave->uuid = (uint32_t)ioctl_ret.ret.ret_val;
            //ioctl.claim.ret = (ioctl_ret.ret.ret_val != 0 ? 0 : -EINVAL);
            //ioctl.claim.id = (uint32_t)ioctl_ret.ret.ret_val;
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
            //ioctl.release.ret = (int)ioctl_ret.ret.ret_val;
            ret1 = ioctl.release.ret;
            ret2 = id;
            break;
        }
        case CASTLE_CTRL_CMD_ATTACH:
        {
            struct castle_device *cdev;
            dev_t userspace_dev;

            userspace_dev = 0;
            //userspace_dev = (uint32_t)ioctl_ret.ret.ret_val;
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
            //ioctl.detach.ret = (int)ioctl_ret.ret.ret_val;
            ret1 = ioctl.detach.ret;
            ret2 = ioctl.detach.dev;
            break;
        case CASTLE_CTRL_CMD_CREATE:
            //ioctl.create.ret = (ioctl_ret.ret.ret_val != 0 ? 0 : -EINVAL); 
            //ioctl.create.id  = (snap_id_t)ioctl_ret.ret.ret_val;
            ret1 = ioctl.create.ret;
            ret2 = ioctl.create.id;
            break;
        case CASTLE_CTRL_CMD_CLONE:
            //ioctl.clone.ret   = (ioctl_ret.ret.ret_val != 0 ? 0 : -EINVAL);
            //ioctl.clone.clone = (snap_id_t)ioctl_ret.ret.ret_val;
            ret1 = ioctl.clone.ret;
            ret2 = ioctl.clone.clone;
            break;
        case CASTLE_CTRL_CMD_SNAPSHOT:
            //ioctl.snapshot.ret     = (ioctl_ret.ret.ret_val != 0 ? 0 : -EINVAL);
            //ioctl.snapshot.snap_id = (snap_id_t)ioctl_ret.ret.ret_val;
            ret1 = ioctl.snapshot.ret;
            ret2 = ioctl.snapshot.snap_id;
            ret3 = ioctl.snapshot.dev;
            break;
        case CASTLE_CTRL_CMD_INIT:
            //ioctl.init.ret = (int)ioctl_ret.ret.ret_val;
            ret1 = ioctl.init.ret;
            break;
        default:
            BUG();
    }
out:
    /* Copy the results back */
    if(copy_to_user(udata, &ioctl, sizeof(cctrl_ioctl_t)))
        return -EFAULT;

    return 0;
}


