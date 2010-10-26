#define __OPTIMIZE__
#include <linux/genhd.h>
#include <linux/miscdevice.h>
#include <linux/skbuff.h>
#include <asm/uaccess.h>
#include <linux/hardirq.h>

#include "castle_public.h"
#include "castle_utils.h"
#include "castle.h"
#include "castle_da.h"
#include "castle_cache.h"
#include "castle_btree.h"
#include "castle_versions.h"
#include "castle_events.h"
#include "castle_rxrpc.h"
#include "castle_back.h"
#include "castle_ctrl.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)  ((void)0)
#else
#define debug(_f, _a...)  (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

static DECLARE_MUTEX(castle_control_lock);

void castle_control_lock_up()
{
    down(&castle_control_lock);
}

void castle_control_lock_down()
{
    up(&castle_control_lock);
}

void castle_control_claim(uint32_t dev, int *ret, slave_uuid_t *id)
{
    struct castle_slave *cs;

    if((cs = castle_claim(dev)))
    {
        *id  = cs->uuid;
        *ret = 0;
    }
    else
    {
        *id  = (uint32_t)-1;
        *ret = -EINVAL;
    }
}

void castle_control_release(slave_uuid_t id, int *ret)
{
    printk("==> Release NOT IMPLEMENTED YET, slave UUID=%d\n", id);
    *ret = -ENOSYS;
}

void castle_control_attach(version_t version, int *ret, uint32_t *dev)
{
    struct castle_attachment *cd;
  
    *dev = 0;
    cd = castle_device_init(version);
    if(!cd)
    {
        *ret = -EINVAL; 
        return;
    }
    *dev = new_encode_dev(MKDEV(cd->dev.gd->major, cd->dev.gd->first_minor));
    *ret = 0;
}

void castle_control_detach(uint32_t dev, int *ret)
{
    dev_t dev_id = new_decode_dev(dev);
    struct castle_attachment *cd = castle_device_find(dev_id);

    if(cd) castle_device_free(cd);
    *ret = (cd ? 0 : -ENODEV);
}

/* Size == 0 means that a collection tree is supposed to be created */ 
void castle_control_create(uint64_t size, int *ret, version_t *id)
{
    int collection_tree = (size == 0);
    da_id_t da_id = INVAL_DA; 
    version_t version;

    if(collection_tree)
    {
        printk("Creating a collection version tree.\n");
        da_id = castle_next_da_id++;
    }

    /* Create a new version which will act as the root for this version tree */
    version = castle_version_new(0, /* clone */ 
                                 0, /* root version */
                                 da_id,
                                 size);

    /* We use doubling arrays for collection trees */
    if(collection_tree &&
       castle_double_array_make(da_id, version))
    {
        printk("Failed creating doubling array for version: %d\n", version);
        version = INVAL_VERSION; 
    }

    if(VERSION_INVAL(version))
    {
        *id  = -1;
        *ret = -EINVAL;
    } else
    {
        *id  = version;
        *ret = 0;
    }
}

void castle_control_clone(version_t version, int *ret, version_t *clone)
{
    if(version == 0)
    {
        printk("Do not clone version 0. Create a new volume.\n");
        *clone = 0;
        *ret   = -EINVAL;
        return;
    }
    
    /* Try to create a new version in the version tree */
    version = castle_version_new(0,        /* clone */ 
                                 version,
                                 INVAL_DA, /* da_id: take parent's */
                                 0);       /* size:  take parent's */
    if(VERSION_INVAL(version))
    {
        *clone = 0;
        *ret = -EINVAL;
    } else
    {
        *clone = version;
        *ret = 0;
    }
}

void castle_control_snapshot(uint32_t dev, int *ret, version_t *version)
{
    dev_t devid = new_decode_dev(dev);
    struct castle_attachment *cd = castle_device_find(devid);
    version_t ver, old_version;

    if(!cd)
    {   
        *version = -1;
        *ret     = -ENOENT;
        return;
    }
    down_write(&cd->lock);
    old_version  = cd->version;
    ver = castle_version_new(1,            /* snapshot */
                             cd->version,
                             INVAL_DA,     /* take da_id from the parent */
                             0);           /* take size  from the parent */ 
    if(VERSION_INVAL(ver))
    {
        *version = -1;
        *ret     = -EINVAL;
    }
    else
    {
        /* Attach the new version */
        BUG_ON(castle_version_attach(ver));
        /* Change the version associated with the device */
        cd->version    = ver;
        /* Release the old version */
        castle_version_detach(old_version);
        *version = ver;
        *ret     = 0;
    }
    up_write(&cd->lock);
    
    castle_events_device_snapshot(ver, cd->dev.gd->major, cd->dev.gd->first_minor);
}
 
void castle_control_fs_init(int *ret)
{
    *ret = castle_fs_init();
}

void castle_control_collection_attach(version_t version,
                                             char *name,
                                             int *ret,
                                             collection_id_t *collection)
{
    struct castle_attachment *ca;

    ca = castle_collection_init(version, name);
    if(!ca)
    {
        *ret = -EINVAL;
        return;
    }
    *collection = ca->col.id; 
    *ret = 0;
}
            
void castle_control_collection_detach(collection_id_t collection,
                                             int *ret)
{
    struct castle_attachment *ca = castle_collection_find(collection);
    
    if(ca) castle_collection_free(ca);
    *ret = (ca ? 0 : -ENODEV);
}

void castle_control_collection_snapshot(collection_id_t collection,
                                               int *ret,
                                               version_t *version)
{
    struct castle_attachment *ca = castle_collection_find(collection);
    version_t ver, old_version;

    if(!ca)
    {   
        *version = -1;
        *ret     = -ENOENT;
        return;
    }
    down_write(&ca->lock);
    old_version  = ca->version;
    ver = castle_version_new(1,            /* snapshot */
                             ca->version,
                             INVAL_DA,     /* take da_id from the parent */
                             0);           /* take size  from the parent */ 
    if(VERSION_INVAL(ver))
    {
        *version = -1;
        *ret     = -EINVAL;
    }
    else
    {
        /* Attach the new version */
        BUG_ON(castle_version_attach(ver));
        /* Change the version associated with the device */
        ca->version    = ver;
        /* Release the old version */
        castle_version_detach(old_version);
        *version = ver;
        *ret     = 0;
    }
    up_write(&ca->lock);
    
    castle_events_collection_snapshot(ver, ca->col.id);
}
            
void castle_control_set_target(slave_uuid_t slave_uuid, int value, int *ret)
{
    struct castle_slave *slave = castle_slave_find_by_uuid(slave_uuid);
    struct castle_slave_superblock *sb;

    if (!slave)
    {
        *ret = -ENOENT;
        return;
    }
    
    sb = castle_slave_superblock_get(slave);
    
    if (value)
        sb->flags |= CASTLE_SLAVE_TARGET;
    else
        sb->flags &= ~CASTLE_SLAVE_TARGET;
    
    castle_slave_superblock_put(slave, 1);

    castle_events_slave_changed(slave->uuid);

    *ret = 0;
}

int castle_control_ioctl(struct file *filp,
                         unsigned int cmd, unsigned long arg)
{
    int err;
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
    debug("Lock taken: in_atomic=%d.\n", in_atomic());
    printk("Got IOCTL command %d.\n", ioctl.cmd);
    switch(ioctl.cmd)
    {
        case CASTLE_CTRL_REQ_CLAIM:
            castle_control_claim( ioctl.claim.dev,
                                 &ioctl.claim.ret,
                                 &ioctl.claim.id);
            break;
        case CASTLE_CTRL_REQ_RELEASE:
            castle_control_release( ioctl.release.id,
                                   &ioctl.release.ret);
            break;
        case CASTLE_CTRL_REQ_INIT:
            castle_control_fs_init(&ioctl.init.ret);
            break;            
        case CASTLE_CTRL_REQ_ATTACH:
            castle_control_attach( ioctl.attach.version,
                                  &ioctl.attach.ret,
                                  &ioctl.attach.dev);
            break;
        case CASTLE_CTRL_REQ_DETACH:
            castle_control_detach( ioctl.detach.dev,
                                  &ioctl.detach.ret);
            break;
        case CASTLE_CTRL_REQ_SNAPSHOT:
            castle_control_snapshot( ioctl.snapshot.dev,
                                    &ioctl.snapshot.ret,
                                    &ioctl.snapshot.version);
            break;

        case CASTLE_CTRL_REQ_COLLECTION_ATTACH:
        {
            char *collection_name = castle_malloc(ioctl.collection_attach.name_length, GFP_KERNEL);
            if (!collection_name)
            {
                err = -ENOMEM;
                goto err;
            }
            
            if (copy_from_user(collection_name, ioctl.collection_attach.name, 
                ioctl.collection_attach.name_length))
            {
                err = -EFAULT;
                goto err;
            }
            
            castle_control_collection_attach(ioctl.collection_attach.version,
                                            collection_name,
                                            &ioctl.collection_attach.ret,
                                            &ioctl.collection_attach.collection);
                                            
            
            break;
        }
        case CASTLE_CTRL_REQ_COLLECTION_DETACH:
            castle_control_collection_detach(ioctl.collection_detach.collection,
                                  &ioctl.collection_detach.ret);
            break;
        case CASTLE_CTRL_REQ_COLLECTION_SNAPSHOT:
            castle_control_collection_snapshot(ioctl.collection_snapshot.collection,
                                    &ioctl.collection_snapshot.ret,
                                    &ioctl.collection_snapshot.version);
            break;

        case CASTLE_CTRL_REQ_CREATE:
            castle_control_create( ioctl.create.size,
                                  &ioctl.create.ret,
                                  &ioctl.create.id);
            break;
        case CASTLE_CTRL_REQ_CLONE:
            castle_control_clone( ioctl.clone.version,
                                 &ioctl.clone.ret,
                                 &ioctl.clone.clone);
            break;

        case CASTLE_CTRL_REQ_TRANSFER_CREATE:
        case CASTLE_CTRL_REQ_TRANSFER_DESTROY:
            err = -ENOSYS;
            goto err;

        default:
            err = -EINVAL;
            goto err;
    }
    up(&castle_control_lock);

    /* Copy the results back */
    if(copy_to_user(udata, &ioctl, sizeof(cctrl_ioctl_t)))
        return -EFAULT;

    return 0;
    
err:
    up(&castle_control_lock);
    return err;
}

long castle_ctrl_unlocked_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    long ret = castle_back_unlocked_ioctl(file, cmd, arg);
    if (ret != -ENOIOCTLCMD)
        return ret;
        
    ret = castle_control_ioctl(file, cmd, arg);
    
    return ret;
}

static struct file_operations castle_control_fops = {
    .owner          = THIS_MODULE,
    .mmap           = castle_back_mmap,
    .unlocked_ioctl = castle_ctrl_unlocked_ioctl,
    .poll           = castle_back_poll,
    .open           = castle_back_open,
    .release        = castle_back_release,
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
    /* Sleep waiting for the last ctrl op to complete, if there is one */
    down(&castle_control_lock);
    up(&castle_control_lock);
}
