#include <linux/module.h>
#include <linux/fs.h>
#include <linux/genhd.h>
#include <linux/miscdevice.h>
#include <linux/skbuff.h>
#include <asm/uaccess.h>

#include "castle_public.h"
#include "castle.h"
#include "castle_cache.h"
#include "castle_btree.h"
#include "castle_versions.h"
#include "castle_transfer.h"
#include "castle_events.h"
#include "castle_rxrpc.h"

static DECLARE_MUTEX(castle_control_lock);

static void castle_control_claim(uint32_t dev, int *ret, slave_uuid_t *id)
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

static void castle_control_release(slave_uuid_t id, int *ret)
{
    printk("==> Release NOT IMPLEMENTED YET, slave UUID=%d\n", id);
    *ret = -ENOSYS;
}

static void castle_control_attach(snap_id_t snap, int *ret, uint32_t *dev)
{
    version_t version = (version_t)snap;
    struct castle_device *cd;
  
    *dev = 0;
    cd = castle_device_init(version);
    if(!cd)
    {
        *ret = -EINVAL; 
        return;
    }
    *dev = new_encode_dev(MKDEV(cd->gd->major, cd->gd->first_minor));
    *ret = 0;
}

static void castle_control_detach(uint32_t dev, int *ret)
{
    dev_t dev_id = new_decode_dev(dev);
    struct castle_device *cd = castle_device_find(dev_id);

    if(cd) castle_device_free(cd);
    *ret = (cd ? 0 : -ENODEV);
}

static void castle_control_create(uint64_t size, int *ret, snap_id_t *id)
{
    version_t version;

    if(size == 0)
    {
        printk("When creating a volume size must be g.t. 0!\n");
        *id  = -1;
        *ret = -EINVAL;
        return;
    }

    version = castle_version_new(0, /* clone */ 
                                 0, /* root version */
                                 size);
    if(VERSION_INVAL(version))
    {
        *id  = -1;
        *ret = -EINVAL;
    } 
    else
    {
        *id  = version;
        *ret = 0;
    }
}

static void castle_control_clone(snap_id_t snap, int *ret, snap_id_t *clone)
{
    version_t version = (version_t)snap;

    if(version == 0)
    {
        printk("Do not clone version 0. Create a new volume.\n");
        *clone = 0;
        *ret   = -EINVAL;
        return;
    }
    
    /* Try to create a new version in the version tree */
    version = castle_version_new(0,       /* clone */ 
                                 version, 
                                 0);      /* size: take parent's */
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

static void castle_control_snapshot(uint32_t dev, int *ret, snap_id_t *snap_id)
{
    dev_t devid = new_decode_dev(dev);
    struct castle_device *cd = castle_device_find(devid);
    version_t version, old_version;

    if(!cd)
    {   
        *snap_id = -1;
        *ret     = -ENOENT;
        return;
    }
    down_write(&cd->lock);
    old_version  = cd->version;
    version = castle_version_new(1,            /* snapshot */
                                 cd->version,
                                 0);           /* take size from the parent */ 
    if(VERSION_INVAL(version))
    {
        *snap_id = -1;
        *ret     = -EINVAL;
    }
    else
    {
        /* Attach the new version */
        castle_version_snap_get(version, NULL, NULL, NULL);
        /* Change the version associated with the device */
        cd->version    = version;
        /* Release the old version */
        castle_version_snap_put(old_version);
        *snap_id = version;
        *ret     = 0;
    }
    up_write(&cd->lock);
    
    castle_events_device_snapshot(version, cd->gd->major, cd->gd->first_minor);
}
 
static void castle_control_fs_init(int *ret)
{
    *ret = castle_fs_init();
}

static void castle_control_region_create(slave_uuid_t slave,
                                         snap_id_t    snapshot,
                                         uint32_t     start,
                                         uint32_t     length,
                                         int         *ret,
                                         region_id_t *id)
{
    struct castle_region *region;

    if(!(region = castle_region_create(slave, snapshot, start, length)))
        goto err_out;

    *id  = region->id;
    *ret = 0;
    
    return;
        
err_out:
    *id  = (uint32_t)-1;
    *ret = -EINVAL;
}

static void castle_control_region_destroy(region_id_t id, int *ret)
{
    struct castle_region *region;
    
    if(!(region = castle_region_find(id)))
    {
        *ret = -EINVAL;
    }
    else
    { 
        *ret = castle_region_destroy(region);
    }
}

static void castle_control_transfer_create(snap_id_t      snapshot,
                                           uint32_t       direction,
                                           int           *ret,
                                           transfer_id_t *id)
{
    struct castle_transfer *transfer;

    if(!(transfer = castle_transfer_create(snapshot, direction, ret)))
        goto err_out;

    /* Return value should have been correctly set by _create() */
    BUG_ON(*ret != 0);
    *id = transfer->id;

    return;

err_out:
    BUG_ON(*ret == 0);
    *id = (uint32_t)-1;
}

static void castle_control_transfer_destroy(transfer_id_t id, int *ret)
{
    struct castle_transfer *transfer;
    
    if(!(transfer = castle_transfer_find(id)))
    {
        *ret = -EINVAL;
    }
    else
    {
        castle_transfer_destroy(transfer);
        *ret = 0;
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
            castle_control_claim( ioctl.claim.dev,
                                 &ioctl.claim.ret,
                                 &ioctl.claim.id);
            break;
        case CASTLE_CTRL_CMD_RELEASE:
            castle_control_release( ioctl.release.id,
                                   &ioctl.release.ret);
            break;
        case CASTLE_CTRL_CMD_ATTACH:
            castle_control_attach( ioctl.attach.snap,
                                  &ioctl.attach.ret,
                                  &ioctl.attach.dev);
            break;
        case CASTLE_CTRL_CMD_DETACH:
            castle_control_detach( ioctl.detach.dev,
                                  &ioctl.detach.ret);
            break;
        case CASTLE_CTRL_CMD_CREATE:
            castle_control_create( ioctl.create.size,
                                  &ioctl.create.ret,
                                  &ioctl.create.id);
            break;
        case CASTLE_CTRL_CMD_CLONE:
            castle_control_clone( ioctl.clone.snap,
                                 &ioctl.clone.ret,
                                 &ioctl.clone.clone);
            break;
        case CASTLE_CTRL_CMD_SNAPSHOT:
            castle_control_snapshot( ioctl.snapshot.dev,
                                    &ioctl.snapshot.ret,
                                    &ioctl.snapshot.snap_id);
            break;
        case CASTLE_CTRL_CMD_INIT:
            castle_control_fs_init(&ioctl.init.ret);
            break;
        case CASTLE_CTRL_CMD_REGION_CREATE:
            castle_control_region_create( ioctl.region_create.slave,
                                          ioctl.region_create.snapshot,
                                          ioctl.region_create.start,
                                          ioctl.region_create.length,
                                         &ioctl.region_create.ret,
                                         &ioctl.region_create.id);
            break;        
        case CASTLE_CTRL_CMD_REGION_DESTROY:
            castle_control_region_destroy( ioctl.region_destroy.id,
                                          &ioctl.region_destroy.ret);
            break;
        case CASTLE_CTRL_CMD_TRANSFER_CREATE:
            castle_control_transfer_create( ioctl.transfer_create.snapshot,
                                            ioctl.transfer_create.direction,
                                           &ioctl.transfer_create.ret,
                                           &ioctl.transfer_create.id);
            break;
        case CASTLE_CTRL_CMD_TRANSFER_DESTROY:
            castle_control_transfer_destroy( ioctl.transfer_destroy.id,
                                            &ioctl.transfer_destroy.ret);
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

int castle_ctrl_packet_process(struct sk_buff *skb, void *reply, int *len_p)
{
    uint32_t *reply32 = reply; /* For now, all reply values are 32 bit wide */
    uint32_t ctrl_op;
    int len, i;

    printk("Ctrl, skb->len=%d.\n", skb->len);
    if(skb->len < 4)
        return -EBADMSG;

    ctrl_op = SKB_L_GET(skb);
    printk("Ctrl op: %d\n", ctrl_op);
    switch(ctrl_op)
    {
        case CASTLE_CTRL_REQ_CLAIM:
            if(skb->len != 4) return -EBADMSG;
            castle_control_claim( SKB_L_GET(skb), 
                                 &reply32[0], 
                                 &reply32[1]);
            len = 8;
            break;
        case CASTLE_CTRL_REQ_RELEASE:
            if(skb->len != 4) return -EBADMSG;
            castle_control_release( SKB_L_GET(skb), 
                                   &reply32[0]);
            len = 4;
            break;
        case CASTLE_CTRL_REQ_ATTACH:
            if(skb->len != 4) return -EBADMSG;
            castle_control_attach( SKB_L_GET(skb), 
                                  &reply32[0], 
                                  &reply32[1]);
            len = 8;
            break;
        case CASTLE_CTRL_REQ_DETACH:
            if(skb->len != 4) return -EBADMSG;
            castle_control_detach( SKB_L_GET(skb), 
                                  &reply32[0]);
            len = 4;
            break;
        case CASTLE_CTRL_REQ_CREATE:
            if(skb->len != 8) return -EBADMSG;
            castle_control_create( SKB_LL_GET(skb), 
                                  &reply32[0], 
                                  &reply32[1]);
            len = 8;
            break;
        case CASTLE_CTRL_REQ_CLONE:
            if(skb->len != 4) return -EBADMSG;
            castle_control_clone( SKB_L_GET(skb), 
                                 &reply32[0], 
                                 &reply32[1]);
            len = 8;
            break;
        case CASTLE_CTRL_REQ_SNAPSHOT:
            if(skb->len != 4) return -EBADMSG;
            castle_control_snapshot( SKB_L_GET(skb), 
                                    &reply32[0], 
                                    &reply32[1]);
            len = 8;
            break;
        case CASTLE_CTRL_REQ_INIT:
            if(skb->len != 0) return -EBADMSG;
            castle_control_fs_init(&reply32[0]);
            len = 4;
            break;
        case CASTLE_CTRL_REQ_REGION_CREATE:
            if(skb->len != 16) return -EBADMSG;
            castle_control_region_create(SKB_L_GET(skb),
                                         SKB_L_GET(skb),  
                                         SKB_L_GET(skb),
                                         SKB_L_GET(skb),
                                         &reply32[0],
                                         &reply32[1]);
            len = 8;
            break;
        case CASTLE_CTRL_REQ_REGION_DESTROY:
            if(skb->len != 4) return -EBADMSG;
            castle_control_region_destroy( SKB_L_GET(skb), 
                                          &reply32[0]);
            len = 4;
            break;
        case CASTLE_CTRL_REQ_TRANSFER_CREATE:
            if(skb->len != 8) return -EBADMSG;
            castle_control_transfer_create(SKB_L_GET(skb),
                                           SKB_L_GET(skb),
                                           &reply32[0],
                                           &reply32[1]);
            len = 8;
            break;
        case CASTLE_CTRL_REQ_TRANSFER_DESTROY:
            if(skb->len != 4) return -EBADMSG;
            castle_control_transfer_destroy(SKB_L_GET(skb),
                                            &reply32[0]);
            len = 4;
            break;
        case CASTLE_CTRL_REQ_COLLECTION_ATTACH:
            if(skb->len < 8) return -EBADMSG;
            return -ENOTSUPP;
            break;
        case CASTLE_CTRL_REQ_COLLECTION_DETACH:
            if(skb->len != 4) return -EBADMSG;
            return -ENOTSUPP;
            break;
        case CASTLE_CTRL_REQ_COLLECTION_SNAPSHOT:
            if(skb->len != 4) return -EBADMSG;
            return -ENOTSUPP;
            break;
    }

    /* Convert to network byte order */
    for(i=0; i<(len/4); i++)
        reply32[i] = htonl(reply32[i]);
    *len_p = len;
    printk("Reply length=%d\n", len);

    return 0;
}



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
