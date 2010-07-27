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
#include "castle_transfer.h"
#include "castle_events.h"
#include "castle_rxrpc.h"
#include "castle_freespace.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)  ((void)0)
#else
#define debug(_f, _a...)  (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

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

static void castle_control_attach(version_t version, int *ret, uint32_t *dev)
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

static void castle_control_detach(uint32_t dev, int *ret)
{
    dev_t dev_id = new_decode_dev(dev);
    struct castle_attachment *cd = castle_device_find(dev_id);

    if(cd) castle_device_free(cd);
    *ret = (cd ? 0 : -ENODEV);
}

/* Size == 0 means that a collection tree is supposed to be created */ 
static void castle_control_create(uint64_t size, int *ret, version_t *id)
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

static void castle_control_clone(version_t version, int *ret, version_t *clone)
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

static void castle_control_snapshot(uint32_t dev, int *ret, version_t *version)
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
 
static void castle_control_fs_init(int *ret)
{
    *ret = castle_fs_init();
}

static void castle_control_transfer_create(version_t      version,
                                           uint32_t       direction,
                                           int           *ret,
                                           transfer_id_t *id)
{
    struct castle_transfer *transfer;

    if(!(transfer = castle_transfer_create(version, direction, ret)))
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

struct castle_attachment *global_attachment_hack = NULL;
static void castle_control_collection_attach(version_t version,
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
    global_attachment_hack = ca;
    *collection = ca->col.id; 
    *ret = 0;
}
            
static void castle_control_collection_detach(collection_id_t collection,
                                             int *ret)
{
    struct castle_attachment *ca = castle_collection_find(collection);
    
    if(ca) castle_collection_free(ca);
    *ret = (ca ? 0 : -ENODEV);
}

static void castle_control_collection_snapshot(collection_id_t collection,
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
    debug("Lock taken: in_atomic=%d.\n", in_atomic());
    //printk("Got IOCTL command %d.\n", ioctl.cmd);
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
        case CASTLE_CTRL_REQ_ATTACH:
            castle_control_attach( ioctl.attach.version,
                                  &ioctl.attach.ret,
                                  &ioctl.attach.dev);
            break;
        case CASTLE_CTRL_REQ_DETACH:
            castle_control_detach( ioctl.detach.dev,
                                  &ioctl.detach.ret);
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
        case CASTLE_CTRL_REQ_SNAPSHOT:
            castle_control_snapshot( ioctl.snapshot.dev,
                                    &ioctl.snapshot.ret,
                                    &ioctl.snapshot.version);
            break;
        case CASTLE_CTRL_REQ_INIT:
            castle_control_fs_init(&ioctl.init.ret);
            break;
        case CASTLE_CTRL_REQ_TRANSFER_CREATE:
            castle_control_transfer_create( ioctl.transfer_create.version,
                                            ioctl.transfer_create.direction,
                                           &ioctl.transfer_create.ret,
                                           &ioctl.transfer_create.id);
            break;
        case CASTLE_CTRL_REQ_TRANSFER_DESTROY:
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


static void castle_control_reply_error(uint32_t *reply, 
                                       int ret_code,
                                       int *len)
{
    reply[0] = CASTLE_CTRL_REPLY;
    reply[1] = CASTLE_CTRL_REPLY_FAIL;
    reply[2] = ret_code;
    *len = 3;
}

static void castle_control_reply_process(uint32_t *reply, int len, int *length)
{
    int i;
    
    /* Convert to network byte order */
    for(i=0; i<len; i++)
        reply[i] = htonl(reply[i]);

    #ifdef DEBUG        
    debug("Reply message:\n");
    for(i=0; i<4*len; i++)
        debug(" [%d]=%d\n", i, *(((uint8_t *)reply) + i));
    debug("\n");
    #endif

    /* length is in bytes */
    *length = 4*len;
}

static void castle_control_reply(uint32_t *reply, 
                                 int *length, 
                                 int op_code, 
                                 int ret_code, 
                                 uint32_t token)
{
    int len;

    /* Deal with error condition first */
    if(ret_code)
    {
        castle_control_reply_error(reply, ret_code, &len);
    } else
    /* Next, void replies */
    if(op_code == CASTLE_CTRL_REPLY_VOID)
    {
        reply[0] = CASTLE_CTRL_REPLY;
        reply[1] = CASTLE_CTRL_REPLY_VOID;
        len = 2;
    } else
    /* All the rest */
    {
        reply[0] = CASTLE_CTRL_REPLY;
        reply[1] = op_code;
        reply[2] = token;
        len = 3;
    } 

    castle_control_reply_process(reply, len, length);
}

int castle_control_packet_process(struct sk_buff *skb, void **reply, int *len_p)
{
    uint32_t *reply32; /* For now, all reply values are 32 bit wide */
    uint32_t ctrl_op;
    int word_len = 0;

    debug("Processing control packet (in_atomic=%d).\n", in_atomic());
#ifdef DEBUG
    skb_print(skb);
#endif
    if(skb->len < 4)
        return -EBADMSG;

    down(&castle_control_lock);
    ctrl_op = SKB_L_GET(skb);
    debug("Ctrl op=%d\n", ctrl_op);
    
    switch(ctrl_op)
    {
        case CASTLE_CTRL_REQ_VALID_STATS:
        case CASTLE_CTRL_REQ_INVALID_STATS:
            word_len = (castle_version_max_get() * 2) + 3;
            break;

        default:
            word_len = 64;
            break;
    }

    *reply = reply32 = kmalloc(word_len * sizeof(uint32_t), GFP_KERNEL);
    if (!reply32)
        return -ENOMEM;
    
    switch(ctrl_op)
    {
        case CASTLE_CTRL_REQ_CLAIM:
        {
            int ret;
            slave_uuid_t id;

            if(skb->len != 4) goto bad_msg;
            castle_control_claim(SKB_L_GET(skb), &ret, &id);
            castle_control_reply(reply32, 
                                 len_p, 
                                 CASTLE_CTRL_REPLY_NEW_SLAVE,
                                 ret, 
                                 id);
            break;
        }
        case CASTLE_CTRL_REQ_RELEASE:
        {
            int ret/*, i*/;
            int len_d;

            if(skb->len != 4) goto bad_msg;
            castle_control_release(SKB_L_GET(skb), &ret); 
            castle_control_reply(reply32,
                                 &len_d,
                                 CASTLE_CTRL_REPLY_VOID,
                                 ret,
                                 0);
            *len_p = len_d;

            break;
        }
        case CASTLE_CTRL_REQ_ATTACH:
        {
            int ret;
            uint32_t dev;

            if(skb->len != 4) goto bad_msg;
            castle_control_attach(SKB_L_GET(skb), 
                                  &ret, 
                                  &dev);
            castle_control_reply(reply32,
                                 len_p,
                                 CASTLE_CTRL_REPLY_NEW_DEVICE,
                                 ret,
                                 dev);
            break;
        }
        case CASTLE_CTRL_REQ_DETACH:
        {
            int ret;

            if(skb->len != 4) goto bad_msg;
            castle_control_detach(SKB_L_GET(skb), &ret); 
            castle_control_reply(reply32,
                                 len_p,
                                 CASTLE_CTRL_REPLY_VOID,
                                 ret,
                                 0);
            break;
        }
        case CASTLE_CTRL_REQ_CREATE:
        {
            int ret;
            version_t version;

            if(skb->len != 8) goto bad_msg;
            castle_control_create(SKB_LL_GET(skb), 
                                  &ret, 
                                  &version);
            castle_control_reply(reply32,
                                 len_p,
                                 CASTLE_CTRL_REPLY_NEW_VERSION,
                                 ret,
                                 version);
            break;
        }
        case CASTLE_CTRL_REQ_CLONE:
        {
            int ret;
            version_t version;

            if(skb->len != 4) goto bad_msg;
            castle_control_clone(SKB_L_GET(skb),
                                 &ret,
                                 &version); 
            castle_control_reply(reply32,
                                 len_p,
                                 CASTLE_CTRL_REPLY_NEW_VERSION,
                                 ret,
                                 version);
            break;
        }
        case CASTLE_CTRL_REQ_SNAPSHOT:
        {
            int ret;
            version_t version;
            
            if(skb->len != 4) goto bad_msg;
            castle_control_snapshot(SKB_L_GET(skb), 
                                    &ret, 
                                    &version);
            castle_control_reply(reply32,
                                 len_p,
                                 CASTLE_CTRL_REPLY_NEW_VERSION,
                                 ret,
                                 version);
            break;
        }
        case CASTLE_CTRL_REQ_INIT:
        {
            int ret;
            
            if(skb->len != 0) goto bad_msg;
            castle_control_fs_init(&ret);
            castle_control_reply(reply32,
                                 len_p,
                                 CASTLE_CTRL_REPLY_VOID,
                                 ret,
                                 0);
            break;
        }
        case CASTLE_CTRL_REQ_RESERVE_FOR_TRANSFER:
        {
            int version, type, reservations_count, i;
            int *reservations_disk, *reservations_length;

            debug("reserve_for_transfer skb->len=%d", skb->len);

            if(skb->len < 12) goto bad_msg;
            
            version = SKB_L_GET(skb);
            type = SKB_L_GET(skb);
            reservations_count = SKB_L_GET(skb);
            
            debug("reserve_for_transfer version=0x%x type=0x%x reservations_count=%d", version, type, reservations_count);
            
            if(skb->len < (reservations_count * 2)) goto bad_msg;
            
            reservations_disk = kmalloc(reservations_count * sizeof(int), GFP_KERNEL);
            reservations_length = kmalloc(reservations_count * sizeof(int), GFP_KERNEL);
            
            for (i = 0; i < reservations_count; i++) {
                reservations_disk[i] = SKB_L_GET(skb);
                reservations_length[i] = SKB_L_GET(skb);
            }
            
            kfree(reservations_disk);
            kfree(reservations_length);
            
            castle_control_reply(reply32,
                                 len_p,
                                 CASTLE_CTRL_REPLY_NEW_REGION,
                                 -EINVAL,
                                 0);
            break;
        }

        case CASTLE_CTRL_REQ_TRANSFER_CREATE:
        {
            int ret;
            transfer_id_t transfer;

            if(skb->len != 8) goto bad_msg;
            castle_control_transfer_create(SKB_L_GET(skb),
                                           SKB_L_GET(skb),
                                           &ret,
                                           &transfer);
            castle_control_reply(reply32,
                                 len_p,
                                 CASTLE_CTRL_REPLY_NEW_TRANSFER,
                                 ret,
                                 transfer);
            break;
        }
        case CASTLE_CTRL_REQ_TRANSFER_DESTROY:
        {
            int ret;

            if(skb->len != 4) goto bad_msg;
            castle_control_transfer_destroy(SKB_L_GET(skb),
                                            &ret);
            castle_control_reply(reply32,
                                 len_p,
                                 CASTLE_CTRL_REPLY_VOID,
                                 ret,
                                 0);
            break;
        }
        case CASTLE_CTRL_REQ_COLLECTION_ATTACH:
        {
            int ret;
            collection_id_t collection;

            version_t version;
            char *name;

            if(skb->len < 8) goto bad_msg;
            version = SKB_L_GET(skb);
            name = SKB_STR_GET(skb, 128);
            if(!name) goto bad_msg;

            castle_control_collection_attach(version, name,
                                             &ret,
                                             &collection);
            if(ret)
                kfree(name);
            castle_control_reply(reply32,
                                 len_p,
                                 CASTLE_CTRL_REPLY_NEW_COLLECTION,
                                 ret,
                                 collection);
            break;
        }
        case CASTLE_CTRL_REQ_COLLECTION_DETACH:
        {
            int ret;
            
            if(skb->len != 4) goto bad_msg;
            castle_control_collection_detach(SKB_L_GET(skb),
                                             &ret);
            castle_control_reply(reply32,
                                 len_p,
                                 CASTLE_CTRL_REPLY_VOID,
                                 ret,
                                 0);
            break;
        }
        case CASTLE_CTRL_REQ_COLLECTION_SNAPSHOT:
        {
            int ret;
            version_t version;

            if(skb->len != 4) goto bad_msg;
            castle_control_collection_snapshot(SKB_L_GET(skb),
                                               &ret,
                                               &version);
            castle_control_reply(reply32,
                                 len_p,
                                 CASTLE_CTRL_REPLY_NEW_VERSION,
                                 ret,
                                 version);
            break;
        }
        case CASTLE_CTRL_REQ_VALID_STATS:
        {
            int ret, count = 0;
            slave_uuid_t slave_uuid;
            struct castle_slave *slave;
            
            if(skb->len != 4) goto bad_msg;
            
            slave_uuid = SKB_L_GET(skb);
            slave = castle_slave_find_by_uuid(slave_uuid);
            
            if (!slave)
            {
                ret = -ENOENT;
                goto stats_error;
            }
            
            debug("get_valid_stats slave_uuid=0x%x slave=%p\n", slave_uuid, slave);
            
            ret = castle_freespace_summary_get(slave, reply32 + 3, word_len - 3, &count);
            if (ret)
                goto stats_error;

            debug("get_valid_stats castle_freespace_summary_get ret=%d\n", ret);

            reply32[0] = CASTLE_CTRL_REPLY;
            reply32[1] = CASTLE_CTRL_REPLY_VALID_COUNTS;
            reply32[2] = count >> 1;
            count += 3;

stats_error:
            if (ret)
                castle_control_reply_error(reply32, ret, &count);
            
            castle_control_reply_process(reply32, count, len_p);
            
            break;
        }
        case CASTLE_CTRL_REQ_INVALID_STATS:
        {
            /* TODO we don't have any invalid blocks atm */
            *len_p = 0;            
            break;
        }
    }
    up(&castle_control_lock);

    return 0;

bad_msg:
    up(&castle_control_lock);

    return -EBADMSG;
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
