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
#include "castle_back.h"
#include "castle_ctrl.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)  ((void)0)
#else
#define debug(_f, _a...)  (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

static DECLARE_MUTEX(castle_control_lock);
static DECLARE_WAIT_QUEUE_HEAD(castle_control_wait_q);

c_mstore_t *castle_attachments_store = NULL;

void castle_ctrl_lock(void)
{
    down(&castle_control_lock);
}

void castle_ctrl_unlock(void)
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
 
    if (!DA_INVAL(castle_version_da_id_get(version)))
    {
        printk("Couldn't attach device to collection.\n");
        *ret = -EINVAL;
        return;
    }

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

void castle_control_destroy(version_t version, int *ret)
{
    version_t       parent;
    da_id_t         da_id;

    printk("Destroying version: %u\n", version);
    *ret = castle_version_read(version, &da_id, &parent, NULL, NULL);
    
    /* Reply immediatly, if the version doesn't correspond to a DA. */
    if ((*ret < 0) || !da_id || parent)
    {
        printk("Invalid version\n");
        *ret = -EINVAL;
        return;
    }

    if (castle_double_array_destroy(da_id) < 0)
    {
        printk("Failed to destroy Collection tree: %u\n", version);
        *ret = -EINVAL;
        return;
    }

    *ret = 0;
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

static int castle_collection_writeback(struct castle_attachment *ca)
{
    struct castle_alist_entry mstore_entry;
    
    BUG_ON(strlen(ca->col.name) > MAX_NAME_SIZE);

    debug("Collection add: %s,%u\n", ca->col.name, ca->version);

    mstore_entry.version = ca->version;
    strcpy(mstore_entry.name, ca->col.name);

    BUG_ON(!MSTORE_KEY_INVAL(ca->key));
    ca->key = castle_mstore_entry_insert(castle_attachments_store, &mstore_entry);

    return 0;
}

static int castle_attachments_writeback(void)
{
    struct castle_attachment *ca;
    struct list_head *lh;

    castle_ctrl_lock();

    /* Increment reference count of all attachments. */
    spin_lock(&castle_attachments.lock);
    list_for_each(lh, &castle_attachments.attachments)
    {
        ca = list_entry(lh, struct castle_attachment, list);
        if(ca->device)
            continue;
        ca->ref_cnt++;
    }
    spin_unlock(&castle_attachments.lock);

    /* Writeback attachments. */
    list_for_each(lh, &castle_attachments.attachments)
    {
        ca = list_entry(lh, struct castle_attachment, list);
        if(ca->device)
            continue;
        if(castle_collection_writeback(ca))
            printk("Failed to writeback collection: (%u, %s)\n", 
                    ca->col.id, ca->col.name);
    }
    
    /* Decrement reference count of all attachments. */
    spin_lock(&castle_attachments.lock);
    list_for_each(lh, &castle_attachments.attachments)
    {
        ca = list_entry(lh, struct castle_attachment, list);
        if(ca->device)
            continue;
        ca->ref_cnt--;
    }
    spin_unlock(&castle_attachments.lock);

    castle_ctrl_unlock();

    return 0;
}

int castle_attachments_store_init(int first)
{
    struct castle_attachment *ca;
    struct list_head *lh;

    if (first)
    {
        printk("Creating new mstore for Collection Attachments\n");
        castle_attachments_store =  castle_mstore_init(MSTORE_ATTACHMENTS_TAG, 
                                            sizeof(struct castle_alist_entry));
    }
    else 
    {
        struct castle_mstore_iter *iterator;
        struct castle_alist_entry mstore_entry;
 
        printk("Openings mstore for Collection Attachments\n");
        castle_attachments_store = castle_mstore_open(MSTORE_ATTACHMENTS_TAG, 
                                            sizeof(struct castle_alist_entry));

        iterator = castle_mstore_iterate(castle_attachments_store);
        if (!iterator)
            return -EINVAL;
        while (castle_mstore_iterator_has_next(iterator))
        {
            struct castle_attachment *ca;
            c_mstore_key_t key;
            char *name = castle_malloc(MAX_NAME_SIZE, GFP_KERNEL);

            BUG_ON(!name);
            castle_mstore_iterator_next(iterator, &mstore_entry, &key);
            strcpy(name, mstore_entry.name);
            debug("Collection Load: %s\n", name);
            ca = castle_collection_init(mstore_entry.version, name);
            if(!ca)
            {
                printk("Failed to create Collection (%s, %u)\n",
                        mstore_entry.name, mstore_entry.version);
                castle_mstore_iterator_destroy(iterator);
                return -EINVAL;
            }
            ca->key = key;
            printk("Created Collection (%s, %u) with id: %u\n",
                    mstore_entry.name, mstore_entry.version, ca->col.id);
        }
        castle_mstore_iterator_destroy(iterator);
    }

    /* TODO: Delete old copies of attachments in mstore. Should remove this afte
     * rcompleting Crash Consistency. */
    list_for_each(lh, &castle_attachments.attachments)
    {
        ca = list_entry(lh, struct castle_attachment, list);
        if(ca->device)
            continue;

        if (!MSTORE_KEY_INVAL(ca->key))
            castle_mstore_entry_delete(castle_attachments_store, ca->key);

        ca->key = INVAL_MSTORE_KEY;
    }

    if (!castle_attachments_store)
        return -ENOMEM;

    return 0;
}

void castle_attachments_store_fini(void)
{
    if (castle_attachments_store)
    {
        castle_attachments_writeback();
        castle_mstore_fini(castle_attachments_store);
    }
}

void castle_control_collection_attach(version_t          version,
                                      char              *name,
                                      int               *ret,
                                      collection_id_t   *collection)
{
    struct castle_attachment *ca;

    BUG_ON(strlen(name) > MAX_NAME_SIZE);

    ca = castle_collection_init(version, name);
    if(!ca)
    {
        printk("Couldn't find collection for version: %u\n", version);
        *ret = -EINVAL;
        return;
    }
    printk("Creating new Collection Attachment %u (%s, %u)\n", 
            ca->col.id, ca->col.name, ca->version);
    
    *collection = ca->col.id; 
    *ret = 0;
}
            
void castle_control_collection_detach(collection_id_t collection,
                                      int            *ret)
{
    struct castle_attachment *ca = castle_attachment_get(collection);
    if (!ca)
    {
        *ret = -ENODEV;
        return;
    }

    printk("Deleting Collection Attachment %u (%s, %u)/%u\n", 
            collection, ca->col.name, ca->version, ca->ref_cnt);

    /* Double put is opposite of what happens in collection_init */
    castle_attachment_put(ca);
    castle_attachment_put(ca);

    *ret = 0;
}

void castle_control_collection_snapshot(collection_id_t collection,
                                               int *ret,
                                               version_t *version)
{
    struct castle_attachment *ca = castle_attachment_get(collection);
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
    castle_attachment_put(ca);
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
        sb->pub.flags |= CASTLE_SLAVE_TARGET;
    else
        sb->pub.flags &= ~CASTLE_SLAVE_TARGET;
    
    castle_slave_superblock_put(slave, 1);

    castle_events_slave_changed(slave->uuid);

    *ret = 0;
}

void castle_control_protocol_version(int *ret, uint32_t *version)
{
    *ret = 0;
    *version = CASTLE_PROTOCOL_VERSION;
}

int castle_control_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int err;
    void __user *udata = (void __user *) arg;
    cctrl_ioctl_t ioctl;

    if(_IOC_TYPE(cmd) != CASTLE_CTRL_IOCTL_TYPE)
    {
        printk("Unknown IOCTL: 0x%x\n", cmd);
        return -EINVAL;
    }

    if (copy_from_user(&ioctl, udata, sizeof(cctrl_ioctl_t)))
        return -EFAULT;

    if(_IOC_NR(cmd) != ioctl.cmd)
    {
        printk("IOCTL number %d, doesn't agree with the command number %d.\n",
                _IOC_NR(cmd), ioctl.cmd);
        return -EINVAL;
    }

    if(!castle_fs_inited && (ioctl.cmd != CASTLE_CTRL_CLAIM) && (ioctl.cmd != CASTLE_CTRL_INIT))
    {
        printk("Disallowed ctrl op %d, before fs gets inited.\n", ioctl.cmd);
        return -EINVAL;
    }

    if(castle_fs_inited && ((ioctl.cmd == CASTLE_CTRL_CLAIM) || (ioctl.cmd == CASTLE_CTRL_INIT))) 
    {
        printk("Disallowed ctrl op %d, after fs gets inited.\n", ioctl.cmd);
        return -EINVAL;
    }

    down(&castle_control_lock);
    debug("Lock taken: in_atomic=%d.\n", in_atomic());
    debug("IOCTL Cmd: %u\n", (uint32_t)ioctl.cmd);
    switch(ioctl.cmd)
    {
        case CASTLE_CTRL_CLAIM:
            castle_control_claim( ioctl.claim.dev,
                                 &ioctl.claim.ret,
                                 &ioctl.claim.id);
            break;
        case CASTLE_CTRL_RELEASE:
            castle_control_release( ioctl.release.id,
                                   &ioctl.release.ret);
            break;
        case CASTLE_CTRL_INIT:
            castle_control_fs_init(&ioctl.init.ret);
            break;            
        case CASTLE_CTRL_PROTOCOL_VERSION:
            castle_control_protocol_version(&ioctl.protocol_version.ret, &ioctl.protocol_version.version);
            break;
        case CASTLE_CTRL_ATTACH:
            castle_control_attach( ioctl.attach.version,
                                  &ioctl.attach.ret,
                                  &ioctl.attach.dev);
            break;
        case CASTLE_CTRL_DETACH:
            castle_control_detach( ioctl.detach.dev,
                                  &ioctl.detach.ret);
            break;
        case CASTLE_CTRL_SNAPSHOT:
            castle_control_snapshot( ioctl.snapshot.dev,
                                    &ioctl.snapshot.ret,
                                    &ioctl.snapshot.version);
            break;

        case CASTLE_CTRL_COLLECTION_ATTACH:
        {
            char *collection_name;
            int name_length = ioctl.collection_attach.name_length;
            
            if (name_length > MAX_NAME_SIZE)
            {
                err = -EINVAL;
                goto err;
            }

            collection_name = castle_malloc(name_length, GFP_KERNEL);

            if (!collection_name)
            {
                err = -ENOMEM;
                goto err;
            }
            
            if (copy_from_user(collection_name, ioctl.collection_attach.name, 
                name_length))
            {
                castle_free(collection_name);
                err = -EFAULT;
                goto err;
            }
            
            if (collection_name[name_length - 1] != '\0')
            {
                castle_free(collection_name);
                err = -EINVAL;
                goto err;
            }
        
            debug("Collection Attach: %s:%lu\n", collection_name, name_length);
            castle_control_collection_attach(ioctl.collection_attach.version,
                                            collection_name,
                                            &ioctl.collection_attach.ret,
                                            &ioctl.collection_attach.collection);
                                            
            
            break;
        }
        case CASTLE_CTRL_COLLECTION_DETACH:
            castle_control_collection_detach(ioctl.collection_detach.collection,
                                  &ioctl.collection_detach.ret);
            break;
        case CASTLE_CTRL_COLLECTION_SNAPSHOT:
            castle_control_collection_snapshot(ioctl.collection_snapshot.collection,
                                    &ioctl.collection_snapshot.ret,
                                    &ioctl.collection_snapshot.version);
            break;

        case CASTLE_CTRL_CREATE:
            castle_control_create( ioctl.create.size,
                                  &ioctl.create.ret,
                                  &ioctl.create.id);
            break;
        case CASTLE_CTRL_DESTROY:
            castle_control_destroy( ioctl.destroy.version,
                                   &ioctl.destroy.ret);
            break;
        case CASTLE_CTRL_CLONE:
            castle_control_clone( ioctl.clone.version,
                                 &ioctl.clone.ret,
                                 &ioctl.clone.clone);
            break;

        case CASTLE_CTRL_TRANSFER_CREATE:
        case CASTLE_CTRL_TRANSFER_DESTROY:
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
