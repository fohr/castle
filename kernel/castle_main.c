#include <linux/module.h>
#include <linux/bio.h>
#include <linux/kobject.h>
#include <linux/device-mapper.h>
#include <linux/blkdev.h>
#include <asm/semaphore.h>

#include "castle.h"
#include "castle_block.h"
#include "castle_btree.h"
#include "castle_cache.h"
#include "castle_ctrl.h"
#include "castle_sysfs.h"

struct castle                castle;
struct castle_volumes        castle_volumes;
struct castle_slaves         castle_slaves;
struct castle_devices        castle_devices;

struct workqueue_struct     *castle_wq;

int                          castle_fs_inited;
struct castle_fs_superblock  castle_fs_super;
struct castle_vtree_node    *castle_vtree_root;

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)  ((void)0)
#else
#define debug(_f, _a...)  (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif


static void castle_fs_superblock_print(struct castle_fs_superblock *fs_sb)
{
    printk("Magic1: %.8x\n"
           "Magic2: %.8x\n"
           "Magic3: %.8x\n"
           "Salt:   %x\n"
           "Pepper: %x\n"
           "F_t_d1: %x\n"
           "F_t_b1: %x\n"
           "F_t_d2: %x\n"
           "F_t_b2: %x\n"
           "R_t_d1: %x\n"
           "R_t_b1: %x\n"
           "R_t_d2: %x\n"
           "R_t_b2: %x\n",
           fs_sb->magic1,
           fs_sb->magic2,
           fs_sb->magic3,
           fs_sb->salt,
           fs_sb->peper,
           fs_sb->fwd_tree_disk1,
           fs_sb->fwd_tree_block1,
           fs_sb->fwd_tree_disk2,
           fs_sb->fwd_tree_block2,
           fs_sb->rev_tree_disk1,
           fs_sb->rev_tree_block1,
           fs_sb->rev_tree_disk2,
           fs_sb->rev_tree_block2);
}

static int castle_fs_superblock_validate(struct castle_fs_superblock *fs_sb)
{
    if(fs_sb->magic1 != 0x19731121) return -1;
    if(fs_sb->magic2 != 0x19880624) return -2;
    if(fs_sb->magic3 != 0x19821120) return -3;

    return 0;
}

static int castle_fs_superblock_read(struct castle_slave *cs,
                                     struct castle_fs_superblock *fs_sb) 
{
    int err;
    
    err = castle_sub_block_read(cs,
                                fs_sb,
                                C_BLK_SIZE, 
                                sizeof(struct castle_fs_superblock),
                                NULL, NULL);
    if(err)
    {
        printk("Failed to read fs superblock.\n");
        return err;
    }

    err = castle_fs_superblock_validate(fs_sb);
    if(err)
    {
        printk("Invalid superblock.\n");
        return err;
    }

    return 0;
}

int castle_fs_init(void)
{
    struct list_head *lh;
    struct castle_slave *cs;
    struct castle_fs_superblock fs_sb;
    int ret, first;
    // TODO: Temporary, replace with c_disk_blk_t in fs_superblock
    c_disk_blk_t blk;

    if(castle_fs_inited)
        return -EEXIST;

    if(list_empty(&castle_slaves.slaves))
        return -ENOENT;

    first = 1;
    list_for_each(lh, &castle_slaves.slaves)
    {
        cs = list_entry(lh, struct castle_slave, list);
        ret = castle_fs_superblock_read(cs, &fs_sb);  
        if(ret)
        {
            // TODO: invalidate/rebuild the slave! 
            printk("Invaild superblock on slave uuid=0x%x, id=%d, err=%d\n",
                    cs->cs_sb.uuid, cs->id, ret);
            continue;
        }
        /* Save fs superblock if the first slave. */
        if(first)
        {
            memcpy(&castle_fs_super, &fs_sb, sizeof(struct castle_fs_superblock));
            first = 0;
        }
        else
        /* Check if fs superblock the save as the one we already know about */
        {
            if(memcmp(&castle_fs_super, &fs_sb, 
                      sizeof(struct castle_fs_superblock)) != 0)
            {
                printk("Castle fs supreblocks do not match!\n");
                return -EINVAL;
            }
        }
    }

    /* If first is True, we've not found a single cs with valid fs superblock */
    if(first)
        return -ENOENT;

    blk.disk  = castle_fs_super.fwd_tree_disk1;
    blk.block = castle_fs_super.fwd_tree_block1;
    ret = castle_version_tree_read(blk, &castle_vtree_root);
    if(ret)
        return -EINVAL;

    printk("Castle FS inited.\n");
    castle_fs_inited = 1;

    return 0;
}

static void castle_slave_superblock_print(struct castle_slave_superblock *cs_sb)
{
    printk("Magic1: %.8x\n"
           "Magic2: %.8x\n"
           "Magic3: %.8x\n"
           "Uuid:   %x\n"
           "Free:   %x\n"
           "Size:   %x\n",
           cs_sb->magic1,
           cs_sb->magic2,
           cs_sb->magic3,
           cs_sb->uuid,
           cs_sb->free,
           cs_sb->size);
}

static int castle_slave_superblock_validate(struct castle_slave_superblock *cs_sb)
{
    if(cs_sb->magic1 != 0x02061985) return -1;
    if(cs_sb->magic2 != 0x16071983) return -2;
    if(cs_sb->magic3 != 0x16061981) return -3;

    return 0;
}

static int castle_slave_superblock_read(struct castle_slave *cs) 
{
    struct castle_slave_superblock *cs_sb = &cs->cs_sb;
    int err;
    
    err = castle_sub_block_read(cs,
                                cs_sb,
                                0,
                                sizeof(struct castle_slave_superblock),
                                NULL, NULL);
    if(err) 
    {
        printk("Failed to read superblock.\n");
        return err;
    }

    err = castle_slave_superblock_validate(cs_sb);
    if(err)
    {
        printk("Invalid superblock.\n");
        return err;
    }
    
    return 0;
}

struct castle_slave* castle_slave_find_by_id(uint32_t id)
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

struct castle_slave* castle_slave_find_by_uuid(uint32_t uuid)
{
    struct list_head *lh;
    struct castle_slave *slave;

    list_for_each(lh, &castle_slaves.slaves)
    {
        slave = list_entry(lh, struct castle_slave, list);
        if(slave->cs_sb.uuid == uuid)
            return slave;
    }

    return NULL;
}

struct castle_slave* castle_slave_find_by_block(c_disk_blk_t cdb)
{
    return castle_slave_find_by_uuid(cdb.disk);
}

struct castle_slave* castle_claim(uint32_t new_dev)
{
    dev_t dev;
    struct block_device *bdev;
    int bdev_claimed = 0;
    int err;
    char b[BDEVNAME_SIZE];
    struct castle_slave *cs = NULL;
    static int slave_id = 0;

    if(!(cs = kmalloc(sizeof(struct castle_slave), GFP_KERNEL)))
        goto err_out;
    cs->id = slave_id++;

    dev = new_decode_dev(new_dev);
    bdev = open_by_devnum(dev, FMODE_READ|FMODE_WRITE);
    if (IS_ERR(bdev)) 
    {
        printk("Could not open %s.\n", __bdevname(dev, b));
        goto err_out;
    }
    err = bd_claim(bdev, &castle);
    if (err) 
    {
        printk("Could not bd_claim %s, err=%d.\n", bdevname(bdev, b), err);
        goto err_out;
    }
    bdev_claimed = 1;
    cs->bdev = bdev;

    err = castle_slave_superblock_read(cs); 
    if(err)
    {
        printk("Invalid superblock. Not initialised(?)\n");
        goto err_out;
    }

    list_add(&cs->list, &castle_slaves.slaves);
    castle_sysfs_slave_add(cs);

    return cs;
err_out:
    if(bdev_claimed) blkdev_put(bdev);
    if(cs) kfree(cs);
    return NULL;    
}

void castle_release(struct castle_slave *cs)
{
    castle_sysfs_slave_del(cs);
    bd_release(cs->bdev);
    blkdev_put(cs->bdev);
    list_del(&cs->list);
    kfree(cs);
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

static void castle_bio_put(c_bio_t *c_bio)
{
    if(atomic_dec_and_test(&c_bio->remaining))
    {
        struct bio *bio = c_bio->bio;
        int err = c_bio->err;
        

        kfree(c_bio->c_bvecs);
        kfree(c_bio);

        debug("Ending bio with ret=%d\n", err);
        bio_endio(bio, err);
    }
}

void castle_bio_data_io_end(c_bvec_t *c_bvec, int err)
{
    debug("Finished the read.\n");
    if(err) c_bvec->c_bio->err = err;
    castle_bio_put(c_bvec->c_bio);
}

void castle_bio_data_copy(c_bvec_t *c_bvec, c2_page_t *c2p)
{
    memcpy(pfn_to_kaddr(page_to_pfn(c_bvec->page)),
           pfn_to_kaddr(page_to_pfn(c2p->page)),
           PAGE_SIZE);
}

void castle_bio_c2p_update(c2_page_t *c2p, int uptodate)
{
    c_bvec_t *c_bvec = c2p->private;
    int err = -EIO;

    if(uptodate)
    {
        set_c2p_uptodate(c2p);
        castle_bio_data_copy(c_bvec, c2p);
        err = 0;
    }
    unlock_c2p(c2p);
    put_c2p(c2p);
    castle_bio_data_io_end(c_bvec, err);
}

void castle_bio_data_io(c_bvec_t *c_bvec)
{
    c2_page_t *c2p;
    int err;

    /* Invalid pointer to on slave data means that it's never been written.
       memset the buffer to zero end exit */
    if(DISK_BLK_INVAL(c_bvec->cdb))
    {
        memset(pfn_to_kaddr(page_to_pfn(c_bvec->page)), 0, PAGE_SIZE);
        castle_bio_put(c_bvec->c_bio);
        return;
    }

    c2p = castle_cache_page_get(c_bvec->cdb);
    lock_c2p(c2p);
    if(c2p_uptodate(c2p))
    {
        castle_bio_data_copy(c_bvec, c2p);
        unlock_c2p(c2p);
        put_c2p(c2p);
        castle_bio_data_io_end(c_bvec, 0); 
    } else
    {
        c2p->private = c_bvec;
        c2p->end_io = castle_bio_c2p_update;
        submit_c2p(READ, c2p);
    }
    return;

error_out:
    printk("Failing the read.\n");
    c_bvec->c_bio->err = err;
    castle_bio_put(c_bvec->c_bio);
}

static int castle_bio_validate(struct bio *bio)
{
    struct bio_vec *bvec;
    int i;

    /* Fail writes */
    if(bio_rw(bio) == WRITE)
    {
        printk("Cannot handle writes yet.\n");
        return -ENOSYS;
    }

    if(bio->bi_sector % (1 << (C_BLK_SHIFT - 9)) != 0)
    {
        printk("Got BIO for unaligned sector: 0x%lx\n", bio->bi_sector);
        return -EINVAL;
    }

    bio_for_each_segment(bvec, bio, i)
    {
        if((bvec->bv_len != C_BLK_SIZE) || (bvec->bv_offset != 0))
        {
            printk("Got unaligned bvec: len=0x%x, offset=0x%x\n", 
                    bvec->bv_len, bvec->bv_offset);
            return -EINVAL;
        }
    }

    return 0;
}

static int castle_device_make_request(struct request_queue *rq, struct bio *bio)
{ 
    c_bio_t *c_bio = NULL;
    c_bvec_t *c_bvecs = NULL;
    struct castle_device *dev = rq->queuedata;
    struct bio_vec *bvec;
    sector_t block;
    int i;

    /* Check if we can handle this bio */
    if(castle_bio_validate(bio))
        goto fail_bio;

    c_bio   = kmalloc(sizeof(c_bio_t), GFP_NOIO);
    c_bvecs = kzalloc(sizeof(c_bvec_t) * bio->bi_vcnt, GFP_NOIO);
    if(!c_bio || !c_bvecs) 
        goto fail_bio;
    
    c_bio->bio = bio;
    c_bio->c_bvecs = c_bvecs; 
    atomic_set(&c_bio->remaining, bio->bi_vcnt);
    c_bio->err = 0;

    block = bio->bi_sector >> (C_BLK_SHIFT - 9);
    bio_for_each_segment(bvec, bio, i)
    {
        c_disk_blk_t cdb;
        c_bvec_t *c_bvec = c_bvecs + i; 

        c_bvec->c_bio   = c_bio;
        c_bvec->page    = bvec->bv_page;
        c_bvec->block   = block;
        c_bvec->version = dev->version; 
        
        cdb = castle_vtree_find(castle_vtree_root, c_bvec->version); 
        if(DISK_BLK_INVAL(cdb))
            castle_bio_data_io_end(c_bvec, -EINVAL);
        else
            castle_ftree_find(c_bvec, cdb); 

        block++;
    }

    return 0;

fail_bio:
    if(c_bio)   kfree(c_bio);
    if(c_bvecs) kfree(c_bvecs);
    bio_endio(bio, -EIO);

    return 0;
}

struct castle_device* castle_device_find(dev_t dev)
{
    struct castle_device *cd;
    struct list_head *lh;

    list_for_each(lh, &castle_devices.devices)
    {
        cd = list_entry(lh, struct castle_device, list);
        if((cd->gd->major == MAJOR(dev)) &&
           (cd->gd->first_minor == MINOR(dev)))
            return cd;
    }
    return NULL;
}

void castle_device_free(struct castle_device *cd)
{
    castle_sysfs_device_del(cd);
    del_gendisk(cd->gd);
    put_disk(cd->gd);
    list_del(&cd->list);
    kfree(cd);
}

struct castle_device* castle_device_init(struct castle_vtree_leaf_slot *version)
{
    struct castle_device *dev;
    struct request_queue *rq;
    struct gendisk *gd;
    static int minor = 0;

    dev = kmalloc(sizeof(struct castle_device), GFP_KERNEL); 
    if(!dev)
        goto error_out;
	spin_lock_init(&dev->lock);
    dev->version = version->version_nr;
        
    gd = alloc_disk(1);
    if(!gd)
        goto error_out;

    sprintf(gd->disk_name, "castle-fs-%d", minor);
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
    set_capacity(gd, (version->size << (C_BLK_SHIFT - 9)));
    add_disk(gd);

    bdget(MKDEV(gd->major, gd->first_minor));
    castle_sysfs_device_add(dev);

    return dev;

error_out:
    printk("Failed to init device.\n");
    return NULL;    
}

static int castle_slaves_init(void)
{
    memset(&castle_slaves, 0, sizeof(struct castle_slaves));
    INIT_LIST_HEAD(&castle_slaves.slaves);

    return 0;
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

static int castle_devices_init(void)
{
    int major;

    memset(&castle_devices, 0, sizeof(struct castle_devices));
    INIT_LIST_HEAD(&castle_devices.devices);

    /* Allocate a major for this device */
    if((major = register_blkdev(0, "castle-fs")) < 0) 
    {
        printk("Couldn't register castle device\n");
        return -ENOMEM;
    }
    castle_devices.major = major;

    castle_wq = create_workqueue("castle_wq");
    if(!castle_wq)
    {
        printk("Could not create worqueue.\n");
        unregister_blkdev(castle_devices.major, "castle-fs"); 
        return -ENOMEM;
    }

    return 0;
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
        unregister_blkdev(castle_devices.major, "castle-fs");

    destroy_workqueue(castle_wq);
}

static int __init castle_init(void)
{
    int ret;

    printk("Castle FS init ... ");

    castle_fs_inited = 0;
    if((ret = castle_cache_init()))   goto err_out1;
    if((ret = castle_btree_init()))   goto err_out2;
    if((ret = castle_devices_init())) goto err_out3;
    if((ret = castle_slaves_init()))  goto err_out4;
    if((ret = castle_control_init())) goto err_out5;
    if((ret = castle_sysfs_init()))   goto err_out6;

    printk("OK.\n");

    return 0;

    /* Unreachable */
    castle_sysfs_fini();
err_out6:
    castle_control_fini();
err_out5:
    castle_slaves_free();
err_out4:
    castle_devices_free();
err_out3:
    castle_btree_free();
err_out2:
    castle_cache_fini();
err_out1:

    return ret;
}


static void __exit castle_exit(void)
{
    printk("Castle FS exit ... ");

    castle_sysfs_fini();
    castle_control_fini();
    castle_slaves_free();
    castle_devices_free();
    castle_btree_free();
    castle_cache_fini();

    printk("done.\n\n\n");
}

module_init(castle_init);
module_exit(castle_exit);

MODULE_LICENSE("GPL");

