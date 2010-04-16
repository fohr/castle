/* TODO: when castle disk mounted, and then castle-fs-test run, later bd_claims on
         disk devices fail (multiple castle_fs_cli 'claim' cause problems?) */
#include <linux/module.h>
#include <linux/bio.h>
#include <linux/kobject.h>
#include <linux/device-mapper.h>
#include <linux/blkdev.h>
#include <linux/random.h>
#include <linux/crc32.h>
#include <asm/semaphore.h>

#include "castle_public.h"
#include "castle.h"
#include "castle_block.h"
#include "castle_cache.h"
#include "castle_btree.h"
#include "castle_freespace.h"
#include "castle_versions.h"
#include "castle_ctrl.h"
#include "castle_transfer.h"
#include "castle_sysfs.h"
#include "castle_debug.h"
#include "castle_events.h"

struct castle                castle;
struct castle_slaves         castle_slaves;
struct castle_devices        castle_devices;
struct castle_regions        castle_regions;

struct workqueue_struct     *castle_wqs[MAX_BTREE_DEPTH+1];

int                          castle_fs_inited;

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)  ((void)0)
#else
#define debug(_f, _a...)  (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif


static void USED castle_fs_superblock_print(struct castle_fs_superblock *fs_sb)
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
           fs_sb->fwd_tree1.disk,
           fs_sb->fwd_tree1.block,
           fs_sb->fwd_tree2.disk,
           fs_sb->fwd_tree2.block,
           fs_sb->rev_tree1.disk,
           fs_sb->rev_tree1.block,
           fs_sb->rev_tree2.disk,
           fs_sb->rev_tree2.block);
}

static int castle_fs_superblock_validate(struct castle_fs_superblock *fs_sb)
{
    if(fs_sb->magic1 != CASTLE_FS_MAGIC1) return -1;
    if(fs_sb->magic2 != CASTLE_FS_MAGIC2) return -2;
    if(fs_sb->magic3 != CASTLE_FS_MAGIC3) return -3;

    return 0;
}

static void castle_fs_superblock_init(struct castle_fs_superblock *fs_sb)
{   
    fs_sb->magic1 = CASTLE_FS_MAGIC1;
    fs_sb->magic2 = CASTLE_FS_MAGIC2;
    fs_sb->magic3 = CASTLE_FS_MAGIC3;
    get_random_bytes(&fs_sb->salt,  sizeof(fs_sb->salt));
    get_random_bytes(&fs_sb->peper, sizeof(fs_sb->peper));
    fs_sb->fwd_tree1 = INVAL_DISK_BLK; 
    fs_sb->fwd_tree2 = INVAL_DISK_BLK;
    fs_sb->rev_tree1 = INVAL_DISK_BLK;
    fs_sb->rev_tree2 = INVAL_DISK_BLK;
}

static void castle_fs_superblocks_init(void)
{
    struct castle_fs_superblock *fs_sb;

    fs_sb = castle_fs_superblocks_get();
    castle_fs_superblock_init(fs_sb);
    castle_fs_superblocks_put(fs_sb, 1);
}

static inline struct castle_fs_superblock* castle_fs_superblock_get(struct castle_slave *cs)
{
    lock_c2p(cs->fs_sblk);
    BUG_ON(!c2p_uptodate(cs->fs_sblk));
    
    return ((struct castle_fs_superblock*) pfn_to_kaddr(page_to_pfn(cs->fs_sblk->page)));
}

static inline void castle_fs_superblock_put(struct castle_slave *cs, int dirty)
{
    if(dirty) dirty_c2p(cs->fs_sblk);
    unlock_c2p(cs->fs_sblk);
}

/* Get all superblocks */
struct castle_fs_superblock* castle_fs_superblocks_get(void)
{
    struct list_head *l;
    struct castle_slave *cs;
    struct castle_fs_superblock *sb = NULL;

    list_for_each(l, &castle_slaves.slaves)
    {
        cs = list_entry(l, struct castle_slave, list);
        sb = castle_fs_superblock_get(cs);
    }

    return sb;
}

/* Put all superblocks */
void castle_fs_superblocks_put(struct castle_fs_superblock *sb, int dirty)
{
    struct list_head *l;
    struct castle_slave *cs;
    struct castle_fs_superblock *curr_sb;

    list_for_each(l, &castle_slaves.slaves)
    {
        cs = list_entry(l, struct castle_slave, list);
        /* The buffer should be locked */
        BUG_ON(!c2p_locked(cs->fs_sblk));
        /* If superblock has been dirtied, copy it, and dirty the buffer */
        if(dirty)
        {
            curr_sb = pfn_to_kaddr(page_to_pfn(cs->fs_sblk->page));
            /* Note, we can be possibly copying from ourselves, memmove is safer */
            memmove(curr_sb, sb, sizeof(struct castle_fs_superblock)); 
            dirty_c2p(cs->fs_sblk);
        }
        /* Finally, unlock the buffer */
        unlock_c2p(cs->fs_sblk);
    }
}

int castle_fs_init(void)
{
    struct list_head *lh;
    struct castle_slave *cs;
    struct castle_fs_superblock fs_sb, *cs_fs_sb;
    int ret, first;

    if(castle_fs_inited)
        return -EEXIST;

    if(list_empty(&castle_slaves.slaves))
        return -ENOENT;

    first = 1;
    /* Make sure that superblocks of the all non-new devices are
       the same, save the results */
    list_for_each(lh, &castle_slaves.slaves)
    {
        cs = list_entry(lh, struct castle_slave, list);
        if(cs->new_dev)
            continue;

        cs_fs_sb = castle_fs_superblock_get(cs);
        BUG_ON(!c2p_uptodate(cs->fs_sblk));

        /* Save fs superblock if the first slave. */
        if(first)
        {
            memcpy(&fs_sb, cs_fs_sb, sizeof(struct castle_fs_superblock));
            first = 0;
        }
        else
        /* Check if fs superblock the save as the one we already know about */
        {
            if(memcmp(&fs_sb, cs_fs_sb, 
                      sizeof(struct castle_fs_superblock)) != 0)
            {
                printk("Castle fs supreblocks do not match!\n");
                castle_fs_superblock_put(cs, 0);
                return -EINVAL;
            }
        }
        castle_fs_superblock_put(cs, 0);
    }

    /* If first is still true, we've not found a single non-new cs.
       Init the fs superblock. */
    if(first) {
        c2_page_t *c2p;

        /* Init the fs superblock */
        castle_fs_superblocks_init();
        /* Init the root btree node */
        c2p = castle_ftree_node_create(0 /* version */, 1 /* is_leaf */);
        /* Init version list */
        ret = castle_versions_list_init(c2p->cdb);
        /* Release btree node c2p */
        unlock_c2p(c2p);
        put_c2p(c2p);
        if(ret) return ret;
        /* Make sure that fs_sb is up-to-date */
        cs_fs_sb = castle_fs_superblocks_get();
        memcpy(&fs_sb, cs_fs_sb, sizeof(struct castle_fs_superblock));
        castle_fs_superblocks_put(cs_fs_sb, 0);
    }
    cs_fs_sb = castle_fs_superblocks_get();
    BUG_ON(!cs_fs_sb);

    /* This will initialise the fs superblock of all the new devices */
    memcpy(cs_fs_sb, &fs_sb, sizeof(struct castle_fs_superblock));
    castle_fs_superblocks_put(cs_fs_sb, 1);
    /* Read versions in */
    ret = castle_versions_read();
    if(ret) return -EINVAL;

    printk("Castle FS inited.\n");
    castle_fs_inited = 1;

    castle_events_init();

    return 0;
}

static void castle_slave_superblock_print(struct castle_slave_superblock *cs_sb)
{
    printk("Magic1: %.8x\n"
           "Magic2: %.8x\n"
           "Magic3: %.8x\n"
           "Uuid:   %x\n"
           "Used:   %x\n"
           "Size:   %x\n",
           cs_sb->magic1,
           cs_sb->magic2,
           cs_sb->magic3,
           cs_sb->uuid,
           cs_sb->used,
           cs_sb->size);
}

static int castle_slave_superblock_validate(struct castle_slave_superblock *cs_sb)
{
    if(cs_sb->magic1 != CASTLE_SLAVE_MAGIC1) return -1;
    if(cs_sb->magic2 != CASTLE_SLAVE_MAGIC2) return -2;
    if(cs_sb->magic3 != CASTLE_SLAVE_MAGIC3) return -3;

    return 0;
}

static int castle_slave_superblock_read(struct castle_slave *cs) 
{
    struct castle_slave_superblock cs_sb;
    int err;
   
    /* We're storing the superblock on the stack, make sure it doesn't
       grow too large */
    BUG_ON(sizeof(struct castle_slave_superblock) > PAGE_SIZE >> 2); 
    err = castle_sub_block_read(cs,
                               &cs_sb,
                                0,
                                sizeof(struct castle_slave_superblock),
                                NULL, NULL);
    if(err) 
    {
        printk("Failed to read superblock.\n");
        return err;
    }

    err = castle_slave_superblock_validate(&cs_sb);
    if(err)
        return -EINVAL;
    //castle_slave_superblock_print(&cs_sb);
    /* Save the uuid and exit */
    cs->uuid = cs_sb.uuid;
    
    return 0;
}

struct castle_slave_superblock* castle_slave_superblock_get(struct castle_slave *cs)
{
    lock_c2p(cs->sblk);
    BUG_ON(!c2p_uptodate(cs->sblk));
    
    return ((struct castle_slave_superblock*) pfn_to_kaddr(page_to_pfn(cs->sblk->page)));
}

void castle_slave_superblock_put(struct castle_slave *cs, int dirty)
{
    if(dirty) dirty_c2p(cs->sblk);
    unlock_c2p(cs->sblk);
}

static int castle_slave_superblocks_cache(struct castle_slave *cs)
{
    c2_page_t *c2p, **c2pp[2];
    c_disk_blk_t cdb;
    block_t i;

    /* We want to read the first two 4K blocks of the slave device
       Frist is the slave superblock, the second is the fs superblock */
    c2pp[0] = &cs->sblk;
    c2pp[1] = &cs->fs_sblk;

    for(i=0; i<2; i++)
    {
        /* Read the superblock */
        cdb.disk  = cs->uuid;
        cdb.block = i;
        c2p = castle_cache_page_get(cdb);
        *(c2pp[i]) = c2p;
        /* We expecting the buffer not to be up to date. 
           We check if it got updated later */
        BUG_ON(c2p_uptodate(c2p));
        lock_c2p(c2p);
        submit_c2p_sync(READ, c2p);
        if(!c2p_uptodate(c2p))
        {
            unlock_c2p(c2p);
            return -EIO;
        }
        unlock_c2p(c2p);
    }

    return 0;
}

static int castle_slave_superblocks_init(struct castle_slave *cs)
{
    struct castle_slave_superblock *cs_sb;
    struct castle_fs_superblock *fs_sb;
    int ret = castle_slave_superblocks_cache(cs);

    if(ret) return ret;

    /* If both superblock have been read correctly. Validate or write. */ 
    cs_sb = castle_slave_superblock_get(cs); 
    fs_sb = castle_fs_superblock_get(cs); 

    if(!cs->new_dev)
    {
                 ret = castle_slave_superblock_validate(cs_sb);
        if(!ret) ret = castle_fs_superblock_validate(fs_sb);
    } else
    {
        printk("Initing slave superblock.\n");
        cs_sb->magic1 = CASTLE_SLAVE_MAGIC1;
        cs_sb->magic2 = CASTLE_SLAVE_MAGIC2;
        cs_sb->magic3 = CASTLE_SLAVE_MAGIC3;
        cs_sb->used   = 2; /* Two blocks used for the superblocks */
        cs_sb->uuid   = cs->uuid;
        cs_sb->size   = get_capacity(cs->bdev->bd_disk) >> (C_BLK_SHIFT - 9);
        cs_sb->flags  = CASTLE_SLAVE_TARGET | CASTLE_SLAVE_SPINNING;
        castle_slave_superblock_print(cs_sb);
        printk("Done.\n");
    }
    castle_slave_superblock_put(cs, cs->new_dev);
    castle_freespace_slave_init(cs, cs->new_dev);
    castle_fs_superblock_put(cs, 0);

    return ret;
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
        if(slave->uuid == uuid)
            return slave;
    }

    return NULL;
}

struct castle_slave* castle_slave_find_by_block(c_disk_blk_t cdb)
{
    return castle_slave_find_by_uuid(cdb.disk);
}

static int castle_slave_add(struct castle_slave *cs)
{
    struct list_head *l;
    struct castle_slave *s;

    list_for_each(l, &castle_slaves.slaves)
    {
        s = list_entry(l, struct castle_slave, list);
        if(s->uuid == cs->uuid)
        {
            printk("Uuid of two slaves match (uuid=0x%x, id1=%d, id2=%d)\n", 
                    cs->uuid, s->id, cs->id);
            return -EINVAL;
        }
    }
    /* If no UUID collision, add to the list */
    list_add(&cs->list, &castle_slaves.slaves);
    return 0;
}

struct castle_slave* castle_claim(uint32_t new_dev)
{
    dev_t dev;
    struct block_device *bdev;
    int bdev_claimed = 0, cs_added = 0;
    int err;
    char b[BDEVNAME_SIZE];
    struct castle_slave *cs = NULL;
    static int slave_id = 0;

    if(!(cs = kzalloc(sizeof(struct castle_slave), GFP_KERNEL)))
        goto err_out;
    cs->id = slave_id++;
    cs->last_access = jiffies;

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
    if(err == -EINVAL)
    {
        printk("Invalid superblock. Will initialise a new one.\n");
        get_random_bytes(&cs->uuid, sizeof(cs->uuid));
        printk("Will use uuid of: 0x%x\n", cs->uuid);
        cs->new_dev = 1;
        err = 0;
    }
    if(err)
    {
        printk("Invalid superblock.\n");
        goto err_out;
    }

    err = castle_slave_add(cs);
    if(err)
    {
        printk("Could not add slave to the list.\n");
        goto err_out;
    }
    cs_added = 1;

    err = castle_slave_superblocks_init(cs);
    if(err)
    {
        printk("Could not cache the superblocks.\n");
        goto err_out;
    }

    err = castle_sysfs_slave_add(cs);
    if(err)
    {
        printk("Could not add slave to sysfs.\n");
        goto err_out;
    }
    
    castle_events_slave_claim(cs->id);

    return cs;
err_out:
    if(cs_added)     list_del(&cs->list);
    if(cs->sblk)     put_c2p(cs->sblk);
    if(cs->fs_sblk)  put_c2p(cs->fs_sblk);
    if(bdev_claimed) blkdev_put(bdev);
    if(cs)           kfree(cs);
    return NULL;    
}

void castle_release(struct castle_slave *cs)
{
    castle_events_slave_release(cs->id);
    castle_sysfs_slave_del(cs);
    bd_release(cs->bdev);
    blkdev_put(cs->bdev);
    list_del(&cs->list);
    kfree(cs);
}

struct castle_region* castle_region_find(region_id_t id)
{
    struct list_head *lh;
    struct castle_region *region;

    list_for_each(lh, &castle_regions.regions)
    {
        region = list_entry(lh, struct castle_region, list);
        if(region->id == id)
            return region;
    }

    return NULL;
}

static int castle_region_add(struct castle_region *region)
{
    struct list_head *l;
    struct castle_region *r;

    list_for_each(l, &castle_regions.regions)
    {
        r = list_entry(l, struct castle_region, list);
        /* Check region does not overlap any other */
        if((region->slave == r->slave) && (region->start + region->length > r->start) && (region->start < r->start + r->length))
        {
            printk("Region overlaps another - existing=(start=%d, length=%d) new=(start=%d, length=%d)\n", 
                    r->start, r->length, region->start, region->length);
            return -EINVAL;            
        }
    }
    
    list_add(&region->list, &castle_regions.regions);
    return 0;
}

/*
 * TODO: ref count slaves with regions or something?
 */
struct castle_region* castle_region_create(uint32_t slave_uuid, version_t version, uint32_t start, uint32_t length)
{
    struct castle_region* region = NULL;
    struct castle_slave* slave = NULL;
    static int region_id = 0;
    int err;
    
    printk("castle_region_create(slave_uuid=%d, version=%d, start=%d, length=%d)\n", slave_uuid, version, start, length);
    
    if(length == 0)
    {
        printk("length must be greater than 0!\n");
        goto err_out;
    }
    
    /* To check if a good snapshot version, try and
       get the snapshot.  If we do get it, then we may
       take the 'lock' out on it.  If we do, then
       release the 'lock' */
    err = castle_version_snap_get(version, NULL, NULL, NULL);
    if(err == -EINVAL)
    {
        printk("Invalid version '%d'!\n", version);
        goto err_out;
    }
    else if(err == 0)
        castle_version_snap_put(version);
    
    if(!(region = kzalloc(sizeof(struct castle_region), GFP_KERNEL)))
        goto err_out;
        
    if(!(slave = castle_slave_find_by_uuid(slave_uuid)))
        goto err_out;
    
    region->id = region_id++;
    region->slave = slave;
    region->version = version;
    region->start = start;
    region->length = length;
    
    err = castle_region_add(region);
    if(err)
    {
        printk("Could not add region to the list.\n");
        goto err_out;
    }
    
    err = castle_sysfs_region_add(region);
    if(err) 
    {
         list_del(&region->list);
         goto err_out;
    }
    
    castle_events_region_create(region->id);
    
    return region;
        
err_out:
    if(region) kfree(region);
    return NULL;
}

void castle_region_destroy(struct castle_region *region)
{
    castle_events_region_destroy(region->id);
    castle_sysfs_region_del(region);
    list_del(&region->list);
    kfree(region);
}

static int castle_regions_init(void)
{
    memset(&castle_regions, 0, sizeof(struct castle_regions));
    INIT_LIST_HEAD(&castle_regions.regions);

    return 0;
}

static void castle_regions_free(void)                                                                 
{                                                                                        
    struct list_head *lh, *th;
    struct castle_region *region;

    list_for_each_safe(lh, th, &castle_regions.regions)
    {
        region = list_entry(lh, struct castle_region, list); 
        castle_region_destroy(region);
    }
}

static int castle_open(struct inode *inode, struct file *filp)
{
	struct castle_device *dev = inode->i_bdev->bd_disk->private_data;

	filp->private_data = dev;
	down_write(&dev->lock);
	if (! dev->users) 
		check_disk_change(inode->i_bdev);
	dev->users++;
	up_write(&dev->lock);
	return 0;
}

static int castle_close(struct inode *inode, struct file *filp)
{
	struct castle_device *dev = inode->i_bdev->bd_disk->private_data;

	down_write(&dev->lock);
	dev->users--;
	up_write(&dev->lock);

	return 0;
}

static struct block_device_operations castle_bd_ops = {
	.owner           = THIS_MODULE,
	.open 	         = castle_open,
	.release 	     = castle_close,
	.media_changed   = NULL,
	.revalidate_disk = NULL,
};

void castle_bio_get(c_bio_t *c_bio)
{
    /* This should never called in race with the last _put */
    BUG_ON(atomic_read(&c_bio->count) == 0);
    atomic_inc(&c_bio->count);
}

/* Do not declare this as static because castle_debug calls this directly. 
   But this is the only external reference */
void castle_bio_put(c_bio_t *c_bio)
{
    struct bio *bio = c_bio->bio;
    int finished, err = c_bio->err;

    finished = atomic_dec_and_test(&c_bio->count);
    castle_debug_bio_put(c_bio);
    if(!finished)
        return;

    kfree(c_bio->c_bvecs);
    kfree(c_bio);

    bio_endio(bio, err);
}

void castle_bio_data_io_end(c_bvec_t *c_bvec, int err)
{
    debug("Finished the IO.\n");
    castle_debug_bvec_update(c_bvec, C_BVEC_IO_END);
    if(err) 
    {
        castle_debug_bvec_update(c_bvec, C_BVEC_IO_END_ERR);
        c_bvec->c_bio->err = err;
    }
    castle_bio_put(c_bvec->c_bio);
}
    

static void castle_bio_data_copy(c_bvec_t *c_bvec, c2_page_t *c2p)
{
    int write = (c_bvec_data_dir(c_bvec) == WRITE);
    struct bio *bio = c_bvec->c_bio->bio;
    sector_t sector = bio->bi_sector;
    struct bio_vec *bvec;
    char *bvec_buf, *buf;
    int i;

    /* Find bvec(s) to IO to/from */
    bio_for_each_segment(bvec, bio, i)
    {
        sector_t bv_first_sec   = sector;
        sector_t bv_last_sec    = sector + (bvec->bv_len >> 9);
        sector_t cbv_first_sec  =  c_bvec->block      << (C_BLK_SHIFT - 9);
        sector_t cbv_last_sec   = (c_bvec->block + 1) << (C_BLK_SHIFT - 9);
        sector_t first_sec, last_sec;

        /* Exit if we've already gone too far */
        if(cbv_last_sec < sector)
            break;

        /* Ignore bvecs which touch different sectors than those in c_bvec */
        if((cbv_first_sec >= bv_last_sec) ||
           (cbv_last_sec  <= bv_first_sec))
        {
            sector += (bvec->bv_len >> 9);
            continue;
        }

        /* Work out which sectors to copy */
        first_sec = (bv_first_sec < cbv_first_sec ? cbv_first_sec : bv_first_sec);
        last_sec  = (bv_last_sec  < cbv_last_sec  ? bv_last_sec   : cbv_last_sec);
        
#ifdef CASTLE_DEBUG        
        /* Some sanity checks */
        BUG_ON(last_sec <= first_sec);
        BUG_ON(last_sec > bv_last_sec);
        BUG_ON(last_sec > cbv_last_sec);
        BUG_ON(first_sec < bv_first_sec);
        BUG_ON(first_sec < cbv_first_sec);
#endif        
        
        bvec_buf  = pfn_to_kaddr(page_to_pfn(bvec->bv_page));
        bvec_buf += bvec->bv_offset + ((first_sec - sector) << 9);
        /* If invalid block, we are handling non-allocated block read */
        if(DISK_BLK_INVAL(c_bvec->cdb))
        {
            /* c2p should be NULL */
            BUG_ON(c2p);
            memset(bvec_buf, 0, (last_sec - first_sec) << 9);
        } else
        {
            /* TODO use better macros than page_to_pfn etc */
            buf  = pfn_to_kaddr(page_to_pfn(c2p->page)); 
            buf += (first_sec - cbv_first_sec) << 9;

            memcpy( write ? buf : bvec_buf,
                    write ? bvec_buf : buf,
                   (last_sec - first_sec) << 9);
        }

        sector += (bvec->bv_len >> 9);
    }

    /* Dirty buffers on writes */
    if(write) 
    {
        BUG_ON(!c2p);
        dirty_c2p(c2p);
    }

    /* Unlock buffers */
    if(c2p)
    {
        unlock_c2p(c2p);
        put_c2p(c2p);
    }
        
    /* End the IO (with no error) */ 
    castle_bio_data_io_end(c_bvec, 0); 
}

static void castle_bio_c2p_update(c2_page_t *c2p, int uptodate)
{
    /* TODO: comment when it gets called */
    c_bvec_t *c_bvec = c2p->private;

    if(uptodate)
    {
        castle_debug_bvec_update(c_bvec, C_BVEC_DATA_C2P_UPTODATE);
        set_c2p_uptodate(c2p);
        castle_bio_data_copy(c_bvec, c2p);
    } else
    {
        /* Just drop the lock, if we failed to update */
        unlock_c2p(c2p);
        put_c2p(c2p);
        castle_bio_data_io_end(c_bvec, -EIO);
    }
}

void castle_bio_data_io(c_bvec_t *c_bvec)
{
    c2_page_t *c2p;
    int write = (c_bvec_data_dir(c_bvec) == WRITE);

    castle_debug_bvec_update(c_bvec, C_BVEC_DATA_IO);
    /* 
     * Invalid pointer to on slave data means that it's never been written before.
     * Memset BIO buffer page to zero.
     * This should not happen on writes, since btree handling code should have 
     * allocated a new block (TODO: what if we've just run out of capacity ...)
     */
    if(DISK_BLK_INVAL(c_bvec->cdb))
    {
        castle_debug_bvec_update(c_bvec, C_BVEC_DATA_IO_NO_BLK);
        BUG_ON(write);
        castle_bio_data_copy(c_bvec, NULL);
        return;
    }

    /* Save last_access time in the slave */
    castle_slave_access(c_bvec->cdb.disk);

    c2p = castle_cache_page_get(c_bvec->cdb);
    lock_c2p(c2p);

    /* We don't need to update the c2p if it's already uptodate
       or if we are doing entire page write, in which case we'll
       overwrite previous content anyway */
    if(c2p_uptodate(c2p) || (write && test_bit(CBV_ONE2ONE_BIT, &c_bvec->flags)))
    {
        set_c2p_uptodate(c2p);
        castle_debug_bvec_update(c_bvec, C_BVEC_DATA_C2P_UPTODATE);
        castle_bio_data_copy(c_bvec, c2p);
    } else
    {
        castle_debug_bvec_update(c_bvec, C_BVEC_DATA_C2P_OUTOFDATE);
        c2p->private = c_bvec;
        c2p->end_io = castle_bio_c2p_update;
        submit_c2p(READ, c2p);
    }
}

static int castle_bio_validate(struct bio *bio)
{
    struct bio_vec *bvec;
    int i;
        
    bio_for_each_segment(bvec, bio, i)
    {
        if(((bvec->bv_offset % (1<<9)) != 0) ||  
           ((bvec->bv_len    % (1<<9)) != 0)) 
        {
            printk("Got non aligned IO: len=0x%x, offset=0x%x\n", 
                    bvec->bv_len, bvec->bv_offset);
            return -EINVAL;
        }
    }

    return 0;
}

static void castle_device_c_bvec_make(c_bio_t *c_bio, 
                                      int idx, 
                                      sector_t block,
                                      int one2one_bvec)
{
    /* Create an appropriate c_bvec */
    c_bvec_t *c_bvec = c_bio->c_bvecs + idx;

    /* Get a reference */
    castle_bio_get(c_bio);

    /* Init the c_bvec */
    c_bvec->c_bio        = c_bio;
    c_bvec->block        = block;
    c_bvec->version      = INVAL_VERSION; 
    if(one2one_bvec)
        set_bit(CBV_ONE2ONE_BIT, &c_bvec->flags);
    castle_debug_bvec_update(c_bvec, C_BVEC_INITIALISED);

    /* Submit the c_bvec for processing */
    castle_ftree_find(c_bvec); 
}
 
static int castle_device_make_request(struct request_queue *rq, struct bio *bio)
{ 
    c_bio_t *c_bio = NULL;
    c_bvec_t *c_bvecs = NULL;
    struct castle_device *dev = rq->queuedata;
    struct bio_vec *bvec;
    sector_t sector, last_block;
    int i, j;

    debug("Request on dev=0x%x\n", MKDEV(dev->gd->major, dev->gd->first_minor));
    /* Check if we can handle this bio */
    if(castle_bio_validate(bio))
        goto fail_bio;

    c_bio   = kmalloc(sizeof(c_bio_t), GFP_NOIO);
    /* We'll generate at most bi_vcnt + 1 castle_bio_vecs (for full page, 
       unaligned bvecs) */
    c_bvecs = kzalloc(sizeof(c_bvec_t) * (bio->bi_vcnt + 1), GFP_NOIO);
    if(!c_bio || !c_bvecs) 
        goto fail_bio;
    
    c_bio->c_dev   = dev;
    c_bio->bio     = bio;
    c_bio->c_bvecs = c_bvecs; 
    /* Take reference to the c_bio before handling all the bvecs.
       Do it directly (castle_bio_get(c_bio) doesn't work with ref_cnt=0). */
    atomic_set(&c_bio->count, 1);
    c_bio->err     = 0;

    sector     = bio->bi_sector;
    last_block = -1;
    j          = 0;
    bio_for_each_segment(bvec, bio, i)
    {
        sector_t block   = sector >> (C_BLK_SHIFT - 9);
        sector_t bv_secs = (bvec->bv_len >> 9);
        int aligned = !(sector % (1 << (C_BLK_SHIFT - 9)));
        int one2one = aligned && (bvec->bv_len == C_BLK_SIZE);

        /* Check if block number is different to the previous one.
           If so, init and submit a new c_bvec. */
        if(block != last_block)
            castle_device_c_bvec_make(c_bio, j++, block, one2one);
        last_block = block;

        /* Check this bvec shouldn't be split into two c_bvecs now. */
        block = (sector + bv_secs - 1) >> (C_BLK_SHIFT - 9);
        if(block != last_block)
        {
            /* We should have only advanced by one block */
            BUG_ON(block != last_block + 1);
            /* Make sure we never try to use too many c_bvecs 
               (we've got bi_vcnt + 1) */
            BUG_ON(j > bio->bi_vcnt);
            /* Block cannot possibly correspond to one bvec exactly */
            BUG_ON(one2one);
            /* Submit the request */
            castle_device_c_bvec_make(c_bio, j++, block, one2one);
        }
        last_block = block;

        /* Advance the sector counter */
        sector += bv_secs;
    }
    castle_debug_bio_add(c_bio, dev->version, j);
    castle_bio_put(c_bio);

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
    version_t version = cd->version;
    
    castle_events_device_detach(cd->gd->major, cd->gd->first_minor);

    castle_sysfs_device_del(cd);
    /* TODO: Should this be done? blk_cleanup_queue(cd->gd->rq); */ 
    del_gendisk(cd->gd);
    put_disk(cd->gd);
    list_del(&cd->list);
    kfree(cd);
    castle_version_snap_put(version);
}

struct castle_device* castle_device_init(version_t version)
{
    struct castle_device *dev = NULL;
    struct request_queue *rq  = NULL;
    struct gendisk *gd        = NULL;
    static int minor = 0;
    uint32_t size;
    int leaf;
    int err;

    if(castle_version_snap_get(version, NULL, &size, &leaf))
        goto error_out;

    dev = kmalloc(sizeof(struct castle_device), GFP_KERNEL); 
    if(!dev)
        goto error_out;
	init_rwsem(&dev->lock);
    dev->version = version;
        
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
    if(!leaf) 
        set_disk_ro(gd, 1);

    list_add(&dev->list, &castle_devices.devices);
    dev->gd = gd;
    
    set_capacity(gd, (size << (C_BLK_SHIFT - 9)));
    add_disk(gd);

    bdget(MKDEV(gd->major, gd->first_minor));
    err = castle_sysfs_device_add(dev);
    if(err) 
    {
        /* TODO: this doesn't do bdput. device_free doesn't 
                 do this neither, and it works ... */
        del_gendisk(gd);
        list_del(&dev->list);
        goto error_out;
    }

    castle_events_device_attach(gd->major, gd->first_minor, version);

    return dev;

error_out:
    if(gd)  put_disk(gd); 
    if(rq)  blk_cleanup_queue(rq); 
    if(dev) kfree(dev);
    printk("Failed to init device.\n");
    return NULL;    
}

void castle_slave_access(uint32_t uuid)
{
    struct castle_slave_superblock *sb;
    struct castle_slave *cs;

    cs = castle_slave_find_by_uuid(uuid);
    BUG_ON(!cs);
    cs->last_access = jiffies; 
        
    sb = castle_slave_superblock_get(cs);
    if(!(sb->flags & CASTLE_SLAVE_SPINNING))
    {
        sb->flags |= CASTLE_SLAVE_SPINNING;
        castle_slave_superblock_put(cs, 1);
        castle_events_spinup(cs->id);
    } else
        castle_slave_superblock_put(cs, 0);
}

static void castle_slaves_spindown(struct work_struct *work)
{
    struct castle_slave_superblock *sb;
    struct list_head *l;

    list_for_each(l, &castle_slaves.slaves)
    {
        struct castle_slave *cs = list_entry(l, struct castle_slave, list);

        sb = castle_slave_superblock_get(cs);
        if(!(sb->flags & CASTLE_SLAVE_SPINNING))
        {
            castle_slave_superblock_put(cs, 0);
            continue;
        }
        /* This slave is spinning, check if there was an access to it within
           the spindown period */
        if((cs->last_access + 30 * HZ < jiffies) &&
           !(sb->flags & CASTLE_SLAVE_TARGET))
        {
            sb->flags &= ~CASTLE_SLAVE_SPINNING; 
            castle_slave_superblock_put(cs, 1);
            castle_events_spindown(cs->id);
        } else
            castle_slave_superblock_put(cs, 0);
    }
}
    
static struct timer_list spindown_timer; 
static void castle_slaves_spindowns_check(unsigned long first)
{
    static struct work_struct work_item;
    unsigned long sleep = 5*HZ;

    /* NOTE: This should really check if we've got waitqueues initialised
       at the moment we assume 10s is enough for that */
    if(first)
        sleep = 10*HZ;
    else
    {
        INIT_WORK(&work_item, castle_slaves_spindown);
        queue_work(castle_wq, &work_item); 
    }
    /* Reschedule ourselves */
    setup_timer(&spindown_timer, castle_slaves_spindowns_check, 0);
    __mod_timer(&spindown_timer, jiffies + sleep);
}

static int castle_slaves_init(void)
{
    memset(&castle_slaves, 0, sizeof(struct castle_slaves));
    INIT_LIST_HEAD(&castle_slaves.slaves);

    castle_slaves_spindowns_check(1);

    return 0;
}

static void castle_slaves_unlock(void)                                                                 
{                                                                                        
    struct list_head *lh, *th;
    struct castle_slave *slave;

    list_for_each_safe(lh, th, &castle_slaves.slaves)
    {
        slave = list_entry(lh, struct castle_slave, list); 
        put_c2p(slave->sblk);
        put_c2p(slave->fs_sblk);
    }
}

static void castle_slaves_free(void)                                                                 
{                                                                                        
    struct list_head *lh, *th;
    struct castle_slave *slave;

    del_singleshot_timer_sync(&spindown_timer);

    list_for_each_safe(lh, th, &castle_slaves.slaves)
    {
        slave = list_entry(lh, struct castle_slave, list); 
        castle_release(slave);
    }
}

static int castle_devices_init(void)
{
    int i, major;
    char *wq_names[MAX_BTREE_DEPTH+1];

    memset(&castle_devices, 0, sizeof(struct castle_devices));
    INIT_LIST_HEAD(&castle_devices.devices);

    /* Allocate a major for this device */
    if((major = register_blkdev(0, "castle-fs")) < 0) 
    {
        printk("Couldn't register castle device\n");
        return -ENOMEM;
    }
    castle_devices.major = major;

    memset(wq_names  , 0, sizeof(char *) * (MAX_BTREE_DEPTH+1));
    memset(castle_wqs, 0, sizeof(struct workqueue_struct *) * (MAX_BTREE_DEPTH+1));
    for(i=0; i<=MAX_BTREE_DEPTH; i++)
    {
        /* At most two characters for the number */
        BUG_ON(i > 99);
        wq_names[i] = kmalloc(strlen("castle_wq")+3, GFP_KERNEL);
        if(!wq_names[i])
            goto err_out;
        sprintf(wq_names[i], "castle_wq%d", i);
        castle_wqs[i] = create_workqueue(wq_names[i]);
        if(!castle_wqs[i])
            goto err_out;
    }

    return 0;

err_out:
    printk("Could not create worqueues.\n");
    
    for(i=0; i<=MAX_BTREE_DEPTH; i++)
    {
        if(wq_names[i])
            kfree(wq_names[i]); 
        if(castle_wqs[i]) 
            destroy_workqueue(castle_wqs[i]);
    }
    unregister_blkdev(castle_devices.major, "castle-fs"); 

    return -ENOMEM;
}

static void castle_devices_free(void)                                                                 
{                                                                                        
    struct list_head *lh, *th;
    struct castle_device *dev;
    int i;

    list_for_each_safe(lh, th, &castle_devices.devices)
    {
        dev = list_entry(lh, struct castle_device, list); 
        castle_device_free(dev);
    }

    if (castle_devices.major)
        unregister_blkdev(castle_devices.major, "castle-fs");

    for(i=0; i<=MAX_BTREE_DEPTH; i++)
        destroy_workqueue(castle_wqs[i]);
}

static int __init castle_init(void)
{
    int ret;

    printk("Castle FS init ... ");

    castle_fs_inited = 0;
              castle_debug_init();
    if((ret = castle_slaves_init()))    goto err_out1;
    if((ret = castle_cache_init()))     goto err_out2;
    if((ret = castle_versions_init()))  goto err_out3;
    if((ret = castle_btree_init()))     goto err_out4;
    if((ret = castle_freespace_init())) goto err_out5;
    if((ret = castle_devices_init()))   goto err_out6;
    if((ret = castle_control_init()))   goto err_out7;
    if((ret = castle_regions_init()))   goto err_out8;
    if((ret = castle_transfers_init())) goto err_out9;
    if((ret = castle_sysfs_init()))     goto err_out10;

    printk("OK.\n");

    return 0;

    castle_sysfs_fini(); /* Unreachable */
err_out10:
    castle_transfers_free();
err_out9:
    castle_regions_free();
err_out8:
    castle_control_fini();
err_out7:
    castle_devices_free();
err_out6:
    castle_freespace_fini();
err_out5:
    castle_btree_free();
err_out4:
    castle_versions_fini();
err_out3:
    /* Cannot fini the cache without unlocking slave superblocks
       but we shouldn't have any slaves at this point. Still, check
       that */
    BUG_ON(!list_empty(&castle_slaves.slaves));
    castle_cache_fini();
err_out2:
    castle_slaves_free();
err_out1:
    castle_debug_fini();

    /* TODO: check if kernel will accept any non-zero return value to mean: we want to exit */
    return ret;
}


static void __exit castle_exit(void)
{
    printk("Castle FS exit ... ");

    castle_transfers_free();
    castle_regions_free();
    castle_control_fini();
    castle_devices_free();
    castle_freespace_fini();
    castle_btree_free();
    castle_versions_fini();
    castle_slaves_unlock();
    castle_cache_fini();
    castle_slaves_free();
    castle_sysfs_fini();
    castle_debug_fini();

    printk("done.\n\n\n");
}

module_init(castle_init);
module_exit(castle_exit);

MODULE_LICENSE("GPL");

