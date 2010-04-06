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
#include "castle_cache.h"
#include "castle_btree.h"
#include "castle_transfer.h"
#include "castle_sysfs.h"
#include "castle_versions.h"
#include "castle_freespace.h"

struct castle_transfers      castle_transfers;

static void castle_move_block(struct castle_transfer *transfer, c_disk_blk_t cdb);
static void castle_transfer_error(struct castle_transfer *transfer, int err); 

static void castle_iter_each(c_iter_t *c_iter, c_disk_blk_t cdb)
{
    struct castle_transfer *transfer = container_of(c_iter, struct castle_transfer, c_iter);

    printk("castle_iter_each: (%d, %d)\n", cdb.disk, cdb.block);
	
	castle_move_block(transfer, cdb);
}

static void castle_iter_error(c_iter_t *c_iter, int err)
{
    struct castle_transfer *transfer = container_of(c_iter, struct castle_transfer, c_iter);

    printk("castle_iter_error: %d\n", err);

	castle_transfer_error(transfer, err);
}

static void castle_iter_end(c_iter_t *c_iter)
{
    printk("castle_iter_end\n");
}

static void castle_transfer_start(struct castle_transfer *transfer)
{
    transfer->c_iter.private = transfer;        
    transfer->c_iter.version = transfer->version;
    transfer->c_iter.each    = castle_iter_each;
    transfer->c_iter.end     = castle_iter_end;
    transfer->c_iter.error   = castle_iter_error;

    castle_ftree_iter(&transfer->c_iter);
}

static void castle_transfer_error(struct castle_transfer *transfer, int err)
{
  /* TODO need callback to userspace */
}

static void castle_transfer_add(struct castle_transfer *transfer)
{    
    list_add(&transfer->list, &castle_transfers.transfers);
}

struct castle_transfer* castle_transfer_find(transfer_id_t id)
{
    struct list_head *lh;
    struct castle_transfer *transfer;

    list_for_each(lh, &castle_transfers.transfers)
    {
        transfer = list_entry(lh, struct castle_transfer, list);
        if(transfer->id == id)
            return transfer;
    }

    return NULL;
}

static int castle_regions_get(version_t version, struct castle_region*** regions_ret)
{
    struct list_head *lh;
    struct castle_region *region;
    struct castle_region **regions;
    int count, i;

    count = i = 0;

    BUG_ON(regions_ret != NULL);

    list_for_each(lh, &castle_regions.regions)
    {
        region = list_entry(lh, struct castle_region, list);
        if (region->version == version)
            count ++;
    }

    if (!(*regions = kzalloc(count * sizeof(struct castle_region*), GFP_KERNEL)))
        return -ENOMEM;

    /* TODO race if someone comes and add another region between the first count and here */

    list_for_each(lh, &castle_regions.regions)
    {
        region = list_entry(lh, struct castle_region, list);
        if (region->version == version)
        {
            regions[i] = region;
            i ++;
        }
    }
    
    *regions_ret = regions;

    return count;
}

void castle_transfer_destroy(struct castle_transfer *transfer)
{
    castle_sysfs_transfer_del(transfer);
    list_del(&transfer->list);
    kfree(transfer->regions);
    kfree(transfer);
}

struct castle_transfer* castle_transfer_create(version_t version, int direction)
{
    struct castle_transfer* transfer = NULL;
    static int transfer_id = 0;
    int err;

    printk("castle_transfer_create(version=%d, direction=%d)\n", version, direction);

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

    if(!(transfer = kzalloc(sizeof(struct castle_transfer), GFP_KERNEL)))
    {
        err = -ENOMEM;
        goto err_out;
    }

    transfer->id = transfer_id++;
    transfer->version = version;
    transfer->direction = direction;
    transfer->regions_count = err = castle_regions_get(version, &transfer->regions);
    
    if(transfer->regions_count < 0)
        goto err_out;

    castle_transfer_add(transfer);

    err = castle_sysfs_transfer_add(transfer);
    if(err) 
    {
         list_del(&transfer->list);
         goto err_out;
    }

    castle_transfer_start(transfer);

    return transfer;

err_out:
    if(transfer->regions) kfree(transfer->regions);
    if(transfer) kfree(transfer);
    return NULL;
}

int castle_transfers_init(void)
{
    memset(&castle_transfers, 0, sizeof(struct castle_transfers));
    INIT_LIST_HEAD(&castle_transfers.transfers);

    return 0;
}

void castle_transfers_free(void)                                                        
{                                                                                        
    struct list_head *lh, *th;
    struct castle_transfer *transfer;

    list_for_each_safe(lh, th, &castle_transfers.transfers)
    {
        transfer = list_entry(lh, struct castle_transfer, list); 
        castle_transfer_destroy(transfer);
    }
}

static void castle_do_transfer_callback(c2_page_t *src, int uptodate);

static int castle_transfer_is_block_on_correct_disk(struct castle_transfer *transfer, c_disk_blk_t cdb)
{
    struct castle_slave *slave = castle_slave_find_by_block(cdb);
    struct castle_slave_superblock *sb;
    struct castle_region *region;
    int target, i;

    if (transfer->direction == CASTLE_TRANSFER_TO_TARGET)
    {
        sb = castle_slave_superblock_get(slave);
        target = sb->flags & CASTLE_SLAVE_TARGET ? 1 : 0;
        castle_slave_superblock_put(slave, 0);
        return target;
    }
    else if (transfer->direction == CASTLE_TRANSFER_TO_REGION)
    {
        /* check the block is on one of the regions' slaves */
        for (i = 0; i < transfer->regions_count; i++)
        {
            region = transfer->regions[i];
            if ((region->slave)->uuid == cdb.disk)
                return true;
        }
        
        return false;
    } 
    else 
        BUG_ON(true);
}

static c_disk_blk_t castle_transfer_get_destination(struct castle_transfer *transfer)
{
    
    int i;
    struct castle_region *region;
    c_disk_blk_t cdb = INVAL_DISK_BLK;
    
    switch (transfer->direction)
    {
        case CASTLE_TRANSFER_TO_TARGET:
            cdb = castle_freespace_block_get(transfer->version);
            break;
            
        case CASTLE_TRANSFER_TO_REGION:
            for (i = 0; (i < transfer->regions_count) && DISK_BLK_INVAL(cdb); i++)
            {
                region = transfer->regions[i];
            
                if (castle_freespace_blks_for_version_get(region->slave, region->version) >= region->length)
                    continue;
            
                //cdb = castle_freespace_cdb_get(region->slave, region->version)
            }
            break;
        
        default:
             BUG_ON(true);
             break;
    }

    return cdb;
}

static void castle_move_block(struct castle_transfer *transfer, c_disk_blk_t cdb)
{
    c2_page_t *src, *dest;
    c_disk_blk_t dest_db;
    
    printk("castle_move_block transfer=%d\n", transfer->id);

    if (true) //!castle_transfer_is_block_on_correct_disk(transfer, cdb))
    {
        atomic_add(1, &transfer->progress);
        castle_ftree_iter_continue(&transfer->c_iter);
        return;
    }

    src = castle_cache_page_get(cdb);
    lock_c2p(src);
    
    dest_db = castle_transfer_get_destination(transfer);
    
    dest = castle_cache_page_get(dest_db);
    lock_c2p(dest);
        
    dest->private = transfer;
    src->private = dest;
        
    if(!c2p_uptodate(src)) 
    {
        src->end_io = castle_do_transfer_callback;
        submit_c2p(READ, src);
    }
    else
    {
        castle_do_transfer_callback(src, true);
    }
}

static void castle_do_transfer_callback(c2_page_t *src, int uptodate)
{
    c2_page_t *dest = src->private;
    struct castle_transfer *transfer = dest->private;

	printk("castle_do_transfer_callback transfer=%d\n", transfer->id);
    
    if (!uptodate)
    {
        memcpy(c2p_buffer(dest), c2p_buffer(src), PAGE_SIZE);

        dirty_c2p(dest);
    }
    else
    {
        castle_transfer_error(transfer, -EIO);
    }
        
    unlock_c2p(src);
    put_c2p(src);   
    
    unlock_c2p(dest);
    put_c2p(dest);

    /* Update counters etc... */
    castle_freespace_block_free(src->cdb);
    atomic_add(1, &transfer->progress);

    castle_ftree_iter_continue(&transfer->c_iter);
}
