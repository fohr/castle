#include <linux/module.h>
#include <linux/bio.h>
#include <linux/kobject.h>
#include <linux/device-mapper.h>
#include <linux/blkdev.h>
#include <linux/random.h>
#include <linux/crc32.h>
#include <linux/sched.h>
#include <asm/semaphore.h>

#include "castle_public.h"
#include "castle.h"
#include "castle_cache.h"
#include "castle_btree.h"
#include "castle_transfer.h"
#include "castle_sysfs.h"
#include "castle_versions.h"
#include "castle_freespace.h"

#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)  ((void)0)
#else
#define debug(_f, _a...)  (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

struct castle_transfers      castle_transfers;

static void castle_block_move(struct castle_transfer *transfer, int index, c_disk_blk_t cdb);

static void castle_transfer_each(c_iter_t *c_iter, int index, c_disk_blk_t cdb)
{
    struct castle_transfer *transfer = container_of(c_iter, struct castle_transfer, c_iter);

    debug("castle_transfer_each: (0x%x, %d)\n", cdb.disk, cdb.block);

    castle_block_move(transfer, index, cdb);
}

static void castle_transfer_node_start(c_iter_t *c_iter)
{
    struct castle_transfer *transfer = container_of(c_iter, struct castle_transfer, c_iter);

    debug("castle_transfer_block_start: transfer=%d\n", transfer->id);

    BUG_ON(atomic_read(&transfer->phase) != 0);

    atomic_inc(&transfer->phase);
}

static void castle_transfer_node_end(c_iter_t *c_iter)
{
    struct castle_transfer *transfer = container_of(c_iter, struct castle_transfer, c_iter);

    debug("castle_transfer_block_end: transfer=%d\n", transfer->id);
    
    if (atomic_dec_and_test(&transfer->phase)) 
        castle_ftree_iter_continue(&transfer->c_iter);
}

static void castle_transfer_end(c_iter_t *c_iter, int err)
{
    struct castle_transfer *transfer = container_of(c_iter, struct castle_transfer, c_iter);

    debug("castle_transfer_end: transfer=%d, err=%d\n", transfer->id, err);

    complete(&transfer->completion);

    /* TODO need callback to userspace */
    //if (!err)
    //    castle_transfer_error(transfer, err);
}

static void castle_transfer_start(struct castle_transfer *transfer)
{
    transfer->c_iter.private    = transfer;        
    transfer->c_iter.version    = transfer->version;
    transfer->c_iter.node_start = castle_transfer_node_start;
    transfer->c_iter.each       = castle_transfer_each;
    transfer->c_iter.node_end   = castle_transfer_node_end;
    transfer->c_iter.end        = castle_transfer_end;

    init_completion(&transfer->completion);
    atomic_set(&transfer->phase, 0);
    castle_ftree_iter(&transfer->c_iter);
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

    BUG_ON(*regions_ret != NULL);

    list_for_each(lh, &castle_regions.regions)
    {
        region = list_entry(lh, struct castle_region, list);
        if (region->version == version)
            count ++;
    }

    if (!(regions = kzalloc(count * sizeof(struct castle_region*), GFP_KERNEL)))
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
    debug("castle_transfer_destroy: transfer=%d\n", transfer->id);
    
    castle_ftree_iter_cancel(&transfer->c_iter, -EINTR);
    wait_for_completion(&transfer->completion);
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

    debug("castle_transfer_create(version=%d, direction=%d)\n", version, direction);

    /* To check if a good snapshot version, try and
       get the snapshot.  If we do get it, then we may
       take the 'lock' out on it.  If we do, then
       release the 'lock' */
    err = castle_version_snap_get(version, NULL, NULL, NULL);
    if(err == -EINVAL)
    {
        debug("Invalid version '%d'!\n", version);
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

    debug("castle_transfers_free\n");

    list_for_each_safe(lh, th, &castle_transfers.transfers)
    {
        transfer = list_entry(lh, struct castle_transfer, list); 
        castle_transfer_destroy(transfer);
    }
}

static int castle_transfer_is_block_on_correct_disk(struct castle_transfer *transfer, c_disk_blk_t cdb)
{
    struct castle_slave *slave = castle_slave_find_by_block(cdb);
    struct castle_slave_superblock *sb;
    struct castle_region *region;
    int target, i;

    switch (transfer->direction)
    {
        case CASTLE_TRANSFER_TO_TARGET:
            sb = castle_slave_superblock_get(slave);
            target = sb->flags & CASTLE_SLAVE_TARGET ? 1 : 0;
            castle_slave_superblock_put(slave, 0);
            return target;
    
        case CASTLE_TRANSFER_TO_REGION:
            /* check the block is on one of the regions' slaves */
            for (i = 0; i < transfer->regions_count; i++)
            {
                region = transfer->regions[i];
                if ((region->slave)->uuid == cdb.disk)
                    return true;
            }
        
            return false;
            
        default:
            BUG_ON(true);
    }
}

static c_disk_blk_t castle_transfer_destination_get(struct castle_transfer *transfer)
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
            
                /* this will update the freespace mapping... */
                cdb = castle_freespace_slave_block_get(region->slave, region->version);
            }
            break;
        
        default:
            BUG_ON(true);
    }

    return cdb;
}

// I just want this after the next function so its looks more inline
static void castle_transfer_callback(c2_page_t *src, int uptodate);

struct castle_block_move_info
{
    int                     index;
    c2_page_t               *dest;
    struct castle_transfer  *transfer;
};

static void castle_block_move(struct castle_transfer *transfer, int index, c_disk_blk_t cdb)
{
    c2_page_t *src, *dest;
    c_disk_blk_t dest_db;
    struct castle_block_move_info *info;
    
    debug("castle_move_block: index=%d, transfer=%d\n", index, transfer->id);

    if (castle_transfer_is_block_on_correct_disk(transfer, cdb))
    {
        debug("castle_move_block: index=%d, block on correct disk...\n", index);
        atomic_add(1, &transfer->progress);
        return;
    }
    
    if(!(info = kzalloc(sizeof(struct castle_block_move_info), GFP_KERNEL)))
    {
        castle_ftree_iter_cancel(&transfer->c_iter, -ENOMEM);
        return;
    }
    
    src = castle_cache_page_get(cdb);
    lock_c2p(src);
    
    dest_db = castle_transfer_destination_get(transfer);
    if (DISK_BLK_INVAL(dest_db))
    {
        debug("castle_move_block: index=%d, couldn't find free block, cancelling\n", index);
        
        kfree(info);
        
        unlock_c2p(src);
        put_c2p(src);
                
        /* 
         * this will eventually call c_iter->end, which is 
         * castle_transfer_error, on the next iter_continue
         */
        castle_ftree_iter_cancel(&transfer->c_iter, -ENOMEM); //ENOMEM? or EOUTOFDISKSPACE?
        return;
    }
    
    dest = castle_cache_page_get(dest_db);
    lock_c2p(dest);
        
    info->index    = index;
    info->dest     = dest;
    info->transfer = transfer;
        
    src->private = info;
        
    atomic_inc(&transfer->phase);
        
    if(!c2p_uptodate(src)) 
    {
        debug("castle_move_block: index=%d, not uptodate, submitting...\n", index);
        src->end_io = castle_transfer_callback;
        submit_c2p(READ, src);
    }
    else
    {
        debug("castle_move_block: index=%d, uptodate, continuing...\n", index);
        castle_transfer_callback(src, true);
    }
}

static void castle_transfer_callback(c2_page_t *src, int uptodate)
{
    struct castle_block_move_info *info = src->private;
    int index = info->index;
    c2_page_t *dest = info->dest;
    struct castle_transfer *transfer = info->transfer;

    debug("castle_do_transfer_callback: index=%d, transfer=%d\n", index, transfer->id);
    
    kfree(info);
    
    if (!uptodate)
    {
        debug("castle_do_transfer_callback: not uptodate, cancelling...\n");
        
        /* 
         * this will eventually call c_iter->end, which is 
         * castle_transfer_error, on the next iter_continue
         */        
        castle_ftree_iter_cancel(&transfer->c_iter, -EIO);
    }    
    else
    {
        memcpy(c2p_buffer(dest), c2p_buffer(src), PAGE_SIZE);
        dirty_c2p(dest);
    }
        
    unlock_c2p(src);
    put_c2p(src);   
    
    unlock_c2p(dest);
    put_c2p(dest);

    if (uptodate)
    {
        /* Update counters etc... */
        castle_ftree_iter_replace(&transfer->c_iter, index, dest->cdb);
        castle_freespace_block_free(src->cdb, transfer->version);
        atomic_inc(&transfer->progress);
    }

    /* if all the block moves have succeeded then continue to next btree block */
    if (atomic_dec_and_test(&transfer->phase)) 
        castle_ftree_iter_continue(&transfer->c_iter);  
}
