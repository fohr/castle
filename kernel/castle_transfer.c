#include <linux/bio.h>
#include <linux/kobject.h>
#include <linux/blkdev.h>
#include <linux/random.h>
#include <linux/crc32.h>
#include <linux/sched.h>
#include <linux/kernel.h>

#include "castle_public.h"
#include "castle.h"
#include "castle_cache.h"
#include "castle_btree.h"
#include "castle_transfer.h"
#include "castle_sysfs.h"
#include "castle_versions.h"
#include "castle_freespace.h"
#include "castle_events.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)     ((void)0)
#else
#define debug(_f, _a...)   (printk("Transfer:%.60s:%.4d:  " _f, __func__, __LINE__ , ##_a))
#endif

struct castle_transfers castle_transfers;

static void castle_block_move(struct castle_transfer *transfer, int index, c_disk_blk_t cdb);

static void castle_transfer_each(c_iter_t *c_iter, 
                                 int index, 
                                 void *key,
                                 version_t version,
                                 c_val_tup_t cvt)
{
    struct castle_transfer *transfer = container_of(c_iter, struct castle_transfer, c_iter);

    debug("---> (0x%x, %d)\n", cvt.cdb.disk, cvt.cdb.block);

    castle_block_move(transfer, index, cvt.cdb);
}

static void castle_transfer_node_start(c_iter_t *c_iter)
{
    struct castle_transfer *transfer = container_of(c_iter, struct castle_transfer, c_iter);

    debug("Transfer=%d\n", transfer->id);

    BUG_ON(atomic_read(&transfer->phase) != 0);

    atomic_inc(&transfer->phase);
}

static void castle_transfer_node_end(c_iter_t *c_iter)
{
    struct castle_transfer *transfer = container_of(c_iter, struct castle_transfer, c_iter);

    debug("Transfer=%d\n", transfer->id);
    
    if (atomic_dec_and_test(&transfer->phase)) 
        castle_btree_iter_continue(&transfer->c_iter);
}

static void castle_transfer_end(c_iter_t *c_iter, int err)
{
    struct castle_transfer *transfer = container_of(c_iter, struct castle_transfer, c_iter);

    debug("castle_transfer_end transfer=%d, err=%d\n", transfer->id, err);
    printk("castle_transfer_end transfer=%d, err=%d\n", transfer->id, err);

    transfer->finished = 1;
    complete(&transfer->completion);

    castle_events_transfer_finished(transfer->id, err);
}

static void castle_transfer_start(struct castle_transfer *transfer)
{
    printk("====> Starting transfer %d.\n", transfer->id);
    transfer->c_iter.private    = transfer;        
    transfer->c_iter.tree       = &castle_global_tree;
    transfer->c_iter.node_start = castle_transfer_node_start;
    transfer->c_iter.each       = castle_transfer_each;
    transfer->c_iter.node_end   = castle_transfer_node_end;
    transfer->c_iter.end        = castle_transfer_end;

    init_completion(&transfer->completion);
    atomic_set(&transfer->phase, 0);
    castle_btree_iter_init(&transfer->c_iter, transfer->version, C_ITER_MATCHING_VERSIONS);
    castle_btree_iter_start(&transfer->c_iter);
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

/*static int castle_regions_get(version_t version, struct castle_region*** regions_ret)
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

    // TODO race if someone comes and add another region between the first count and here

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
}*/

void castle_transfer_destroy(struct castle_transfer *transfer)
{
    printk("====> Destroying transfer %d.\n", transfer->id);
    debug("castle_transfer_destroy id=%d\n", transfer->id);
    
    castle_btree_iter_cancel(&transfer->c_iter, -EINTR);
    wait_for_completion(&transfer->completion);
    
    castle_events_transfer_destroy(transfer->id);    
    castle_sysfs_transfer_del(transfer);

    list_del(&transfer->list);
    kfree(transfer);    

    debug("castle_transfer_destroy'd id=%d\n", transfer->id);
}

static int castle_transfer_check(struct castle_transfer *transfer)
{
    struct list_head *l;
    struct castle_transfer *t;

    list_for_each(l, &castle_transfers.transfers)
    {
        t = list_entry(l, struct castle_transfer, list);
        if(t->finished)
            continue;
        if(t->version == transfer->version)
        {
            printk("Found existing transfer when creating transfer "
                   "id=%d, version=%d, direction=%d\n"
                   "The other transfer is: id=%d, direction=%d\n", 
                    transfer->id, transfer->version, transfer->direction,
                    t->id, t->direction);
            return -EBUSY;
        }
    }

    return 0;
}

struct castle_transfer* castle_transfer_create(version_t version, int direction, int *ret)
{
    struct castle_transfer* transfer = NULL;
    static int transfer_id = 0;
    int err = 0;
    
    BUG_ON(ret == NULL);

    debug("castle_transfer_create(version=%d, direction=%d)\n", version, direction);

    err = castle_version_read(version, NULL, NULL, NULL, NULL);
    if(err)
    {
        debug("Invalid version '%d'!\n", version);
        goto err_out;
    }

    if(!(transfer = kzalloc(sizeof(struct castle_transfer), GFP_KERNEL)))
    {
        err = -ENOMEM;
        goto err_out;
    }

    transfer->id = transfer_id++;
    transfer->version = version;
    transfer->direction = direction;
    
    if((err = castle_transfer_check(transfer)) != 0)
        goto err_out;

    castle_transfer_add(transfer);

    err = castle_sysfs_transfer_add(transfer);
    if(err) 
    {
         list_del(&transfer->list);
         goto err_out;
    }

    castle_transfer_start(transfer);

    castle_events_transfer_create(transfer->id);

    printk("castle_transfer_create(version=%d, direction=%d) -> id=%d\n", 
            version, direction, transfer->id);

    BUG_ON(err != 0);
    *ret = 0;
    return transfer;

err_out:
    printk("castle_transfer_create has failed.\n");
    if(transfer)          kfree(transfer);

    BUG_ON(err == 0);
    *ret = err;
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

    debug("Freeing transfer.\n");

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
    int target;

    switch (transfer->direction)
    {
        case CASTLE_TRANSFER_TO_TARGET:
            sb = castle_slave_superblock_get(slave);
            target = sb->flags & CASTLE_SLAVE_TARGET ? 1 : 0;
            castle_slave_superblock_put(slave, 0);
            return target;
    
 /*       case CASTLE_TRANSFER_TO_REGION:
            // check the block is on one of the regions' slaves
            for (i = 0; i < transfer->regions_count; i++)
            {
                region = transfer->regions[i];
                if ((region->slave)->uuid == cdb.disk)
                    return true;
            }
        
            return false;
*/            
        default:
            BUG();
            return false;
    }
}

static c_disk_blk_t castle_transfer_destination_get(struct castle_transfer *transfer)
{
    c_disk_blk_t cdb = INVAL_DISK_BLK;
    
    debug("transfer->regions_count=%i\n", transfer->regions_count);
    
    switch (transfer->direction)
    {
        case CASTLE_TRANSFER_TO_TARGET:
            cdb = castle_freespace_block_get(transfer->version, 1);
            break;
            
/*        case CASTLE_TRANSFER_TO_REGION:
            for (i = 0; (i < transfer->regions_count) && DISK_BLK_INVAL(cdb); i++)
            {
                region = transfer->regions[i];
            
                if (castle_freespace_version_slave_blocks_get(region->slave, region->version) >= 
                    region->length)
                    continue;
                    
                debug("region=%i\n", region->id);
            
                // this will update the summaries... 
                cdb = castle_freespace_slave_block_get(region->slave, region->version, 1);

                debug("cdb=(%i,%i)\n", cdb.disk, cdb.block);
            }
            break;*/
        
        default:
            BUG();
    }

    return cdb;
}

struct castle_block_move_info
{
    int                     index;
    union {
        c2_block_t          *dest;
        c_disk_blk_t        dest_cdb;
    };
    c_disk_blk_t            src_cdb;
    struct castle_transfer *transfer;
    int                     err;
    struct work_struct      work;
};

static void castle_block_move_complete(struct work_struct *work)
{
    struct castle_block_move_info *info = container_of(work, struct castle_block_move_info, work);
    struct castle_transfer *transfer = info->transfer;
    c_disk_blk_t src_cdb = info->src_cdb;
    c_disk_blk_t dest_cdb = info->dest_cdb;
    int index = info->index;
    int err = info->err;

    /* Save last_access time in the slave */
    castle_slave_access(src_cdb.disk);
    castle_slave_access(dest_cdb.disk);

    kfree(info);
    if(!err)
    {
        c_val_tup_t dest_cvt;
        CDB_TO_CVT(dest_cvt, dest_cdb, 1);
        /* Update counters etc... */
        castle_btree_iter_replace(&transfer->c_iter, index, dest_cvt);
        castle_freespace_block_free(src_cdb, transfer->version, 1);
        atomic_inc(&transfer->progress);
    }

    /* if all the block moves have succeeded then continue to next btree block */
    if (atomic_dec_and_test(&transfer->phase)) 
        castle_btree_iter_continue(&transfer->c_iter);  
}

static void castle_block_move_io_end(c2_block_t *src, int uptodate)
{
    struct castle_block_move_info *info = src->private;
    c2_block_t *dest = info->dest;

    debug("Index=%d, transfer=%d\n", info->index, info->transfer->id);
    
    BUG_ON(info->err != 0);
    if (!uptodate)
    {
        debug("Not uptodate, cancelling...\n");
        
        /* 
         * This will eventually call c_iter->end, which is 
         * castle_transfer_error, on the next iter_continue.
         * It's safe to use it from the interrupt context because 
         * it initially only sets a flag. 
         */        
        castle_btree_iter_cancel(&info->transfer->c_iter, -EIO);
        info->err = -EIO;
    }    
    else
    {
        set_c2b_uptodate(src);

        memcpy(c2b_buffer(dest), c2b_buffer(src), PAGE_SIZE);
        set_c2b_uptodate(dest);
        dirty_c2b(dest);

#ifdef DEBUG        
        memcpy(c2b_buffer(src), "----MOVED----", strlen("----MOVED----"));
        dirty_c2b(src);
#endif        

        /* Save CDBs for move_complete */
        info->src_cdb  = src->cdb;
        info->dest_cdb = dest->cdb;
    }

    unlock_c2b(dest);
    put_c2b(dest);
        
    unlock_c2b(src);
    put_c2b(src);   

    CASTLE_INIT_WORK(&info->work, castle_block_move_complete);
    queue_work(castle_wqs[MAX_BTREE_DEPTH-1], &info->work);
}    

static void castle_block_move(struct castle_transfer *transfer, int index, c_disk_blk_t cdb)
{
    c2_block_t *src, *dest;
    c_disk_blk_t dest_db;
    struct castle_block_move_info *info;
    
    debug("Index=%d, transfer=%d\n", index, transfer->id);

    if (castle_transfer_is_block_on_correct_disk(transfer, cdb))
    {
        debug("Index=%d, block on correct disk...\n", index);
        atomic_add(1, &transfer->progress);
        return;
    }
    
    if(!(info = kzalloc(sizeof(struct castle_block_move_info), GFP_KERNEL)))
    {
        castle_btree_iter_cancel(&transfer->c_iter, -ENOMEM);
        return;
    }
    
    debug("Index=%d, getting src...\n", index);
    
    src = castle_cache_page_block_get(cdb);
    lock_c2b(src);
    
    dest_db = castle_transfer_destination_get(transfer);
    if (DISK_BLK_INVAL(dest_db))
    {
        debug("Index=%d, couldn't find free block, cancelling\n", index);
        
        kfree(info);
        
        unlock_c2b(src);
        put_c2b(src);
                
        /* 
         * this will eventually call c_iter->end, which is 
         * castle_transfer_error, on the next iter_continue
         */
        castle_btree_iter_cancel(&transfer->c_iter, -ENOMEM); //ENOMEM? or EOUTOFDISKSPACE?
        return;
    }
    
    debug("Index=%d, getting dest...\n", index);
    
    dest = castle_cache_page_block_get(dest_db);
    debug("Index=%d, locking dest...\n", index);
    lock_c2b(dest);
        
    info->index    = index;
    info->dest     = dest;
    info->transfer = transfer;
    info->err      = 0;
        
    src->private = info;
        
    atomic_inc(&transfer->phase);
        
    if(!c2b_uptodate(src)) 
    {
        debug("Index=%d, not uptodate, submitting...\n", index);
        src->end_io = castle_block_move_io_end;
        submit_c2b(READ, src);
    }
    else
    {
        debug("Index=%d, uptodate, continuing...\n", index);
        castle_block_move_io_end(src, true);
    }
}

