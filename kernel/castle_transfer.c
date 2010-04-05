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

struct castle_transfers      castle_transfers;

//struct list_head castle_transfers_queue;

//DEFINE_MUTEX(castle_transfers_mutex);
//DECLARE_WAIT_QUEUE_HEAD(castle_transfers_wait_queue);

static void castle_transfer_add(struct castle_transfer *transfer)
{
//    mutex_lock(&castle_transfers_mutex);
    
    list_add(&transfer->list, &castle_transfers.transfers);
//    list_add_tail(&transfer->list, &castle_transfers_queue);
    
//   mutex_unlock(&castle_transfers_mutex);
//   wake_up (&castle_transfers_wait_queue);
}

/*struct castle_transfer* castle_get_next_transfer(void)
{
    castle_transfer* transfer = NULL;
    
    mutex_lock (&castle_transfers_mutex);
    while (list_empty(castle_transfers_queue)) {
        mutex_unlock (&castle_transfers_mutex);
        wait_event (&castle_transfers_wait_queue, list_empty(castle_transfers_queue));
        mutex_lock (&castle_transfers_mutex);
    }

    transfer = list_first_entry(&castle_transfers_queue, struct castle_transfer, list);
    list_del(&transfer->list);

    mutex_unlock (&castle_transfers_mutex);
}*/

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

static c_disk_blk_t castle_iter_each(c_iter_t *iter, c_disk_blk_t cdb)
{
    printk("castle_iter_each: (%d, %d)", cdb.disk, cdb.block);
    return cdb;
}

static void castle_iter_error(c_iter_t *iter, int err)
{
    printk("castle_iter_error: %d", err);
}

void castle_init_ftree_iter(struct castle_transfer *transfer)
{
    c_iter_t *c_iter;
    
    if(!(c_iter = kzalloc(sizeof(c_iter_t), GFP_KERNEL)))
        return;

    c_iter->private = transfer;        
    c_iter->version = transfer->version;
    c_iter->each    = castle_iter_each;
    c_iter->end     = NULL;
    c_iter->error   = castle_iter_error;

    castle_ftree_iter(c_iter);
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
    else if(err == -EAGAIN)
    {
        castle_version_snap_put(version);
    }

    if(!(transfer = kzalloc(sizeof(struct castle_transfer), GFP_KERNEL)))
        goto err_out;

    transfer->id = transfer_id++;
    transfer->version = version;
    transfer->direction = direction;

    castle_transfer_add(transfer);

    err = castle_sysfs_transfer_add(transfer);
    if(err) 
    {
         list_del(&transfer->list);
         goto err_out;
    }

    castle_init_ftree_iter(transfer);

    return transfer;

err_out:
    if(transfer) kfree(transfer);
    return NULL;
}

void castle_transfer_destroy(struct castle_transfer *transfer)
{
    castle_sysfs_transfer_del(transfer);
    list_del(&transfer->list);
    kfree(transfer);
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

/*void castle_abort_transfer(struct castle_transfer *transfer, int reason, )
{
    
}

void castle_do_transfer(struct castle_transfer *transfer)
{
    c2_page_t *src, *dest;
    
    while(true)
    {
        src = get_c2p();
        lock_c2p(src);
        
        dest = get_c2p();
        lock_c2p(dest);
        
        dest->private = transfer;
        src->private = dest;
        
        if(!c2p_up2date(src)) {
            src->callback = castle_do_transfer_callback;
            submit_c2p(READ, src);
        }
        else
        {
            castle_do_transfer_callback(src)
        }
    }
}

void castle_do_transfer_callback(c2_page_t *src, int uptodate)
{
    c2_page_t *dest = src->private;
    castle_transfer *transfer = dest->private;
    
    if (!uptodate) 
    {
        memcpy(c2p_buffer(dest), c2p_buffer(src), PAGE_SIZE);

        dirty_c2p(dest);
    }
    else
    {
        castle_abort_transfer(transfer, )
    }
    
    unlock_c2p(src);
    put_c2p(src);   
    
    unlock_c2p(dest);
    put_c2p(dest);
}*/
