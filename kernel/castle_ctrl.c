#include <linux/genhd.h>
#include <linux/miscdevice.h>
#include <linux/skbuff.h>
#include <asm/uaccess.h>
#include <linux/hardirq.h>
#include <linux/mutex.h>

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
#include "castle_trace.h"
#include "castle_extent.h"
#include "castle_rebuild.h"
#include "castle_ctrl_prog.h"
#include "castle_mstore.h"

/* Define string array for userspace error-codes. */
#undef CASTLE_ERROR_CODE
#define CASTLE_ERROR_CODE(err_no, err_code, err_str)  [err_no] = err_str,
const char *castle_error_strings[CASTLE_ERROR_MAX+1] =
{
    CASTLE_ERRORS
};

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)  ((void)0)
#else
#define debug(_f, _a...)  (castle_printk(LOG_DEBUG, "%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

static DEFINE_MUTEX(castle_control_lock);
static DECLARE_WAIT_QUEUE_HEAD(castle_control_wait_q);

struct task_struct *ctrl_lock_holder = NULL;
void castle_ctrl_lock(void)
{
    mutex_lock(&castle_control_lock);
    ctrl_lock_holder = current;
}

void castle_ctrl_unlock(void)
{
    /* if we BUG here, it means we just did a CASTLE_TRANSACTION_END without
       first doing a CASTLE_TRANSACTION_BEGIN. */
    BUG_ON(!castle_ctrl_is_locked());
    ctrl_lock_holder = NULL;
    mutex_unlock(&castle_control_lock);
}

int castle_ctrl_is_locked(void)
{
    return mutex_is_locked(&castle_control_lock);
}

void castle_control_claim(uint32_t dev, int *ret, c_slave_uuid_t *id)
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

void castle_control_attach(c_ver_t version, int *ret, uint32_t *dev)
{
    struct castle_attachment *cd;

    if (!DA_INVAL(castle_version_da_id_get(version)))
    {
        castle_printk(LOG_WARN, "Couldn't attach device to collection.\n");
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

/**
 * Create a new doubling array.
 *
 * @param size  Size of new doubling array (as a multiple of C_BLK_SIZE)
 *              If size == 0 a new collection tree is to be created
 *
 * @return ret  0   SUCCESS
 *              -1  FAILURE
 * @return id   Root version of newly created doubling array
 *              -1 in case of failure
 *
 * @also castle_double_array_make()
 */
void castle_control_create(uint64_t size, int *ret, c_ver_t *id)
{
    castle_control_create_with_opts(size, CASTLE_DA_OPTS_NONE, ret, id);
}
void castle_control_create_with_opts(uint64_t size, c_da_opts_t opts, int *ret, c_ver_t *id)
{
    int collection_tree = (size == 0);
    c_da_t da_id = INVAL_DA;
    c_ver_t version;

    if(collection_tree)
    {
        castle_printk(LOG_USERINFO, "Creating a collection version tree.\n");
        da_id = castle_next_da_id++;
    }

    /* If size isn't zero, make sure it's a multiple of block size. */
    if(size % C_BLK_SIZE != 0)
    {
        castle_printk(LOG_ERROR,
                "When creating a block device size must be a multiple of %d, got %lld.\n",
                C_BLK_SIZE, size);
        goto err_out;
    }

    /* Create a new version which will act as the root for this version tree */
    *ret = castle_version_new(0, /* clone */
                              0, /* root version */
                              da_id,
                              size,
                              &version);

    /* We use doubling arrays for collection trees */
    if (collection_tree && (*ret = castle_double_array_make(da_id, version, opts)))
    {
        /* Free the created version. */
        BUG_ON(castle_version_free(version));

        castle_printk(LOG_ERROR, "Failed creating doubling array for version: %d\n", version);
        version = INVAL_VERSION;
    }

    if(VERSION_INVAL(version))
        goto err_out;
    *id  = version;
    *ret = 0;
    return;

err_out:
    *id  = -1;
}

/**
 * Clone an existing version.
 *
 * @param   version [in]    Version to clone
 * @param   ret     [out]   Return code from operation
 * @param   clone   [out]   Resulting version ID of clone
 *
 * @return  0           Version cloned successfully
 * @return -EINVAL      Attempted to clone version 0
 * @return -ECANCELED   Version marked for deletion
 * @return -EROFS       Version is non-leaf
 * @return -EUNATCH     Version is attached
 * @return -EFBIG       Global version limit reached
 * @return -E2BIG       Per-DA live version limit reached
 * @return -EEXIST      Non-existent parent
 * @return -ENOMEM      Allocation failure
 */
void castle_control_clone(c_ver_t version, int *ret, c_ver_t *clone)
{
    if (version == 0)
    {
        castle_printk(LOG_WARN, "Do not clone version 0. Create a new volume.\n");
        *clone = 0;
        *ret   = -EINVAL;
        return;
    }

    if (castle_version_deleted(version))
    {
        castle_printk(LOG_WARN, "Version is already marked for deletion. Can't clone it.\n");
        *clone = 0;
        *ret = -ECANCELED;
        return;
    }

    /* Try to create a new version in the version tree */
    *ret = castle_version_new(0,             /* clone */
                              version,
                              INVAL_DA,      /* da_id: take parent's */
                              0,             /* size:  take parent's */
                              &version);
    BUG_ON(*ret == 0 && VERSION_INVAL(version));
    BUG_ON(*ret != 0 && !VERSION_INVAL(version));
    if (VERSION_INVAL(version))
        *clone = 0;
    else
        *clone = version;
}

void castle_control_snapshot(uint32_t dev, int *ret, c_ver_t *version)
{
    dev_t devid = new_decode_dev(dev);
    struct castle_attachment *cd = castle_device_find(devid);
    c_ver_t ver, old_version;

    if(!cd)
    {
        *version = -1;
        *ret     = -ENOENT;
        return;
    }
    down_write(&cd->lock);
    old_version = cd->version;
    *ret = castle_version_new(1,            /* snapshot */
                             cd->version,
                             INVAL_DA,      /* take da_id from the parent */
                             0,             /* take size from the parent */
                             &ver);
    if(VERSION_INVAL(ver))
    {
        *version = -1;
        *ret     = -EINVAL; // currently ignoring castle_version_new()
    }
    else
    {
        /* Attach the new version */
        BUG_ON(castle_version_attach(ver));
        /* Change the version associated with the device */
        cd->version    = ver;
        /* Release the old version */
        castle_version_detach(old_version);
        *version = old_version;
        *ret     = 0;
    }
    up_write(&cd->lock);

    castle_events_device_snapshot(ver, cd->dev.gd->major, cd->dev.gd->first_minor);
}

void castle_control_fs_init(int *ret)
{
    *ret = castle_fs_init();
}

static int castle_collection_writeback(struct castle_mstore *mstore, struct castle_attachment *ca)
{
    struct castle_alist_entry mstore_entry;

    BUG_ON(strlen(ca->col.name) > MAX_NAME_SIZE);

    debug("Collection add: %s,%u\n", ca->col.name, ca->version);

    mstore_entry.version = ca->version;
    mstore_entry.flags   = ca->col.flags;
    strcpy(mstore_entry.name, ca->col.name);

    castle_mstore_entry_insert(mstore,
                               &mstore_entry,
                               sizeof(struct castle_alist_entry));

    return 0;
}

int castle_attachments_writeback(void)
{ /* Should be called in CASTLE_TRANSACTION. */
    struct castle_mstore *mstore;
    struct castle_attachment *ca;
    struct list_head *lh;

    mstore = castle_mstore_init(MSTORE_ATTACHMENTS_TAG);
    if(!mstore)
        return -ENOMEM;

    /* Note: Shouldn't take attachments lock here. Writeback function can sleep.
     * This function should be called in CASTLE_TRANSACTION and it guarantees
     * no changes to attachments list. */
    /* Writeback attachments. */
    list_for_each(lh, &castle_attachments.attachments)
    {
        ca = list_entry(lh, struct castle_attachment, list);
        if(ca->device)
            continue;
        if(castle_collection_writeback(mstore, ca))
            castle_printk(LOG_WARN, "Failed to writeback collection: (%u, %s)\n",
                    ca->col.id, ca->col.name);
    }

    castle_mstore_fini(mstore);

    return 0;
}

int castle_attachments_read(void)
{
    struct castle_mstore_iter *iterator = NULL;
    int ret = 0;

    iterator = castle_mstore_iterate(MSTORE_ATTACHMENTS_TAG);
    if (!iterator)
    {
        ret = -EINVAL;
        goto out;
    }

    while (castle_mstore_iterator_has_next(iterator))
    {
        struct castle_alist_entry mstore_entry;
        struct castle_attachment *ca;
        size_t mstore_entry_size;
        char *name = castle_alloc(MAX_NAME_SIZE);

        BUG_ON(!name);
        castle_mstore_iterator_next(iterator, &mstore_entry, &mstore_entry_size);
        BUG_ON(mstore_entry_size != sizeof(struct castle_alist_entry));
        strcpy(name, mstore_entry.name);
        debug("Collection Load: %s\n", name);

        ca = castle_collection_init(mstore_entry.version, mstore_entry.flags, name);
        if(!ca)
        {
            castle_printk(LOG_WARN, "Failed to create Collection (%s, %u)\n",
                    mstore_entry.name, mstore_entry.version);
            ret = -EINVAL;
            goto out;
        }
        castle_printk(LOG_USERINFO, "Created Collection (%s, %u) with id: %u\n",
                mstore_entry.name, mstore_entry.version, ca->col.id);
    }

out:
    if (iterator)
        castle_mstore_iterator_destroy(iterator);

    return ret;
}

void castle_control_collection_attach(c_ver_t            version,
                                      char              *name,
                                      int               *ret,
                                      c_collection_id_t *collection)
{
    struct list_head            *lh;
    struct castle_attachment *ca;
    uint32_t flags = 0;

    BUG_ON(strlen(name) > MAX_NAME_SIZE);

    /* Check for, and reject, duplicate collection names. */
    list_for_each(lh, &castle_attachments.attachments)
    {
        ca = list_entry(lh, struct castle_attachment, list);
        if (ca->device)
            continue;
        if (strcmp(name, ca->col.name) == 0)
        {
            castle_printk(LOG_WARN, "Collection name %s already exists\n", ca->col.name);
            castle_free(name);
            *ret = -EEXIST;
            return;
        }
    }

    if (castle_version_deleted(version))
    {
        castle_printk(LOG_WARN, "Version is already marked for deletion. Can't be attached\n");
        castle_free(name);
        *ret = -EINVAL;
        return;
    }

    /* Check if the read-only flag can be set. */
    /* Note: If an attachment is marked as RD_ONLY it can't be changed back to writable,
     * even when the version becomes writable (all children got deleted). */
    if (!castle_version_is_mutable(version))
        __set_bit(CASTLE_ATTACH_RDONLY, &flags);

    ca = castle_collection_init(version, flags, name);
    if(!ca)
    {
        castle_printk(LOG_WARN, "Couldn't find collection for version: %u\n", version);
        *ret = -EINVAL;
        return;
    }
    castle_printk(LOG_USERINFO, "Creating new Collection Attachment %u (%s, %u)\n",
            ca->col.id, ca->col.name, ca->version);

    *collection = ca->col.id;
    *ret = 0;
}

void castle_control_collection_reattach(c_collection_id_t  collection,
                                        c_ver_t            new_version,
                                        int               *ret)
{
    struct castle_attachment *ca;
    c_da_t new_da_id, old_da_id;
    c_ver_t old_version;
    int err;

    /* Checks on new_version. It must exist and it mustn't be deleted. */
    if((err = castle_version_deleted(new_version)))
    {
        /* -EINVAL means that version doesn't exist. */
        if(err == -EINVAL)
            castle_printk(LOG_WARN,
                          "Version %d doesn't exist. Collection %d cannot be re-attached\n",
                          new_version, collection);
        else
            castle_printk(LOG_WARN,
                          "Version %d is already marked for deletion. "
                          "Collection %d cannot be re-attached\n",
                          new_version, collection);
        *ret = -EINVAL;
        return;
    }

    /* It mustn't be attached. */
    if(castle_version_attached(new_version))
    {
        castle_printk(LOG_WARN,
                      "Version %d is already attached. Collection %d cannot be re-attached\n",
                      new_version, collection);
        *ret = -EEXIST;
        return;
    }

    /* Next, try to get the attachment. */
    ca = castle_attachment_get(collection, READ);
    if(!ca)
    {
        castle_printk(LOG_WARN,
                      "Collection %d cannot be re-attached, it cannot be found.\n",
                      collection);
        *ret = -ENODEV;
        return;
    }
    old_version = ca->version;
    /* Current version must be attached. */
    BUG_ON(!castle_version_attached(old_version));

    /* Check whether DA associated with the new_version matches the old version's DA. */
    BUG_ON(castle_version_read(new_version, &new_da_id, NULL, NULL, NULL, NULL));
    BUG_ON(castle_version_read(old_version, &old_da_id, NULL, NULL, NULL, NULL));
    if(new_da_id != old_da_id)
    {
        castle_printk(LOG_WARN,
                      "Version %d and %d are not from the same doubling array (%d, %d)."
                      "Collection %d cannot be re-attached\n",
                      new_version, old_version, new_da_id, old_da_id, collection);
        castle_attachment_put(ca);
        *ret = -EBADE;
        return;
    }

    /* We are past the point of no-return. Version will be changed. Attach it.
       This should never fail, since we checked whether version is attached earlier on,
       and we are doing everything under control lock. */
    BUG_ON(castle_version_attach(new_version));

    /* Get lock on the collection, we are going to be changing the version. */
    down_write(&ca->lock);
    ca->version = new_version;
    /* Set read-only bit if the version is not leaf. */
    if (!castle_version_is_mutable(new_version))
        __set_bit(CASTLE_ATTACH_RDONLY, &ca->col.flags);
    up_write(&ca->lock);

    /* Detach the old version. */
    castle_version_detach(old_version);

    /* Send an event to userspace. */
    castle_events_collection_reattach(ca->col.id, new_version);

    /* Put the temporary attachment reference. */
    castle_attachment_put(ca);

    *ret = 0;
}


void castle_control_collection_detach(c_collection_id_t  collection,
                                      int               *ret)
{
    struct castle_attachment *ca = castle_attachment_get(collection, READ);
    if (!ca)
    {
        *ret = -ENODEV;
        return;
    }

    /* Matk attachment as deleted. */
    castle_attachment_free(ca);

    castle_events_collection_detach(ca->col.id);

    castle_printk(LOG_USERINFO, "Deleting Collection Attachment %u (%s, %u)/%u\n",
            collection, ca->col.name, ca->version, ca->ref_cnt);

    /* Release reference. */
    castle_attachment_put(ca);

    /* Release transaction lock, we don't want to block on attachment delete with the lock. */
    CASTLE_TRANSACTION_END;

    /* Complete free. This would block until attachment is removed. */
    castle_attachment_free_complete(ca);

    /* Get the lock again and finish the ioctl. */
    CASTLE_TRANSACTION_BEGIN;

    *ret = 0;
}

void castle_control_collection_snapshot(c_collection_id_t collection,
                                        int *ret,
                                        c_ver_t *version)
{
    struct castle_attachment *ca = castle_attachment_get(collection, READ);
    c_ver_t ver, old_version;

    if(!ca)
    {
        *version = -1;
        *ret     = -ENOENT;
        return;
    }
    down_write(&ca->lock);
    old_version  = ca->version;
    *ret = castle_version_new(1,            /* snapshot */
                              ca->version,
                              INVAL_DA,     /* take da_id from the parent */
                              0,            /* take size  from the parent */
                              &ver);
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
        *version = old_version;
        *ret     = 0;
    }
    up_write(&ca->lock);

    castle_events_collection_snapshot(ver, ca->col.id);
    castle_attachment_put(ca);
}

/**
 * Marks a version for delete. Attached version couldn't be marked for deletion.
 * Data gets deleted during merges (or occasional compaction).
 *
 * @param version [in] Version to delete.
 * @param ret [out] Returns non-zero on failure.
 *
 * @see castle_control_destroy
 */
void castle_control_collection_snapshot_delete(c_ver_t version,
                                               int *ret)
{
    if (DA_INVAL(castle_version_da_id_get(version)))
    {
        castle_printk(LOG_WARN, "Version %d is not deletable. DA doesn't exist.\n", version);
        *ret = -EINVAL;
        return;
    }

    if (castle_version_attached(version))
    {
        castle_printk(LOG_WARN, "Version %d is attached. Couldn't be deleted.\n", version);
        *ret = -EINVAL;
        return;
    }

    if (castle_version_deleted(version))
    {
        castle_printk(LOG_WARN, "Version %d is already deleted. Couldn't be deleted.\n", version);
        *ret = -EINVAL;
        return;
    }

    *ret = castle_version_delete(version);

    return;
}

void castle_control_protocol_version(int *ret, uint32_t *version)
{
    *ret = 0;
    *version = CASTLE_PROTOCOL_VERSION;
}

void castle_control_environment_set(c_env_var_t var_id, char *var_str, int *ret)
{
    /* Check that the id is in range. */
    if(var_id >= NR_ENV_VARS)
    {
        castle_free(var_str);
        *ret = -EINVAL;
        return;
    }

    /* Save the environment var. */
    strncpy(castle_environment[var_id], var_str, MAX_ENV_LEN);
    castle_free(var_str);

    *ret = 0;
}

/**
 * Handle a fault request (for testing).
 *
 * @param fault     The fault code.
 * @param arg       An argument for the fault.
 */
void castle_control_fault(uint32_t fault, uint32_t fault_arg, int *ret)
{
    *ret = 0;
    castle_fault = fault;
    castle_fault_arg = fault_arg;
    debug("castle_control_fault got fault %u arg 0x%x\n", castle_fault, castle_fault_arg);
}

void castle_control_trace_setup(char *dir, int *ret)
{
    *ret = castle_trace_setup(dir);
}

void castle_control_trace_start(int *ret)
{
    *ret = castle_trace_start();
}

void castle_control_trace_stop(int *ret)
{
    *ret = castle_trace_stop();
}

void castle_control_trace_teardown(int *ret)
{
    *ret = castle_trace_teardown();
}

/**
 * Check extents for mappings containing a slave (currently used for testing only).
 *
 * @param uuid      The slave to check for
 * @param ret       Returns EINVAL if slave is already marked as out-of-service
 *                  Returns EEXIST if slave is already marked as evacuated
 *                  Returns ENOENT if slave was not found
 *                  Returns EXIT_SUCCESS if slave is now marked as evacuated
 */
void castle_control_slave_scan(uint32_t uuid, int *ret)
{
    *ret = castle_extents_slave_scan(uuid);
}

/**
 * Initiate evacuation (removal from service) of a slave
 *
 * @param uuid      The slave to evacuate
 * @param force     0 = evacuate, 1 = oos (a.k.a. force evacuate).
 * @param ret       Returns EEXIST if slave is already marked as out-of-service
 *                          or evacuating.
 *                  Returns EINVAL if force argument is invalid.
 *                  Returns ENOENT if slave was not found
 *                  Returns EXIT_SUCCESS if slave is now marked as evacuated
 */
void castle_control_slave_evacuate(uint32_t uuid, uint32_t force, int *ret)
{
    struct  castle_slave *slave;
    struct  list_head *lh;
    int     nr_live_slaves=0;

    if (force != 0 && force != 1)
    {
        castle_printk(LOG_WARN, "Error: invalid evacuation force argument %d. "
                                "Ignoring request.\n", force);
        *ret = -EINVAL;
        return;
    }

    slave = castle_slave_find_by_uuid(uuid);
    if(!slave)
    {
        castle_printk(LOG_WARN, "Error: slave 0x%x not found. Ignoring request.\n", uuid);
        *ret = -ENOENT;
        return;
    }

    /*
     * If this slave is not an SSD, make sure that we will preserve the minimum number of working
     * disks. Forced evacuation is not allowed if any extents in this fs are 1 RDA.
     */
    if (!(slave->cs_superblock.pub.flags & CASTLE_SLAVE_SSD))
    {
        struct  castle_slave *cs;

        rcu_read_lock();
        list_for_each_rcu(lh, &castle_slaves.slaves)
        {
            cs = list_entry(lh, struct castle_slave, list);
            if (force)
            {
                /* If there's a another slave already oos (but not yet remapped), then reject. */
                if (test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags) &&
                    !test_bit(CASTLE_SLAVE_REMAPPED_BIT, &cs->flags) &&
                    cs->uuid != uuid)
                {
                    castle_printk(LOG_WARN, "Error: forced evacuation rejected. Another disk "
                                  "is already out-of-service but not yet remapped.\n");
                    *ret = -EPERM;
                    return;
                }
            }
            if (!test_bit(CASTLE_SLAVE_EVACUATE_BIT, &cs->flags) &&
                !test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags) &&
                !(cs->cs_superblock.pub.flags & CASTLE_SLAVE_SSD))
                nr_live_slaves++;
        }
        rcu_read_unlock();

        BUG_ON(nr_live_slaves < MIN_LIVE_SLAVES);

        if (((castle_extent_min_rda_lvl_get() == RDA_1) && (force == 1)) ||
             (nr_live_slaves == MIN_LIVE_SLAVES))
        {
            castle_printk(LOG_WARN, "Error: evacuation rejected to preserve minimum "
                          "number of working disks.\n");
            *ret = -EPERM;
            return;
        }
    }

    if (test_bit(CASTLE_SLAVE_GHOST_BIT, &slave->flags))
    {
        /* Slave is a 'ghost' - missing from the expected set of slaves - error */
        castle_printk(LOG_WARN, "Error: slave 0x%x is missing. Ignoring.\n", slave->uuid);
        *ret = -ENOSYS;
        return;
    }

    if (test_bit(CASTLE_SLAVE_OOS_BIT, &slave->flags))
    {
        /* Slave is already marked as out-of-service - ignore */
        castle_printk(LOG_WARN, "Warning: slave 0x%x [%s] has already been marked out-of-service. "
               "Ignoring request.\n",
                slave->uuid, slave->bdev_name);
        *ret = -EEXIST;
        return;
    }

    /* All of the below is happening under the ioctl lock, so we don't have to use atomic
       test_and_set. */
    if (test_bit(CASTLE_SLAVE_EVACUATE_BIT, &slave->flags))
    {
        /* Slave is already marked as evacuated - ignore */
        castle_printk(LOG_WARN, "Warning: slave 0x%x [%s] has already been evacuated. Ignoring.\n",
                slave->uuid, slave->bdev_name);
        *ret = -EEXIST;
        return;
    }

    /*
     * Mark that this slave is evacuating or out-of-service. Allocations from this slave
     * should now stop, and all future I/O submissions should ignore this slave.
     */
    if (force)
    {
        set_bit(CASTLE_SLAVE_OOS_BIT, &slave->flags);
        castle_printk(LOG_USERINFO, "Slave 0x%x [%s] has been marked as out-of-service.\n",
                      slave->uuid, slave->bdev_name);
        if (atomic_read(&slave->io_in_flight) == 0)
            castle_release_device(slave);

    } else
    {
        set_bit(CASTLE_SLAVE_EVACUATE_BIT, &slave->flags);
        castle_printk(LOG_USERINFO, "Slave 0x%x [%s] has been marked as evacuating.\n",
                      slave->uuid, slave->bdev_name);
    }
    castle_extents_rebuild_wake();
    *ret = EXIT_SUCCESS;
}

int castle_nice_value = -5;

/**
 * Change priority of a work thread. This function gets scheduled by driver
 * function castle_wq_priority_set.
 */
static void castle_thread_priority_set(struct work_struct *work)
{
    int nice_value;

    memcpy(&nice_value, &work->data, sizeof(int));
    set_user_nice(current, castle_nice_value);
    /* It is safe to free work structure here. Kernel is not going to use it
     * anymore.*/
    castle_free(work);
}

/**
 * Set nice value for all threads in a WQ to global nice value.
 *
 * This function just schedules the priority_set() which would change the
 * priority later.
 */
void castle_wq_priority_set(struct workqueue_struct *wq)
{
    int cpu;

    if (!wq)
        return;

    for_each_online_cpu(cpu)
    {
        struct work_struct *work;

        work = castle_alloc(sizeof(struct work_struct));
        if (!work)
        {
            castle_printk(LOG_WARN, "Couldn't allocate memory for work structures, not able to"
                   "change nice value\n");
            return;
        }

        CASTLE_INIT_WORK(work, castle_thread_priority_set);
        queue_work_on(cpu, wq, work);
    }
}

extern struct workqueue_struct *castle_back_wq;
extern struct task_struct *castle_cache_flush_thread;
extern struct task_struct *checkpoint_thread;
extern struct task_struct *extproc_thread;
extern struct task_struct *resubmit_thread;
#ifdef CASTLE_DEBUG
extern struct task_struct *debug_thread;
#endif
#ifdef CASTLE_PERF_DEBUG
extern struct task_struct *time_thread;
#endif

/**
 * Change nice value of merge threads and castle_back threads
 *
 * @param nice_value [in] nice value that the merge process has to be set to.
 *                        (High priority) -19 < nice_value < 19 (Low priority)
 * @param ret [out] return value
 */
void castle_control_thread_priority(int nice_value, int *ret)
{
    int i;

    /* Set the global nice value. */
    castle_nice_value = nice_value;

    /* Change nice value for DA threads. */
    castle_da_threads_priority_set(nice_value);

    /* Castle back threads. */
    castle_wq_priority_set(castle_back_wq);

    /* B-Tree work queues. */
    for(i=0; i<=2*MAX_BTREE_DEPTH; i++)
        castle_wq_priority_set(castle_wqs[i]);

    /* Cache threads. */
    set_user_nice(castle_cache_flush_thread, nice_value);

    /* Checkpoint thread. */
    set_user_nice(checkpoint_thread, nice_value);

    /* Rebuild threads. */
    set_user_nice(extproc_thread, nice_value);
    set_user_nice(resubmit_thread, nice_value);

    *ret = 0;
}

static int castle_control_fs_inited = 0;
int castle_control_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int err;
    void __user *udata = (void __user *) arg;
    cctrl_ioctl_t ioctl;

    if(_IOC_TYPE(cmd) != CASTLE_CTRL_IOCTL_TYPE)
    {
        castle_printk(LOG_WARN, "Unknown IOCTL: 0x%x\n", cmd);
        return -EINVAL;
    }

    if (copy_from_user(&ioctl, udata, sizeof(cctrl_ioctl_t)))
        return -EFAULT;

    if(_IOC_NR(cmd) != ioctl.cmd)
    {
        castle_printk(LOG_WARN, "IOCTL number %d, doesn't agree with the command number %d.\n",
                _IOC_NR(cmd), ioctl.cmd);
        return -EINVAL;
    }

    if(!castle_control_fs_inited && (ioctl.cmd != CASTLE_CTRL_CLAIM) &&
                                    (ioctl.cmd != CASTLE_CTRL_INIT) &&
                                    (ioctl.cmd != CASTLE_CTRL_PROTOCOL_VERSION) &&
                                    (ioctl.cmd != CASTLE_CTRL_ENVIRONMENT_SET) &&
                                    (ioctl.cmd != CASTLE_CTRL_FAULT) &&
                                    (ioctl.cmd != CASTLE_CTRL_SLAVE_EVACUATE) &&
                                    (ioctl.cmd != CASTLE_CTRL_SLAVE_SCAN) &&
                                    (ioctl.cmd != CASTLE_CTRL_STATE_QUERY))
    {
        castle_printk(LOG_WARN, "Disallowed ctrl op %d, before fs gets inited.\n", ioctl.cmd);
        return -EINVAL;
    }

    if(castle_control_fs_inited && (ioctl.cmd == CASTLE_CTRL_INIT))
    {
        castle_printk(LOG_WARN, "Disallowed ctrl op %d, after fs gets inited.\n", ioctl.cmd);
        return -EINVAL;
    }

    /* Handle ioctl from the control program outside of the transaction lock. */
    if(castle_ctrl_prog_ioctl(&ioctl))
        goto copy_out;

    CASTLE_TRANSACTION_BEGIN;
    debug("Lock taken: in_atomic=%d.\n", in_atomic());
    debug("IOCTL Cmd: %u\n", (uint32_t)ioctl.cmd);
    switch(ioctl.cmd)
    {
        case CASTLE_CTRL_CLAIM:
            castle_control_claim( ioctl.claim.dev,
                                 &ioctl.claim.ret,
                                 &ioctl.claim.id);
            break;
        case CASTLE_CTRL_INIT:
            castle_control_fs_init(&ioctl.init.ret);
            if(ioctl.init.ret == 0)
                castle_control_fs_inited = 1;
            break;
        case CASTLE_CTRL_PROTOCOL_VERSION:
            castle_control_protocol_version(&ioctl.protocol_version.ret,
                                            &ioctl.protocol_version.version);
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

            err = castle_from_user_copy( ioctl.collection_attach.name,
                                         ioctl.collection_attach.name_length,
                                         MAX_NAME_SIZE,
                                        &collection_name);
            if(err)
            {
                castle_printk(LOG_WARN, "Invalid string provided for collection name.\n");
                goto err;
            }

            debug("Collection Attach: %s\n", collection_name);
            castle_control_collection_attach(ioctl.collection_attach.version,
                                            collection_name,
                                            &ioctl.collection_attach.ret,
                                            &ioctl.collection_attach.collection);
            break;
        }
        case CASTLE_CTRL_COLLECTION_REATTACH:
            castle_control_collection_reattach(ioctl.collection_reattach.collection,
                                               ioctl.collection_reattach.new_version,
                                              &ioctl.collection_reattach.ret);
            break;
        case CASTLE_CTRL_COLLECTION_DETACH:
            castle_control_collection_detach(ioctl.collection_detach.collection,
                                  &ioctl.collection_detach.ret);
            break;
        case CASTLE_CTRL_COLLECTION_SNAPSHOT:
            castle_control_collection_snapshot(ioctl.collection_snapshot.collection,
                                    &ioctl.collection_snapshot.ret,
                                    &ioctl.collection_snapshot.version);
            break;
        case CASTLE_CTRL_CREATE_WITH_OPTS:
            castle_control_create_with_opts( ioctl.create_with_opts.size,
                                            ioctl.create_with_opts.opts,
                                            &ioctl.create_with_opts.ret,
                                            &ioctl.create_with_opts.id);
            break;
        case CASTLE_CTRL_CREATE:
            castle_control_create( ioctl.create.size,
                                  &ioctl.create.ret,
                                  &ioctl.create.id);
            break;
        case CASTLE_CTRL_DESTROY_VERTREE:
            ioctl.destroy_vertree.ret =
                            castle_double_array_destroy(ioctl.destroy_vertree.vertree_id);
            break;

        case CASTLE_CTRL_DELETE_VERSION:
            castle_control_collection_snapshot_delete(ioctl.delete_version.version,
                                                     &ioctl.delete_version.ret);
            break;

        case CASTLE_CTRL_VERTREE_COMPACT:
            err = -EINVAL;
            goto err;

        case CASTLE_CTRL_CLONE:
            castle_control_clone( ioctl.clone.version,
                                 &ioctl.clone.ret,
                                 &ioctl.clone.clone);
            break;

        case CASTLE_CTRL_FAULT:
            castle_control_fault( ioctl.fault.fault_id,
                                  ioctl.fault.fault_arg,
                                 &ioctl.fault.ret);
            break;

        case CASTLE_CTRL_ENVIRONMENT_SET:
        {
            char *var_str;
            c_env_var_t var_id;

            err = castle_from_user_copy( ioctl.environment_set.var_str,
                                         ioctl.environment_set.var_len,
                                         MAX_ENV_LEN-1,
                                        &var_str);
            if(err)
                goto err;

            var_id = ioctl.environment_set.var_id;
            debug("Setting environment var[%d]=%s\n", var_id, var_str);
            castle_control_environment_set( var_id,
                                            var_str,
                                           &ioctl.environment_set.ret);
            break;
        }
        case CASTLE_CTRL_TRACE_SETUP:
        {
            char *dir_str;

            err = castle_from_user_copy( ioctl.trace_setup.dir_str,
                                         ioctl.trace_setup.dir_len,
                                         128,
                                        &dir_str);

            if(err)
                goto err;

            castle_control_trace_setup( dir_str,
                                       &ioctl.trace_setup.ret);

            break;
        }
        case CASTLE_CTRL_TRACE_START:
            castle_control_trace_start(&ioctl.trace_start.ret);
            break;
        case CASTLE_CTRL_TRACE_STOP:
            castle_control_trace_stop(&ioctl.trace_stop.ret);
            break;
        case CASTLE_CTRL_TRACE_TEARDOWN:
            castle_control_trace_teardown(&ioctl.trace_teardown.ret);
            break;
        case CASTLE_CTRL_SLAVE_EVACUATE:
            castle_control_slave_evacuate(ioctl.slave_evacuate.id,
                                          ioctl.slave_evacuate.force,
                                         &ioctl.slave_evacuate.ret);
            break;
        case CASTLE_CTRL_SLAVE_SCAN:
            castle_control_slave_scan(ioctl.slave_scan.id, &ioctl.slave_scan.ret);
            break;
        case CASTLE_CTRL_THREAD_PRIORITY:
            castle_control_thread_priority(ioctl.thread_priority.nice_value,
                                          &ioctl.thread_priority.ret);
            break;
        case CASTLE_CTRL_VERTREE_TDP_SET:
            ioctl.vertree_tdp_set.ret = castle_da_vertree_tdp_set(ioctl.vertree_tdp_set.vertree_id,
                                                                  ioctl.vertree_tdp_set.seconds);
            break;


        /* Golden Nugget. */
        case CASTLE_CTRL_MERGE_THREAD_CREATE:
        case CASTLE_CTRL_MERGE_THREAD_DESTROY:
        case CASTLE_CTRL_MERGE_THREAD_ATTACH:
            err = -EINVAL;
            goto err;
        case CASTLE_CTRL_MERGE_START:
        {
            c_merge_cfg_t *merge_cfg = &ioctl.merge_start.merge_cfg;
            c_array_id_t __user *arrays_list = merge_cfg->arrays;
            c_data_ext_id_t __user *data_exts = merge_cfg->data_exts;
            size_t size = sizeof(c_array_id_t) * merge_cfg->nr_arrays;

            merge_cfg->data_exts = NULL;
            merge_cfg->arrays = castle_alloc(size);
            if (!merge_cfg->arrays || copy_from_user(merge_cfg->arrays, arrays_list, size))
            {
                castle_printk(LOG_WARN, "Failed to copy to user space\n");
                ioctl.merge_start.ret = -ENOMEM;
                goto err_out;
            }

            if (!merge_cfg->nr_data_exts || (merge_cfg->nr_data_exts == MERGE_ALL_DATA_EXTS))
                merge_cfg->data_exts = NULL;
            else
            {
                castle_printk(LOG_INFO, "Dataextents: %u, %llu, %llu\n", merge_cfg->nr_data_exts, data_exts[0], data_exts[1]);
                size = sizeof(c_ext_id_t) * merge_cfg->nr_data_exts;
                merge_cfg->data_exts = castle_alloc(size);
                if (!merge_cfg->data_exts || copy_from_user(merge_cfg->data_exts, data_exts, size))
                {
                    castle_printk(LOG_WARN, "Failed to copy to user space\n");
                    ioctl.merge_start.ret = -ENOMEM;
                    goto err_out;
                }
            }

            ioctl.merge_start.ret = castle_merge_start(merge_cfg, &ioctl.merge_start.merge_id, -1);

            /* In case of SUCCESS don't free data_exts. */
            merge_cfg->data_exts = NULL;
err_out:
            castle_check_free(merge_cfg->data_exts);
            castle_check_free(merge_cfg->arrays);
            merge_cfg->arrays = arrays_list;
            merge_cfg->data_exts = data_exts;
            break;
        }
        case CASTLE_CTRL_MERGE_DO_WORK:
            ioctl.merge_do_work.ret = castle_merge_do_work(ioctl.merge_do_work.merge_id,
                                                           ioctl.merge_do_work.work_size,
                                                          &ioctl.merge_do_work.work_id);
            break;
        case CASTLE_CTRL_MERGE_STOP:
            ioctl.merge_stop.ret = castle_merge_stop(ioctl.merge_stop.merge_id);
            break;
        case CASTLE_CTRL_INSERT_RATE_SET:
            ioctl.insert_rate_set.ret =
                            castle_da_insert_rate_set(ioctl.insert_rate_set.vertree_id,
                                                      ioctl.insert_rate_set.insert_rate);
            break;
        case CASTLE_CTRL_READ_RATE_SET:
            ioctl.read_rate_set.ret =
                            castle_da_read_rate_set(ioctl.read_rate_set.vertree_id,
                                                    ioctl.read_rate_set.read_rate);
            break;
        case CASTLE_CTRL_STATE_QUERY:
            ioctl.state_query.state = castle_fs_state;
            /* This ioctl always succeeds. */
            ioctl.state_query.ret   = 0;
            break;
        default:
            err = -EINVAL;
            goto err;
    }
    CASTLE_TRANSACTION_END;

copy_out:
    /* Copy the results back */
    if(copy_to_user(udata, &ioctl, sizeof(cctrl_ioctl_t)))
        return -EFAULT;

    return 0;

err:
    CASTLE_TRANSACTION_END;
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
        castle_printk(LOG_INIT, "Castle control device could not be registered (%d).", ret);

    return ret;
}

void castle_control_fini(void)
{
    int ret;

    if((ret = misc_deregister(&castle_control)))
        castle_printk(LOG_INIT, "Could not unregister castle control node (%d).\n", ret);
    /* Sleep waiting for the last ctrl op to complete, if there is one */
    CASTLE_TRANSACTION_BEGIN;
    CASTLE_TRANSACTION_END;
}
