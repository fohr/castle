#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/blkdev.h>

#include "castle_public.h"
#include "castle.h"
#include "castle_sysfs.h"
#include "castle_versions.h"
#include "castle_freespace.h"

struct castle_volumes {
    struct kobject kobj;
};
static struct castle_volumes castle_volumes;

struct castle_sysfs_entry {
    struct attribute attr;
    ssize_t (*show) (struct kobject *kobj, struct attribute *attr, char *buf);
    ssize_t (*store)(struct kobject *kobj, struct attribute *attr, const char *buf, size_t count);
};

struct castle_sysfs_version {
    version_t version;
    char name[10];
    struct castle_sysfs_entry csys_entry; 
};


static ssize_t versions_list_show(struct kobject *kobj, 
							      struct attribute *attr, 
								  char *buf)
{
    struct castle_sysfs_entry *csys_entry = 
                container_of(attr, struct castle_sysfs_entry, attr);
    struct castle_sysfs_version *v =
                container_of(csys_entry, struct castle_sysfs_version, csys_entry);
    version_t parent;
    uint32_t size;
    ssize_t len;
    int leaf;
    int ret;

    ret = castle_version_snap_get(v->version, &parent, &size, &leaf);
    if((ret == 0) || (ret == -EAGAIN))
    {
        len = sprintf(buf,
                "Id\tParentId\tLogicalSize\tIsLeaf\n%d\t%d\t%d\t%d\n",
                 v->version, parent, size, leaf);
        /* Put the version, if we 'attached' it */
        if(ret == 0) castle_version_snap_put(v->version);

        return len;
    }

    return sprintf(buf, "Could not read the version, err %d\n", ret); 
}

static ssize_t versions_list_store(struct kobject *kobj,
							       struct attribute *attr, 
								   const char *buf, 
								   size_t count)
{
    printk("Got write to volumes: %s\n", buf);
    return count;
}


int castle_sysfs_version_add(version_t version)
{
    struct castle_sysfs_version *v;
    int ret;

    /* We've got 10 chars for the name, 'ver-%d'. This means
       version has to be less than 100000 */
    if(version >= 100000)
    {
        printk("ERROR: version number > 100000. Not adding to sysfs.\n");
        return -E2BIG;
    }
    v = kmalloc(sizeof(struct castle_sysfs_version), GFP_KERNEL);
    if(!v) return -ENOMEM;

    v->version = version;
    sprintf(v->name, "%d", version); 
    v->csys_entry.attr.name = v->name;
    v->csys_entry.attr.mode = S_IRUGO|S_IWUSR;
    v->csys_entry.show  = versions_list_show;
    v->csys_entry.store = versions_list_store;

    ret = sysfs_create_file(&castle_volumes.kobj, &v->csys_entry.attr);
    if(ret)
        printk("Warning: could not create a version file in sysfs.\n");

    return 0;
}

static ssize_t slaves_number_show(struct kobject *kobj, 
								  struct attribute *attr, 
							      char *buf)
{
    struct castle_slaves *slaves = 
                container_of(kobj, struct castle_slaves, kobj);
    struct list_head *lh;
    int nr_slaves = 0;

    list_for_each(lh, &slaves->slaves)
        nr_slaves++;

    return sprintf(buf, "%d\n", nr_slaves);
}

static ssize_t slaves_number_store(struct kobject *kobj, 
								  struct attribute *attr, 
                                  const char *buf, 
                                  size_t count)
{
    printk("Got write to disks: %s\n", buf);
    return count;
}

static ssize_t slave_uuid_show(struct kobject *kobj, 
						       struct attribute *attr, 
                               char *buf)
{
    struct castle_slave *slave = container_of(kobj, struct castle_slave, kobj); 

    return sprintf(buf, "0x%x\n", slave->uuid);
}

static ssize_t slave_id_show(struct kobject *kobj, 
						     struct attribute *attr, 
                             char *buf)
{
    struct castle_slave *slave = container_of(kobj, struct castle_slave, kobj); 

    return sprintf(buf, "%d\n", slave->id);
}

static ssize_t slave_size_show(struct kobject *kobj, 
						       struct attribute *attr, 
                               char *buf)
{
    struct castle_slave *slave = container_of(kobj, struct castle_slave, kobj); 
    struct castle_slave_superblock *sb;
    uint32_t size;

    sb = castle_slave_superblock_get(slave);
    size = sb->size;
    castle_slave_superblock_put(slave, 0);

    return sprintf(buf, "%d\n", size);
}

static ssize_t slave_used_show(struct kobject *kobj, 
						       struct attribute *attr, 
                               char *buf)
{
    struct castle_slave *slave = container_of(kobj, struct castle_slave, kobj); 
    struct castle_slave_superblock *sb;
    uint32_t used;

    sb = castle_slave_superblock_get(slave);
    used = sb->used;
    castle_slave_superblock_put(slave, 0);

    return sprintf(buf, "%d\n", used);
}

static ssize_t slave_target_show(struct kobject *kobj, 
                                 struct attribute *attr, 
                                 char *buf)
{
    struct castle_slave *slave = container_of(kobj, struct castle_slave, kobj); 
    struct castle_slave_superblock *sb;
    int target;
    
    sb = castle_slave_superblock_get(slave);
    target = sb->flags & CASTLE_SLAVE_TARGET ? 1 : 0;
    castle_slave_superblock_put(slave, 0);

    return sprintf(buf, "%d\n", target);
}

static ssize_t slave_target_store(struct kobject *kobj, 
                                  struct attribute *attr, 
                                  const char *buf,
                                  size_t count)
{
    struct castle_slave_superblock *sb;
    struct castle_slave *slave = container_of(kobj, struct castle_slave, kobj); 
    
    if(count != 1 || (buf[0] != '0' && buf[0] != '1'))
        return -EINVAL;
    
    sb = castle_slave_superblock_get(slave);
    
    if (buf[0] == '1')
        sb->flags |= CASTLE_SLAVE_TARGET;
    else
        sb->flags &= ~CASTLE_SLAVE_TARGET;
    
    castle_slave_superblock_put(slave, 1);
    
    return count;
}

static ssize_t slave_spinning_show(struct kobject *kobj, 
                                   struct attribute *attr, 
                                   char *buf)
{
    struct castle_slave *slave = container_of(kobj, struct castle_slave, kobj); 
    struct castle_slave_superblock *sb;
    int spinning;
    
    sb = castle_slave_superblock_get(slave);
    spinning = !!(sb->flags & CASTLE_SLAVE_SPINNING);
    castle_slave_superblock_put(slave, 0);

    return sprintf(buf, "%d\n", spinning);
}

static ssize_t slave_spinning_store(struct kobject *kobj, 
                                    struct attribute *attr, 
                                    const char *buf,
                                    size_t count)
{
#if 0    
    struct castle_slave_superblock *sb;
    struct castle_slave *slave = container_of(kobj, struct castle_slave, kobj); 
#endif    
    
    if(count != 1 || (buf[0] != '0' && buf[0] != '1'))
        return -EINVAL;

    return -ENOSYS;
}

static ssize_t slave_block_cnts_show(struct kobject *kobj, 
						             struct attribute *attr, 
                                     char *buf)
{
    struct castle_slave *slave = container_of(kobj, struct castle_slave, kobj); 

    return castle_freespace_summary_get(slave, buf);
}

static ssize_t devices_number_show(struct kobject *kobj, 
						           struct attribute *attr, 
                                   char *buf)
{
    struct castle_devices *devices = 
                container_of(kobj, struct castle_devices, kobj);
    struct list_head *lh;
    int nr_devices = 0;

    list_for_each(lh, &devices->devices)
        nr_devices++;

    return sprintf(buf, "%d\n", nr_devices);
}

static ssize_t device_version_show(struct kobject *kobj, 
						           struct attribute *attr, 
                                   char *buf)
{
    struct castle_device *device = container_of(kobj, struct castle_device, kobj); 

    return sprintf(buf, "0x%x\n", device->version);
}


static ssize_t castle_attr_show(struct kobject *kobj,
                                struct attribute *attr,
                                char *page)
{
    struct castle_sysfs_entry *entry = 
                container_of(attr, struct castle_sysfs_entry, attr);

    if (!entry->show)
        return -EIO;
    
    return entry->show(kobj, attr, page);
}

static ssize_t castle_attr_store(struct kobject *kobj, 
                                 struct attribute *attr,
                                 const char *page, 
                                 size_t length)
{
    struct castle_sysfs_entry *entry = 
                container_of(attr, struct castle_sysfs_entry, attr);

    if (!entry->store)
        return -EIO;
    if (!capable(CAP_SYS_ADMIN))
        return -EACCES;
    return entry->store(kobj, attr, page, length);
}

static struct sysfs_ops castle_sysfs_ops = {
    .show   = castle_attr_show,
    .store  = castle_attr_store,
};

static struct attribute *castle_root_attrs[] = {
    NULL,
};

static struct kobj_type castle_root_ktype = {
    .sysfs_ops      = &castle_sysfs_ops,
    .default_attrs  = castle_root_attrs,
};

static struct attribute *castle_volumes_attrs[] = {
    NULL,
};

static struct kobj_type castle_volumes_ktype = {
    .sysfs_ops      = &castle_sysfs_ops,
    .default_attrs  = castle_volumes_attrs,
};

/* Definition of slaves sysfs directory attributes */
static struct castle_sysfs_entry slaves_number =
__ATTR(number, S_IRUGO|S_IWUSR, slaves_number_show, slaves_number_store);

static struct attribute *castle_slaves_attrs[] = {
    &slaves_number.attr,
    NULL,
};

static struct kobj_type castle_slaves_ktype = {
    .sysfs_ops      = &castle_sysfs_ops,
    .default_attrs  = castle_slaves_attrs,
};

/* Definition of each slave sysfs directory attributes */
static struct castle_sysfs_entry slave_id =
__ATTR(id, S_IRUGO|S_IWUSR, slave_id_show, NULL);

static struct castle_sysfs_entry slave_uuid =
__ATTR(uuid, S_IRUGO|S_IWUSR, slave_uuid_show, NULL);

static struct castle_sysfs_entry slave_size =
__ATTR(size, S_IRUGO|S_IWUSR, slave_size_show, NULL);

static struct castle_sysfs_entry slave_used =
__ATTR(used, S_IRUGO|S_IWUSR, slave_used_show, NULL);

static struct castle_sysfs_entry slave_target =
__ATTR(target, S_IRUGO|S_IWUSR, slave_target_show, slave_target_store);

static struct castle_sysfs_entry slave_spinning =
__ATTR(spinning, S_IRUGO|S_IWUSR, slave_spinning_show, slave_spinning_store);

static struct castle_sysfs_entry slave_block_cnts =
__ATTR(block_cnts, S_IRUGO|S_IWUSR, slave_block_cnts_show, NULL);

static struct attribute *castle_slave_attrs[] = {
    &slave_id.attr,
    &slave_uuid.attr,
    &slave_size.attr,
    &slave_used.attr,
    &slave_target.attr,
    &slave_spinning.attr,
    &slave_block_cnts.attr,
    NULL,
};

static struct kobj_type castle_slave_ktype = {
    .sysfs_ops      = &castle_sysfs_ops,
    .default_attrs  = castle_slave_attrs,
};

int castle_sysfs_slave_add(struct castle_slave *slave)
{
    int ret;
    
    memset(&slave->kobj, 0, sizeof(struct kobject));
    slave->kobj.parent = &castle_slaves.kobj; 
    slave->kobj.ktype  = &castle_slave_ktype; 
    ret = kobject_set_name(&slave->kobj, "slave%d", slave->id);
    if(ret < 0) 
        return ret;
    ret = kobject_register(&slave->kobj);
    if(ret < 0)
        return ret;
    ret = sysfs_create_link(&slave->kobj, &slave->bdev->bd_disk->kobj, "dev");
    if (ret < 0)
        return ret;

    return 0;
}

void castle_sysfs_slave_del(struct castle_slave *slave)
{
    sysfs_remove_link(&slave->kobj, "dev");
    kobject_unregister(&slave->kobj);
}

/* Definition of devices sysfs directory attributes */
static struct castle_sysfs_entry devices_number =
__ATTR(number, S_IRUGO|S_IWUSR, devices_number_show, NULL);

static struct attribute *castle_devices_attrs[] = {
    &devices_number.attr,
    NULL,
};

static struct kobj_type castle_devices_ktype = {
    .sysfs_ops      = &castle_sysfs_ops,
    .default_attrs  = castle_devices_attrs,
};

/* Definition of each device sysfs directory attributes */
static struct castle_sysfs_entry device_version =
__ATTR(version, S_IRUGO|S_IWUSR, device_version_show, NULL);

static struct attribute *castle_device_attrs[] = {
    &device_version.attr,
    NULL,
};

static struct kobj_type castle_device_ktype = {
    .sysfs_ops      = &castle_sysfs_ops,
    .default_attrs  = castle_device_attrs,
};

int castle_sysfs_device_add(struct castle_device *device)
{
    int ret;

    memset(&device->kobj, 0, sizeof(struct kobject));
    device->kobj.parent = &castle_devices.kobj; 
    device->kobj.ktype  = &castle_device_ktype; 
    ret = kobject_set_name(&device->kobj, "castle-%d", device->gd->first_minor);
    if(ret < 0) 
        return ret;
    ret = kobject_register(&device->kobj);
    if(ret < 0)
        return ret;

    ret = sysfs_create_link(&device->kobj, &device->gd->kobj, "dev");
    if (ret < 0)
        return ret;

    return 0;
}

void castle_sysfs_device_del(struct castle_device *device)
{
    sysfs_remove_link(&device->kobj, "dev");
    kobject_unregister(&device->kobj);
}

/* REGIONS */

static ssize_t regions_number_show(struct kobject *kobj, 
						           struct attribute *attr, 
                                   char *buf)
{
    struct castle_regions *regions = 
                container_of(kobj, struct castle_regions, kobj);
    struct list_head *lh;
    int nr_regions = 0;

    list_for_each(lh, &regions->regions)
        nr_regions++;

    return sprintf(buf, "%d\n", nr_regions);
}

static ssize_t region_start_show(struct kobject *kobj, 
						           struct attribute *attr, 
                                   char *buf)
{
    struct castle_region *region = container_of(kobj, struct castle_region, kobj); 

    return sprintf(buf, "0x%x\n", region->start);
}

static ssize_t region_length_show(struct kobject *kobj, 
						           struct attribute *attr, 
                                   char *buf)
{
    struct castle_region *region = container_of(kobj, struct castle_region, kobj); 

    return sprintf(buf, "0x%x\n", region->length);
}

static ssize_t region_snapshot_show(struct kobject *kobj, 
						           struct attribute *attr, 
                                   char *buf)
{
    struct castle_region *region = container_of(kobj, struct castle_region, kobj); 

    return sprintf(buf, "%d\n", region->version);
}

/* Definition of regions sysfs directory attributes */
static struct castle_sysfs_entry regions_number =
__ATTR(number, S_IRUGO|S_IWUSR, regions_number_show, NULL);

static struct attribute *castle_regions_attrs[] = {
    &regions_number.attr,
    NULL,
};

static struct kobj_type castle_regions_ktype = {
    .sysfs_ops      = &castle_sysfs_ops,
    .default_attrs  = castle_regions_attrs,
};

/* Definition of each region sysfs directory attributes */
static struct castle_sysfs_entry region_start =
__ATTR(start, S_IRUGO|S_IWUSR, region_start_show, NULL);

static struct castle_sysfs_entry region_length =
__ATTR(length, S_IRUGO|S_IWUSR, region_length_show, NULL);

static struct castle_sysfs_entry region_snapshot =
__ATTR(snapshot, S_IRUGO|S_IWUSR, region_snapshot_show, NULL);

static struct attribute *castle_region_attrs[] = {
    &region_start.attr,
    &region_length.attr,
    &region_snapshot.attr,
    NULL,
};

static struct kobj_type castle_region_ktype = {
    .sysfs_ops      = &castle_sysfs_ops,
    .default_attrs  = castle_region_attrs,
};

int castle_sysfs_region_add(struct castle_region *region)
{
    int ret;

    memset(&region->kobj, 0, sizeof(struct kobject));
    region->kobj.parent = &castle_regions.kobj; 
    region->kobj.ktype  = &castle_region_ktype; 
    ret = kobject_set_name(&region->kobj, "%d", region->id);
    if(ret < 0) 
        return ret;
        
    ret = kobject_register(&region->kobj);
    if(ret < 0)
        return ret;

    ret = sysfs_create_link(&region->kobj, &region->slave->kobj, "slave");
    if (ret < 0)
        return ret;

    return 0;
}

void castle_sysfs_region_del(struct castle_region *region)
{
    sysfs_remove_link(&region->kobj, "slave");
    kobject_unregister(&region->kobj);
}

/* TRANSFERS */

static ssize_t transfers_number_show(struct kobject *kobj, 
						           struct attribute *attr, 
                                   char *buf)
{
    struct castle_transfers *transfers = 
                container_of(kobj, struct castle_transfers, kobj);
    struct list_head *lh;
    int nr_transfers = 0;

    list_for_each(lh, &transfers->transfers)
        nr_transfers++;

    return sprintf(buf, "%d\n", nr_transfers);
}

static ssize_t transfer_direction_show(struct kobject *kobj, 
						           struct attribute *attr, 
                                   char *buf)
{
    struct castle_transfer *transfer = 
                container_of(kobj, struct castle_transfer, kobj);

    return sprintf(buf, "%d\n", transfer->direction);
}

static ssize_t transfer_version_show(struct kobject *kobj, 
						           struct attribute *attr, 
                                   char *buf)
{
    struct castle_transfer *transfer = 
                container_of(kobj, struct castle_transfer, kobj);

    return sprintf(buf, "%d\n", transfer->version);
}

static ssize_t transfer_progress_show(struct kobject *kobj, 
						           struct attribute *attr, 
                                   char *buf)
{
    struct castle_transfer *transfer = 
                container_of(kobj, struct castle_transfer, kobj);

    return sprintf(buf, "%d\n", atomic_read(&transfer->progress));
}

/* Definition of regions sysfs directory attributes */
static struct castle_sysfs_entry transfers_number =
__ATTR(number, S_IRUGO|S_IWUSR, transfers_number_show, NULL);

static struct attribute *castle_transfers_attrs[] = {
    &transfers_number.attr,
    NULL,
};

static struct kobj_type castle_transfers_ktype = {
    .sysfs_ops      = &castle_sysfs_ops,
    .default_attrs  = castle_transfers_attrs,
};

/* Definition of each region sysfs directory attributes */
static struct castle_sysfs_entry transfer_version =
__ATTR(direction, S_IRUGO|S_IWUSR, transfer_direction_show, NULL);

static struct castle_sysfs_entry transfer_direction =
__ATTR(version, S_IRUGO|S_IWUSR, transfer_version_show, NULL);

static struct castle_sysfs_entry transfer_progress =
__ATTR(progress, S_IRUGO|S_IWUSR, transfer_progress_show, NULL);

static struct attribute *castle_transfer_attrs[] = {
    &transfer_version.attr,
    &transfer_direction.attr,
    &transfer_progress.attr,
    NULL,
};

static struct kobj_type castle_transfer_ktype = {
    .sysfs_ops      = &castle_sysfs_ops,
    .default_attrs  = castle_transfer_attrs,
};

int castle_sysfs_transfer_add(struct castle_transfer *transfer)
{
    int ret;

    memset(&transfer->kobj, 0, sizeof(struct kobject));
    transfer->kobj.parent = &castle_transfers.kobj; 
    transfer->kobj.ktype  = &castle_transfer_ktype; 
    ret = kobject_set_name(&transfer->kobj, "%d", transfer->id);
    if(ret < 0) 
        return ret;
        
    ret = kobject_register(&transfer->kobj);
    if(ret < 0)
        return ret;
        
    return 0;
}

void castle_sysfs_transfer_del(struct castle_transfer *transfer)
{
    kobject_unregister(&transfer->kobj);
}

/* Initialisation of sysfs dirs == kobjs registration */
int castle_sysfs_init(void)
{
    int ret;
    int castle_registered, volumes_registered, slaves_registered, devices_registered, regions_registered, transfers_registered;

    castle_registered = volumes_registered = slaves_registered = devices_registered = regions_registered = transfers_registered = 0;

    memset(&castle.kobj, 0, sizeof(struct kobject));
    castle.kobj.parent = &fs_subsys.kobj;
    castle.kobj.kset   = &fs_subsys;
    castle.kobj.ktype  = &castle_root_ktype;
    ret = kobject_set_name(&castle.kobj, "%s", "castle-fs");
    if(ret < 0) goto error_out;
    ret = kobject_register(&castle.kobj);
    if(ret < 0) goto error_out;
    castle_registered = 1;

    memset(&castle_volumes.kobj, 0, sizeof(struct kobject));
    castle_volumes.kobj.parent = &castle.kobj;
    castle_volumes.kobj.ktype  = &castle_volumes_ktype;
    ret = kobject_set_name(&castle_volumes.kobj, "%s", "volumes");
    if(ret < 0) goto error_out;
    ret = kobject_register(&castle_volumes.kobj);
    if(ret < 0) goto error_out;
    volumes_registered = 1;

    memset(&castle_slaves.kobj, 0, sizeof(struct kobject));
    castle_slaves.kobj.parent = &castle.kobj;
    castle_slaves.kobj.ktype  = &castle_slaves_ktype;
    ret = kobject_set_name(&castle_slaves.kobj, "%s", "slaves");
    if(ret < 0) goto error_out;
    ret = kobject_register(&castle_slaves.kobj);
    if(ret < 0) goto error_out;
    slaves_registered = 1;

    memset(&castle_devices.kobj, 0, sizeof(struct kobject));
    castle_devices.kobj.parent = &castle.kobj;
    castle_devices.kobj.ktype  = &castle_devices_ktype;
    ret = kobject_set_name(&castle_devices.kobj, "%s", "devices");
    if(ret < 0) goto error_out;
    ret = kobject_register(&castle_devices.kobj);
    if(ret < 0) goto error_out;
    devices_registered = 1;

    memset(&castle_regions.kobj, 0, sizeof(struct kobject));
    castle_regions.kobj.parent = &castle.kobj;
    castle_regions.kobj.ktype  = &castle_regions_ktype;
    ret = kobject_set_name(&castle_regions.kobj, "%s", "regions");
    if(ret < 0) goto error_out;
    ret = kobject_register(&castle_regions.kobj);
    if(ret < 0) goto error_out;
    regions_registered = 1;

    memset(&castle_transfers.kobj, 0, sizeof(struct kobject));
    castle_transfers.kobj.parent = &castle.kobj;
    castle_transfers.kobj.ktype  = &castle_transfers_ktype;
    ret = kobject_set_name(&castle_transfers.kobj, "%s", "transfers");
    if(ret < 0) goto error_out;
    ret = kobject_register(&castle_transfers.kobj);
    if(ret < 0) goto error_out;
    transfers_registered = 1;

    return 0;

error_out:
    if(castle_registered)  kobject_unregister(&castle.kobj);
    if(volumes_registered) kobject_unregister(&castle_volumes.kobj);
    if(slaves_registered)  kobject_unregister(&castle_slaves.kobj);
    if(devices_registered) kobject_unregister(&castle_devices.kobj);
    if(regions_registered) kobject_unregister(&castle_regions.kobj);
    if(transfers_registered) kobject_unregister(&castle_transfers.kobj);

    return ret;
}

void castle_sysfs_fini(void)
{
    kobject_unregister(&castle_regions.kobj);
    kobject_unregister(&castle_slaves.kobj);
    kobject_unregister(&castle_volumes.kobj);
    kobject_unregister(&castle.kobj);
}


