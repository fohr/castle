#include <linux/kernel.h>
#include <linux/capability.h>
#include <linux/blkdev.h>

#include "castle_public.h"
#include "castle.h"
#include "castle_events.h"
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
    void *private;
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
    ssize_t len, phys_size;
    int leaf;
    int ret;

    ret = castle_version_read(v->version, &parent, &size, &leaf);
    if(ret == 0)
    {
        phys_size = castle_freespace_version_blocks_get(v->version);
        len = sprintf(buf,
                "Id: 0x%x\n"
                "ParentId: 0x%x\n"
                "LogicalSize: %d\n"
                "PhysicalSize: %ld\n"
                "IsLeaf: %d\n",
                 v->version, 
                 parent, 
                 size, 
                 phys_size,
                 leaf);

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
    sprintf(v->name, "%x", version); 
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
    
    castle_events_slave_changed(slave->uuid);
    
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
    const char *name = attr->name;

    unsigned long offset = simple_strtoul(name + 10, NULL, 10) * 200; // 10 = length of "block_cnts"

    return castle_freespace_summary_get(slave, buf, offset, 200);
}

static ssize_t devices_number_show(struct kobject *kobj, 
						           struct attribute *attr, 
                                   char *buf)
{
    struct castle_attachments *devices = 
                container_of(kobj, struct castle_attachments, devices_kobj);
    struct castle_attachment *device;
    struct list_head *lh;
    int nr_devices = 0;

    list_for_each(lh, &devices->attachments)
    {
        device = list_entry(lh, struct castle_attachment, list);
        if(!device->device)
            continue;
        nr_devices++;
    }

    return sprintf(buf, "%d\n", nr_devices);
}

static ssize_t device_version_show(struct kobject *kobj, 
						           struct attribute *attr, 
                                   char *buf)
{
    struct castle_attachment *device = container_of(kobj, struct castle_attachment, kobj); 

    return sprintf(buf, "0x%x\n", device->version);
}

static ssize_t device_id_show(struct kobject *kobj, 
				              struct attribute *attr, 
                              char *buf)
{
    struct castle_attachment *device = container_of(kobj, struct castle_attachment, kobj); 

    return sprintf(buf, "0x%x\n", new_encode_dev(MKDEV(device->dev.gd->major, device->dev.gd->first_minor)));
}

static ssize_t collections_number_show(struct kobject *kobj, 
						               struct attribute *attr, 
                                       char *buf)
{
    struct castle_attachments *collections = 
                container_of(kobj, struct castle_attachments, collections_kobj);
    struct castle_attachment *collection;
    struct list_head *lh;
    int nr_collections = 0;

    list_for_each(lh, &collections->attachments)
    {
        collection = list_entry(lh, struct castle_attachment, list);
        if(collection->device)
            continue;
        nr_collections++;
    }

    return sprintf(buf, "%d\n", nr_collections);
}

static ssize_t collection_version_show(struct kobject *kobj, 
						               struct attribute *attr, 
                                       char *buf)
{
    struct castle_attachment *collection = container_of(kobj, struct castle_attachment, kobj); 

    return sprintf(buf, "0x%x\n", collection->version);
}

static ssize_t collection_id_show(struct kobject *kobj, 
						          struct attribute *attr, 
                                  char *buf)
{
    struct castle_attachment *collection = container_of(kobj, struct castle_attachment, kobj); 

    return sprintf(buf, "0x%x\n", collection->col.id);
}

static ssize_t collection_name_show(struct kobject *kobj, 
						            struct attribute *attr, 
                                    char *buf)
{
    struct castle_attachment *collection = container_of(kobj, struct castle_attachment, kobj); 

    return sprintf(buf, "%s\n", collection->col.name);
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

/* TODO we should dynamically create these files */
static struct castle_sysfs_entry slave_block_cnts0 =
__ATTR(block_cnts0, S_IRUGO|S_IWUSR, slave_block_cnts_show, NULL);

static struct castle_sysfs_entry slave_block_cnts1 =
__ATTR(block_cnts1, S_IRUGO|S_IWUSR, slave_block_cnts_show, NULL);

static struct castle_sysfs_entry slave_block_cnts2 =
__ATTR(block_cnts2, S_IRUGO|S_IWUSR, slave_block_cnts_show, NULL);

static struct castle_sysfs_entry slave_block_cnts3 =
__ATTR(block_cnts3, S_IRUGO|S_IWUSR, slave_block_cnts_show, NULL);

static struct castle_sysfs_entry slave_block_cnts4 =
__ATTR(block_cnts4, S_IRUGO|S_IWUSR, slave_block_cnts_show, NULL);

static struct castle_sysfs_entry slave_block_cnts5 =
__ATTR(block_cnts5, S_IRUGO|S_IWUSR, slave_block_cnts_show, NULL);

static struct castle_sysfs_entry slave_block_cnts6 =
__ATTR(block_cnts6, S_IRUGO|S_IWUSR, slave_block_cnts_show, NULL);

static struct castle_sysfs_entry slave_block_cnts7 =
__ATTR(block_cnts7, S_IRUGO|S_IWUSR, slave_block_cnts_show, NULL);

static struct castle_sysfs_entry slave_block_cnts8 =
__ATTR(block_cnts8, S_IRUGO|S_IWUSR, slave_block_cnts_show, NULL);

static struct castle_sysfs_entry slave_block_cnts9 =
__ATTR(block_cnts9, S_IRUGO|S_IWUSR, slave_block_cnts_show, NULL);

static struct attribute *castle_slave_attrs[] = {
    &slave_uuid.attr,
    &slave_size.attr,
    &slave_used.attr,
    &slave_target.attr,
    &slave_spinning.attr,
    &slave_block_cnts0.attr,
    &slave_block_cnts1.attr,
    &slave_block_cnts2.attr,
    &slave_block_cnts3.attr,
    &slave_block_cnts4.attr,
    &slave_block_cnts5.attr,
    &slave_block_cnts6.attr,
    &slave_block_cnts7.attr,
    &slave_block_cnts8.attr,
    &slave_block_cnts9.attr,
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
    ret = kobject_set_name(&slave->kobj, "%x", slave->uuid);
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

/* Definition of collections sysfs directory attributes */
static struct castle_sysfs_entry collections_number =
__ATTR(number, S_IRUGO|S_IWUSR, collections_number_show, NULL);

static struct attribute *castle_collections_attrs[] = {
    &collections_number.attr,
    NULL,
};

static struct kobj_type castle_collections_ktype = {
    .sysfs_ops      = &castle_sysfs_ops,
    .default_attrs  = castle_collections_attrs,
};

/* Definition of each device sysfs directory attributes */
static struct castle_sysfs_entry device_version =
__ATTR(version, S_IRUGO|S_IWUSR, device_version_show, NULL);

static struct castle_sysfs_entry device_id =
__ATTR(id, S_IRUGO|S_IWUSR, device_id_show, NULL);

static struct attribute *castle_device_attrs[] = {
    &device_id.attr,
    &device_version.attr,
    NULL,
};

static struct kobj_type castle_device_ktype = {
    .sysfs_ops      = &castle_sysfs_ops,
    .default_attrs  = castle_device_attrs,
};

int castle_sysfs_device_add(struct castle_attachment *device)
{
    int ret;

    memset(&device->kobj, 0, sizeof(struct kobject));
    device->kobj.parent = &castle_attachments.devices_kobj; 
    device->kobj.ktype  = &castle_device_ktype; 
    ret = kobject_set_name(&device->kobj, 
                           "%x", 
                           new_encode_dev(MKDEV(device->dev.gd->major, 
                                                device->dev.gd->first_minor)));
    if(ret < 0) 
        return ret;
    ret = kobject_register(&device->kobj);
    if(ret < 0)
        return ret;

    ret = sysfs_create_link(&device->kobj, &device->dev.gd->kobj, "dev");
    if (ret < 0)
        return ret;

    return 0;
}

void castle_sysfs_device_del(struct castle_attachment *device)
{
    sysfs_remove_link(&device->kobj, "dev");
    kobject_unregister(&device->kobj);
}

/* Definition of each collection sysfs directory attributes */
static struct castle_sysfs_entry collection_version =
__ATTR(version, S_IRUGO|S_IWUSR, collection_version_show, NULL);

static struct castle_sysfs_entry collection_id =
__ATTR(id, S_IRUGO|S_IWUSR, collection_id_show, NULL);

static struct castle_sysfs_entry collection_name =
__ATTR(name, S_IRUGO|S_IWUSR, collection_name_show, NULL);

static struct attribute *castle_collection_attrs[] = {
    &collection_id.attr,
    &collection_version.attr,
    &collection_name.attr,
    NULL,
};

static struct kobj_type castle_collection_ktype = {
    .sysfs_ops      = &castle_sysfs_ops,
    .default_attrs  = castle_collection_attrs,
};

int castle_sysfs_collection_add(struct castle_attachment *collection)
{
    int ret;

    memset(&collection->kobj, 0, sizeof(struct kobject));
    collection->kobj.parent = &castle_attachments.collections_kobj; 
    collection->kobj.ktype  = &castle_collection_ktype; 
    ret = kobject_set_name(&collection->kobj, 
                           "%x", 
                           collection->col.id);
    if(ret < 0) 
        return ret;
    ret = kobject_register(&collection->kobj);
    if(ret < 0)
        return ret;

    return 0;
}

void castle_sysfs_collection_del(struct castle_attachment *collection)
{
    kobject_unregister(&collection->kobj);
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

static ssize_t region_id_show(struct kobject *kobj, 
						           struct attribute *attr, 
                                   char *buf)
{
    struct castle_region *region = container_of(kobj, struct castle_region, kobj); 

    return sprintf(buf, "0x%x\n", region->id);
}

static ssize_t region_start_show(struct kobject *kobj, 
						           struct attribute *attr, 
                                   char *buf)
{
    struct castle_region *region = container_of(kobj, struct castle_region, kobj); 

    return sprintf(buf, "%d\n", region->start);
}

static ssize_t region_length_show(struct kobject *kobj, 
						           struct attribute *attr, 
                                   char *buf)
{
    struct castle_region *region = container_of(kobj, struct castle_region, kobj); 

    return sprintf(buf, "%d\n", region->length);
}

static ssize_t region_version_show(struct kobject *kobj, 
						           struct attribute *attr, 
                                   char *buf)
{
    struct castle_region *region = container_of(kobj, struct castle_region, kobj); 

    return sprintf(buf, "0x%x\n", region->version);
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

static struct castle_sysfs_entry region_id =
__ATTR(id, S_IRUGO|S_IWUSR, region_id_show, NULL);

static struct castle_sysfs_entry region_start =
__ATTR(start, S_IRUGO|S_IWUSR, region_start_show, NULL);

static struct castle_sysfs_entry region_length =
__ATTR(length, S_IRUGO|S_IWUSR, region_length_show, NULL);

static struct castle_sysfs_entry region_version =
__ATTR(version, S_IRUGO|S_IWUSR, region_version_show, NULL);

static struct attribute *castle_region_attrs[] = {
    &region_id.attr,
    &region_start.attr,
    &region_length.attr,
    &region_version.attr,
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
    ret = kobject_set_name(&region->kobj, "%x", region->id);
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

static ssize_t transfer_id_show(struct kobject *kobj, 
						           struct attribute *attr, 
                                   char *buf)
{
    struct castle_transfer *transfer = 
                container_of(kobj, struct castle_transfer, kobj);

    return sprintf(buf, "0x%x\n", transfer->id);
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

    return sprintf(buf, "0x%x\n", transfer->version);
}

static ssize_t transfer_progress_show(struct kobject *kobj, 
						           struct attribute *attr, 
                                   char *buf)
{
    struct castle_transfer *transfer = 
                container_of(kobj, struct castle_transfer, kobj);

    return sprintf(buf, "%d\n", atomic_read(&transfer->progress));
}

static ssize_t transfer_finished_show(struct kobject *kobj, 
						           struct attribute *attr, 
                                   char *buf)
{
    struct castle_transfer *transfer = 
                container_of(kobj, struct castle_transfer, kobj);

    return sprintf(buf, "%d\n", transfer->finished);
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
static struct castle_sysfs_entry transfer_id =
__ATTR(id, S_IRUGO|S_IWUSR, transfer_id_show, NULL);

static struct castle_sysfs_entry transfer_version =
__ATTR(direction, S_IRUGO|S_IWUSR, transfer_direction_show, NULL);

static struct castle_sysfs_entry transfer_direction =
__ATTR(version, S_IRUGO|S_IWUSR, transfer_version_show, NULL);

static struct castle_sysfs_entry transfer_progress =
__ATTR(progress, S_IRUGO|S_IWUSR, transfer_progress_show, NULL);

static struct castle_sysfs_entry transfer_finished =
__ATTR(finished, S_IRUGO|S_IWUSR, transfer_finished_show, NULL);

static struct attribute *castle_transfer_attrs[] = {
    &transfer_id.attr,
    &transfer_version.attr,
    &transfer_direction.attr,
    &transfer_progress.attr,
    &transfer_finished.attr,
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
    ret = kobject_set_name(&transfer->kobj, "%x", transfer->id);
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

    memset(&castle.kobj, 0, sizeof(struct kobject));
    castle.kobj.parent = &fs_subsys.kobj;
    castle.kobj.kset   = &fs_subsys;
    castle.kobj.ktype  = &castle_root_ktype;
    ret = kobject_set_name(&castle.kobj, "%s", "castle-fs");
    if(ret < 0) goto out1;
    ret = kobject_register(&castle.kobj);
    if(ret < 0) goto out1;

    memset(&castle_volumes.kobj, 0, sizeof(struct kobject));
    castle_volumes.kobj.parent = &castle.kobj;
    castle_volumes.kobj.ktype  = &castle_volumes_ktype;
    ret = kobject_set_name(&castle_volumes.kobj, "%s", "versions");
    if(ret < 0) goto out2;
    ret = kobject_register(&castle_volumes.kobj);
    if(ret < 0) goto out2;

    memset(&castle_slaves.kobj, 0, sizeof(struct kobject));
    castle_slaves.kobj.parent = &castle.kobj;
    castle_slaves.kobj.ktype  = &castle_slaves_ktype;
    ret = kobject_set_name(&castle_slaves.kobj, "%s", "slaves");
    if(ret < 0) goto out3;
    ret = kobject_register(&castle_slaves.kobj);
    if(ret < 0) goto out3;

    memset(&castle_attachments.devices_kobj, 0, sizeof(struct kobject));
    castle_attachments.devices_kobj.parent = &castle.kobj;
    castle_attachments.devices_kobj.ktype  = &castle_devices_ktype;
    ret = kobject_set_name(&castle_attachments.devices_kobj, "%s", "devices");
    if(ret < 0) goto out4;
    ret = kobject_register(&castle_attachments.devices_kobj);
    if(ret < 0) goto out4;

    memset(&castle_attachments.collections_kobj, 0, sizeof(struct kobject));
    castle_attachments.collections_kobj.parent = &castle.kobj;
    castle_attachments.collections_kobj.ktype  = &castle_collections_ktype;
    ret = kobject_set_name(&castle_attachments.collections_kobj, "%s", "collections");
    if(ret < 0) goto out5;
    ret = kobject_register(&castle_attachments.collections_kobj);
    if(ret < 0) goto out5;

    memset(&castle_regions.kobj, 0, sizeof(struct kobject));
    castle_regions.kobj.parent = &castle.kobj;
    castle_regions.kobj.ktype  = &castle_regions_ktype;
    ret = kobject_set_name(&castle_regions.kobj, "%s", "regions");
    if(ret < 0) goto out6;
    ret = kobject_register(&castle_regions.kobj);
    if(ret < 0) goto out6;

    memset(&castle_transfers.kobj, 0, sizeof(struct kobject));
    castle_transfers.kobj.parent = &castle.kobj;
    castle_transfers.kobj.ktype  = &castle_transfers_ktype;
    ret = kobject_set_name(&castle_transfers.kobj, "%s", "transfers");
    if(ret < 0) goto out7;
    ret = kobject_register(&castle_transfers.kobj);
    if(ret < 0) goto out7;

    return 0;
    
    kobject_unregister(&castle_transfers.kobj); /* Unreachable */
out7:  
    kobject_unregister(&castle_regions.kobj);
out6: 
    kobject_unregister(&castle_attachments.collections_kobj);
out5:
    kobject_unregister(&castle_attachments.devices_kobj);
out4:
    kobject_unregister(&castle_slaves.kobj);
out3:
    kobject_unregister(&castle_volumes.kobj);
out2:
    kobject_unregister(&castle.kobj);
out1:

    return ret;
}

void castle_sysfs_fini(void)
{
    kobject_unregister(&castle_transfers.kobj);
    kobject_unregister(&castle_regions.kobj);
    kobject_unregister(&castle_attachments.collections_kobj);
    kobject_unregister(&castle_attachments.devices_kobj);
    kobject_unregister(&castle_slaves.kobj);
    kobject_unregister(&castle_volumes.kobj);
    kobject_unregister(&castle.kobj);
}


