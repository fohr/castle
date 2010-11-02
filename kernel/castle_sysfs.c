#include <linux/kernel.h>
#include <linux/capability.h>
#include <linux/blkdev.h>

#include "castle_public.h"
#include "castle.h"
#include "castle_events.h"
#include "castle_sysfs.h"
#include "castle_debug.h"
#include "castle_versions.h"
#include "castle_da.h"

struct castle_sysfs_versions {
    struct kobject kobj;
    struct list_head version_list;
};
static struct castle_sysfs_versions castle_sysfs_versions;

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
    struct list_head list;
};

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
    #define fs_kobject  (&fs_subsys.kset.kobj)
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,24)
    #define fs_kobject  (&fs_subsys.kobj)
#else /* KERNEL_VERSION(2,6,24+) */
    #define fs_kobject  (fs_kobj)
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,24)
/* Helper function which mimicks newer sysfs interfaces */
#define kobject_tree_add(_kobj, _parent, _ktype, _fmt, _a...)                    \
({                                                                               \
    int _ret = 0;                                                                \
                                                                                 \
    (_kobj)->ktype = (_ktype);                                                   \
    (_kobj)->parent = (_parent);                                                 \
    _ret = kobject_set_name(_kobj, _fmt, ##_a);                                  \
    if(!_ret)                                                                    \
        _ret = kobject_register(_kobj);                                          \
    _ret;                                                                        \
})

#define kobject_remove(_kobj)                                                    \
    kobject_unregister(_kobj)

#else /* KERNEL_VERSION(2,6,24+) */

#define kobject_tree_add(_kobj, _parent, _ktype, _fmt, _a...)                    \
({                                                                               \
    int _ret;                                                                    \
                                                                                 \
    kobject_init(_kobj, _ktype);                                                 \
    _ret = kobject_add(_kobj, _parent, _fmt, ##_a);                              \
    _ret;                                                                        \
})

#define kobject_remove(_kobj)                                                    \
    kobject_del(_kobj)
    
#endif

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
    c_byte_off_t phys_size = 0;
    da_id_t da_id;

    ret = castle_version_read(v->version, &da_id, &parent, &size, &leaf);
    if(ret == 0)
    {
	if (parent == 0)
	{	
		// this is a root collection/device version.  Work out it's size.
		castle_double_array_size_get(da_id, &phys_size);
	}

        len = sprintf(buf,
                "Id: 0x%x\n"
                "ParentId: 0x%x\n"
                "LogicalSize: %llu\n"
                "PhysicalSize: %llu\n"
                "IsLeaf: %d\n",
                 v->version, 
                 parent, 
                 (c_byte_off_t)size,
                 phys_size * C_CHK_SIZE,
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

static void castle_sysfs_versions_fini(void)
{
    struct castle_sysfs_version *v;
    struct list_head *l, *t;

    kobject_remove(&castle_sysfs_versions.kobj);
    list_for_each_safe(l, t, &castle_sysfs_versions.version_list)
    {
        list_del(l);
        v = list_entry(l, struct castle_sysfs_version, list);
        castle_free(v);
    }
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
    v = castle_malloc(sizeof(struct castle_sysfs_version), GFP_KERNEL);
    if(!v) return -ENOMEM;

    v->version = version;
    sprintf(v->name, "%x", version); 
    v->csys_entry.attr.name  = v->name;
    v->csys_entry.attr.mode  = S_IRUGO|S_IWUSR;
    v->csys_entry.attr.owner = THIS_MODULE;
    v->csys_entry.show  = versions_list_show;
    v->csys_entry.store = versions_list_store;

    ret = sysfs_create_file(&castle_sysfs_versions.kobj, &v->csys_entry.attr);
    if(ret)
    {
        printk("Warning: could not create a version file in sysfs.\n");
        castle_free(v);
    } else
    {
        /* Succeeded at adding the version, add it to the list, so that it gets cleaned up */
        INIT_LIST_HEAD(&v->list);
        list_add(&v->list, &castle_sysfs_versions.version_list);
    }

    return ret;
}

int castle_sysfs_version_del(version_t version)
{
    struct castle_sysfs_version *v = NULL;
    struct list_head *pos, *tmp;

    list_for_each_safe(pos, tmp, &castle_sysfs_versions.version_list)
    {
        v = list_entry(pos, struct castle_sysfs_version, list);
        if (v->version == version)
        {
            list_del(pos);
            break;
        }
    }
    if (!v)
        return -1;

    sysfs_remove_file(&castle_sysfs_versions.kobj, &v->csys_entry.attr);

    castle_free(v);
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

static struct attribute *castle_versions_attrs[] = {
    NULL,
};

static struct kobj_type castle_versions_ktype = {
    .sysfs_ops      = &castle_sysfs_ops,
    .default_attrs  = castle_versions_attrs,
};

/* Definition of slaves sysfs directory attributes */
static struct castle_sysfs_entry slaves_number =
__ATTR(number, S_IRUGO|S_IWUSR, slaves_number_show, NULL);

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
__ATTR(target, S_IRUGO|S_IWUSR, slave_target_show, NULL);

static struct castle_sysfs_entry slave_spinning =
__ATTR(spinning, S_IRUGO|S_IWUSR, slave_spinning_show, NULL);

static struct attribute *castle_slave_attrs[] = {
    &slave_uuid.attr,
    &slave_size.attr,
    &slave_used.attr,
    &slave_target.attr,
    &slave_spinning.attr,
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
    ret = kobject_tree_add(&slave->kobj, 
                           &castle_slaves.kobj, 
                           &castle_slave_ktype, 
                           "%x", slave->uuid);
    if(ret < 0) 
        return ret;
    /* TODO: do we need a link for >32?. If so, how do we get hold of the right kobj */ 
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,24)
    ret = sysfs_create_link(&slave->kobj, &slave->bdev->bd_disk->kobj, "dev");
    if (ret < 0)
        return ret;
#endif

    return 0;
}

void castle_sysfs_slave_del(struct castle_slave *slave)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,24)
    sysfs_remove_link(&slave->kobj, "dev");
#endif
    kobject_remove(&slave->kobj);
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
    ret = kobject_tree_add(&device->kobj, 
                           &castle_attachments.devices_kobj,
                           &castle_device_ktype,
                           "%x", 
                           new_encode_dev(MKDEV(device->dev.gd->major, 
                                                device->dev.gd->first_minor)));
    if(ret < 0) 
        return ret;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,24)
    ret = sysfs_create_link(&device->kobj, &device->dev.gd->kobj, "dev");
    if (ret < 0)
        return ret;
#endif

    return 0;
}

void castle_sysfs_device_del(struct castle_attachment *device)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,24)
    sysfs_remove_link(&device->kobj, "dev");
#endif
    kobject_remove(&device->kobj);
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
    ret = kobject_tree_add(&collection->kobj, 
                           &castle_attachments.collections_kobj,
                           &castle_collection_ktype,
                           "%x", 
                           collection->col.id);
    if(ret < 0) 
        return ret;

    return 0;
}

void castle_sysfs_collection_del(struct castle_attachment *collection)
{
    kobject_remove(&collection->kobj);
}

/* Initialisation of sysfs dirs == kobjs registration */
int castle_sysfs_init(void)
{
    int ret;

    memset(&castle.kobj, 0, sizeof(struct kobject));

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
    kobj_set_kset_s(&castle, fs_subsys);
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,24)
    /* TODO should probably be kobj_set_kset_s(&castle, fs_subsys); */
    castle.kobj.kset   = &fs_subsys; 
#endif

    ret = kobject_tree_add(&castle.kobj, 
                            fs_kobject, 
                           &castle_root_ktype, 
                           "%s", "castle-fs");
    if(ret < 0) goto out1;

    memset(&castle_sysfs_versions.kobj, 0, sizeof(struct kobject));
    INIT_LIST_HEAD(&castle_sysfs_versions.version_list);
    ret = kobject_tree_add(&castle_sysfs_versions.kobj, 
                           &castle.kobj, 
                           &castle_versions_ktype, 
                           "%s", "versions");
    if(ret < 0) goto out2;

    memset(&castle_slaves.kobj, 0, sizeof(struct kobject));
    ret = kobject_tree_add(&castle_slaves.kobj, 
                           &castle.kobj, 
                           &castle_slaves_ktype, 
                           "%s", "slaves");
    if(ret < 0) goto out3;

    memset(&castle_attachments.devices_kobj, 0, sizeof(struct kobject));
    ret = kobject_tree_add(&castle_attachments.devices_kobj, 
                           &castle.kobj, 
                           &castle_devices_ktype, 
                           "%s", "devices");
    if(ret < 0) goto out4;

    memset(&castle_attachments.collections_kobj, 0, sizeof(struct kobject));
    ret = kobject_tree_add(&castle_attachments.collections_kobj, 
                           &castle.kobj, 
                           &castle_collections_ktype, 
                           "%s", "collections");
    if(ret < 0) goto out5;

    return 0;
    
    kobject_remove(&castle_attachments.collections_kobj); /* Unreachable */
out5:
    kobject_remove(&castle_attachments.devices_kobj);
out4:
    kobject_remove(&castle_slaves.kobj);
out3:
    kobject_remove(&castle_sysfs_versions.kobj);
out2:
    kobject_remove(&castle.kobj);
out1:

    return ret;
}

void castle_sysfs_fini(void)
{
    kobject_remove(&castle_attachments.collections_kobj);
    kobject_remove(&castle_attachments.devices_kobj);
    kobject_remove(&castle_slaves.kobj);
    castle_sysfs_versions_fini();
    kobject_remove(&castle.kobj);
}


