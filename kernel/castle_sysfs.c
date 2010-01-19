#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/blkdev.h>

#include "castle.h"

static ssize_t test_show(struct kobject *kobj, char *buf)
{
    return sprintf(buf, "%s\n", "Test castle attribute file");
}

static ssize_t test_store(struct kobject *kobj, const char *buf, size_t count)
{
    printk("Got write: %s\n", buf);
    return count;
}

static ssize_t volumes_test_show(struct kobject *kobj, char *buf)
{
    return sprintf(buf, "%s\n", "Test volumes attribute file");
}

static ssize_t volumes_test_store(struct kobject *kobj, const char *buf, size_t count)
{
    printk("Got write to volumes: %s\n", buf);
    return count;
}

static ssize_t slaves_number_show(struct kobject *kobj, char *buf)
{
    struct castle_slaves *slaves = 
                container_of(kobj, struct castle_slaves, kobj);
    struct list_head *lh;
    int nr_slaves = 0;

    list_for_each(lh, &slaves->slaves)
        nr_slaves++;

    return sprintf(buf, "%d\n", nr_slaves);
}

static ssize_t slaves_number_store(struct kobject *kobj, const char *buf, size_t count)
{
    printk("Got write to disks: %s\n", buf);
    return count;
}

static ssize_t slave_uuid_show(struct kobject *kobj, char *buf)
{
    struct castle_slave *slave = container_of(kobj, struct castle_slave, kobj); 

    return sprintf(buf, "%d\n", slave->cs_sb.uuid);
}


struct castle_sysfs_entry {
    struct attribute attr;
    ssize_t (*show) (struct kobject *kobj, char *buf);
    ssize_t (*store)(struct kobject *kobj, const char *buf, size_t count);
};


static ssize_t castle_attr_show(struct kobject *kobj,
                                struct attribute *attr,
                                char *page)
{
    struct castle_sysfs_entry *entry = 
                container_of(attr, struct castle_sysfs_entry, attr);

    if (!entry->show)
        return -EIO;
    
    return entry->show(kobj, page);
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
    return entry->store(kobj, page, length);
}

static struct sysfs_ops castle_sysfs_ops = {
    .show   = castle_attr_show,
    .store  = castle_attr_store,
};


/* Definition of castle root sysfs directory attributes */
static struct castle_sysfs_entry test =
__ATTR(test_attr, S_IRUGO|S_IWUSR, test_show, test_store);

static struct attribute *castle_root_attrs[] = {
    &test.attr,
    NULL,
};

static struct kobj_type castle_root_ktype = {
    .sysfs_ops      = &castle_sysfs_ops,
    .default_attrs  = castle_root_attrs,
};

/* Definition of volumes sysfs directory attributes */
static struct castle_sysfs_entry volumes_test =
__ATTR(vols_test_attr, S_IRUGO|S_IWUSR, volumes_test_show, volumes_test_store);

static struct attribute *castle_volumes_attrs[] = {
    &volumes_test.attr,
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

static struct attribute *castle_slave_attrs[] = {
    &slave_uuid.attr,
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

int castle_sysfs_slave_del(struct castle_slave *slave)
{
    sysfs_remove_link(&slave->kobj, "dev");
    kobject_unregister(&slave->kobj);

    return 0;
}

/* Initialisation of sysfs dirs == kobjs registration */
int castle_sysfs_init(void)
{
    int ret;
    int castle_registered, volumes_registered, slaves_registered;

    castle_registered = volumes_registered = slaves_registered = 0;

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

    return 0;

error_out:
    if(castle_registered)  kobject_unregister(&castle.kobj);
    if(volumes_registered) kobject_unregister(&castle_volumes.kobj);
    if(slaves_registered)  kobject_unregister(&castle_slaves.kobj);

    return ret;
}

void castle_sysfs_fini(void)
{
    kobject_unregister(&castle_slaves.kobj);
    kobject_unregister(&castle_volumes.kobj);
    kobject_unregister(&castle.kobj);
}


