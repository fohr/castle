#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/capability.h>
#include <linux/fs.h>

#include "castle.h"

static ssize_t test_show(char *buf)
{
    return sprintf(buf, "%s\n", "Test castle attribute file");
}

static ssize_t test_store(const char *buf, size_t count)
{
    printk("Got write: %s\n", buf);
    return count;
}

static ssize_t volumes_test_show(char *buf)
{
    return sprintf(buf, "%s\n", "Test volumes attribute file");
}

static ssize_t volumes_test_store(const char *buf, size_t count)
{
    printk("Got write to volumes: %s\n", buf);
    return count;
}

static ssize_t disks_test_show(char *buf)
{
    return sprintf(buf, "%s\n", "Test disks attribute file");
}

static ssize_t disks_test_store(const char *buf, size_t count)
{
    printk("Got write to disks: %s\n", buf);
    return count;
}


struct castle_static_sysfs_entry {
    struct attribute attr;
    ssize_t (*show)(char *buf);
    ssize_t (*store)(const char *buf, size_t count);
};


static ssize_t castle_static_attr_show(struct kobject *kobj,
                                       struct attribute *attr,
                                       char *page)
{
    struct castle_static_sysfs_entry *entry = 
                container_of(attr, struct castle_static_sysfs_entry, attr);

    if (!entry->show)
        return -EIO;
    return entry->show(page);
}

static ssize_t castle_static_attr_store(struct kobject *kobj, 
                                        struct attribute *attr,
                                        const char *page, 
                                        size_t length)
{
    struct castle_static_sysfs_entry *entry = 
                container_of(attr, struct castle_static_sysfs_entry, attr);

    if (!entry->store)
        return -EIO;
    if (!capable(CAP_SYS_ADMIN))
        return -EACCES;
    return entry->store(page, length);
}

static struct sysfs_ops castle_static_sysfs_ops = {
    .show   = castle_static_attr_show,
    .store  = castle_static_attr_store,
};


/* Definition of castle root sysfs directory attributes */
static struct castle_static_sysfs_entry test =
__ATTR(test_attr, S_IRUGO|S_IWUSR, test_show, test_store);

static struct attribute *castle_root_default_attrs[] = {
    &test.attr,
    NULL,
};

static struct kobj_type castle_root_ktype = {
    .sysfs_ops      = &castle_static_sysfs_ops,
    .default_attrs  = castle_root_default_attrs,
};

/* Definition of volumes sysfs directory attributes */
static struct castle_static_sysfs_entry volumes_test =
__ATTR(vols_test_attr, S_IRUGO|S_IWUSR, volumes_test_show, volumes_test_store);

static struct attribute *castle_volumes_default_attrs[] = {
    &volumes_test.attr,
    NULL,
};

static struct kobj_type castle_volumes_ktype = {
    .sysfs_ops      = &castle_static_sysfs_ops,
    .default_attrs  = castle_volumes_default_attrs,
};

/* Definition of disk_pool sysfs directory attributes */
static struct castle_static_sysfs_entry disks_test =
__ATTR(disks_test_attr, S_IRUGO|S_IWUSR, disks_test_show, disks_test_store);

static struct attribute *castle_disks_default_attrs[] = {
    &disks_test.attr,
    NULL,
};

static struct kobj_type castle_disks_ktype = {
    .sysfs_ops      = &castle_static_sysfs_ops,
    .default_attrs  = castle_disks_default_attrs,
};

/* Initialisation of sysfs dirs == kobjs registration */
int castle_kobjs_init(void)
{
    int ret;
    int castle_registered, volumes_registered, disks_registered;

    castle_registered = volumes_registered = disks_registered = 0;

    memset(&castle.kobj, 0, sizeof(struct kobject));
    castle.kobj.parent = &fs_subsys.kobj;
    castle.kobj.kset   = &fs_subsys;
    castle.kobj.ktype  = &castle_root_ktype;
    ret = kobject_set_name(&castle.kobj, "%s", "castle");
    if(ret < 0) goto error_out;
    ret = kobject_register(&castle.kobj);
    if(ret < 0) goto error_out;
    castle_registered = 1;
    kobject_uevent(&castle.kobj, KOBJ_ADD);

    memset(&castle_volumes.kobj, 0, sizeof(struct kobject));
    castle_volumes.kobj.parent = &castle.kobj;
    castle_volumes.kobj.ktype  = &castle_volumes_ktype;
    ret = kobject_set_name(&castle_volumes.kobj, "%s", "volumes");
    if(ret < 0) goto error_out;
    ret = kobject_register(&castle_volumes.kobj);
    if(ret < 0) goto error_out;
    volumes_registered = 1;

    memset(&castle_disks.kobj, 0, sizeof(struct kobject));
    castle_disks.kobj.parent = &castle.kobj;
    castle_disks.kobj.ktype  = &castle_disks_ktype;
    ret = kobject_set_name(&castle_disks.kobj, "%s", "disk_pool");
    if(ret < 0) goto error_out;
    ret = kobject_register(&castle_disks.kobj);
    if(ret < 0) goto error_out;
    disks_registered = 1;

    return 0;

error_out:
    if(castle_registered)  kobject_unregister(&castle.kobj);
    if(volumes_registered) kobject_unregister(&castle_volumes.kobj);
    if(disks_registered)   kobject_unregister(&castle_disks.kobj);

    return ret;
}

void castle_kobjs_exit(void)
{
    kobject_unregister(&castle_disks.kobj);
    kobject_unregister(&castle_volumes.kobj);
    kobject_unregister(&castle.kobj);
}


