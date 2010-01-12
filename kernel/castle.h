#ifndef __CASTLE_H__
#define __CASTLE_H__

struct castle {
    struct kobject kobj;
};

struct castle_volumes {
    struct kobject kobj;
};

struct castle_slave {
    struct kobject       kobj;
    struct list_head     list;
    struct block_device *bdev;
};

struct castle_slaves {
    struct kobject   kobj;
    struct list_head slaves;
};

struct castle_device {
    spinlock_t        lock;
    struct list_head  list;
    struct gendisk   *gd;
    int               users;
    int               sysfs_registered;

    /* At the moment we use loop devices as the base */
    struct block_device *bdev;
};

struct castle_devices { 
    struct kobject kobj;
    int major;
    struct list_head devices;
};

extern struct castle         castle;
extern struct castle_volumes castle_volumes;
extern struct castle_slaves  castle_slaves;
extern struct castle_devices castle_devices;

#endif /* __CASTLE_H__ */
