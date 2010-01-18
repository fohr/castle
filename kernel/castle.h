#ifndef __CASTLE_H__
#define __CASTLE_H__

struct castle {
    struct kobject kobj;
};

struct castle_volumes {
    struct kobject kobj;
};

struct castle_slave {
    uint32_t             id;
    uint32_t             uuid;
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

struct castle_device* castle_dev_mirror       (dev_t base_dev);
void                  castle_device_free      (struct castle_device *cd);
struct castle_slave*  castle_claim            (uint32_t new_dev);
struct castle_slave*  castle_slave_find_by_id (uint32_t id);
void                  castle_release          (struct castle_slave *cs);

#endif /* __CASTLE_H__ */
