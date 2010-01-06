#ifndef __CASTLE_H__
#define __CASTLE_H__

struct castle {
    struct kobject kobj;
};

struct castle_volumes {
    struct kobject kobj;
};

struct castle_disks {
    struct kobject kobj;
};

struct castle_disk {
    int ma;
    int mi;
    struct block_device *bdev;
};

struct castle_device {
    spinlock_t        lock;
    struct list_head  list;
    struct gendisk   *gd;
    int               users;

    /* At the moment we use loop devices as the base */
    struct block_device *bdev;
};

struct castle_devices { 
    int major;
    struct list_head devices;
};

extern struct castle         castle;
extern struct castle_volumes castle_volumes;
extern struct castle_disks   castle_disks;
extern struct castle_devices castle_devices;

#endif /* __CASTLE_H__ */
