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

extern struct castle         castle;
extern struct castle_volumes castle_volumes;
extern struct castle_disks   castle_disks;

#endif /* __CASTLE_H__ */
