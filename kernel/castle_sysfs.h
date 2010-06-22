#ifndef __CASTLE_SYSFS_H__
#define __CASTLE_SYSFS_H__

int  castle_sysfs_init           (void);
void castle_sysfs_fini           (void);
int  castle_sysfs_version_add    (version_t version);
int  castle_sysfs_slave_add      (struct castle_slave *slave);
void castle_sysfs_slave_del      (struct castle_slave *slave);
int  castle_sysfs_device_add     (struct castle_attachment *attachment);
void castle_sysfs_device_del     (struct castle_attachment *attachment);
int  castle_sysfs_collection_add (struct castle_attachment *attachment);
void castle_sysfs_collection_del (struct castle_attachment *attachment);
int  castle_sysfs_region_add     (struct castle_region *region);
void castle_sysfs_region_del     (struct castle_region *region);
int  castle_sysfs_transfer_add   (struct castle_transfer *transfer);
void castle_sysfs_transfer_del   (struct castle_transfer *transfer);

#endif /* __CASTLE_SYSFS_H__ */
