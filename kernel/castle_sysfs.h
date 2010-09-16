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

#endif /* __CASTLE_SYSFS_H__ */
