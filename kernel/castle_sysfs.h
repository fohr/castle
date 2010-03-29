#ifndef __CASTLE_SYSFS_H__
#define __CASTLE_SYSFS_H__

int  castle_sysfs_init(void);
void castle_sysfs_fini(void);
int  castle_sysfs_version_add(version_t version);
int  castle_sysfs_slave_add(struct castle_slave *slave);
void castle_sysfs_slave_del(struct castle_slave *slave);
int  castle_sysfs_device_add(struct castle_device *device);
void castle_sysfs_device_del(struct castle_device *device);

#endif /* __CASTLE_SYSFS_H__ */
