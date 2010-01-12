#ifndef __CASTLE_SYSFS_H__
#define __CASTLE_SYSFS_H__

int  castle_sysfs_init(void);
void castle_sysfs_exit(void);
void castle_sysfs_slave_add(struct castle_slave *slave);
void castle_sysfs_slave_del(struct castle_slave *slave);

#endif /* __CASTLE_SYSFS_H__ */
