#ifndef __CASTLE_CTRL_H__
#define __CASTLE_CTRL_H__

int castle_control_ioctl(struct inode *inode, struct file *filp,
                         unsigned int cmd, unsigned long arg);


#endif /* __CASTLE_CTRL_H__ */
