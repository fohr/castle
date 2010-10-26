#ifndef __CASTLE_BACK_H__
#define __CASTLE_BACK_H__

int castle_back_open(struct inode *inode, struct file *file);
int castle_back_mmap(struct file *file, struct vm_area_struct *vma);
long castle_back_unlocked_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
unsigned int castle_back_poll(struct file *file, poll_table *wait);
int castle_back_release(struct inode *inode, struct file *file);

void castle_back_fini(void);
int castle_back_init(void);

#endif /* __CASTLE_BACK_H__ */
