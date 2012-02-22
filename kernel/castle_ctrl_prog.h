#ifndef __CASTLE_CTRL_PROG_H__
#define __CASTLE_CTRL_PROG_H__

int castle_ctrl_prog_present(void);
int  castle_ctrl_prog_ioctl(cctrl_ioctl_t *ioctl);

int  castle_ctrl_prog_init (void);
void castle_ctrl_prog_fini (void);

#endif /* __CASTLE_CTRL_PROG_H__ */

