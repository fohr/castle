#include <linux/kernel.h>
#include <linux/module.h>

#include "castle_public.h"
#include "castle_defines.h"
#include "castle.h"

int castle_ctrl_prog_ioctl(cctrl_ioctl_t *ioctl)
{
    switch(ioctl->cmd)
    {
        case CASTLE_CTRL_PROG_REGISTER:
            ioctl->ctrl_prog_register.ret = 0;
            break;

        case CASTLE_CTRL_PROG_DEREGISTER:
            ioctl->ctrl_prog_deregister.ret = 0;
            break;

        case CASTLE_CTRL_PROG_HEARTBEAT:
            ioctl->ctrl_prog_heartbeat.ret = 0;
            break;

        default:
            return 0;
    }

    return 1;
}

int castle_ctrl_prog_init(void)
{
    return 0;
}

void castle_ctrl_prog_fini(void)
{
}
