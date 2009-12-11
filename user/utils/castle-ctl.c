#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <sys/ioctl.h>

#include "castle_public.h"

#define NODE    "/dev/castle/control"

int main(int argc, char* argv[])
{
    int fd, ret;
    uint16_t cmd;
    struct castle_control_ioctl ctl;

    if(argc != 2)
    {
        printf("usage: castle-ctl <cmd-id>\n");
        return -1;
    }
    cmd = (uint16_t)strtol(argv[1], NULL, 10);
    printf("Cmd: %d\n", cmd);
    ctl.cmd = cmd;
    fd = open(NODE);
    if(fd < 0)
    {
        printf("Could not open " NODE " %d\n", errno);
        return -1;
    }
    ret = ioctl(fd, CASTLE_CTRL_IOCTL, &ctl);
    printf("ioctl ret: %d\n", ret);
    close(fd);

    return 0;
}
