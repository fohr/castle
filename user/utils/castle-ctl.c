#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "castle_public.h"

#define NODE    "/dev/castle/control"

int main(int argc, char* argv[])
{
    int fd, ret;
    uint16_t cmd;
    uint64_t arg, ret_val;
    struct castle_control_ioctl ctl;

    if(argc != 3)
    {
        printf("usage: castle-ctl <cmd-id> <hex-arg>\n");
        return -1;
    }
    cmd = (uint16_t)strtoul(argv[1], NULL, 10);
    arg = (uint64_t)strtoul(argv[2], NULL, 16);
    printf("Cmd: %d, arg=0x%lx\n", cmd, arg);
    ctl.cmd = cmd;
    switch(cmd)
    {
        case CASTLE_CTRL_CMD_CLAIM:
            ctl.claim.dev = (uint32_t)arg;
            break;
        case CASTLE_CTRL_CMD_RELEASE:
            ctl.release.dev = (uint32_t)arg;
            break;
        case CASTLE_CTRL_CMD_ATTACH:
            ctl.attach.snap = (uint64_t)arg;
            break;
        case CASTLE_CTRL_CMD_DETACH:
            ctl.detach.dev = (uint32_t)arg;
            break;
        case CASTLE_CTRL_CMD_CREATE:
            ctl.create.size = (uint64_t)arg;
            break;
        case CASTLE_CTRL_CMD_CLONE:
            ctl.clone.snap = (uint64_t)arg;
            break;
        case CASTLE_CTRL_CMD_SNAPSHOT:
            ctl.snapshot.dev = (uint32_t)arg;
            break;
        case CASTLE_CTRL_CMD_RET:
            ctl.ret.ret_val = (uint64_t)arg;
            break;
        default:
            printf("Unknown command. Exiting\n");
            return -1;
    }
    fd = open(NODE, O_RDWR);
    if(fd < 0)
    {
        printf("Could not open " NODE " %d\n", errno);
        return -1;
    }
    ret = ioctl(fd, CASTLE_CTRL_IOCTL, &ctl);
    printf("ioctl ret: %d\n", ret);
    if(ret < 0)
    {
        printf("ioctl failed. Exiting.\n");
        close(fd);
        return -2;
    }
    switch(cmd)
    {
        case CASTLE_CTRL_CMD_CLAIM:
            ret_val = (uint64_t)ctl.claim.ret;
            break;
        case CASTLE_CTRL_CMD_RELEASE:
            ret_val = (uint64_t)ctl.release.ret;
            break;
        case CASTLE_CTRL_CMD_ATTACH:
            ret_val = (uint64_t)ctl.attach.ret;
            break;
        case CASTLE_CTRL_CMD_DETACH:
            ret_val = (uint64_t)ctl.detach.ret;
            break;
        case CASTLE_CTRL_CMD_CREATE:
            ret_val = (uint64_t)ctl.create.id;
            break;
        case CASTLE_CTRL_CMD_CLONE:
            ret_val = (uint64_t)ctl.clone.clone;
            break;
        case CASTLE_CTRL_CMD_SNAPSHOT:
            ret_val = (uint64_t)ctl.snapshot.snap_id;
            break;
        case CASTLE_CTRL_CMD_RET:
            ret_val = (uint64_t)-1; 
            break;
        default:
            printf("Unknown command. Exiting\n");
            return -1;
    }
    close(fd);
    printf("Ret val: 0x%"PRIx64".\n", ret_val);

    return 0;
}
