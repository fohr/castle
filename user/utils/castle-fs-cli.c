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

#define NODE    "/dev/castle-fs/control"

struct ctrl_cmd
{
    int        id;
    int        args;
    char      *name;
    void     (*set_args)(cctrl_ioctl_t *ctl, char* argv[]);
    uint64_t (*get_ret)(cctrl_ioctl_t *ctl);
};

#define CTRL_CMD1(_id, _name, _arg_t, _arg, _ret)                       \
    static void __##_name##_set_args(cctrl_ioctl_t *ctl, char* argv[])  \
    {                                                                   \
        ctl->_arg = (_arg_t)strtoul(argv[0], NULL, 16);                 \
    };                                                                  \
    static uint64_t __##_name##_get_ret(cctrl_ioctl_t *ctl)             \
    {                                                                   \
        return (uint64_t)ctl->_ret;                                     \
    };                                                                  \
    static struct ctrl_cmd _name##_ctrl_cmd =                           \
    {                                                                   \
        .id   = _id,                                                    \
        .args = 1,                                                      \
        .name = #_name,                                                 \
        .set_args = __##_name##_set_args,                               \
        .get_ret = __##_name##_get_ret,                                 \
    }                                                                   \

#define CTRL_CMD4(_id, _name, _arg1_t, _arg1, _arg2_t, _arg2, _arg3_t, _arg3, _arg4_t, _arg4, _ret)\
    static void __##_name##_set_args(cctrl_ioctl_t *ctl, char* argv[])  \
    {                                                                   \
        ctl->_arg1 = (_arg1_t)strtoul(argv[0], NULL, 16);               \
        ctl->_arg2 = (_arg2_t)strtoul(argv[1], NULL, 16);               \
        ctl->_arg3 = (_arg3_t)strtoul(argv[2], NULL, 16);               \
        ctl->_arg4 = (_arg4_t)strtoul(argv[3], NULL, 16);               \
    };                                                                  \
    static uint64_t __##_name##_get_ret(cctrl_ioctl_t *ctl)             \
    {                                                                   \
        return (uint64_t)ctl->_ret;                                     \
    };                                                                  \
    static struct ctrl_cmd _name##_ctrl_cmd =                           \
    {                                                                   \
        .id   = _id,                                                    \
        .args = 4,                                                      \
        .name = #_name,                                                 \
        .set_args = __##_name##_set_args,                               \
        .get_ret = __##_name##_get_ret,                                 \
    }                                                                   \

CTRL_CMD1(CASTLE_CTRL_CMD_CLAIM,    claim,    uint32_t, claim.dev,    claim.id);
CTRL_CMD1(CASTLE_CTRL_CMD_RELEASE,  release,  uint32_t, release.id,   release.ret);
CTRL_CMD1(CASTLE_CTRL_CMD_ATTACH,   attach,   uint64_t, attach.snap,  attach.dev);
CTRL_CMD1(CASTLE_CTRL_CMD_DETACH,   detach,   uint32_t, detach.dev,   detach.ret);
CTRL_CMD1(CASTLE_CTRL_CMD_CREATE,   create,   uint64_t, create.size,  create.id);
CTRL_CMD1(CASTLE_CTRL_CMD_CLONE,    clone,    uint64_t, clone.snap,   clone.clone);
CTRL_CMD1(CASTLE_CTRL_CMD_SNAPSHOT, snapshot, uint32_t, snapshot.dev, snapshot.snap_id);
CTRL_CMD1(CASTLE_CTRL_CMD_INIT,     init,     uint32_t, claim.dev,    init.ret);    // No arg really
CTRL_CMD4(CASTLE_CTRL_CMD_REGION_CREATE, region_create, uint32_t, region_create.slave, snap_id_t, region_create.snapshot, uint32_t, region_create.start, uint32_t, region_create.length, region_create.id);
CTRL_CMD1(CASTLE_CTRL_CMD_REGION_DESTROY, region_destroy, region_id_t, region_destroy.id, region_destroy.ret);

static struct ctrl_cmd *ctrl_cmds[] = 
{
    &claim_ctrl_cmd,
    &release_ctrl_cmd,
    &attach_ctrl_cmd,
    &detach_ctrl_cmd,
    &create_ctrl_cmd,
    &clone_ctrl_cmd,
    &snapshot_ctrl_cmd,
    &init_ctrl_cmd,
    &region_create_ctrl_cmd,
    NULL,
};

int main(int argc, char* argv[])
{
    int i, fd, ret, args;
    char *cmd;
    uint64_t arg, ret_val;
    struct castle_control_ioctl ctl;
    struct ctrl_cmd *ctrl_cmd;

    if(argc < 3)
    {
        printf("usage: castle-cli <cmd-string> <hex-arg>\n\n");
        printf("Available commands:\n");
        printf("    Command       Argument               Return value \n");
        printf("------------------------------------------------------\n");
        printf("    claim         (maj,min) of disk      slave id     \n");
        printf("    release       slave id               error #      \n");
        printf("    init          unused                 error #      \n");
        printf("    create        volume size            snapshot id  \n");
        printf("    attach        snapshot id            dev (maj,min)\n");
        printf("    detach        dev (maj,min)          error #      \n");
        printf("    clone         snapshot id            clone id     \n");
        printf("    snapshot      dev (maj,min)          snapshot id  \n\n");
        exit(1);
    }
    cmd = argv[1];
    printf("Cmd: %s, arg=%s\n", cmd, argv[2]);

    i=0;
    while(ctrl_cmds[i] != NULL && 
          (strcmp(ctrl_cmds[i]->name, cmd) != 0)) i++;
    ctrl_cmd = ctrl_cmds[i];

    if(!ctrl_cmd)
    {
        printf("Could not find command \"%s\"\n", cmd);
        exit(2);
    }

    // check we have enough arguments
    args = ctrl_cmd->args + 2;
    if(argc != args)
    {
        printf("Need %d arguments for command \"%s\" (found %d)\n", args, cmd, argc);
        exit(2);
    }
    
    // Set up ctl structure
    ctl.cmd = ctrl_cmd->id;
    ctrl_cmd->set_args(&ctl, &argv[2]);

    fd = open(NODE, O_RDWR);
    if(fd < 0)
    {
        printf("Could not open " NODE " %d\n", errno);
        exit(3);
    }
    ret = ioctl(fd, CASTLE_CTRL_IOCTL, &ctl);
    close(fd);

    printf("ioctl ret: %d\n", ret);
    if(ret < 0)
    {
        printf("ioctl failed. Exiting.\n");
        exit(4);
    }

    ret_val = ctrl_cmd->get_ret(&ctl);
    printf("Ret val: 0x%"PRIx64".\n", ret_val);

    return 0;
}
