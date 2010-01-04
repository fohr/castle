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

struct ctrl_cmd
{
    int        id;
    char      *name;
    void     (*set_arg)(cctrl_ioctl_t *ctl, uint64_t arg);
    uint64_t (*get_ret)(cctrl_ioctl_t *ctl);
};

#define CTRL_CMD(_id, _name, _arg_t, _arg, _ret)                        \
    static void __##_name##_set_arg(cctrl_ioctl_t *ctl, uint64_t arg)   \
    {                                                                   \
        ctl->_arg = (_arg_t)arg;                                        \
    };                                                                  \
    static uint64_t __##_name##_get_ret(cctrl_ioctl_t *ctl)             \
    {                                                                   \
        return (uint64_t)ctl->_ret;                                     \
    };                                                                  \
    static struct ctrl_cmd _name##_ctrl_cmd =                           \
    {                                                                   \
        .id   = _id,                                                    \
        .name = #_name,                                                 \
        .set_arg = __##_name##_set_arg,                                 \
        .get_ret = __##_name##_get_ret,                                 \
    }                                                                   \

CTRL_CMD(CASTLE_CTRL_CMD_CLAIM,    claim,    uint32_t, claim.dev,    claim.ret);
CTRL_CMD(CASTLE_CTRL_CMD_RELEASE,  release,  uint32_t, release.dev,  release.ret);
CTRL_CMD(CASTLE_CTRL_CMD_ATTACH,   attach,   uint64_t, attach.snap,  attach.dev);
CTRL_CMD(CASTLE_CTRL_CMD_DETACH,   detach,   uint32_t, detach.dev,   detach.ret);
CTRL_CMD(CASTLE_CTRL_CMD_CREATE,   create,   uint64_t, create.size,  create.id);
CTRL_CMD(CASTLE_CTRL_CMD_CLONE,    clone,    uint64_t, clone.snap,   clone.clone);
CTRL_CMD(CASTLE_CTRL_CMD_SNAPSHOT, snapshot, uint32_t, snapshot.dev, snapshot.snap_id);
CTRL_CMD(CASTLE_CTRL_CMD_INIT,     init,     uint32_t, claim.dev,    init.ret);    // No arg really 
CTRL_CMD(CASTLE_CTRL_CMD_RET,      ret,      uint64_t, ret.ret_val,  ret.ret_val); // No ret really

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
    &ret_ctrl_cmd,
    NULL,
};

int main(int argc, char* argv[])
{
    int i, fd, ret;
    char *cmd;
    uint64_t arg, ret_val;
    struct castle_control_ioctl ctl;
    struct ctrl_cmd *ctrl_cmd;

    if(argc != 3)
    {
        printf("usage: castle-ctl <cmd-string> <hex-arg>\n");
        exit(1);
    }
    cmd = argv[1];
    arg = (uint64_t)strtoul(argv[2], NULL, 16);
    printf("Cmd: %s, arg=0x%lx\n", cmd, arg);

    i=0;
    while(ctrl_cmds[i] != NULL && 
          (strcmp(ctrl_cmds[i]->name, cmd) != 0)) i++;
    ctrl_cmd = ctrl_cmds[i];

    if(!ctrl_cmd)
    {
        printf("Could not find command \"%s\"\n", cmd);
        exit(2);
    }

    // Set up ctl structure
    ctl.cmd = ctrl_cmd->id;
    ctrl_cmd->set_arg(&ctl, arg);

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
