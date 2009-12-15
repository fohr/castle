#include <sys/ioctl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <caml/config.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/mlvalues.h>
#include <caml/fail.h>

#include "castle_public.h"

int castle_ctl(int fd, uint16_t cmd, uint64_t arg)
{
    int ret;
 	uint64_t ret_val;
    struct castle_control_ioctl ctl;
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
        case CASTLE_CTRL_CMD_INIT:
            /* No arguments to init */
            break;
        case CASTLE_CTRL_CMD_RET:
            ctl.ret.ret_val = (uint64_t)arg;
            break;
        default:
            //printf("Unknown command. Exiting\n");
            return -1;
    }
    ret = ioctl(fd, CASTLE_CTRL_IOCTL, &ctl);

    //printf("ioctl ret: %d\n", ret);
    if(ret < 0)
    {
        //printf("ioctl failed. Exiting.\n");
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
        case CASTLE_CTRL_CMD_INIT:
            ret_val = (uint64_t)ctl.init.ret;
            break;
        case CASTLE_CTRL_CMD_RET:
            ret_val = (uint64_t)-1; 
            break;
        default:
            //printf("Unknown command. Exiting\n");
            return -1;
    }
    //printf("Ret val: 0x%"PRIx64".\n", ret_val);

    return 0;
}

CAMLprim value
castle_ioctl (value fdv, value cmdv, value argv)
{
  CAMLparam3 (fdv, cmdv, argv);
  CAMLlocal1 (rv);

  int fd, r;
  uint16_t cmd;
  uint64_t arg;

  fd = Int_val (fdv);
  cmd = (uint16_t) Int_val (cmdv);
  arg = Int64_val (argv);
 
  r = castle_ctl(fd, cmd, arg);

  /* XXX Better to raise Unix_error here, but I'm lazy. */
  if (r < 0)
    caml_failwith (strerror (errno));

  rv = caml_copy_int32 (r);

  CAMLreturn (rv);
}
