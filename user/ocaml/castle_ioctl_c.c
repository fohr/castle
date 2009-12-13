#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <caml/config.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/mlvalues.h>
#include <caml/fail.h>

#include "../utils/castle_public.h"

CAMLprim value
castle_ioctl (value fdv, value cmdv)
{
  CAMLparam2 (fdv, cmdv);
  CAMLlocal1 (rv);

  int fd, cmd, r;
  struct castle_control_ioctl ctl;

  fd = Int_val (fdv);
  cmd = Int_val (cmdv);

  ctl.cmd = cmd;

  r = ioctl (fd, CASTLE_CTRL_IOCTL, &ctl);

  /* XXX Better to raise Unix_error here, but I'm lazy. */
  if (r == -1)
    caml_failwith (strerror (errno));

  rv = caml_copy_int32 (r);

  CAMLreturn (rv);
}
