OCAMLMAKEFILE = OCamlMakefile

SOURCES = castle_ioctl_c.c castle_ioctl.ml
RESULT  = castle_ioctl
THREADS = yes
LIBINSTALL_FILES = castle_ioctl.cmi castle_ioctl.cmx castle_ioctl.a castle_ioctl.cmxa libcastle_ioctl_stubs.a

all: native-code-library
include $(OCAMLMAKEFILE)
