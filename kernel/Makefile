# Comment/uncomment the following line to disable/enable debugging
DEBUG = y

TARGET = castle-fs

obj-m          := $(TARGET).o
$(TARGET)-objs := castle_main.o castle_cache.o castle_block.o castle_btree.o castle_freespace.o castle_versions.o castle_ctrl.o castle_sysfs.o castle_transfer.o castle_events.o

# Add your debugging flag (or not) to CFLAGS
ifeq ($(DEBUG),y)
  DEBFLAGS = -Werror -O0 -g -DCASTLE_DEBUG # "-O" is needed to expand inlines
  $(TARGET)-objs += castle_debug.o
else
  DEBFLAGS = -O0 -g
endif

EXTRA_CFLAGS += $(DEBFLAGS)
EXTRA_CFLAGS += -I..

KVER       ?= 2.6.24
KERNEL_DIR ?= /lib/modules/$(KVER)/build
PWD        := $(shell pwd)

.PHONY: all
all: $(TARGET).ko

# Make castle_compile.h PHONY, to get it refreshed every build
.PHONY: castle_compile.h
castle_compile.h:
	echo "#define CASTLE_COMPILE_CHANGESET \"$(shell ((hg parents --template "{date|date} {rev}:{node|short}" >/dev/null && hg parents --template "{date|date} {rev}:{node|short}") || echo "unavailable") 2>/dev/null)\"" > castle_compile.h

.PHONY: $(TARGET).ko
$(TARGET).ko: castle_compile.h
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

install: $(TARGET).ko
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules_install
	depmod -aq $(KVER)

clean:
	rm -rf *.o *~ core .depend .*.o.d .*.cmd *.ko *.mod.c .tmp_versions Module.symvers

depend .depend dep:
	$(CC) $(EXTRA_FLAGS) -M *.c > .depend

ifeq (.depend,$(wildcard .depend))
include .depend
endif
