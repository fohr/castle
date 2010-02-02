# Comment/uncomment the following line to disable/enable debugging
#DEBUG = y

# Add your debugging flag (or not) to CFLAGS
ifeq ($(DEBUG),y)
  DEBFLAGS = -O0 -g -DCASTLE_DEBUG # "-O" is needed to expand inlines
else
  DEBFLAGS = -O0 -g
endif

EXTRA_CFLAGS += $(DEBFLAGS)
EXTRA_CFLAGS += -I..

TARGET = castle-fs

obj-m          := $(TARGET).o
$(TARGET)-objs := castle_main.o castle_cache.o castle_block.o castle_btree.o castle_ctrl.o castle_sysfs.o

KVER       ?= 2.6.24
KERNEL_DIR ?= /lib/modules/$(KVER)/build
PWD        := $(shell pwd)

.PHONY: $(TARGET).ko
$(TARGET).ko:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

all: $(TARGET).ko

install: $(TARGET).ko
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules_install
	depmod -aq $(KVER)

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions Module.symvers

depend .depend dep:
	$(CC) $(EXTRA_FLAGS) -M *.c > .depend

ifeq (.depend,$(wildcard .depend))
include .depend
endif
