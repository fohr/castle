# Comment/uncomment the following line to disable/enable debugging
#DEBUG = y

all: castle.ko

# Add your debugging flag (or not) to CFLAGS
ifeq ($(DEBUG),y)
  DEBFLAGS = -O0 -g -DCASTLE_DEBUG # "-O" is needed to expand inlines
else
  DEBFLAGS = -O0 -g
endif

EXTRA_CFLAGS += $(DEBFLAGS)
EXTRA_CFLAGS += -I..

ifneq ($(KERNELRELEASE),)
# call from kernel build system
obj-m         := castle.o
castle-objs   := castle_main.o castle_sysfs.o

else

KERNEL_DIR ?= /lib/modules/$(KVER)/build
PWD        := $(shell pwd)

castle.ko: clean $(castle-objs)
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules
endif

install: castle.ko
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules_install
	depmod -aq `uname -r` 

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions Module.symvers

depend .depend dep:
	$(CC) $(EXTRA_FLAGS) -M *.c > .depend

ifeq (.depend,$(wildcard .depend))
include .depend
endif
