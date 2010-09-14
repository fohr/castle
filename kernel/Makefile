# Comment/uncomment the following line to disable/enable debugging
DEBUG = y
PERF_DEBUG = y

TARGET = castle-fs

obj-m          := $(TARGET).o
$(TARGET)-objs := castle_utils.o castle_main.o castle_cache.o castle_block.o castle_btree.o castle_freespace.o castle_versions.o castle_ctrl.o castle_sysfs.o castle_transfer.o castle_events.o castle_rxrpc.o castle_da.o castle_objects.o dev_extent.o dev_freespace.o dev_rda.o

# Add your debugging flag (or not) to CFLAGS
ifeq ($(DEBUG),y)
  DEBFLAGS = -Werror -O0 -g -DCASTLE_DEBUG # "-O" is needed to expand inlines
  $(TARGET)-objs += castle_debug.o
else
  DEBFLAGS = -O0 -g
endif

ifeq ($(PERF_DEBUG),y)
  EXTRA_CFLAGS += -DCASTLE_PERF_DEBUG 
  $(TARGET)-objs += castle_time.o
endif

EXTRA_CFLAGS += $(DEBFLAGS)
EXTRA_CFLAGS += -I..

KVER       ?= 2.6.18-194.11.3.el5.acunu
KERNEL_DIR ?= /lib/modules/$(KVER)/build
PWD        := $(shell pwd)

.PHONY: all
all: $(TARGET).ko

# Make castle_compile.h PHONY, to get it refreshed every build
.PHONY: castle_compile.h
castle_compile.h:
	@if [ ! -e ../.hg-rev ]; then echo "\nCould not find hg revision number. Please add the following to your fs.hg/.hg/hgrc:\n[hooks]\nupdate = hg tip --template \"{date|date} {rev}:{node|short}\" > .hg-rev\ncommit = hg tip --template \"{date|date} {rev}:{node|short}\" > .hg-rev\n"; fi
	@echo "#define CASTLE_COMPILE_CHANGESET \"$(shell (if [ -e ../.hg-rev ]; then cat ../.hg-rev; else echo "unavailable"; fi) 2>/dev/null)\"" > $@

.PHONY: $(TARGET).ko
$(TARGET).ko: castle_compile.h
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

install: $(TARGET).ko
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules_install
	depmod -aq $(KVER)

clean:
	rm -rf *.o *~ core .depend .*.o.d .*.cmd *.ko *.mod.c .tmp_versions Module.symvers

define all_sources	
	(find . -name '*.[ch]' -print)
endef

.PHONY: tags
tags:
	$(all_sources) | xargs ctags

.PHONY: cscope
cscope:
	$(all_sources) > cscope.files
	cscope -k -b -q

depend .depend dep:
	$(CC) $(EXTRA_FLAGS) -M *.c > .depend

ifeq (.depend,$(wildcard .depend))
include .depend
endif
