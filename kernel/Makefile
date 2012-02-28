# Comment/uncomment the following line to disable/enable debugging
DEBUG = y
PERF_DEBUG = n

TARGET = castle-fs

obj-m          := $(TARGET).o
$(TARGET)-objs := castle_utils.o castle_main.o castle_cache.o \
	castle_btree.o castle_freespace.o castle_versions.o \
	castle_ctrl.o castle_sysfs.o castle_events.o castle_da.o \
	castle_objects.o castle_extent.o castle_rda.o castle_back.o \
	castle_vmap.o castle_trace.o castle_rebuild.o castle_bloom.o \
	castle_btree_mtree.o castle_btree_vlba_tree.o castle_btree_slim.o \
	castle_keys_vlba.o castle_keys_normalized.o castle_ctrl_prog.o \
	castle_timestamps.o castle_mstore.o

# Add your debugging flag (or not) to CFLAGS
ifeq ($(DEBUG),y)
  # "-O" is needed to expand inlines and make warnings work
  DEBFLAGS = -O1 -DCASTLE_DEBUG
  $(TARGET)-objs += castle_debug.o
else
  DEBFLAGS = -O2
endif

DEBFLAGS += -Wall -Werror -g

ifeq ($(PERF_DEBUG),y)
  EXTRA_CFLAGS += -DCASTLE_PERF_DEBUG
  $(TARGET)-objs += castle_time.o
endif

EXTRA_CFLAGS += $(DEBFLAGS)
EXTRA_CFLAGS += -I..
EXTRA_CFLAGS += -msoft-float
EXTRA_CFLAGS += -mtune=core2

KVER       ?= $(shell uname -r)
KERNEL_DIR ?= /lib/modules/$(KVER)/build
PWD        := $(shell pwd)

INSTALL_MOD_DIR = extra/castle

.PHONY: all
all: $(TARGET).ko

# Make castle_compile.h PHONY, to get it refreshed every build
.PHONY: castle_compile.h
castle_compile.h:
	@if [ ! -e ../.hg-rev ]; then echo -e "\nCould not find hg revision number. Please add the following to your fs.hg/.hg/hgrc:\n[hooks]\nupdate = hg tip --template \"{date|date} {rev}:{node|short}\" > .hg-rev\ncommit = hg tip --template \"{date|date} {rev}:{node|short}\" > .hg-rev\n"; fi
	@echo "#define CASTLE_COMPILE_CHANGESET \"$(shell (if [ -e ../.hg-rev ]; then cat ../.hg-rev; else echo "unavailable"; fi) 2>/dev/null)\"" > $@.new
	@if cmp -s $@ $@.new; then rm -f $@.new; else mv -f $@.new $@; fi

.PHONY: $(TARGET).ko
$(TARGET).ko: castle_compile.h
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

install: $(TARGET).ko
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) INSTALL_MOD_DIR=$(INSTALL_MOD_DIR) modules_install
	install -m 0644 castle_systemtap.h $(KERNEL_DIR)/include/trace
	depmod -aq $(KVER)

clean:
	rm -rf *.o *~ core .depend .*.o.d .*.cmd *.ko *.mod.c .tmp_versions Module.symvers

define all_sources
	(find . -name '*.[ch]' -print)
endef

.PHONY: tags
tags:
	$(all_sources) | xargs ctags

.PHONY: etags
etags:
	$(all_sources) | xargs etags

.PHONY: cscope
cscope:
	$(all_sources) > cscope.files
	cscope -k -b

depend .depend dep:
	$(CC) $(EXTRA_FLAGS) -M *.c > .depend

ifeq (.depend,$(wildcard .depend))
include .depend
endif
