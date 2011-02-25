ARCH?= $(shell uname -m | sed -e s/i.86/x86_32/)
LIB_POSTFIX      = $(shell echo $(ARCH) | sed -e s/x86_// | grep -v 32 | grep -v Power)

SOURCE_FILES     := $(wildcard *.c)
OBJECT_FILES     := $(patsubst %.c,%.o,$(SOURCE_FILES))
HEADER_FILES     := $(wildcard *.h)

CC := gcc
##
## Build options
##

CFLAGS			+= -I../../kernel
CFLAGS          += -Werror
CFLAGS          += -Wall
CFLAGS          += -Wno-unused
CFLAGS          += -D_GNU_SOURCE
#CFLAGS          += -fPIC
CFLAGS          += -g

LIBS = -L/usr/lib$(LIB_POSTFIX)

MAIN_OBJS  = castle_probe_device

##
## "all" Target
##

all: $(MAIN_OBJS) mkcastlefs

##
## Other targets
##

$(MAIN_OBJS): $(OBJECT_FILES) $(HEADER_FILES)
	$(CC) $(CFLAGS) $@.o $(LIBS) -o $@

mkcastlefs: mkcastlefs.o

%.o: %.c $(HEADER_FILES)
	$(CC) $(CFLAGS) -c -o $*.o $*.c

tags: $(SOURCE_FILES) $(HEADER_FILES)
	ctags $(SOURCE_FILES) $(HEADER_FILES)

.PHONY: clean
clean:
	rm -f *.o $(MAIN_OBJS) mkcastlefs

.PHONY: install
install: castle_probe_device mkcastlefs
	install $(MAIN_OBJS) /usr/sbin
	install -D castle /etc/rc.d/init.d/
	install -D castle_claim_empty /etc/rc.d/init.d/
	install -D init-utils /usr/share/castle-fs/init-utils
	install -D castle-fs-init.sh /usr/share/castle-fs/castle-fs-init
	install -D castle-fs-fini.sh /usr/share/castle-fs/castle-fs-fini
	install -D castle-scan /usr/sbin/castle-scan
	install -D castle-claim-empty /usr/sbin/castle-claim-empty
	install -D castle-create /usr/sbin/castle-create
	install -D check-ssd /usr/sbin/check-ssd
	install -D mkcastlefs /sbin/mkcastlefs
	install -D castle_probe_device /usr/sbin/castle-probe-device
