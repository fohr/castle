ARCH?= $(shell uname -m | sed -e s/i.86/x86_32/)
LIB_POSTFIX      = $(shell echo $(ARCH) | sed -e s/x86_// | grep -v 32 | grep -v Power)

SOURCE_FILES     := $(wildcard *.c)
OBJECT_FILES     := $(patsubst %.c,%.o,$(SOURCE_FILES))
HEADER_FILES     := $(wildcard *.h)

CC := gcc
##
## Build options
##

CFLAGS          += -Werror
CFLAGS          += -Wall
CFLAGS          += -Wno-unused
CFLAGS          += -D_GNU_SOURCE
CFLAGS          += -fPIC
CFLAGS          += -g

LIBS = -L/usr/lib$(LIB_POSTFIX)

MAIN_OBJS  = castle-fs-cli 

##
## "all" Target
##

all: $(MAIN_OBJS)

##
## Other targets
##

$(MAIN_OBJS): $(OBJECT_FILES) $(HEADER_FILES)
	$(CC) $(CFLAGS) $@.o $(LIBS) -o $@

%.o: %.c $(HEADER_FILES)
	$(CC) $(CFLAGS) -c -o $*.o $*.c

tags: $(SOURCE_FILES) $(HEADER_FILES)
	ctags $(SOURCE_FILES) $(HEADER_FILES)

.PHONY: clean
clean:
	rm -f *.o $(MAIN_OBJS) 

.PHONY: install
install: $(MAIN_OBJS)
	install $(MAIN_OBJS) /usr/sbin
	install -D CONFIG /opt/acunu/castle-fs/bin/CONFIG
	install -D utils  /opt/acunu/castle-fs/bin/utils
	install -D castle-fs-init.sh /opt/acunu/castle-fs/bin/castle-fs-init.sh
	install -D castle-fs-fini.sh /opt/acunu/castle-fs/bin/castle-fs-fini.sh

