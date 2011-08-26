KVER=$(shell uname -r)

all:
	make -C kernel KVER=$(KVER)

install:
	make -C kernel install KVER=$(KVER)

clean:
	make -C kernel clean

bs-install: install
