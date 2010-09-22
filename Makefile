KVER=$(shell uname -r)

all:
	make -C kernel KVER=$(KVER)
	make -C user 

install:
	make -C kernel install KVER=$(KVER)
	make -C user install
	
clean:
	make -C kernel clean
	make -C user clean

bs-install: install
