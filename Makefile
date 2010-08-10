KVER = 2.6.18-194.8.1.el5.acunu

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
