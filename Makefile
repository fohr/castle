KVER = 2.6.24
KERNEL_DIR = /lib/modules/$(KVER)/build
all:
	make -C kernel KERNEL_DIR=$(KERNEL_DIR) KVER=$(KVER)
	make -C kernel install KERNEL_DIR=$(KERNEL_DIR) KVER=$(KVER)

	make -C user 
	make -C user install
	
clean:
	make -C kernel clean
	make -C user clean
