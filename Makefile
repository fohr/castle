all:
	make -C kernel KERNEL_DIR=/lib/modules/2.6.24/build
	make -C kernel install KERNEL_DIR=/lib/modules/2.6.24/build

	make -C user 
	make -C user install
	
clean:
	make -C kernel clean
	make -C user clean