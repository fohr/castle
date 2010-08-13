#!/bin/bash
# Relies on tests script machinery to do that 

set -eu

cd `dirname $0`

# Include utils scripts (it may be in the current directory, on product VM)
if [ -e utils ]; then
    . utils
elif [ -e tests/utils ]; then
    cd tests
    . utils
fi
# Override CONFIG variables (e.g. DISKS) here 

case $(hostname) in
	jarek.theisland.acunu.com|lech.theisland.acunu.com)
		echo foo;
		DISKS=`ls /dev/sd*2`;;
	*)
		DISKS="disk1 disk2 disk3";;
esac

DISK_SIZE=2000 # in MB

umount_fs
init_disks
init_fs

echo "Castle initialised successfully"
castle-fs-cli "create" 0x280000 
castle-fs-cli "attach" 1
