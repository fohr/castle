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

DISKS="disk1 disk2 disk3 disk4 disk5 disk6"
DISK_SIZE=100 # in MB

umount_fs
init_disks
init_fs

echo "Castle initialised successfully"

