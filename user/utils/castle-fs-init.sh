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

DISKS="/dev/hdb5 /dev/hdb6 /dev/hdb7 /dev/hdb8 /dev/hdb9 /dev/hdb10 /dev/hdb11 /dev/hdb12"
DISK_SIZE=1000 # in MB

umount_fs
init_disks
init_fs

echo "Castle initialised successfully"
castle-fs-cli "create" 0x3D090 
castle-fs-cli "attach" 1
