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

DISKS="/dev/hdc5 /dev/hdc6 /dev/hdc7 /dev/hdc8 /dev/hdc9 /dev/hdc10 /dev/hdc11 /dev/hdc12"
DISK_SIZE=1000 # in MB

umount_fs
init_disks
init_fs

echo "Castle initialised successfully"

