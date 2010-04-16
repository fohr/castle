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

umount_fs

echo "Castle cleaned up successfully"

