#!/bin/bash
# Relies on tests script machinery to do that 

set -eu

cd `dirname $0`

. /etc/acunu/fs-utils

# Override CONFIG variables (e.g. DISKS) here 

umount_fs

echo "Castle cleaned up successfully"

