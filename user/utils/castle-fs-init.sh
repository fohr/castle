#!/bin/bash
# Relies on tests script machinery to do that 

set -eu

cd `dirname $0`

. /etc/acunu/fs-utils


DISK_SIZE=20000 # in MB

umount_fs
init_disks
init_fs $@

echo "Castle initialised successfully"
castle-fs-cli "create" 0x280000 
castle-fs-cli "attach" 1
