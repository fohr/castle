#!/bin/bash
# Relies on tests script machinery to do that 

set -eu

. /usr/share/castle-fs/init-utils

unmount_kernel_fs
rm -f /var/lib/castle-fs/dirty

disks=$(castle-scan)

for disk in $disks
do
  for loop in $(losetup -a | grep "($disk)" | cut -d: -f1)
  do
    losetup -d "$loop"
  done
done

echo "castle-fs shut down successfully"
