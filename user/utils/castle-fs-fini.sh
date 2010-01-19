#!/bin/bash
# This script cleans up inited castle instance. It's called from castle-init.sh,
# but it can also be called manually.

DISKS=/tmp/castle-disks

set -eu

function umount_fs {
    if [ `lsmod | grep "castle_fs " | wc -l` != 0 ]; then 
        rmmod castle
    fi
    # Delete the disk loop files
    for LOOP in `losetup -a | grep "${DISKS}" | cut -d":" -f1`; do
        losetup -d $LOOP
    done
}

umount_fs

echo "Castle cleaned up successfully"
