#!/bin/bash
# Relies on tests script machinery to do that 

set -e

. /usr/share/castle-fs/init-utils

if kernel_fs_running
then
    echo "castle-fs is already running"
    exit 0
fi

disks=$(castle-scan)

compute_devids $disks
setup_loopbacks
init_kernel_fs
claim_all
castle-cli init

echo "castle-fs initialised successfully"
