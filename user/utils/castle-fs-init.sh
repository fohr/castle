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

load_fs_and_claim $disks
castle-cli init

echo "castle-fs initialised successfully"
