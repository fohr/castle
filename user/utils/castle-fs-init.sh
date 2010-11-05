#!/bin/bash
# Relies on tests script machinery to do that 

set -e

. /usr/share/castle-fs/init-utils

if kernel_fs_running
then
    echo "castle-fs is already running"
    exit 0
fi

if [ -e /var/lib/castle-fs/dirty ]
then
    cat <<EOF
castle-fs was not cleanly shut down

At this stage of beta, starting castle-fs on a dirty filesystem is not
supported and will probably crash your kernel. To erase all the stored
data and start over, please run:

   acunu_nuke all
EOF
    exit 1
fi

disks=$(castle-scan)

load_fs_and_claim $disks
castle-cli init
touch /var/lib/castle-fs/dirty

echo "castle-fs initialised successfully"
