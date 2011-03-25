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

Please help us to debug the problem by notifying Acunu of the problem.
You can force the filesystem to restart from the last successful checkpoint
by removing the dirty flag:
	# rm /var/lib/castle-fs/dirty
followed by restart of the system.
EOF
    exit 1
fi

disks=$(castle-scan)

load_fs_and_claim $disks
sync
echo "All disks claimed"
castle-cli init

echo "castle-fs initialised successfully"
