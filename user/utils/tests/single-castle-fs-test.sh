#!/bin/bash

if [ $# != 1 ]; then
	echo Usage: ${0} name_of_test_file
	echo e.g.,  ${0} 10-two-snapshots
	exit 1
fi

cd `dirname $0`

# This includes CONFIG recursively
. utils

# Remove the FS if it's running currently
umount_fs

# Initialise disks 
init_disks

# Initialise the FS (insert module, claim disks) 
init_fs

# Do the individual tests
. ${1}
