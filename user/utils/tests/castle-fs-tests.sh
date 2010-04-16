#!/bin/bash

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
. 00-hello-world
. 10-two-snapshots
. 20-regions
. 30-transfers
. 40-large-volume
. 50-n-snapshots
. 60-ext3-init
. 61-ext3-single-file
. 62-ext3-random-file
. 63-ext3-snapshots
