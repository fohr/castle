#!/bin/bash
# Relies on tests script machinery to do that 

cd `dirname $0`
cd tests

. utils
# Override CONFIG variables (e.g. DISKS) here 

umount_fs
init_disks
init_fs

do_control_create 100
echo "Castle initialised successfully"

