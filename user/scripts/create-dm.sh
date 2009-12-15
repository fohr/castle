#!/bin/bash

set -e
if [ $# != 2 ]; then
    echo "Usage create-dm.sh <new-dm-name> <block-device>";
    exit 1;
fi

DM_NAME=$1
BLOCK_DEV=$2

MAJMIN=`cat /proc/partitions | grep $BLOCK_DEV | sed -e 's/[ ]*\([0-9]*\)[ ]*\([0-9]*\).*/\1,\2/g'`
MAJOR=`echo $MAJMIN | cut -d"," -f1`
MINOR=`echo $MAJMIN | cut -d"," -f2`
CMD="0 `blockdev --getsize /dev/$BLOCK_DEV` castle $MAJOR $MINOR"

echo "Executing dmsetup create with tbl=\"$CMD\""
echo $CMD | dmsetup create $DM_NAME 
