#!/bin/bash

set -e

DEVS=`ls /dev/mapper | grep -v control` 
for DEV in $DEVS; do
    echo "Removing /dev/mapper/$DEV"
    dmsetup remove /dev/mapper/$DEV
done
