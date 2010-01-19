#!/bin/bash
# This script is to start castle IN THE PRODUCT VM
# it gets installed to /opt/acunu/castle/bin

CASTLE=/opt/acunu/castle/bin/castle
TEST=/tmp/castle-disks
DISKS="disk1 disk2 disk3"
DISK_SIZE=1000000 # MBs
MOUNT_POINT=/fs

set -eu
cd `dirname $0`

function onexit() {
	local exit_status=${1:-$?}
    if [ $exit_status != 0 ]; then
        echo "Failed to initialise $exit_status!!!!"
        ./castle-fini.sh
    fi
    exit $exit_status
}

trap onexit EXIT

function dev_to_majmin {
    local DEV=$1
    # We only handle loop and castle devices for now
    if [ "x`echo $DEV | grep loop`" != "x" ]; then
        local LOOP_NR=`echo $DEV | sed -e 's#/dev/loop\(.*\)#\1#g'`
        local MAJMIN=`cat /proc/partitions | grep "loop${LOOP_NR}$" | awk '{print ( $1":"$2) }'`
    elif [ "x`echo $DEV | grep castle`" != "x" ]; then
        local CASTLE_NR=`echo $DEV | sed -e 's#/dev/castle/castle\(.*\)#\1#g'`
        local MAJMIN=`cat /proc/partitions | grep "castle${CASTLE_NR}$" | awk '{print ( $1":"$2) }'`
     else
        echo "Could not dev_to_majmin for dev: $DEV"
        false
    fi
    local MAJ=`echo $MAJMIN | cut -d":" -f1`
    local MIN=`echo $MAJMIN | cut -d":" -f2`
    local DEVID=$(( ($MIN & 0xFF) | ( ($MIN & 0xFFF00) << 12 ) | ($MAJ << 8) ))
    DEVID_HEX=`printf "%X" $DEVID`
}

function majmin_to_dev {
    local MAJMIN=`printf "%d" 0x$1`
    local MAJ=$(( ($MAJMIN >> 8) & 0xFFF ))
    local MIN=$(( ($MAJMIN & 0xFF) | (( $MAJMIN >> 12 ) & 0xFFF00 ) ))
    # At the moment we only handle loop and castle devices
    if [ $MAJ == 7 ]; then
        DEV="/dev/loop$MIN"
    elif [ "x`grep "252 *castle" /proc/devices`" != "x" ]; then
        DEV="/dev/castle/castle$MIN"
    else
        echo "Script does not support devs with major: $MAJ"
        false
    fi
}

function write_phrase {
	local filename="$1"
	local phrase="$2"
	
    echo -n "${phrase}" | dd of=$filename 2> /dev/null
}

function check_contents {
	local filename="$1"
	local phrase="$2"
	
    ls -lah ${filename}
	READ=`dd if=${filename} 2> /dev/null`
	if [ "${READ}" == "${phrase}" ]; then
		echo "Got '${READ}', correct."
	else
		echo "Got '${READ}', INCORRECT!"
	fi
}

function check_contents_file {
	local file1="$1"
	local file2="$2"
	
	local CHK1=`dd if=${file1} 2>/dev/null | md5sum -b -`
	local CHK2=`dd if=${file2} 2>/dev/null | md5sum -b -`

	if [ "${CHK1}" == "${CHK2}" ]; then
		echo "File ${file2} still stored correctly"
	else
		echo "Massive fail in snapshot ${file2}"
	fi
}

function do_control_internal {
    echo ""
	echo "Command: $1 0x$2"
	IOCTL_RET=`castle-ctl $1 0x$2 | grep "Ret val:"` 
	IOCTL_RET=`echo $IOCTL_RET | sed -e "s/Ret val: 0x\([0-9a-f]*\)./\1/g"`
}

function do_control_claim {
    local FILE=$1
    local LOOP=`losetup -f`
    losetup $LOOP $FILE
    dev_to_majmin $LOOP
    do_control_internal "claim" $DEVID_HEX
}

function do_control_init {
    do_control_internal "init" 0
}

function do_control_create {
    do_control_internal "create" `printf "%X" $1`
}

function do_control_attach {
    do_control_internal "attach" `printf "%X" $1`
    usleep 500000
    majmin_to_dev $IOCTL_RET
}

function do_control_snapshot {
    dev_to_majmin $1
    do_control_internal "snapshot" $DEVID_HEX 
}

function do_control_clone {
    do_control_internal "clone" `printf "%X" $1`
}

function mod_init {
    if [ `whoami` != root ]; then
        echo "Please run as root"
        exit 1
    fi

    if [ `type castle-fs-cli > /dev/null 2>&1; echo $?` != 0 ]; then
        echo "Command \"castle-fs-cli\" not installed."
        exit 1
    fi

    if [ `lsmod | grep "castle_fs " | wc -l` == 0 ]; then
        echo "Castle FS kernel module not found, trying to insert."
        modprobe castle-fs
    fi
}

function initdisks {
    echo "Disks will be kept in ${TEST}"
    echo "Creating empty disk(s)..."

	for DISK in ${DISKS}; do
		echo "Making empty ${DISK_SIZE} MB file ${TEST}/${DISK}"
		rm -f ${TEST}/${DISK}
		# make spase files with seek=...
    	dd if=/dev/zero of=${TEST}/${DISK} bs=1M count=1 seek=${DISK_SIZE} 2>/dev/null 
	done
}

function initfs {
    mod_init
    echo
    echo "Initing FS..."
	
	for DISK in ${DISKS}; do
		do_control_claim "${TEST}/${DISK}" 
	done

	do_control_init
}

./castle-fini.sh
initdisks
initfs

do_control_create 10

echo "Castle initialised successfully"
