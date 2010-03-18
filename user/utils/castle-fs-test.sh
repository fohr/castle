#!/bin/bash
# This script is to start castle IN THE PRODUCT VM
# it gets installed to /opt/acunu/castle/bin

TEST=/tmp/castle-disks
DISKS="disk1 disk2 disk3"
DISK_SIZE=100 # in MB
#DISKS="/dev/hdb /dev/hdc /dev/hdd"
MOUNT_POINT=/tmp/mnt
MOUNT_POINT2=/tmp/mnt2

set -eu
cd `dirname $0`

function onexit() {
	local exit_status=${1:-$?}
    umount ${MOUNT_POINT} 2>/dev/null  || true
    umount ${MOUNT_POINT2} 2>/dev/null || true
    if [ $exit_status != 0 ]; then
        echo "FAILED THE TEST. EXIT STATUS: $exit_status."
        ./castle-fs-fini.sh
    fi
    exit $exit_status
}

trap onexit EXIT

function dev_to_majmin {
    local DEV=$1
    # We only handle loop and castle and hdX devices for now
    if [ "x`echo $DEV | grep loop`" != "x" ]; then
        local LOOP_NR=`echo $DEV | sed -e 's#/dev/loop\(.*\)#\1#g'`
        local MAJMIN=`cat /proc/partitions | grep "loop${LOOP_NR}$" | awk '{print ( $1":"$2) }'`
    elif [ "x`echo $DEV | grep castle`" != "x" ]; then
        local CASTLE_NR=`echo $DEV | sed -e 's#/dev/castle-fs/castle-\(.*\)#\1#g'`
        local MAJMIN=`cat /proc/partitions | grep "castle-fs-${CASTLE_NR}$" | awk '{print ( $1":"$2) }'`
    elif [ "x`echo $DEV | grep hd`" != "x" ]; then
        local HD=`echo $DEV | sed -e 's#/dev/hd\(.\)#hd\1#g'`
        local MAJMIN=`cat /proc/partitions | grep "${HD}$" | awk '{print ( $1":"$2) }'`
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
        DEV="/dev/castle-fs/castle-$MIN"
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
    #echo "==> Comparing ${file1} with ${file2}"
    #echo "    ${file1}"
	#dd if=${file1} 2>/dev/null | hexdump -C
    #echo "    ${file2}"
	#dd if=${file2} 2>/dev/null | hexdump -C 

	if [ "${CHK1}" == "${CHK2}" ]; then
		echo "Files ${file1} and ${file2} match"
	else
		echo "FAILED content check for ${file1} & ${file2}"
	fi
}

function do_control_internal {
	echo -n "   Command: $1 0x$2"
	IOCTL_RET=`castle-fs-cli $1 0x$2 | grep "Ret val:"` 
	IOCTL_RET=`echo $IOCTL_RET | sed -e "s/Ret val: 0x\([0-9a-f]*\)./\1/g"`
	echo "    ret: $IOCTL_RET"
}

function do_control_claim {
    local FILE=$1
    if [ `echo "${FILE}" | grep "/dev" | wc -l` == 0 ]; then
        local LOOP=`losetup -f`
        losetup $LOOP ${TEST}/${FILE}
        dev_to_majmin $LOOP
    else
        dev_to_majmin $FILE
    fi
    do_control_internal "claim" $DEVID_HEX
}

function do_control_init {
    do_control_internal "init" 0
}

function do_control_create {
    do_control_internal "create" `printf "%X" $1`
    VOL_VER=$IOCTL_RET
}

function do_control_attach {
    do_control_internal "attach" $1
    majmin_to_dev $IOCTL_RET
}

function do_control_detach {
    dev_to_majmin $1
    do_control_internal "detach" $DEVID_HEX
}

function do_control_snapshot {
    dev_to_majmin $1
    do_control_internal "snapshot" $DEVID_HEX 
    SNAP_VER=$IOCTL_RET
}

function do_control_clone {
    do_control_internal "clone" $1
    CLONE_VER=$IOCTL_RET
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

function initfs {
    mod_init
    echo
    echo "Initing FS..."
	
	for DISK in ${DISKS}; do
		do_control_claim "${DISK}" 
	done

	do_control_init
}

mkdir -p ${TEST}
./castle-fs-fini.sh
for DISK in ${DISKS}; do
    if [ `echo "$DISK" | grep dev | wc -l` == 0 ]; then 
        echo "Creating backing file: $DISK"
	    dd              if=/dev/zero of=${TEST}/${DISK} bs=1M count=1 seek=$DISK_SIZE 2>/dev/null
	    dd conv=notrunc if=/dev/zero of=${TEST}/${DISK} bs=4K count=2 2>/dev/null
    else
	    # clear the superblocks
        echo "Invalidating superblocks in $DISK"
	    dd if=/dev/zero of=${DISK} bs=4K count=2 2>/dev/null
    fi
done
initfs
echo "Castle initialised successfully"


echo
echo "Simple Hello World Test..."

do_control_create 10
do_control_attach ${VOL_VER}

PHRASE="Hello World!"
write_phrase   $DEV "$PHRASE"
check_contents $DEV "$PHRASE"

echo
echo "Removing module, reinitialising the FS ..."
./castle-fs-fini.sh
initfs
do_control_attach 1
check_contents $DEV "$PHRASE"
echo





echo "Create two snapshots"

echo "Dev is: $DEV"
do_control_snapshot $DEV
do_control_snapshot $DEV

NEW_PHRASE="This is some stuff written to snapshot 3"
write_phrase   $DEV "$NEW_PHRASE" 
check_contents $DEV "$NEW_PHRASE"

echo "Check snapshot 1 and 2"

for I in 1 2; do
	echo "Check contents now of snapshot ${I}"
    do_control_attach ${I}
    check_contents $DEV "$PHRASE"
done






echo "Large volume (btree split) test"
SIZE=5000
TEST_FILE=/tmp/bigvol
do_control_create ${SIZE}
do_control_attach ${VOL_VER}
echo -n "   Zeroing $DEV ... "
dd if=/dev/zero of=${DEV}      bs=4K count=${SIZE}  2> /dev/null
echo    " done."
echo -n "   Zeroing ${TEST_FILE} ... "
dd if=/dev/zero of=${TEST_FILE} bs=4K count=${SIZE} 2> /dev/null
echo    " done."

check_contents_file ${DEV} ${TEST_FILE}








echo
echo "More intense snapshots/clones"
INTENSITY=1000
TEST_FILE=/tmp/a_block_of_as
COMP_FILES=/scratch/gmilos/tmp/snap
rm -f $TEST_FILE
# a block of 1s (for dd'ing in)
for i in `seq 4096`; do echo -n "a">> ${TEST_FILE}; done
# create file (for comparison) 
dd if=/dev/zero of=${COMP_FILES}0 bs=4K count=${INTENSITY} 2>/dev/null
do_control_create ${INTENSITY}
do_control_attach ${VOL_VER}
CURR_SNAP=${VOL_VER}
FIRST_CLONE=""
for I in `seq 1 $(( ${INTENSITY} - 1 ))`; do
	H=$(( $I - 1 ))
	
	echo "Snapshotting and cloneing snapshot ${CURR_SNAP}, dev ${DEV} ($I of ${INTENSITY})"
	
	do_control_snapshot ${DEV}
	do_control_clone    ${CURR_SNAP}
    if [ "x"$FIRST_CLONE == "x" ]; then
        FIRST_CLONE=${CLONE_VER}
    fi
    CURR_SNAP=${SNAP_VER}
	
	dd conv=notrunc if=${TEST_FILE} of=${DEV} bs=4K count=1 seek=$I 2>/dev/null
	cp ${COMP_FILES}${H} ${COMP_FILES}${I}
	dd conv=notrunc if=${TEST_FILE} of=${COMP_FILES}${I} bs=4K count=1 seek=$I 2>/dev/null
done

echo "Comparing saved files and snapshots"
for I in `seq 1 $(( ${INTENSITY} - 1 ))`; do
	H=$(( $I - 1 ))
    CURR_SNAP=$(($FIRST_CLONE + 2*$H))
    echo "Comparing ${COMP_FILES}${H} with snapshot ${CURR_SNAP}"
    do_control_attach `printf "%X" ${CURR_SNAP}`
    echo "Got device: ${DEV}"
    check_contents_file ${DEV} ${COMP_FILES}${H}
    do_control_detach ${DEV}
done





echo
echo "Mkfs ext3 ..."

FSSIZE=100000
do_control_create ${FSSIZE}
CURR_SNAP=${VOL_VER}
do_control_attach ${CURR_SNAP}


# TODO re-enable for full tests (disabled to make the script run faster 
#dd if=/dev/zero of=${DEV} bs=4k count=${FSSIZE} 2>/dev/null

mkfs.ext3 ${DEV} > /dev/null

mkdir -p ${MOUNT_POINT}
mount ${DEV} ${MOUNT_POINT}

touch ${MOUNT_POINT}/testfile

echo
echo "Remounting ext3..."

umount ${MOUNT_POINT}

mount ${DEV} ${MOUNT_POINT}

if [ -f ${MOUNT_POINT}/testfile ]; then
	echo "  File exists, OK"
else
	echo "  File doesn't exist, FAIL"
fi





echo
echo "Random file test..."

RANDOM_FILE_SIZE=15 # in MB
RANDOM_FILE=/tmp/some_random_file
RANDOM_FILE_ON_FS=some_random_file
RANDOM_FILE2=/tmp/another_random_file

dd if=/dev/urandom of=${RANDOM_FILE}  bs=1M count=$RANDOM_FILE_SIZE &>/dev/null
dd if=/dev/urandom of=${RANDOM_FILE2} bs=1M count=$RANDOM_FILE_SIZE &>/dev/null
echo "  Files created"

cp ${RANDOM_FILE} ${MOUNT_POINT}/${RANDOM_FILE_ON_FS}
echo "  Random file copied to the fs"

check_contents_file ${RANDOM_FILE} ${MOUNT_POINT}/${RANDOM_FILE_ON_FS}
umount ${MOUNT_POINT}
echo "  Restarting the fs"
./castle-fs-fini.sh
initfs

do_control_attach ${CURR_SNAP} 
mount ${DEV} ${MOUNT_POINT}
check_contents_file ${RANDOM_FILE} ${MOUNT_POINT}/${RANDOM_FILE_ON_FS}
umount ${MOUNT_POINT}



echo
echo "Now snapshot file system and mount old image..."

RW_DEV=${DEV}
do_control_snapshot ${DEV} 
do_control_attach ${CURR_SNAP}
RO_DEV=${DEV}

mkdir -p ${MOUNT_POINT2}
mount ${RO_DEV} ${MOUNT_POINT2} -o ro

check_contents_file ${RANDOM_FILE} ${MOUNT_POINT2}/${RANDOM_FILE_ON_FS}

echo "Also remount RW volume.."
mount ${RW_DEV} ${MOUNT_POINT}
check_contents_file ${RANDOM_FILE} ${MOUNT_POINT}/${RANDOM_FILE_ON_FS}

echo "Overwrite the random file..."
cp ${RANDOM_FILE2} ${MOUNT_POINT}/${RANDOM_FILE_ON_FS}
check_contents_file ${RANDOM_FILE2} ${MOUNT_POINT}/${RANDOM_FILE_ON_FS}

echo "Check contents of file in RO snapshot unaffected..."
check_contents_file ${RANDOM_FILE} ${MOUNT_POINT2}/${RANDOM_FILE_ON_FS}

umount ${MOUNT_POINT2}
umount ${MOUNT_POINT}

