#!/bin/bash
# Relies on tests script machinery to do that 

set -eu

. /usr/share/castle-fs/init-utils

if [ -e "/dev/castle-fs/control" ] || lsmod | grep -q '^castle_fs$'
then
    echo "castle-fs is already running"
    exit 0
fi

disks=$(castle-scan)
declare -a devids loops

for disk in $disks
do
  if [ -e "$disk" ] && [ -b "$disk" ]
  then
      # Block special
      devids=("${devids[@]}" $(devid_of_disk "$disk"))
      continue
  fi

  if ! [ -e "$disk" ]
  then
      if echo $disk | grep -q '^/dev/' then
          # Presumably block special device (not existing)
          echo "Device $disk does not exist, aborting"
          exit 1
      fi

      # Loopback file (not existing)
      dd conv=excl if=/dev/zero of=$disk bs=1M count=1 seek=$DISK_SIZE 2>/dev/null
  fi

  if [ -e "$disk" ] && [ -f "$disk" ]
  then
      # Loopback file (existing)
      loops=("${loops[@]}" "$disk")
  fi
done

# Setup loopback devices
for disk in "${loops[@]}"
do
  loop=$(losetup -f)
  losetup "$loop" "$disk"
  devids=("${devids[@]}" $(devid_of_disk "$loop"))
done

# Claim devices
for devid in "${devids[@]}"
do
  runcli claim "$devid"
done

# Init filesystem
runcli init

echo "castle-fs initialised successfully"
