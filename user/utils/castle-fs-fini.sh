#!/bin/bash
# Relies on tests script machinery to do that 

set -eu

. /usr/share/castle-fs/init-utils

unmount_kernel_fs

echo "castle-fs shut down successfully"
