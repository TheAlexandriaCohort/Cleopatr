#!/bin/sh
set -eu
export PATH=/usr/local/bin:/usr/bin:/bin:/sbin
trap 'echo CLEO_VM_FAILED; busybox poweroff -f' EXIT
mount -t cgroup2 none /sys/fs/cgroup
busybox ip link set lo up
echo 'CLEO_VM_START'
cleo-supervisor doctor
if [ -x /test/kernel-tests ]; then /test/kernel-tests --test-threads=1 --include-ignored --nocapture; fi
if [ -f /test/vm-session.sh ]; then sh /test/vm-session.sh; fi
echo 'CLEO_VM_COMPLETE'
sync
trap - EXIT
busybox poweroff -f
