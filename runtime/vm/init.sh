#!/bin/sh
set -eu
export PATH=/usr/local/bin:/usr/bin:/bin:/sbin
trap 'busybox poweroff -f' EXIT
mount -t cgroup2 none /sys/fs/cgroup
busybox ip link set lo up
busybox ip link set eth0 up
busybox ip addr add 10.0.2.15/24 dev eth0
busybox ip route add default via 10.0.2.2
printf 'nameserver 10.0.2.3\n' > /etc/resolv.conf
mkdir -p /session-live /srv/workspace
mount -t 9p -o trans=virtio,version=9p2000.L,cache=none session /session-live
mount -t 9p -o trans=virtio,version=9p2000.L,cache=mmap workspace /srv/workspace
echo '+memory +pids' > /sys/fs/cgroup/cgroup.subtree_control
mkdir /sys/fs/cgroup/cleopatr
node /usr/lib/cleopatr/guest.js
sync
