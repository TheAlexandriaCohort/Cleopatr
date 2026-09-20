#!/bin/sh
set -eu
kernel=$(basename /lib/modules/*)
mkdir -p /ram/bin /ram/proc /ram/sys /ram/dev /ram/lower /ram/upper /ram/root /ram/lib/modules
cp /bin/busybox /ram/bin/busybox
for app in sh mount mkdir modprobe switch_root; do ln -s busybox /ram/bin/$app; done
cp -a "/lib/modules/$kernel" /ram/lib/modules/
cat > /ram/init <<'INIT'
#!/bin/sh
set -eu
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
modprobe virtio_pci
modprobe virtio_rng
modprobe virtio_net
modprobe 9pnet_virtio
modprobe 9p
modprobe overlay
mount -t 9p -o trans=virtio,version=9p2000.L,ro hostroot /lower
mount -t tmpfs tmpfs /upper
mkdir /upper/files /upper/work
mount -t overlay overlay -o lowerdir=/lower,upperdir=/upper/files,workdir=/upper/work /root
mount --move /proc /root/proc
mount --move /sys /root/sys
mount --move /dev /root/dev
exec switch_root /root /usr/lib/cleopatr/vm/init.sh
INIT
chmod 755 /ram/init
(cd /ram && find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -1 > /initramfs.gz)
