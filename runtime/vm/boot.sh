#!/bin/sh
set -eu
kernel=$(basename /lib/modules/*)
exec qemu-system-aarch64 -machine virt -cpu cortex-a72 -smp 2 -m 2048 -display none -monitor none -serial stdio -no-reboot \
  -kernel "/boot/vmlinuz-$kernel" -initrd /initramfs.gz \
  -append 'console=ttyAMA0 rdinit=/init panic=1 quiet loglevel=3 lsm=landlock,lockdown,yama,integrity,apparmor,bpf' \
  -object rng-random,filename=/dev/urandom,id=rng0 -device virtio-rng-pci,rng=rng0 \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0,romfile= \
  -virtfs local,path=/,mount_tag=hostroot,security_model=none,readonly=on \
  -virtfs local,path=/workspace-host,mount_tag=workspace,security_model=none \
  -virtfs local,path=/session,mount_tag=session,security_model=none
