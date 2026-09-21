#!/bin/sh
set -eu
root=/opt/cleopatr-rootfs
mkdir -p "$root/workspace" "$root/tmp" "$root/proc" "$root/dev" "$root/etc/ssl/certs"
copy_file() {
  mkdir -p "$root$(dirname "$1")"
  cp -L "$1" "$root$1"
}
for binary in /usr/local/bin/node /usr/bin/curl /usr/bin/env /bin/sh /bin/bash /bin/busybox; do
  copy_file "$binary"
  ldd "$binary" 2>/dev/null | awk '$1 ~ /^\// { print $1 } $3 ~ /^\// { print $3 }' | while read -r library; do
    copy_file "$library"
  done
done
cp /etc/ssl/certs/ca-certificates.crt "$root/etc/ssl/certs/"
printf 'hosts: files dns\n' > "$root/etc/nsswitch.conf"
printf '127.0.0.1 localhost\n' > "$root/etc/hosts"
printf 'nameserver 127.0.0.53\n' > "$root/etc/resolv.conf"
# This restricted preview supplies a read-only EOF file for shell stdin only.
# General device access and writes to /dev/null are not part of this rootfs.
touch "$root/dev/null"
chmod -R go-w "$root"
