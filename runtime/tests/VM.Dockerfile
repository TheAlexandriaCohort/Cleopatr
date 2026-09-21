FROM node:24.21.0-bookworm-slim AS node
FROM cleopatr-runtime-test AS native
FROM debian:trixie-slim
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends qemu-system-arm linux-image-arm64 busybox-static cpio kmod ca-certificates python3 && rm -rf /var/lib/apt/lists/*
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=native /build/runtime/native/target/release/cleo-supervisor /usr/local/bin/cleo-supervisor
COPY runtime/tests/vm-boot.sh /usr/local/bin/vm-boot
RUN chmod 755 /usr/local/bin/vm-boot
ENTRYPOINT ["/usr/local/bin/vm-boot"]
