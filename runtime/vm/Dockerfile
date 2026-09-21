FROM rust:1.92.0-slim-bookworm AS native
WORKDIR /build
COPY native ./native
RUN cargo build --locked --release --manifest-path native/Cargo.toml

FROM node:24.21.0-bookworm-slim AS node
FROM debian:trixie-slim
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends qemu-system-arm linux-image-arm64 busybox-static cpio kmod ca-certificates curl python3 && rm -rf /var/lib/apt/lists/*
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=native /build/native/target/release/cleo-supervisor /usr/lib/cleopatr/cleo-supervisor
COPY worker.js guest.js cleo.js package.json /usr/lib/cleopatr/
COPY cedar /usr/lib/cleopatr/node_modules/@cedar-policy/cedar-wasm
COPY boot.sh init.sh rootfs.sh initramfs.sh /usr/lib/cleopatr/vm/
RUN sh /usr/lib/cleopatr/vm/initramfs.sh && sh /usr/lib/cleopatr/vm/rootfs.sh && chmod 755 /usr/lib/cleopatr/vm/boot.sh /usr/lib/cleopatr/vm/init.sh
ENTRYPOINT ["/usr/lib/cleopatr/vm/boot.sh"]
