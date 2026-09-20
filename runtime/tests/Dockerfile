FROM rust:1.92.0-slim-bookworm
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends ca-certificates python3 && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY runtime/native /build/runtime/native
RUN cargo build --locked --manifest-path runtime/native/Cargo.toml --release
ENTRYPOINT ["/build/runtime/native/target/release/cleo-supervisor"]
