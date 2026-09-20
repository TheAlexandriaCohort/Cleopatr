#!/bin/sh
set -eu
cargo test --locked --manifest-path runtime/native/Cargo.toml -- --test-threads=1
cargo test --locked --manifest-path runtime/native/Cargo.toml --no-run --message-format=json > /tmp/cleo-test-artifacts.json
python3 - <<'PY'
import json, shutil
for line in open('/tmp/cleo-test-artifacts.json'):
    data = json.loads(line)
    if data.get('reason') == 'compiler-artifact' and data.get('profile', {}).get('test') and data.get('executable'):
        shutil.copyfile(data['executable'], '/artifacts/vm/kernel-tests')
        break
else:
    raise RuntimeError('Test executable not found')
PY
chmod 755 /artifacts/vm/kernel-tests
cargo build --locked --release --manifest-path runtime/native/Cargo.toml
cp runtime/native/target/release/cleo-supervisor /artifacts/cleo-supervisor

cc -static -O2 -Wall -Wextra /test/syscall-probe.c -o /artifacts/vm/syscall-probe
