import { build } from 'esbuild';
import { mkdir, copyFile, writeFile, cp, rm } from 'node:fs/promises';
await mkdir('dist-runtime', { recursive: true });
await cp(
  'node_modules/@cedar-policy/cedar-wasm',
  'dist-runtime/node_modules/@cedar-policy/cedar-wasm',
  { recursive: true },
);
await copyFile('docs/LINUX_HARNESS.md', 'dist-runtime/README.md');
await copyFile('docs/ENCLAVE_ACTIONS.md', 'dist-runtime/ENCLAVE_ACTIONS.md');
await cp('docs/examples', 'dist-runtime/examples', { recursive: true });
await build({
  entryPoints: ['runtime/worker.ts'],
  outfile: 'dist-runtime/worker.js',
  bundle: true,
  platform: 'node',
  format: 'esm',
  packages: 'external',
  target: 'node22',
});
await build({
  entryPoints: ['cli/main.ts'],
  outfile: 'dist-runtime/cleo.js',
  bundle: true,
  platform: 'node',
  format: 'esm',
  packages: 'external',
  target: 'node22',
});
await writeFile(
  'dist-runtime/package.json',
  JSON.stringify(
    {
      private: true,
      type: 'module',
      dependencies: { '@cedar-policy/cedar-wasm': '4.12.0' },
    },
    null,
    2,
  ),
);
for (const file of [
  'supervisor.example.json',
  'systemd/cleopatr-supervisor.service',
])
  await copyFile(`runtime/${file}`, `dist-runtime/${file.split('/').at(-1)}`);

await build({
  entryPoints: ['runtime/vm/guest.ts'],
  outfile: 'dist-runtime/guest.js',
  bundle: true,
  platform: 'node',
  format: 'esm',
  packages: 'external',
  target: 'node22',
});
const context = 'dist-runtime/vm-runtime';
await mkdir(context + '/native', { recursive: true });
for (const file of [
  'Dockerfile',
  'boot.sh',
  'init.sh',
  'rootfs.sh',
  'initramfs.sh',
])
  await copyFile('runtime/vm/' + file, context + '/' + file);
for (const file of ['Cargo.toml', 'Cargo.lock'])
  await copyFile('runtime/native/' + file, context + '/native/' + file);
await cp('runtime/native/src', context + '/native/src', { recursive: true });
for (const file of ['worker.js', 'guest.js', 'cleo.js', 'package.json'])
  await copyFile('dist-runtime/' + file, context + '/' + file);
await rm(context + '/node_modules', { recursive: true, force: true });
await cp(
  'dist-runtime/node_modules/@cedar-policy/cedar-wasm',
  context + '/cedar',
  { recursive: true },
);
