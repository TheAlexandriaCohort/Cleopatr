import { build } from 'esbuild';
import {
  mkdir,
  readFile,
  writeFile,
  copyFile,
  chmod,
  cp,
  rm,
} from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
await import('./build-runtime.mjs');
await mkdir('dist-cli', { recursive: true });
await mkdir('public/downloads', { recursive: true });
await build({
  entryPoints: ['cli/main.ts'],
  outfile: 'dist-cli/cleo.js',
  bundle: true,
  platform: 'node',
  format: 'esm',
  packages: 'external',
  target: 'node22',
});
await chmod('dist-cli/cleo.js', 0o755);
await writeFile(
  'dist-cli/package.json',
  JSON.stringify(
    {
      name: 'cleopatr-cli',
      version: '0.6.0',
      description: 'Cleopatr local Cedar policy authorization CLI',
      type: 'module',
      bin: { cleo: 'cleo.js' },
      engines: { node: '>=22.13.0' },
      files: [
        'cleo.js',
        'README.md',
        'LINUX_HARNESS.md',
        'ENCLAVE_ACTIONS.md',
        'assets',
        'vm',
        'examples',
      ],
      dependencies: { '@cedar-policy/cedar-wasm': '4.12.0' },
    },
    null,
    2,
  ),
);
await mkdir('dist-cli/assets', { recursive: true });
await copyFile(
  'public/brand/cleopatr-feather.png',
  'dist-cli/assets/cleopatr-feather.png',
);
await writeFile(
  'dist-cli/README.md',
  (await readFile('cli/README.md', 'utf8'))
    .replace('../docs/LINUX_HARNESS.md', 'LINUX_HARNESS.md')
    .replace('../docs/ENCLAVE_ACTIONS.md', 'ENCLAVE_ACTIONS.md')
    .replace(
      '../public/brand/cleopatr-feather.png',
      'assets/cleopatr-feather.png',
    ),
);
await copyFile('docs/LINUX_HARNESS.md', 'dist-cli/LINUX_HARNESS.md');
await copyFile('docs/ENCLAVE_ACTIONS.md', 'dist-cli/ENCLAVE_ACTIONS.md');
await cp('docs/examples', 'dist-cli/examples', { recursive: true });
await rm('dist-cli/vm', { recursive: true, force: true });
await cp('dist-runtime/vm-runtime', 'dist-cli/vm', { recursive: true });
execFileSync('npm', ['pack', '--pack-destination', '../public/downloads'], {
  cwd: 'dist-cli',
  stdio: 'inherit',
});
