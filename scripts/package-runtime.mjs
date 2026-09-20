import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
const binary = await readFile('dist-runtime/cleo-supervisor');
if (
  binary.subarray(0, 4).toString('hex') !== '7f454c46' ||
  binary[4] !== 2 ||
  binary[5] !== 1
)
  throw new Error(
    'Build a little-endian 64-bit Linux ELF supervisor before packaging',
  );
const architecture = new Map([
  [183, 'arm64'],
  [62, 'x64'],
]).get(binary.readUInt16LE(18));
if (!architecture) throw new Error('Unsupported supervisor architecture');
const file = `cleopatr-linux-${architecture}-0.6.0-preview.tgz`;
await mkdir('public/downloads', { recursive: true });
execFileSync(
  'tar',
  [
    ...(process.platform === 'darwin'
      ? ['--uid', '0', '--gid', '0', '--uname', 'root', '--gname', 'root']
      : ['--owner=0', '--group=0', '--numeric-owner']),
    '-czf',
    `public/downloads/${file}`,
    '-C',
    'dist-runtime',
    'cleo-supervisor',
    'cleo.js',
    'worker.js',
    'package.json',
    'README.md',
    'ENCLAVE_ACTIONS.md',
    'examples',
    'node_modules',
    'supervisor.example.json',
    'cleopatr-supervisor.service',
  ],
  { env: { ...process.env, COPYFILE_DISABLE: '1' } },
);
const digest = createHash('sha256')
  .update(await readFile(`public/downloads/${file}`))
  .digest('hex');
await writeFile(`public/downloads/${file}.sha256`, `${digest}  ${file}\n`);
console.log(`Created ${file} (${digest})`);
