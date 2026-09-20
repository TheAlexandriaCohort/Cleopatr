import { spawn } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const args = process.argv.slice(2);
if (args.some((arg) => arg !== '--live'))
  throw new Error('Usage: npm run test:runtime:linux -- [--live]');
const live = args.includes('--live');
const artifacts = resolve('dist-runtime');
const name = `cleopatr-tests-${process.pid}`;
await mkdir(`${artifacts}/vm`, { recursive: true });
async function run(command, args, name, timeout = 300000) {
  if (live) console.log(`\n[cleo tests] ${name}\n`);
  const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  let text = '';
  for (const stream of [child.stdout, child.stderr])
    stream.on('data', (chunk) => {
      text += chunk.toString();
      if (live) process.stdout.write(chunk);
    });
  const timer = setTimeout(() => child.kill('SIGKILL'), timeout);
  const code = await new Promise((res, reject) => {
    child.on('error', reject);
    child.on('close', res);
  });
  clearTimeout(timer);
  await writeFile(`${artifacts}/vm/${name}.log`, text);
  if (code !== 0)
    throw new Error(`${name} failed (${code}):\n${text.slice(-7000)}`);
  return text;
}
const volume = (source, target, readonly = true) => [
  '-v',
  `${resolve(source)}:${target}${readonly ? ':ro' : ''}`,
];
try {
  await run(process.execPath, ['scripts/build-runtime.mjs'], 'worker-build');
  await run(
    process.execPath,
    [
      '--import',
      'tsx',
      'runtime/tests/vm-fixture.ts',
      `${artifacts}/vm/fixtures`,
    ],
    'fixtures',
  );
  await run(
    'docker',
    [
      'build',
      '-f',
      'runtime/tests/Dockerfile',
      '-t',
      'cleopatr-runtime-test',
      '.',
    ],
    'image-build',
  );
  await run(
    'docker',
    [
      'run',
      '--rm',
      '--privileged',
      '--entrypoint',
      'sh',
      ...volume('runtime/native', '/build/runtime/native', false),
      ...volume(artifacts, '/artifacts', false),
      ...volume('runtime/tests/build-native.sh', '/test/build-native.sh'),
      ...volume('runtime/tests/syscall-probe.c', '/test/syscall-probe.c'),
      'cleopatr-runtime-test',
      '/test/build-native.sh',
    ],
    'native-tests',
  );
  await run(
    'docker',
    [
      'build',
      '-f',
      'runtime/tests/VM.Dockerfile',
      '-t',
      'cleopatr-kernel-vm',
      '.',
    ],
    'vm-build',
  );
  const output = await run(
    'docker',
    [
      'run',
      '--rm',
      '--name',
      name,
      ...volume('runtime/tests/vm-boot.sh', '/usr/local/bin/vm-boot'),
      ...volume('runtime/tests/vm-init.sh', '/test/vm-init.sh'),
      ...volume('runtime/tests/vm-session.sh', '/test/vm-session.sh'),
      ...volume(`${artifacts}/vm/kernel-tests`, '/test/kernel-tests'),
      ...volume(artifacts, '/artifacts'),
      ...volume(`${artifacts}/vm/fixtures`, '/fixtures'),
      ...volume('node_modules/@cedar-policy', '/cedar'),
      'cleopatr-kernel-vm',
    ],
    'vm-tests',
    240000,
  );
  if (
    !output.includes('CLEO_VM_COMPLETE') ||
    !output.includes('CLEO_FULL_SESSION_COMPLETE') ||
    !output.includes('CLEO_ACTIONS_AUDIT_PASSED') ||
    !output.includes('CLEO_ACTIONS_ENFORCE_PASSED') ||
    output.includes('CLEO_VM_FAILED')
  )
    throw new Error(`Linux containment checks failed:\n${output.slice(-7000)}`);
  console.log(
    `Linux kernel and signed-session tests passed. Logs: ${artifacts}/vm/`,
  );
} finally {
  // Only this runner's explicitly named disposable VM is eligible for cleanup.
  await new Promise((resolve) => {
    const child = spawn('docker', ['rm', '-f', name], { stdio: 'ignore' });
    child.on('error', resolve);
    child.on('close', resolve);
  });
}
