import { spawn } from 'node:child_process';
import {
  mkdir,
  readFile,
  writeFile,
  cp,
  chmod,
  chown,
  readdir,
  unlink,
  stat,
  rename,
} from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { activate, atomicJson, loadBundle } from '../../cli/cache.ts';

const shared = '/session-live';
const state = '/var/lib/cleopatr';
const request = JSON.parse(
  await readFile(join(shared, 'request.json'), 'utf8'),
);
if (
  !Number.isSafeInteger(request.uid) ||
  request.uid < 1 ||
  !Number.isSafeInteger(request.gid) ||
  request.gid < 0
)
  throw new Error('Invalid VM workload identity');
let daemon: ReturnType<typeof spawn> | undefined;
let timer: ReturnType<typeof setInterval> | undefined;
let running = false;
let code = 125;
async function exportEvents(limit = 100) {
  const files = (await readdir(join(state, 'spool')).catch(() => []))
    .filter((file) => file.endsWith('.json'))
    .slice(0, limit);
  for (const file of files) {
    const output = join(shared, 'events', file);
    await writeFile(
      output + '.tmp',
      await readFile(join(state, 'spool', file)),
      { mode: 0o600 },
    );
    await chown(output + '.tmp', request.uid, request.gid);
    const { rename } = await import('node:fs/promises');
    await rename(output + '.tmp', output);
    await unlink(join(state, 'spool', file));
  }
}
async function update() {
  if (running) return;
  running = true;
  try {
    const incoming = JSON.parse(
      await readFile(join(shared, 'bundle.json'), 'utf8'),
    );
    const current = await loadBundle(state);
    if (JSON.parse(incoming.signed.payload).sequence > current.bundle.sequence)
      await activate(incoming.signed, state);
    await exportEvents();
  } catch (error) {
    process.stderr.write(`cleo VM sync: ${(error as Error).message}\n`);
  } finally {
    running = false;
  }
}
try {
  await mkdir(state, { recursive: true, mode: 0o700 });
  await chmod(state, 0o700);
  const config = JSON.parse(
    await readFile(join(shared, 'config.json'), 'utf8'),
  );
  await atomicJson(join(state, 'config'), config);
  const incoming = JSON.parse(
    await readFile(join(shared, 'bundle.json'), 'utf8'),
  );
  await atomicJson(join(state, 'bundle.json'), incoming);
  await loadBundle(state);
  await cp('/opt/cleopatr-rootfs', '/var/lib/cleopatr-rootfs', {
    recursive: true,
  });
  await mkdir('/etc/cleopatr', { recursive: true });
  await atomicJson('/etc/cleopatr/supervisor.json', {
    allowedUids: [request.uid],
    node: '/usr/local/bin/node',
    worker: '/usr/lib/cleopatr/worker.js',
    state,
    rootfs: '/var/lib/cleopatr-rootfs',
    workspace: '/srv/workspace',
    workspaceMasks: request.masks,
    cgroupRoot: '/sys/fs/cgroup/cleopatr',
    memoryMax: 1073741824,
    pidsMax: 256,
  });
  daemon = spawn('/usr/lib/cleopatr/cleo-supervisor', ['serve'], {
    stdio: ['ignore', 'ignore', 'inherit'],
  });
  daemon.on('error', (error) =>
    process.stderr.write(`cleo supervisor: ${error.message}\n`),
  );
  let ready = false;
  for (let attempt = 0; attempt < 100; attempt++) {
    if (
      await stat('/run/cleopatr/supervisor.sock')
        .then((s) => s.isSocket())
        .catch(() => false)
    ) {
      ready = true;
      break;
    }
    if (daemon.exitCode !== null) break;
    await delay(100);
  }
  if (!ready) throw new Error('Linux supervisor did not become ready');
  // This directory is available to the trusted guest, never the workload.
  // The host bounds boot time, then allows long-running agents to continue.
  const readyFile = join(shared, 'ready.json');
  await atomicJson(readyFile + '.pending', { sessionId: request.sessionId });
  await chown(readyFile + '.pending', request.uid, request.gid);
  await rename(readyFile + '.pending', readyFile);
  timer = setInterval(() => void update(), 1000);
  const args = [
    '/usr/lib/cleopatr/cleo.js',
    '--backend',
    'linux',
    '--env',
    request.environment,
  ];
  if (request.enforce) args.push('--enforce');
  if (request.audit) args.push('--audit');
  args.push('--', ...request.argv);
  const child = spawn('/usr/local/bin/node', args, {
    uid: request.uid,
    gid: request.gid,
    stdio: 'inherit',
    env: {
      PATH: '/usr/local/bin:/usr/bin:/bin',
      HOME: '/tmp',
      NODE_ENV: 'production',
    },
  });
  code = await new Promise<number>((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (status, signal) =>
      resolve(status ?? (signal === 'SIGINT' ? 130 : 143)),
    );
  });
} catch (error) {
  process.stderr.write(`cleo VM: ${(error as Error).message}\n`);
} finally {
  if (timer) clearInterval(timer);
  while (running) await delay(10);
  await exportEvents(Number.MAX_SAFE_INTEGER).catch((error) =>
    process.stderr.write(`cleo VM audit export: ${(error as Error).message}\n`),
  );
  daemon?.kill('SIGTERM');
  const output = join(shared, 'exit.json');
  await atomicJson(output, { code });
  await chown(output, request.uid, request.gid);
}
