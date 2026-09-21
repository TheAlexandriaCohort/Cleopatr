import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, writeFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  createSeed,
  publishedSnapshot,
  SCHEMA,
  type Bundle,
} from '../core/model.ts';
import { makeKeys, signBundle } from '../core/crypto.ts';
import { atomicJson, activate } from '../cli/cache.ts';
async function fixture(
  mode: 'AUDIT' | 'ENFORCE' = 'AUDIT',
  permitLaunch = true,
) {
  const dir = await mkdtemp(join(tmpdir(), 'cleo-cli-'));
  const keys = await makeKeys();
  await atomicJson(join(dir, 'config.json'), {
    server: 'https://offline.example',
    token: 'test',
    tenant: 'test',
    publicKey: keys.publicKey,
    environmentIds: ['development'],
    clientId: 'client',
    clientName: 'Test client',
  });
  const seed = createSeed();
  seed.environments.find((e) => e.id === 'development')!.name = 'PCI';
  if (permitLaunch)
    seed.policies.push({
      ...seed.policies[0],
      id: 'allow_process',
      cedar:
        'permit(principal, action == Cleopatr::Action::"process.execute", resource);',
    });
  seed.policies.forEach((p) => (p.status = 'PUBLISHED'));
  seed.environments.forEach((e) => (e.mode = mode));
  const b: Bundle = {
    ...publishedSnapshot(seed),
    schema: SCHEMA,
    schemaVersion: '3.0',
    tenant: 'test',
    sequence: 1,
    bundleId: 'policies_1',
    createdAt: new Date().toISOString(),
    environmentIds: ['development'],
    minimumClientVersion: '0.3.0',
    client: { id: 'client', name: 'Test client' },
  };
  await activate(await signBundle(b, keys.privateKey), dir);
  return { dir, keys, b };
}
function run(args: string[], dir: string, input?: string, raw = false) {
  // These tests cover the explicitly selected cooperative adapter. Kernel
  // backends have their own real Linux/managed-VM integration tests.
  if (!raw && args[0] === 'run')
    args = ['run', '--backend=cooperative', ...args.slice(1)];
  else if (
    !raw &&
    args[0]?.startsWith('-') &&
    args.includes('--') &&
    !args.some((arg) => arg.startsWith('--backend'))
  )
    args = ['--backend=cooperative', ...args];
  return new Promise<{ code: number | null; out: string; err: string }>(
    (done, reject) => {
      const p = spawn(
        process.execPath,
        ['--import', 'tsx', resolve('cli/main.ts'), ...args],
        {
          env: { ...process.env, CLEO_HOME: dir },
          stdio: ['pipe', 'pipe', 'pipe'],
        },
      );
      let out = '',
        err = '';
      p.stdout.on('data', (b) => (out += b));
      p.stderr.on('data', (b) => (err += b));
      p.on('error', reject);
      p.on('close', (code) => done({ code, out, err }));
      p.stdin.end(input ?? '');
    },
  );
}
void test('launcher preserves argument boundaries, stdio and exit status', async () => {
  const f = await fixture('ENFORCE');
  const r = await run(
    [
      'run',
      '--',
      process.execPath,
      '-e',
      'console.log(JSON.stringify(process.argv.slice(1)));process.exit(7)',
      'space value',
      '--mode',
      'unknown',
    ],
    f.dir,
  );
  assert.equal(r.code, 7);
  assert.deepEqual(JSON.parse(r.out), ['space value', '--mode', 'unknown']);
});
void test('no-run launcher selects PCI by name and propagates effective mode and stdin', async () => {
  const f = await fixture();
  const r = await run(
    [
      '--enforce',
      '--env=PCI',
      '--',
      process.execPath,
      '-e',
      "let s='';process.stdin.on('data',c=>s+=c);process.stdin.on('end',()=>console.log(JSON.stringify({mode:process.env.CLEO_MODE,env:process.env.CLEO_ENVIRONMENT,input:s})))",
    ],
    f.dir,
    'agent input',
  );
  assert.equal(r.code, 0, r.err);
  assert.deepEqual(JSON.parse(r.out), {
    mode: 'ENFORCE',
    env: 'development',
    input: 'agent input',
  });
});
void test('audit defaults to launch on would-deny; enforce never starts a denied process', async () => {
  const f = await fixture('AUDIT', false);
  const agent = [process.execPath, '-e', "console.log('AGENT_STARTED')"];
  const audit = await run(['--', ...agent], f.dir);
  assert.equal(audit.code, 0, audit.err);
  assert.match(audit.out, /AGENT_STARTED/);
  assert.match(audit.err, /AUDIT.*ALLOWED_AUDIT/);
  const enforce = await run(['--enforce', '--', ...agent], f.dir);
  assert.equal(enforce.code, 2, enforce.err);
  assert.equal(enforce.out, '');
});
void test('flagless execution honors Enforce; explicit audit overrides it without changing the cache', async () => {
  const f = await fixture('ENFORCE', false);
  const agent = [process.execPath, '-e', "console.log('AGENT_STARTED')"];
  const missing = await run(['--env=missing', '--', ...agent], f.dir);
  assert.equal(missing.code, 3);
  assert.equal(missing.out, '');
  assert.match(missing.err, /Environment not found/);
  const before = await readFile(join(f.dir, 'bundle.json'), 'utf8');
  const denied = await run(['--', ...agent], f.dir);
  assert.equal(denied.code, 2);
  assert.equal(denied.out, '');
  assert.match(denied.err, /ENFORCE/);
  for (const flag of ['--audit', '--mode=audit']) {
    const audit = await run([flag, '--', ...agent], f.dir);
    assert.equal(audit.code, 0, audit.err);
    assert.match(audit.out, /AGENT_STARTED/);
    assert.match(audit.err, /AUDIT.*ALLOWED_AUDIT/);
  }
  assert.equal(await readFile(join(f.dir, 'bundle.json'), 'utf8'), before);
  const events = await Promise.all(
    (await readdir(join(f.dir, 'spool')))
      .filter((name) => name.endsWith('.json'))
      .map(async (name) =>
        JSON.parse(await readFile(join(f.dir, 'spool', name), 'utf8')),
      ),
  );
  assert.ok(
    events.some(
      (event) =>
        event.decision === 'DENY' &&
        event.mode === 'AUDIT' &&
        event.effectiveResult === 'ALLOWED_AUDIT',
    ),
  );
});
void test('bare pipe invocation emits a diagnostic on stderr and no stdout', async () => {
  const f = await fixture();
  for (const args of [[], ['--enforce'], ['--enforce', '--env=PCI']]) {
    const result = await run(args, f.dir);
    assert.equal(result.code, 3);
    assert.equal(result.out, '');
    assert.match(result.err, /may already be running/);
  }
});
void test('an unknown environment in a stale cache still schedules a non-blocking refresh', async () => {
  const f = await fixture();
  const config = JSON.parse(await readFile(join(f.dir, 'config.json'), 'utf8'));
  await atomicJson(join(f.dir, 'config.json'), {
    ...config,
    server: 'http://127.0.0.1:1',
  });
  const cache = JSON.parse(await readFile(join(f.dir, 'bundle.json'), 'utf8'));
  await atomicJson(join(f.dir, 'bundle.json'), { ...cache, checkedAt: 0 });
  const result = await run(
    [
      '--env=missing',
      '--',
      process.execPath,
      '-e',
      "console.log('AGENT_STARTED')",
    ],
    f.dir,
  );
  assert.equal(result.code, 3);
  assert.equal(result.out, '');
  // The detached worker either still owns its lock or has recorded completion.
  const evidence = await readFile(join(f.dir, 'refresh.lock'), 'utf8').catch(
    () => readFile(join(f.dir, 'refresh-status.json'), 'utf8'),
  );
  assert.ok(evidence.length > 0);
  assert.equal(
    JSON.parse(await readFile(join(f.dir, 'bundle.json'), 'utf8')).signed
      .signature,
    cache.signed.signature,
  );
});
void test('CLI audit would-deny returns zero; enforce returns two', async () => {
  const f = await fixture();
  const path = join(f.dir, 'action.json');
  await writeFile(
    path,
    JSON.stringify({
      environmentId: 'development',
      sessionId: 'test',
      action: 'file.write',
      resource: { type: 'File', id: 'x' },
      context: { withinWorkspace: false },
    }),
  );
  assert.equal((await run(['authorize', '--request', path], f.dir)).code, 0);
  const e = await run(
    ['authorize', '--mode', 'enforce', '--request', path],
    f.dir,
  );
  assert.equal(e.code, 2);
  assert.equal(JSON.parse(e.out).effectiveResult, 'BLOCKED');
});
void test('MCP denied tool call is never forwarded to the server', async () => {
  const f = await fixture('ENFORCE');
  const server = join(f.dir, 'mcp-server.mjs');
  await writeFile(
    server,
    "import {createInterface} from 'node:readline'; const r=createInterface({input:process.stdin});r.on('line',l=>{const m=JSON.parse(l);console.log(JSON.stringify({jsonrpc:'2.0',id:m.id,result:{forwarded:m.method}}))});",
  );
  const r = await run(
    ['mcp', '--', process.execPath, server],
    f.dir,
    [
      { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
      {
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: { name: 'refund', arguments: { amount: 999 } },
      },
    ]
      .map((v) => JSON.stringify(v))
      .join('\n') + '\n',
  );
  assert.equal(r.code, 0, r.err);
  const lines = r.out
    .trim()
    .split('\n')
    .map((l) => JSON.parse(l));
  assert.equal(lines.find((l) => l.id === 1).result.forwarded, 'initialize');
  assert.equal(lines.find((l) => l.id === 2).error.code, -32003);
  assert.ok(!r.out.includes('"forwarded":"tools/call"'));
});
void test('.cleo/config format selects environment by name and explicit --env wins', async () => {
  const f = await fixture();
  const config = JSON.parse(await readFile(join(f.dir, 'config.json'), 'utf8'));
  await atomicJson(join(f.dir, 'config'), { ...config, environment: 'PCI' });
  const agent = [
    process.execPath,
    '-e',
    'console.log(process.env.CLEO_ENVIRONMENT)',
  ];
  const result = await run(['--', ...agent], f.dir);
  assert.equal(result.code, 0, result.err);
  assert.equal(result.out.trim(), 'development');
  await atomicJson(join(f.dir, 'config'), {
    ...config,
    environment: 'missing',
  });
  assert.equal((await run(['--', ...agent], f.dir)).code, 3);
  assert.equal(
    (await run(['--env=development', '--', ...agent], f.dir)).code,
    0,
  );
});
void test('Custom environment does not turn audit policies into Enforce for nested adapters', async () => {
  const f = await fixture();
  f.b.environments.find((e) => e.id === 'development')!.mode = 'CUSTOM';
  f.b.environments.find((e) => e.id === 'development')!.policyModes = {
    allow_process: 'ENFORCE',
  };
  f.b.sequence++;
  await activate(await signBundle(f.b, f.keys.privateKey), f.dir);
  const result = await run(
    ['--', process.execPath, '-e', 'console.log(process.env.CLEO_MODE)'],
    f.dir,
  );
  assert.equal(result.code, 0, result.err);
  assert.equal(result.out.trim(), 'POLICY');
  assert.match(result.err, /CUSTOM/);
});
void test('CLI explicit calls and process launch use the client name rather than session or request principal', async () => {
  const f = await fixture('ENFORCE');
  f.b.client = { id: 'client', name: 'Test client' };
  f.b.policies = [
    {
      ...f.b.policies[0],
      id: 'named-client',
      cedar:
        'permit(principal == Cleopatr::AgentSession::"Test client", action, resource);',
    },
  ];
  f.b.sequence++;
  await activate(await signBundle(f.b, f.keys.privateKey), f.dir);
  const path = join(f.dir, 'named-action.json');
  await writeFile(
    path,
    JSON.stringify({
      environmentId: 'development',
      sessionId: 'unrelated-session',
      principal: 'Spoofed client',
      action: 'file.read',
      resource: { type: 'File', id: 'x' },
      context: {},
    }),
  );
  const explicit = await run(['authorize', '--request', path], f.dir);
  assert.equal(explicit.code, 0, explicit.err);
  assert.equal(JSON.parse(explicit.out).parc.principal.id, 'Test client');
  const launch = await run(
    ['--', process.execPath, '-e', 'console.log("NAMED_CLIENT_STARTED")'],
    f.dir,
  );
  assert.equal(launch.code, 0, launch.err);
  assert.equal(launch.out.trim(), 'NAMED_CLIENT_STARTED');
});

void test(
  'default macOS launch refuses absent Process permissions without starting an uncontained agent',
  { skip: process.platform !== 'darwin' || process.arch !== 'arm64' },
  async () => {
    const f = await fixture('ENFORCE', false);
    f.b.policies = [];
    f.b.sequence++;
    await activate(await signBundle(f.b, f.keys.privateKey), f.dir);
    const result = await run(
      ['--enforce', '--', process.execPath, '-e', 'console.log("UNCONTAINED")'],
      f.dir,
      undefined,
      true,
    );
    assert.equal(result.code, 3);
    assert.equal(result.out, '');
    assert.match(result.err, /No executable is permitted/);
  },
);
