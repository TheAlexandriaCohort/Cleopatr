import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import {
  mkdtemp,
  mkdir,
  writeFile,
  readFile,
  copyFile,
  readdir,
  rm,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  SCHEMA,
  type Bundle,
  type Resource,
  type Policy,
} from '../../core/model.ts';
import { makeKeys, signBundle } from '../../core/crypto.ts';
import { atomicJson, activate } from '../../cli/cache.ts';
import { tlsFixture } from './tls-fixture.ts';

const project = resolve('.');
const cli = process.argv[2]
  ? resolve(process.argv[2])
  : join(project, 'dist-runtime/cleo.js');
const workspace = await mkdtemp(join(tmpdir(), 'cleo-managed-test-'));
const state = join(workspace, '.cleo');
const keys = await makeKeys();
let received = 0;
const origin = http.createServer((_req, res) => {
  received++;
  res.end('audit forwarded');
});
await new Promise<void>((resolve) => origin.listen(0, '0.0.0.0', resolve));
const target = `http://host.docker.internal:${(origin.address() as AddressInfo).port}/test`;
const tlsOrigin = await tlsFixture('0.0.0.0');
const tlsTarget = `https://host.docker.internal:${tlsOrigin.port}/test?q=audit`;
await mkdir(state, { mode: 0o700 });
const files = ['/workspace', '/usr', '/bin', '/lib', '/etc', '/tmp', '/dev'];
const processes = [
  '/workspace/agent.js',
  '/usr/bin/env',
  '/usr/local/bin/node',
  '/usr/bin/curl',
  '/lib/ld-linux-aarch64.so.1',
];
const resources: Resource[] = [
  ...files.map((locator) => ({ type: 'File', locator })),
  ...processes.map((locator) => ({ type: 'Process', locator })),
].map((r, i) => ({
  ...r,
  type: r.type as Resource['type'],
  id: 'resource-' + i,
  name: r.locator,
  environmentId: 'development',
  description: '',
}));
const policy = (id: string, name: string, cedar: string): Policy => ({
  id,
  name,
  cedar,
  environmentIds: ['development'],
  enabled: true,
  description: '',
  revision: 1,
  updatedAt: '',
  status: 'PUBLISHED',
});
resources.push({
  id: 'test-http',
  name: 'Local HTTP fixture',
  type: 'Endpoint',
  locator: target,
  environmentId: 'development',
  description: '',
});
const bundle: Bundle = {
  tenant: 'managed-vm-test',
  schemaVersion: '3.0',
  minimumClientVersion: '0.3.0',
  sequence: 1,
  bundleId: 'managed-vm-1',
  createdAt: new Date().toISOString(),
  schema: SCHEMA,
  client: { id: 'fixture-client', name: 'curl-agent' },
  environmentIds: ['development'],
  environments: [
    {
      id: 'development',
      name: 'Development',
      kind: 'environment',
      parentId: null,
      description: '',
      mode: 'ENFORCE',
    },
  ],
  resources,
  policies: [
    policy(
      'launch',
      'Allow test runtime',
      'permit(principal, action in [Cleopatr::Action::"file.read", Cleopatr::Action::"file.metadata", Cleopatr::Action::"process.signal", Cleopatr::Action::"process.execute"], resource);',
    ),
    policy(
      'network',
      'Prevent network requests',
      'forbid(principal, action == Cleopatr::Action::"http.request", resource);',
    ),
  ],
};
await atomicJson(join(state, 'config'), {
  server: 'http://127.0.0.1:1',
  token: 'TEST-CREDENTIAL-MUST-NOT-BE-READABLE',
  tenant: bundle.tenant,
  publicKey: keys.publicKey,
  environmentIds: ['development'],
  clientId: 'fixture-client',
  clientName: 'curl-agent',
});
await activate(await signBundle(bundle, keys.privateKey), state);
await copyFile(tlsOrigin.cert, join(workspace, 'test-ca.pem'));
await writeFile(join(workspace, 'protected.txt'), 'preserved');
await writeFile(
  join(workspace, 'cleopatr-enrollment.json'),
  'TEST-LOOSE-ENROLLMENT',
);
await writeFile(
  join(workspace, 'agent.js'),
  `#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import {spawnSync} from 'node:child_process';
const audit = process.argv.includes('audit');
assert.equal(fs.readFileSync('/workspace/protected.txt', 'utf8'), 'preserved');
console.log('[PASS] Node reads the permitted workspace');
assert.throws(() => fs.readFileSync('/workspace/.cleo/config'), {code: 'EACCES'});
assert.throws(() => fs.readFileSync('/workspace/cleopatr-enrollment.json'), {code: 'EACCES'});
console.log('[PASS] Enrollment credentials and loose enrollment file are masked');
if (audit) fs.writeFileSync('/workspace/protected.txt', 'audit permitted');
else assert.throws(() => fs.writeFileSync('/workspace/protected.txt', 'tampered'), {code: 'EACCES'});
console.log('[PASS] Filesystem overwrite follows selected mode');
const child = spawnSync('/usr/local/bin/node', ['-e', 'require("fs").unlinkSync("/workspace/protected.txt")'], {encoding:'utf8'});
if (audit) assert.equal(child.status, 0, child.stderr);
else { assert.notEqual(child.status, 0); assert.match(child.stderr, /EACCES/); }
console.log('[PASS] Descendant deletion follows selected mode');
assert.equal(spawnSync('/bin/sh', ['-c', 'echo BYPASS']).error?.code, 'EACCES');
console.log('[PASS] Undeclared executable blocked by kernel');
await new Promise((resolve, reject) => {
 const socket = net.connect({host:'1.1.1.1', port:443});
 socket.on('connect', () => {socket.destroy(); reject(new Error('Direct network bypass'));});
 socket.on('error', error => {assert.ok(['EPERM', 'EACCES'].includes(error.code)); resolve();});
 socket.setTimeout(4000, () => {socket.destroy(); reject(new Error('Expected synchronous kernel denial'));});
});
console.log('[PASS] Direct network bypass blocked synchronously');
const plain = spawnSync('/usr/bin/curl', ['--silent', '--show-error', '--max-time', '15', '--write-out', '%{http_code}', ${JSON.stringify(target)}], {encoding:'utf8', timeout:20000});
assert.equal(plain.status, 0, JSON.stringify(plain));
assert.match(plain.stdout, audit ? /audit forwarded200$/ : /403$/);
console.log('[PASS] Supported HTTP request ' + (audit ? 'allowed under audit override' : 'blocked by Environment policy without --enforce'));
const curl = spawnSync('/usr/bin/curl', ['--silent', '--show-error', '--include', '--max-time', '15', '--cacert', '/workspace/test-ca.pem', ${JSON.stringify(tlsTarget)}], {encoding:'utf8', timeout:20000});
if (!audit) { process.stdout.write(curl.stdout ?? ''); process.stderr.write(curl.stderr ?? ''); }
assert.equal(curl.status, audit ? 0 : 56, JSON.stringify(curl));
if (audit) { assert.ok(curl.stdout.includes('HTTP/2 200')); assert.ok(curl.stdout.endsWith('x'.repeat(256 * 1024) + 'HTTPS reached destination')); }
else assert.match(curl.stderr, /CONNECT tunnel failed, response 403/);
console.log('[PASS] HTTPS CONNECT follows audit-only versus enforced session');
console.log('CLEO_MANAGED_VM_COMPLETE');
`,
  { mode: 0o755 },
);
try {
  const syntax = spawnSync(
    process.execPath,
    ['--check', join(workspace, 'agent.js')],
    { encoding: 'utf8' },
  );
  assert.equal(syntax.status, 0, syntax.stderr);
  for (const variant of ['enforce', 'audit-override', 'audit-environment']) {
    const audit = variant !== 'enforce';
    await writeFile(join(workspace, 'protected.txt'), 'preserved');
    if (variant === 'audit-environment') {
      bundle.environments[0].mode = 'AUDIT';
      bundle.sequence++;
      bundle.bundleId = 'managed-vm-2';
      await activate(await signBundle(bundle, keys.privateKey), state);
    }
    const previousEvents = new Set(
      await readdir(join(state, 'spool')).catch(() => [] as string[]),
    );
    const child = spawn(
      process.execPath,
      [
        cli,
        ...(variant === 'audit-override' ? ['--audit'] : []),
        '--env=Development',
        '--',
        './agent.js',
        ...(audit ? ['audit'] : []),
      ],
      {
        cwd: workspace,
        env: { ...process.env, CLEO_HOME: state },
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
    let output = '';
    for (const stream of [child.stdout, child.stderr])
      stream.on('data', (data) => {
        output += data;
        process.stdout.write(data);
      });
    const timer = setTimeout(() => child.kill('SIGTERM'), 240000);
    const code = await new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('close', resolve);
    });
    clearTimeout(timer);
    await mkdir(join(project, 'dist-runtime/vm'), { recursive: true });
    await writeFile(
      join(project, `dist-runtime/vm/managed-vm-${variant}.log`),
      output,
    );
    assert.equal(code, 0, output);
    assert.match(output, /CLEO_MANAGED_VM_COMPLETE/);
    assert.match(
      output,
      audit
        ? /http.request · ALLOWED_AUDIT · "Prevent network requests"/
        : /http.request · BLOCKED · "Prevent network requests"/,
    );
    if (!audit)
      assert.equal(
        await readFile(join(workspace, 'protected.txt'), 'utf8'),
        'preserved',
      );
    else
      await assert.rejects(readFile(join(workspace, 'protected.txt')), {
        code: 'ENOENT',
      });
    const expectedRequests =
      variant === 'enforce' ? 0 : variant === 'audit-override' ? 1 : 2;
    assert.equal(received, expectedRequests);
    assert.equal(tlsOrigin.received.length, expectedRequests);
    const events = await Promise.all(
      (await readdir(join(state, 'spool')))
        .filter((file) => file.endsWith('.json') && !previousEvents.has(file))
        .map(async (file) =>
          JSON.parse(await readFile(join(state, 'spool', file), 'utf8')),
        ),
    );
    assert.ok(
      events.some(
        (event) =>
          event.policyName === 'Prevent network requests' &&
          event.decision === 'DENY' &&
          event.adapter === 'http-proxy',
      ),
    );
    const denied = events.find(
      (event) =>
        event.policyName === 'Prevent network requests' &&
        event.mode === (audit ? 'AUDIT' : 'ENFORCE') &&
        event.assessment.payload.context.method === 'CONNECT',
    );
    assert.ok(denied);
    assert.equal(denied.effectiveResult, audit ? 'ALLOWED_AUDIT' : 'BLOCKED');
    assert.equal(denied.assessment.status, 'captured');
    assert.deepEqual(denied.assessment.payload.principal, {
      type: 'Cleopatr::AgentSession',
      id: 'curl-agent',
    });
    assert.equal(denied.assessment.payload.context.method, 'CONNECT');
    assert.equal(denied.assessment.payload.context.path, undefined);
    assert.equal(
      denied.assessment.payload.context.host,
      'host.docker.internal',
    );
    assert.equal(denied.assessment.payload.context.semanticAvailable, false);
    console.log(
      '[PASS] Named policy decision and exact observed Cedar payload exported to host audit spool',
    );
    console.log(
      audit
        ? '[PASS] Audit allows filesystem and HTTP effects while preserving the enclave'
        : '[PASS] Protected host file remains unchanged',
    );
  }
} finally {
  origin.closeAllConnections();
  origin.close();
  await tlsOrigin.close();
  await rm(workspace, { recursive: true, force: true });
}
