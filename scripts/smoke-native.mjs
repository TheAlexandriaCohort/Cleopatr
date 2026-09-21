import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';

const trace = JSON.parse(
  await readFile('.next/server/app/api/v1/[...path]/route.js.nft.json', 'utf8'),
);
assert.ok(
  trace.files.some(
    (file) => file.includes('/migrations/') && file.endsWith('.sql'),
  ),
  'Production trace must include schema migrations',
);
assert.ok(
  !trace.files.some(
    (file) =>
      /\/(?:\.local|\.cleo|\.git)\//.test(file) ||
      /\/(?:\.env[^/]*|cleopatr-enrollment\.json)$/.test(file),
  ),
  'Production trace must not include private runtime state',
);

const directory = await mkdtemp(join(tmpdir(), 'cleopatr-web-'));
const token = crypto.randomUUID();
let child,
  origin,
  output = '';
async function stop() {
  if (!child || child.exitCode !== null) return;
  const exited = once(child, 'exit');
  child.kill('SIGTERM');
  await exited;
}
async function start(authenticated = true) {
  const socket = createServer();
  socket.listen(0, '127.0.0.1');
  await once(socket, 'listening');
  const port = socket.address().port;
  await new Promise((done) => socket.close(done));
  origin = `http://127.0.0.1:${port}`;
  child = spawn(process.execPath, ['scripts/web.mjs', 'start'], {
    env: {
      ...process.env,
      NODE_ENV: 'production',
      PORT: String(port),
      CLEO_HOST: '127.0.0.1',
      CLEO_SERVER_DATA: directory,
      CLEO_ADMIN_TOKEN: authenticated ? token : '',
      CLEO_SIGNING_JWK: '',
      CLEO_AUTHORING_ENDPOINT: '',
      CLEO_AUTHORING_TOKEN: '',
      CLEO_WORKSPACE_ID: 'test-workspace',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  output = '';
  child.stdout.on('data', (bytes) => {
    output += bytes;
  });
  child.stderr.on('data', (bytes) => {
    output += bytes;
  });
  for (let i = 0; i < 150; i++) {
    if (child.exitCode !== null) throw new Error(output);
    try {
      if ((await fetch(origin + '/login')).ok) return;
    } catch {
      /* Starting. */
    }
    await new Promise((done) => setTimeout(done, 100));
  }
  throw new Error('Server startup timed out: ' + output);
}
async function call(path, body, headers = {}) {
  return fetch(origin + path, {
    method: body ? 'POST' : 'GET',
    headers: {
      origin,
      ...headers,
      ...(body ? { 'content-type': 'application/json' } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
    redirect: 'manual',
  });
}
try {
  await start();
  assert.equal((await call('/api/v1/state')).status, 401);
  assert.equal((await call('/')).status, 307);
  assert.equal((await call('/api/session', { token: 'wrong' })).status, 401);
  assert.equal(
    (await call('/api/session', { token: 'x'.repeat(5000) })).status,
    413,
  );
  const login = await call('/api/session', { token });
  assert.equal(login.status, 200);
  assert.match(login.headers.get('set-cookie'), /HttpOnly/);
  const cookie = login.headers.get('set-cookie').split(';')[0];
  const admin = { cookie };
  const html = await call('/', undefined, admin);
  assert.equal(html.status, 200);
  assert.match(await html.text(), /Rules for your agents/);
  for (const [page, heading] of [
    ['environments', 'A place for every policy'],
    ['resources', 'Know what'],
    ['simulator', 'Test before you trust'],
    ['activity', 'Every decision has a story'],
    ['deploy', 'Put your policies to work'],
    ['unknown', 'Rules for your agents'],
  ]) {
    const screen = await call('/?page=' + page, undefined, admin);
    assert.equal(screen.status, 200);
    assert.ok(
      (await screen.text()).includes(heading),
      `Direct load preserves ${page}`,
    );
  }
  const before = await (await call('/api/v1/state', undefined, admin)).json();
  assert.ok(before.policies.length && before.environments.length);
  assert.equal(
    (
      await (
        await call(
          '/api/v1/validate',
          { cedar: before.policies[0].cedar },
          admin,
        )
      ).json()
    ).valid,
    true,
  );
  const enrolled = await (
    await call(
      '/api/v1/enroll',
      { name: 'Native smoke client', environmentIds: ['development'] },
      admin,
    )
  ).json();
  const collision = await call(
    '/api/v1/enroll',
    { name: ' Native smoke client ', environmentIds: ['development'] },
    admin,
  );
  assert.equal(collision.status, 409);
  assert.match((await collision.json()).error, /already exists/);
  const configuration = await (
    await call('/api/v1/configuration', undefined, admin)
  ).json();
  assert.equal(configuration.clients, undefined);
  assert.equal(configuration.events, undefined);
  configuration.environments.push({
    id: 'smoke-imported',
    name: 'Imported environment',
    description: '',
    parentId: 'development',
    kind: 'environment',
    mode: 'AUDIT',
    policyModes: {},
  });
  const input = { configuration, revision: before.revision };
  const preview = await call('/api/v1/configuration/preview', input, admin);
  assert.equal(preview.status, 200, await preview.text());
  assert.equal(
    (await call('/api/v1/configuration/import', input, admin)).status,
    200,
  );
  const after = await (await call('/api/v1/state', undefined, admin)).json();
  assert.equal(after.sequence, before.sequence + 1);
  assert.ok(after.environments.some((e) => e.id === 'smoke-imported'));
  assert.deepEqual(after.publicKey, before.publicKey);
  const client = { authorization: 'Bearer ' + enrolled.token };
  const onlineResponse = await call('/api/v1/bundles', undefined, client);
  assert.equal(onlineResponse.status, 200);
  const online = await onlineResponse.json();
  assert.equal(
    (await call('/api/v1/bundles?environment=development', undefined, admin))
      .status,
    400,
  );
  const offlineResponse = await call(
    '/api/v1/bundles?clientId=' + encodeURIComponent(enrolled.clientId),
    undefined,
    admin,
  );
  assert.equal(offlineResponse.status, 200);
  const offline = await offlineResponse.json();
  assert.deepEqual(offline, online);
  assert.deepEqual(JSON.parse(offline.payload).client, {
    id: enrolled.clientId,
    name: enrolled.clientName,
  });
  assert.equal(
    (await call('/api/v1/configuration', undefined, client)).status,
    403,
  );
  await stop();
  await start();
  const reopened = await (await call('/api/v1/state', undefined, admin)).json();
  assert.deepEqual(reopened, after);
  assert.equal((await call('/api/v1/bundles', undefined, client)).status, 200);
  const logout = await call('/api/session', { logout: true }, admin);
  assert.match(logout.headers.get('set-cookie'), /Max-Age=0/);
  await stop();
  await start(false);
  const local = await call('/api/v1/state');
  assert.equal(local.status, 200);
  assert.equal((await local.json()).sequence, after.sequence);
  console.info(
    'Native web smoke passed: first boot, login, Cedar, configuration preview/import, client sync, restart persistence, logout, and local access.',
  );
} catch (error) {
  console.error(output);
  throw error;
} finally {
  await stop();
  await rm(directory, { recursive: true, force: true });
}
