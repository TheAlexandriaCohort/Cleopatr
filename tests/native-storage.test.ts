import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, cpSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import * as cedar from '@cedar-policy/cedar-wasm/nodejs';
import { openStorage } from '../control-plane/storage.ts';
import { SQLiteDatabase } from '../control-plane/sqlite.ts';
import { ControlPlane } from '../control-plane/service.ts';
import { requestOrigin } from '../control-plane/http.ts';
import {
  isAdministrator,
  createSession,
  SESSION_COOKIE,
} from '../control-plane/auth.ts';
function directory(t: { after: (fn: () => void) => void }) {
  const dir = mkdtempSync(join(tmpdir(), 'cleo-storage-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}
void test('browser origin checks use the real Host despite an internal Next.js URL and ignore forwarded hosts', () => {
  const request = (host: string) =>
    new Request('http://localhost:3000/api/v1/mutate', {
      headers: { host, 'x-forwarded-host': 'attacker.example' },
    });
  assert.equal(
    requestOrigin(request('127.0.0.1:3000')),
    'http://127.0.0.1:3000',
  );
  assert.equal(
    requestOrigin(request('localhost:3000')),
    'http://localhost:3000',
  );
  assert.equal(
    requestOrigin(request('allowed.example@attacker.example')),
    null,
  );
  assert.equal(requestOrigin(request('example.com/path')), null);
  assert.equal(requestOrigin(request('[::1]:3000')), 'http://[::1]:3000');
});
void test('native database initializes automatically and preserves data and signing identity across restarts', async (t) => {
  const dir = directory(t);
  let storage = openStorage({ dataDir: dir });
  const before = await new ControlPlane(storage.db, cedar).state(
    storage.workspaceId,
  );
  storage.db.close();
  storage = openStorage({ dataDir: dir });
  const after = await new ControlPlane(storage.db, cedar).state(
    storage.workspaceId,
  );
  assert.deepEqual(after, before);
  assert.equal(statSync(storage.file).mode & 0o777, 0o600);
  storage.db.close();
});
void test('moving SQL migrations preserves applied IDs, clients, signing identity, history and events', async (t) => {
  const dir = directory(t);
  const previousDirectory = join(dir, 'previous-migrations');
  cpSync(resolve('migrations'), previousDirectory, { recursive: true });
  const db = new SQLiteDatabase(
    join(dir, 'cleopatr.sqlite'),
    previousDirectory,
  );
  const beforePlane = new ControlPlane(db, cedar);
  const client = await beforePlane.enroll('existing-owner', 'A', {
    name: 'Existing client',
    environmentIds: ['development'],
  });
  let before = await beforePlane.state('existing-owner');
  const policy = before.policies.find((p) => p.published)!;
  await beforePlane.mutation('existing-owner', 'A', {
    kind: 'policy',
    publish: true,
    item: { ...policy, name: 'Second publication' },
    revision: before.revision,
  });
  before = await beforePlane.state('existing-owner');
  const history = await beforePlane.history('existing-owner', policy.id);
  const applied = db.raw
    .prepare('SELECT name FROM _cleo_migrations ORDER BY name')
    .all();
  db.close();
  const storage = openStorage({ dataDir: dir });
  try {
    const plane = new ControlPlane(storage.db, cedar);
    assert.equal(storage.workspaceId, 'existing-owner');
    assert.deepEqual(await plane.state(storage.workspaceId), before);
    assert.deepEqual(
      await plane.history(storage.workspaceId, policy.id),
      history,
    );
    assert.equal(
      (await plane.authorizeClient(client.token)).id,
      client.clientId,
    );
    assert.deepEqual(
      storage.db.raw
        .prepare('SELECT name FROM _cleo_migrations ORDER BY name')
        .all(),
      applied,
    );
  } finally {
    storage.db.close();
  }
});
void test('administrator workspace must be explicit when an existing database contains multiple tenants', async (t) => {
  const dir = directory(t);
  const storage = openStorage({ dataDir: dir });
  const plane = new ControlPlane(storage.db, cedar);
  await plane.state('alice');
  await plane.state('bob');
  storage.db.close();
  assert.throws(() => openStorage({ dataDir: dir }), /Multiple workspaces/);
  const selected = openStorage({ dataDir: dir, workspaceId: 'alice' });
  assert.equal(selected.workspaceId, 'alice');
  selected.db.close();
  assert.throws(
    () => openStorage({ dataDir: dir, workspaceId: 'wrong' }),
    /does not match/,
  );
});
void test('administrator authentication ignores spoofed platform identity, limits unauthenticated access to loopback, and expires sessions', () => {
  const token = 'a-test-token',
    now = Date.now();
  assert.equal(
    isAdministrator(new Headers({ host: 'localhost:3000' }), ''),
    true,
  );
  assert.equal(
    isAdministrator(
      new Headers({ host: 'evil.test', 'x-forwarded-host': 'localhost' }),
      '',
    ),
    false,
  );
  assert.equal(
    isAdministrator(
      new Headers({ 'oai-authenticated-user-id': 'alice', host: 'localhost' }),
      token,
    ),
    false,
  );
  assert.equal(
    isAdministrator(new Headers({ 'x-cleo-admin-token': token }), token),
    true,
  );
  const session = createSession(token, now);
  const headers = new Headers({ cookie: `${SESSION_COOKIE}=${session}` });
  assert.equal(isAdministrator(headers, token, now), true);
  assert.equal(isAdministrator(headers, 'rotated-token', now), false);
  assert.equal(
    isAdministrator(headers, token, now + 13 * 60 * 60 * 1000),
    false,
  );
});
