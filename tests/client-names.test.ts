import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as cedar from '@cedar-policy/cedar-wasm/nodejs';
import { SQLiteDatabase } from '../control-plane/sqlite.ts';
import { ControlPlane } from '../control-plane/service.ts';
import { digest } from '../core/crypto.ts';

function enroll(plane: ControlPlane, name: string, tenant = 'alice') {
  return plane.handle(
    new Request('https://cleo.example/api/v1/enroll', {
      method: 'POST',
      headers: {
        origin: 'https://cleo.example',
        'content-type': 'application/json',
      },
      body: JSON.stringify({ name, environmentIds: ['development'] }),
    }),
    { id: tenant, name: 'Administrator' },
  );
}

void test('enrollment rejects trimmed duplicate names per workspace, including revoked and expired clients', async (t) => {
  const db = new SQLiteDatabase(':memory:', 'migrations');
  t.after(() => db.close());
  const plane = new ControlPlane(db, cedar);
  const first = await enroll(plane, ' Research Agent ');
  assert.equal(first.status, 200);
  const client = await first.json();
  assert.equal(client.clientName, 'Research Agent');
  const duplicate = await enroll(plane, '\tResearch Agent\n');
  assert.equal(duplicate.status, 409);
  assert.match((await duplicate.json()).error, /already exists/);
  assert.equal(db.raw.prepare('SELECT count(*) AS n FROM clients').get()!.n, 1);
  assert.equal(
    db.raw
      .prepare("SELECT count(*) AS n FROM events WHERE kind = 'administration'")
      .get()!.n,
    1,
  );
  assert.equal((await enroll(plane, 'research agent')).status, 200);
  assert.equal((await enroll(plane, 'Research Agent', 'bob')).status, 200);
  db.raw
    .prepare('UPDATE clients SET expires_at = ? WHERE id = ?')
    .run('2000-01-01', client.clientId);
  assert.equal((await enroll(plane, 'Research Agent')).status, 409);
  db.raw
    .prepare('UPDATE clients SET revoked = 1 WHERE id = ?')
    .run(client.clientId);
  assert.equal((await enroll(plane, 'Research Agent')).status, 409);
});

void test('database guards reject duplicate inserts and renames, and concurrent API creation returns one success', async (t) => {
  const db = new SQLiteDatabase(':memory:', 'migrations');
  t.after(() => db.close());
  const plane = new ControlPlane(db, cedar);
  await plane.state('alice');
  const attempts = await Promise.all([
    enroll(plane, 'Concurrent agent'),
    enroll(plane, 'Concurrent agent'),
  ]);
  assert.deepEqual(
    attempts.map((r) => r.status).sort((a, b) => a - b),
    [200, 409],
  );
  assert.equal(db.raw.prepare('SELECT count(*) AS n FROM clients').get()!.n, 1);
  assert.equal(
    db.raw
      .prepare("SELECT count(*) AS n FROM events WHERE kind = 'administration'")
      .get()!.n,
    1,
  );
  const insert = db.raw.prepare(
    'INSERT INTO clients (id, tenant, name, token_hash, environment_ids, created_at) VALUES (?, ?, ?, ?, ?, ?)',
  );
  const direct = (id: string, tenant: string, name: string) =>
    insert.run(id, tenant, name, id, '["development"]', '2026-09-20');
  assert.throws(
    () => direct('collision', 'alice', 'Concurrent agent'),
    /already exists/,
  );
  direct('other', 'alice', 'Other agent');
  assert.throws(
    () =>
      db.raw
        .prepare('UPDATE clients SET name = ? WHERE id = ?')
        .run('Concurrent agent', 'other'),
    /already exists/,
  );
  direct('cross-tenant', 'bob', 'Concurrent agent');
  assert.throws(
    () =>
      db.raw
        .prepare('UPDATE clients SET tenant = ? WHERE id = ?')
        .run('alice', 'cross-tenant'),
    /already exists/,
  );
  assert.equal(
    db.raw.prepare('SELECT name FROM clients WHERE id = ?').get('other')!.name,
    'Other agent',
  );
});

void test('upgrading preserves legacy duplicate identities, credentials and activity while preventing further collisions', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'cleo-name-migration-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, 'legacy.sqlite');
  const old = new SQLiteDatabase(path);
  old.raw.exec('CREATE TABLE _cleo_migrations (name TEXT PRIMARY KEY)');
  for (const name of [
    '0000_known_shiva.sql',
    '0001_lyrical_texas_twister.sql',
    '0002_fancy_masked_marvel.sql',
  ]) {
    old.raw.exec(await readFile(join('migrations', name), 'utf8'));
    old.raw.prepare('INSERT INTO _cleo_migrations VALUES (?)').run(name);
  }
  for (const id of ['one', 'two'])
    old.raw
      .prepare(
        'INSERT INTO clients (id,tenant,token_hash,name,environment_ids,created_at) VALUES (?,?,?,?,?,?)',
      )
      .run(
        id,
        'alice',
        await digest(id),
        'Legacy agent',
        '["development"]',
        '2026-09-20',
      );
  old.raw
    .prepare('INSERT INTO events (id,tenant,time,kind,body) VALUES (?,?,?,?,?)')
    .run(
      'history',
      'alice',
      '2026-09-20',
      'administration',
      '{"clientName":"Legacy agent"}',
    );
  const clients = old.raw.prepare('SELECT * FROM clients ORDER BY id').all();
  const events = old.raw.prepare('SELECT * FROM events').all();
  old.close();
  const upgraded = new SQLiteDatabase(path, 'migrations');
  t.after(() => upgraded.close());
  assert.deepEqual(
    upgraded.raw.prepare('SELECT * FROM clients ORDER BY id').all(),
    clients,
  );
  assert.deepEqual(upgraded.raw.prepare('SELECT * FROM events').all(), events);
  assert.equal((await readdir(join(dir, 'backups'))).length, 1);
  const plane = new ControlPlane(upgraded, cedar);
  for (const id of ['one', 'two'])
    assert.equal((await plane.authorizeClient(id)).id, id);
  assert.equal((await enroll(plane, 'Legacy agent')).status, 409);
  // Updating check-in or revocation must remain possible for legacy duplicates.
  upgraded.raw
    .prepare('UPDATE clients SET last_seen = ?, revoked = 1 WHERE id = ?')
    .run('2026-09-21', 'two');
  assert.equal((await enroll(plane, 'New agent')).status, 200);
});
