import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as cedar from '@cedar-policy/cedar-wasm/nodejs';
import { SQLiteDatabase } from '../control-plane/sqlite.ts';
import { ControlPlane } from '../control-plane/service.ts';
import { evaluate, validatePolicies } from '../core/engine.ts';
import { verifyBundle } from '../core/crypto.ts';
import {
  ACTIONS,
  createDefaultPolicies,
  createSeed,
  effectivePolicies,
  generateCedar,
  publishedSnapshot,
  type Rule,
} from '../core/model.ts';

const setup = () =>
  new ControlPlane(new SQLiteDatabase(':memory:', 'drizzle'), cedar);

void test('every action has a published, unassigned wildcard permit; assigning them permits all schema actions', async () => {
  const defaults = createDefaultPolicies();
  assert.deepEqual(
    defaults.map((p) => p.rule!.action).sort(),
    Object.keys(ACTIONS).sort(),
  );
  assert.equal(validatePolicies(cedar, defaults).valid, true);
  for (const policy of defaults) {
    assert.ok(policy.name.startsWith('Default - '));
    assert.equal(policy.status, 'PUBLISHED');
    assert.deepEqual(policy.environmentIds, []);
    assert.deepEqual(policy.published!.environmentIds, []);
    assert.match(policy.cedar, /permit\(\s+principal,\s+action ==/);
    assert.match(policy.cedar, /,\s+resource\s+\);$/);
  }
  const p = setup();
  const state = await p.state('alice');
  for (const env of state.environments)
    assert.ok(
      effectivePolicies(state, env.id).every(
        (policy) => !policy.id.startsWith('pol_default_'),
      ),
    );
  const empty = await verifyBundle(
    await p.bundle('alice', ['development']),
    state.publicKey,
    'alice',
  );
  assert.equal(empty.policies.length, 0);
  await p.mutation('alice', 'Alice', {
    revision: state.revision,
    kind: 'environment',
    operation: 'policies',
    item: { id: 'development' },
    policyIds: [...defaults, ...effectivePolicies(state, 'development')].map(
      (policy) => policy.id,
    ),
  });
  const bundle = await verifyBundle(
    await p.bundle('alice', ['development']),
    state.publicKey,
    'alice',
  );
  assert.equal(bundle.policies.length, Object.keys(ACTIONS).length);
  for (const [action, type] of Object.entries(ACTIONS)) {
    const result = evaluate(cedar, bundle, {
      environmentId: 'development',
      principal: 'Any new client',
      sessionId: 'test',
      action,
      resource: { type, id: 'any-resource' },
      context: {},
    });
    assert.equal(result.decision, 'ALLOW', action);
    assert.deepEqual(result.errors, []);
  }
});

void test('existing workspace upgrade adds defaults once, preserves policy content and leaves all new permissions unassigned', async () => {
  const p = setup();
  const initial = await p.state('alice');
  const snapshot = createSeed();
  snapshot.policies = snapshot.policies.filter(
    (policy) => !policy.id.startsWith('pol_default_'),
  );
  snapshot.policies[0].name = 'User edited policy';
  await p.db
    .prepare(
      'UPDATE workspaces SET snapshot = ?, model_version = 3 WHERE id = ?',
    )
    .bind(JSON.stringify(snapshot), 'alice')
    .run();
  const upgraded = await p.state('alice');
  assert.equal(upgraded.sequence, initial.sequence + 1);
  assert.equal(upgraded.revision, initial.revision + 1);
  assert.deepEqual(
    upgraded.policies.slice(0, snapshot.policies.length),
    snapshot.policies,
  );
  assert.deepEqual(upgraded.environments, snapshot.environments);
  assert.deepEqual(upgraded.resources, snapshot.resources);
  assert.equal(
    upgraded.policies.length,
    snapshot.policies.length + Object.keys(ACTIONS).length,
  );
  for (const policy of upgraded.policies.slice(snapshot.policies.length))
    assert.deepEqual(policy.environmentIds, []);
  assert.equal((await p.state('alice')).sequence, upgraded.sequence);
  const id = createDefaultPolicies()[0].id;
  await p.mutation('alice', 'Alice', {
    revision: upgraded.revision,
    kind: 'policy',
    operation: 'delete',
    item: { id },
  });
  assert.equal(
    (await p.state('alice')).policies.some((policy) => policy.id === id),
    false,
  );
  assert.equal(
    (await p.state('bob')).policies.filter((policy) =>
      policy.id.startsWith('pol_default_'),
    ).length,
    Object.keys(ACTIONS).length,
  );
});

void test('all enrolled clients survive database reopen without the previous 100-client limit or stored plaintext credentials', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'cleo-clients-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = join(dir, 'clients.sqlite');
  const db = new SQLiteDatabase(file, 'drizzle');
  const p = new ControlPlane(db, cedar);
  let first;
  for (let i = 0; i < 101; i++) {
    const enrollment = await p.enroll('alice', 'Alice', {
      name: 'Client ' + i,
      environmentIds: ['development'],
    });
    assert.equal(enrollment.expiresAt, null);
    first ??= enrollment;
  }
  db.close();
  const reopened = new SQLiteDatabase(file, 'drizzle');
  t.after(() => reopened.close());
  const service = new ControlPlane(reopened, cedar);
  const state = await service.state('alice');
  assert.equal(state.clients.length, 101);
  assert.ok(state.clients.every((client) => client.expires_at === null));
  assert.ok(!JSON.stringify(state).includes(first!.token));
  assert.ok(
    state.clients.every(
      (client) => !('token_hash' in client) && !('token' in client),
    ),
  );
  assert.equal(
    (await service.authorizeClient(first!.token)).id,
    first!.clientId,
  );
  assert.equal((await service.state('bob')).clients.length, 0);
});

void test('non-expiring credentials can be revoked and explicit expirations remain enforced', async () => {
  const p = setup();
  const permanent = await p.enroll('alice', 'Alice', {
    name: 'Permanent',
    environmentIds: ['development'],
  });
  assert.equal(permanent.expiresAt, null);
  const expiry = new Date(Date.now() + 86400000).toISOString();
  const timed = await p.enroll('alice', 'Alice', {
    name: 'Timed',
    environmentIds: ['development'],
    expiresAt: expiry,
  });
  assert.equal(timed.expiresAt, expiry);
  await p.authorizeClient(timed.token);
  for (const expiresAt of ['', 'bad', '2000-01-01T00:00:00.000Z'])
    await assert.rejects(
      () =>
        p.enroll('alice', 'Alice', {
          name: 'Invalid',
          environmentIds: ['development'],
          expiresAt,
        }),
      /future date/,
    );
  await p.db
    .prepare('UPDATE clients SET expires_at = ? WHERE id = ?')
    .bind('2000-01-01T00:00:00.000Z', timed.clientId)
    .run();
  await assert.rejects(() => p.authorizeClient(timed.token), /expired/);
  const revoked = await p.handle(
    new Request('https://cleo.example/api/v1/revoke', {
      method: 'POST',
      headers: {
        origin: 'https://cleo.example',
        'content-type': 'application/json',
      },
      body: JSON.stringify({ id: permanent.clientId }),
    }),
    { id: 'alice', name: 'Alice' },
  );
  assert.equal(revoked.status, 200);
  await assert.rejects(() => p.authorizeClient(permanent.token), /revoked/);
  assert.equal((await p.state('alice')).clients.length, 2);
});

void test('nullable expiration migration preserves existing clients, dates, hashes, and revocations', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'cleo-client-migration-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = join(dir, 'legacy.sqlite');
  const old = new SQLiteDatabase(file);
  old.raw.exec('CREATE TABLE _cleo_migrations (name TEXT PRIMARY KEY)');
  for (const name of [
    '0000_known_shiva.sql',
    '0001_lyrical_texas_twister.sql',
  ]) {
    old.raw.exec(await readFile(join('drizzle', name), 'utf8'));
    old.raw.prepare('INSERT INTO _cleo_migrations VALUES (?)').run(name);
  }
  old.raw
    .prepare(
      'INSERT INTO clients (id,tenant,token_hash,name,environment_ids,created_at,expires_at,last_seen,revoked) VALUES (?,?,?,?,?,?,?,?,?)',
    )
    .run(
      'old',
      'alice',
      'hash',
      'Old client',
      '["development"]',
      '2026-01-01',
      '2026-02-01',
      '2026-01-02',
      1,
    );
  const before = old.raw.prepare('SELECT * FROM clients').get();
  old.close();
  const updated = new SQLiteDatabase(file, 'drizzle');
  t.after(() => updated.close());
  assert.deepEqual(updated.raw.prepare('SELECT * FROM clients').get(), before);
  updated.raw
    .prepare('UPDATE clients SET expires_at = NULL WHERE id = ?')
    .run('old');
  assert.equal(
    updated.raw.prepare('SELECT expires_at FROM clients').get()!.expires_at,
    null,
  );
});

void test('named-client builder policies retain exact escaped principal through publish, assignment and reload', async () => {
  const p = setup();
  const name = 'Agent "quoted" \\ path';
  await p.enroll('alice', 'Alice', { name, environmentIds: ['development'] });
  const rule: Rule = {
    effect: 'permit',
    principal: name,
    action: 'process.execute',
    resourceId: '',
    field: '',
    operator: 'equals',
    value: '',
  };
  const code = generateCedar(rule, []);
  assert.equal(
    validatePolicies(cedar, [{ id: 'named', cedar: code }]).valid,
    true,
  );
  await p.mutation('alice', 'Alice', {
    revision: (await p.state('alice')).revision,
    kind: 'policy',
    publish: true,
    item: {
      id: 'named',
      name: 'Named client only',
      rule,
      cedar: code,
      environmentIds: [],
    },
  });
  let state = await p.state('alice');
  assert.equal(
    state.policies.find((policy) => policy.id === 'named')!.rule!.principal,
    name,
  );
  assert.equal(state.clients[0].name, name);
  await p.mutation('alice', 'Alice', {
    revision: state.revision,
    kind: 'environment',
    operation: 'policies',
    item: { id: 'development' },
    policyIds: [
      'named',
      ...effectivePolicies(state, 'development').map((policy) => policy.id),
    ],
  });
  state = await p.state('alice');
  for (const [principal, expected] of [
    [name, 'ALLOW'],
    ['Other agent', 'DENY'],
  ]) {
    assert.equal(
      evaluate(cedar, publishedSnapshot(state), {
        environmentId: 'development',
        sessionId: 'test',
        principal,
        action: 'process.execute',
        resource: { type: 'Process', id: 'any-process' },
        context: {},
      }).decision,
      expected,
    );
  }
  // Wildcard remains selectable and preserves the existing resource/action scope.
  assert.match(
    generateCedar({ ...rule, principal: '' }, []),
    /permit\(\s+principal,/,
  );
});
