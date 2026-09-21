import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as cedar from '@cedar-policy/cedar-wasm/nodejs';
import { SQLiteDatabase } from '../control-plane/sqlite.ts';
import { ControlPlane } from '../control-plane/service.ts';
import { verifyBundle, signBundle } from '../core/crypto.ts';
import { BUNDLE_MINIMUM_CLIENT_VERSION } from '../core/model.ts';
import { activate, atomicJson, sync } from '../cli/cache.ts';
import { authorize } from '../cli/runtime.ts';

const request = (
  plane: ControlPlane,
  params: Record<string, string> = {},
  token?: string,
) =>
  plane.handle(
    new Request(
      'https://cleo.example/api/v1/bundles?' + new URLSearchParams(params),
      {
        headers: token ? { authorization: 'Bearer ' + token } : {},
      },
    ),
    token ? null : { id: 'alice', name: 'Administrator' },
  );

void test('offline export requires an active client in the administrator workspace and uses its saved scope and identity', async (t) => {
  const db = new SQLiteDatabase(':memory:', 'migrations');
  t.after(() => db.close());
  const plane = new ControlPlane(db, cedar);
  const create = (tenant: string, name: string, env = 'development') =>
    plane.enroll(tenant, 'Administrator', { name, environmentIds: [env] });
  const client = await create('alice', 'Selected client');
  const other = await create('alice', 'Other client', 'production');
  const foreign = await create('bob', 'Foreign client');
  assert.equal(
    (await request(plane, { environment: 'development' })).status,
    400,
  );
  assert.equal((await request(plane, { clientId: 'missing' })).status, 404);
  assert.equal(
    (await request(plane, { clientId: foreign.clientId })).status,
    404,
  );
  const response = await request(plane, {
    clientId: client.clientId,
    clientName: 'Forged',
    environment: 'production',
  });
  assert.equal(response.status, 200);
  const signed = await response.json();
  const bundle = await verifyBundle(signed, client.publicKey, client.tenant);
  assert.deepEqual(bundle.client, {
    id: client.clientId,
    name: client.clientName,
  });
  assert.deepEqual(bundle.environmentIds, ['development']);
  assert.equal(bundle.minimumClientVersion, BUNDLE_MINIMUM_CLIENT_VERSION);
  assert.equal(JSON.stringify(signed).includes(client.token), false);
  const online = await (
    await request(
      plane,
      { clientId: other.clientId, environment: 'production' },
      client.token,
    )
  ).json();
  assert.deepEqual(
    online,
    signed,
    'Bearer token identity overrides all client/scope query parameters',
  );
  db.raw
    .prepare('UPDATE clients SET revoked = 1 WHERE id = ?')
    .run(client.clientId);
  assert.equal(
    (await request(plane, { clientId: client.clientId })).status,
    403,
  );
  db.raw
    .prepare('UPDATE clients SET expires_at = ? WHERE id = ?')
    .run('2000-01-01', other.clientId);
  assert.equal(
    (await request(plane, { clientId: other.clientId })).status,
    403,
  );
});

void test('client-specific offline bundles import only for that enrollment and ignore an edited configuration name', async (t) => {
  const db = new SQLiteDatabase(':memory:', 'migrations');
  const dir = await mkdtemp(join(tmpdir(), 'cleo-offline-identity-'));
  t.after(async () => {
    db.close();
    await rm(dir, { recursive: true, force: true });
  });
  const plane = new ControlPlane(db, cedar);
  const client = await plane.enroll('alice', 'Administrator', {
    name: 'Actual client',
    environmentIds: ['development'],
  });
  const other = await plane.enroll('alice', 'Administrator', {
    name: 'Privileged client',
    environmentIds: ['development'],
  });
  await plane.mutation('alice', 'Administrator', {
    revision: (await plane.state('alice')).revision,
    kind: 'policy',
    publish: true,
    item: {
      name: 'Only privileged client',
      environmentIds: ['development'],
      cedar:
        'permit(principal == Cleopatr::AgentSession::"Privileged client", action, resource);',
    },
  });
  const config = {
    ...client,
    server: 'https://offline.example',
    clientName: 'Privileged client',
  };
  await atomicJson(join(dir, 'config'), config);
  const signed = await (
    await request(plane, { clientId: client.clientId })
  ).json();
  await activate(signed, dir);
  const result = await authorize(
    {
      environmentId: 'development',
      sessionId: 'offline',
      action: 'file.read',
      resource: { type: 'File', id: 'project-workspace' },
      context: { withinWorkspace: true },
    },
    { dir, refresh: false, mode: 'ENFORCE' },
  );
  assert.equal(result.allowed, false);
  assert.equal(result.parc.principal.id, 'Actual client');
  const otherBundle = await (
    await request(plane, { clientId: other.clientId })
  ).json();
  await assert.rejects(activate(otherBundle, dir), /identity does not match/);
  const payload = JSON.parse(signed.payload);
  payload.client.name = 'Privileged client';
  await assert.rejects(
    activate({ ...signed, payload: JSON.stringify(payload) }, dir),
    /digest|signature/i,
  );
});

void test('identity contract upgrade advances the sequence once and replaces an old unbound cache without relaxing rollback checks', async (t) => {
  const db = new SQLiteDatabase(':memory:', 'migrations');
  const dir = await mkdtemp(join(tmpdir(), 'cleo-identity-upgrade-'));
  t.after(async () => {
    db.close();
    await rm(dir, { recursive: true, force: true });
  });
  const plane = new ControlPlane(db, cedar);
  const client = await plane.enroll('alice', 'Administrator', {
    name: 'Existing client',
    environmentIds: ['development'],
  });
  const before = await plane.state('alice');
  const signed = await plane.bundleForClient('alice', client.clientId);
  const payload = JSON.parse(signed.payload);
  delete payload.client;
  payload.minimumClientVersion = '0.4.2';
  const key = JSON.parse(
    db.raw
      .prepare('SELECT private_key FROM workspaces WHERE id = ?')
      .get('alice')!.private_key as string,
  );
  const old = await signBundle(payload, key);
  await atomicJson(join(dir, 'config'), {
    ...client,
    server: 'https://offline.example',
  });
  await atomicJson(join(dir, 'bundle.json'), {
    signed: old,
    checkedAt: Date.now(),
    activatedAt: Date.now(),
    highWater: before.sequence,
    etag: `"${old.digest}"`,
  });
  db.raw
    .prepare('UPDATE workspaces SET model_version = 5 WHERE id = ?')
    .run('alice');
  const upgraded = await plane.bundleForClient('alice', client.clientId);
  const after = await plane.state('alice');
  assert.equal(after.sequence, before.sequence + 1);
  assert.deepEqual(after.policies, before.policies);
  assert.deepEqual(after.clients, before.clients);
  assert.deepEqual(after.publicKey, before.publicKey);
  assert.equal((await plane.state('alice')).sequence, after.sequence);
  await sync(dir, (async () => Response.json(upgraded)) as typeof fetch);
  await assert.rejects(activate(signed, dir), /rollback/);
});
