import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as cedar from '@cedar-policy/cedar-wasm/nodejs';
import { ControlPlane } from '../control-plane/service.ts';
import { SQLiteDatabase } from '../control-plane/sqlite.ts';
import {
  exportConfiguration,
  parseConfiguration,
} from '../control-plane/configuration.ts';
import { effectivePolicies, publishedSnapshot } from '../core/model.ts';
import { verifyBundle } from '../core/crypto.ts';

function setup(t: { after: (fn: () => void) => void }) {
  const db = new SQLiteDatabase(':memory:', 'migrations');
  t.after(() => db.close());
  return new ControlPlane(db, cedar);
}
void test('configuration exports explicitly exclude credentials, clients, activity, history, and runtime provenance', async (t) => {
  const plane = setup(t);
  const state = await plane.state('alice');
  const enrollment = await plane.enroll('alice', 'A', {
    name: 'Secret enrollment',
    environmentIds: ['development'],
  });
  const exported = exportConfiguration({
    ...state,
    token: enrollment.token,
    private_key: 'secret',
  } as typeof state);
  const serialized = JSON.stringify(exported);
  for (const absent of [
    enrollment.token,
    enrollment.clientId,
    'private_key',
    'publicKey',
    'clients',
    'events',
    'tenant',
    'sequence',
    'revision',
    'token_hash',
  ])
    assert.equal(serialized.includes(absent), false, absent);
  assert.equal(
    parseConfiguration(exported).policies.length,
    state.policies.length,
  );
});
void test('export/import round trip preserves hierarchy, draft/active content, assignments, and effective modes', async (t) => {
  const source = setup(t),
    target = setup(t);
  let state = await source.state('alice');
  const policy = state.policies[0];
  await source.mutation('alice', 'A', {
    revision: state.revision,
    kind: 'policy',
    publish: true,
    item: policy,
  });
  state = await source.state('alice');
  await source.mutation('alice', 'A', {
    revision: state.revision,
    kind: 'policy',
    item: { ...policy, name: 'Pending draft', environmentIds: ['production'] },
  });
  state = await source.state('alice');
  await source.mutation('alice', 'A', {
    revision: state.revision,
    kind: 'environment',
    operation: 'mode',
    item: { id: 'organization' },
    mode: 'ENFORCE',
  });
  const before = await source.state('alice');
  const configuration = exportConfiguration(before);
  const revision = (await target.state('bob')).revision;
  const preview = await target.importConfiguration(
    'bob',
    'B',
    { configuration, revision },
    true,
  );
  assert.equal((await target.state('bob')).revision, revision);
  assert.equal(preview.changes.policies.updated, before.policies.length);
  await target.importConfiguration('bob', 'B', { configuration, revision });
  const after = await target.state('bob');
  const { exportedAt: _a, ...a } = exportConfiguration(before);
  const { exportedAt: _b, ...b } = exportConfiguration(after);
  assert.deepEqual(b, a);
  assert.equal(after.policies[0].status, 'DRAFT');
  assert.equal(after.policies[0].name, 'Pending draft');
  assert.equal(
    effectivePolicies(publishedSnapshot(after), 'development')[0].mode,
    'ENFORCE',
  );
});
void test('merge keeps clients, keys, unrelated objects and events; active changes create rollback history and advance signed sequence', async (t) => {
  const plane = setup(t);
  const client = await plane.enroll('alice', 'A', {
    name: 'Agent',
    environmentIds: ['development'],
  });
  await plane.ingest('alice', client.clientId, {
    events: [
      {
        id: 'kept',
        environmentId: 'development',
        action: 'file.read',
        decision: 'ALLOW',
      },
    ],
  });
  const before = await plane.state('alice');
  const configuration = exportConfiguration(before);
  const original = configuration.policies.find((p) => p.published)!;
  configuration.policies = [
    {
      ...original,
      name: 'Imported publication',
      published: { ...original.published!, name: 'Imported publication' },
    },
  ];
  configuration.environments = [];
  configuration.resources = [];
  await plane.importConfiguration('alice', 'A', {
    configuration,
    revision: before.revision,
  });
  const after = await plane.state('alice');
  assert.deepEqual(after.publicKey, before.publicKey);
  assert.deepEqual(after.clients, before.clients);
  assert.equal((await plane.authorizeClient(client.token)).id, client.clientId);
  assert.equal(after.policies.length, before.policies.length);
  assert.equal(after.events.filter((e) => e.kind === 'decision').length, 1);
  assert.equal(after.sequence, before.sequence + 1);
  const history = await plane.history('alice', original.id);
  assert.equal(history.previous[0].name, original.name);
  assert.equal(history.current?.version, 2);
  await verifyBundle(
    await plane.bundle('alice', ['development'], {
      id: 'test-client',
      name: 'Test client',
    }),
    before.publicKey,
    'alice',
    before.sequence,
  );
  await plane.mutation('alice', 'A', {
    kind: 'policy',
    operation: 'rollback',
    item: { id: original.id },
    revision: after.revision,
  });
  assert.equal(
    (await plane.history('alice', original.id)).current?.name,
    original.name,
  );
});
void test('invalid configuration, duplicate IDs, cycles, references and unsupported fields fail without changing data', async (t) => {
  const plane = setup(t);
  const before = await plane.state('alice');
  const edits = [
    (c: ReturnType<typeof exportConfiguration>) => {
      (c as unknown as Record<string, unknown>).clients = [];
    },
    (c: ReturnType<typeof exportConfiguration>) => {
      c.policies.push(c.policies[0]);
    },
    (c: ReturnType<typeof exportConfiguration>) => {
      c.environments[0].parentId = c.environments[0].id;
    },
    (c: ReturnType<typeof exportConfiguration>) => {
      c.resources[0].environmentId = 'missing';
    },
    (c: ReturnType<typeof exportConfiguration>) => {
      c.policies[0].cedar = 'not cedar';
    },
    (c: ReturnType<typeof exportConfiguration>) => {
      c.policies[0].published = { ...c.policies[0], cedar: 'invalid' };
    },
    (c: ReturnType<typeof exportConfiguration>) => {
      c.environments[0].policyModes = { missing: 'ENFORCE' };
    },
    (c: ReturnType<typeof exportConfiguration>) => {
      c.environments[0].mode = 'bad' as 'AUDIT';
    },
  ];
  for (const edit of edits) {
    const configuration = exportConfiguration(before);
    edit(configuration);
    await assert.rejects(() =>
      plane.importConfiguration('alice', 'A', {
        configuration,
        revision: before.revision,
      }),
    );
    assert.deepEqual(await plane.state('alice'), before);
  }
});
void test('concurrent imports cannot overwrite edits and failed history writes roll back the entire import', async (t) => {
  const plane = setup(t);
  const before = await plane.state('alice');
  const configuration = exportConfiguration(before);
  const results = await Promise.allSettled(
    [1, 2].map(() =>
      plane.importConfiguration('alice', 'A', {
        configuration,
        revision: before.revision,
      }),
    ),
  );
  assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
  const current = await plane.state('alice');
  const changed = exportConfiguration(current);
  changed.policies.find((p) => p.published)!.published!.name = 'New version';
  (plane.db as SQLiteDatabase).raw.exec(
    "CREATE TRIGGER reject_history BEFORE INSERT ON policy_history BEGIN SELECT RAISE(ABORT, 'test failure'); END",
  );
  await assert.rejects(
    () =>
      plane.importConfiguration('alice', 'A', {
        configuration: changed,
        revision: current.revision,
      }),
    /test failure/,
  );
  assert.deepEqual(await plane.state('alice'), current);
});
void test('configuration endpoints require administrator authorization and same-origin writes', async (t) => {
  const plane = setup(t);
  const state = await plane.state('alice');
  const client = await plane.enroll('alice', 'A', {
    name: 'Agent',
    environmentIds: ['development'],
  });
  const admin = { id: 'alice', name: 'A' };
  const request = (route: string, body?: unknown, headers = {}) =>
    new Request(`https://cleo.example/api/v1/${route}`, {
      method: body ? 'POST' : 'GET',
      headers,
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
  assert.equal(
    (await plane.handle(request('configuration'), null)).status,
    401,
  );
  assert.equal(
    (
      await plane.handle(
        request('configuration', undefined, {
          authorization: `Bearer ${client.token}`,
        }),
        null,
      )
    ).status,
    403,
  );
  const response = await plane.handle(request('configuration'), admin);
  assert.equal(response.status, 200);
  assert.match(response.headers.get('content-disposition')!, /attachment/);
  const input = {
    revision: state.revision,
    configuration: await response.json(),
  };
  assert.equal(
    (await plane.handle(request('configuration/import', input), admin)).status,
    403,
  );
  assert.equal(
    (
      await plane.handle(
        request('configuration/preview', input, {
          origin: 'https://cleo.example',
        }),
        admin,
      )
    ).status,
    200,
  );
  assert.equal(
    (
      await plane.handle(
        request('configuration/import', input, {
          origin: 'https://cleo.example',
        }),
        admin,
      )
    ).status,
    200,
  );
  assert.equal(
    (
      await plane.handle(
        request('configuration/import', input, {
          origin: 'https://cleo.example',
        }),
        admin,
      )
    ).status,
    409,
  );
});
