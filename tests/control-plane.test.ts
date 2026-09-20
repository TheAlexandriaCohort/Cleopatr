import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as cedar from '@cedar-policy/cedar-wasm/nodejs';
import { ControlPlane } from '../control-plane/service.ts';
import { SQLiteDatabase } from '../control-plane/sqlite.ts';
import {
  createSeed,
  effectivePolicies,
  policyContent,
  publishedSnapshot,
} from '../core/model.ts';
import type { ApiInput } from '../core/api-types.ts';
import { verifyBundle } from '../core/crypto.ts';
function setup() {
  return new ControlPlane(new SQLiteDatabase(':memory:', 'drizzle'), cedar);
}
async function mutate(p: ControlPlane, input: ApiInput) {
  return p.mutation('alice', 'Alice', {
    revision: (await p.state('alice')).revision,
    ...input,
  });
}
async function bundle(p: ControlPlane, env = 'development') {
  return verifyBundle(
    await p.bundle('alice', [env]),
    (await p.state('alice')).publicKey,
    'alice',
  );
}
void test('direct publishing isolates drafts, signs policies, and rollback creates a newer version', async () => {
  const p = setup();
  const s = await p.state('alice');
  assert.equal((await bundle(p)).policies.length, 0);
  const policy = s.policies[0];
  await mutate(p, {
    kind: 'policy',
    operation: 'publish',
    item: { id: policy.id },
  });
  const initial = await p.bundle('alice', ['development']);
  const live = await bundle(p);
  assert.deepEqual(live.environmentIds, ['development']);
  assert.equal(live.policies.length, 1);
  assert.equal(live.policies[0].name, policy.name);
  await assert.rejects(
    () => verifyBundle(initial, s.publicKey, 'bob'),
    /different tenant/,
  );
  await assert.rejects(
    () =>
      verifyBundle(
        { ...initial, payload: initial.payload + ' ' },
        s.publicKey,
        'alice',
      ),
    /digest/,
  );
  await assert.rejects(() =>
    verifyBundle(
      { ...initial, signature: 'a'.repeat(88) },
      s.publicKey,
      'alice',
    ),
  );
  await mutate(p, {
    kind: 'policy',
    item: {
      ...policy,
      name: 'Changed',
      requirement: 'secret draft requirement',
      environmentIds: ['production'],
    },
  });
  assert.equal((await bundle(p)).policies[0].name, policy.name);
  assert.equal(
    JSON.stringify(await bundle(p)).includes('secret draft requirement'),
    false,
  );
  await mutate(p, {
    kind: 'policy',
    operation: 'publish',
    item: { id: policy.id },
  });
  assert.equal((await bundle(p)).policies.length, 0);
  const promoted = await bundle(p, 'production');
  assert.equal(promoted.policies[0].name, 'Changed');
  const history = await p.history('alice', policy.id);
  assert.equal(history.previous.length, 1);
  assert.equal(history.previous[0].version, 1);
  assert.ok(Date.parse(history.previous[0].supersededAt));
  await mutate(p, {
    kind: 'policy',
    item: { ...policy, name: 'Pending edits' },
  });
  await mutate(p, {
    kind: 'policy',
    operation: 'rollback',
    item: { id: policy.id },
  });
  const restored = await bundle(p, 'production');
  assert.equal(restored.policies[0].name, policy.name);
  assert.equal(restored.policies[0].revision, 3);
  assert.ok(restored.sequence > promoted.sequence);
  assert.equal(
    (await p.state('alice')).policies.find((x) => x.id === policy.id)!.name,
    'Pending edits',
  );
  assert.deepEqual(restored.policies[0].environmentIds, ['production']);
  await assert.rejects(
    () => verifyBundle(initial, s.publicKey, 'alice', restored.sequence),
    /rollback/,
  );
});
void test('stale writes, cycles, invalid policies and unsafe deletes do not mutate the workspace', async () => {
  const p = setup();
  const s = await p.state('alice');
  await assert.rejects(
    () =>
      p.mutation('alice', 'A', {
        revision: 0,
        kind: 'environment',
        item: { name: 'Bad' },
      }),
    /changed/,
  );
  await assert.rejects(
    () =>
      p.mutation('alice', 'A', {
        revision: s.revision,
        kind: 'environment',
        item: { ...s.environments[0], parentId: 'production' },
      }),
    /cycle/,
  );
  await assert.rejects(
    () =>
      p.mutation('alice', 'A', {
        revision: s.revision,
        kind: 'environment',
        operation: 'delete',
        item: s.environments[0],
      }),
    /children/,
  );
  await assert.rejects(() =>
    p.mutation('alice', 'A', {
      revision: s.revision,
      kind: 'policy',
      item: { ...s.policies[0], cedar: 'bad' },
    }),
  );
  assert.equal((await p.state('alice')).revision, s.revision);
});
void test('API isolates users, denies anonymous access, rejects CSRF and limits client credentials', async () => {
  const p = setup();
  const req = (
    path: string,
    body?: unknown,
    headers: Record<string, string> = {},
  ) =>
    new Request('https://cleo.example/api/v1/' + path, {
      method: body ? 'POST' : 'GET',
      headers: {
        ...(body ? { 'content-type': 'application/json' } : {}),
        ...headers,
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
  assert.equal((await p.handle(req('state'), null)).status, 401);
  const a = await p.state('alice');
  const b = await p.state('bob');
  assert.notEqual(a.tenant, b.tenant);
  assert.equal(
    (
      await p.handle(
        req('mutate', {
          revision: a.revision,
          kind: 'environment',
          item: { name: 'Unsafe' },
        }),
        { id: 'alice', name: 'Alice' },
      )
    ).status,
    403,
  );
  const enrollment = await p.enroll('alice', 'Alice', {
    name: 'Dev agent',
    environmentIds: ['development'],
  });
  const headers = { authorization: 'Bearer ' + enrollment.token };
  assert.equal(
    (await p.handle(req('state', undefined, headers), null)).status,
    403,
  );
  assert.equal(
    (
      await p.handle(
        req('mutate', { kind: 'policy', operation: 'publish' }, headers),
        null,
      )
    ).status,
    403,
  );
  const bundleResponse = await p.handle(
    req('bundles', undefined, headers),
    null,
  );
  assert.equal(bundleResponse.status, 200);
  const etag = bundleResponse.headers.get('etag')!;
  assert.equal(
    (
      await p.handle(
        req('bundles', undefined, { ...headers, 'if-none-match': etag }),
        null,
      )
    ).status,
    304,
  );
  const c = await p.authorizeClient(enrollment.token);
  await p.ingest('alice', c.id, {
    events: [
      {
        id: 'one',
        action: 'database.query',
        decision: 'DENY',
        mode: 'ENFORCE',
        effectiveResult: 'BLOCKED',
        context: { password: 'secret' },
        argv: ['token'],
        sql: 'DELETE SECRET',
      },
    ],
  });
  const events = (await p.state('alice')).events;
  assert.equal(JSON.stringify(events).includes('secret'), false);
  assert.equal(JSON.stringify(events).includes('DELETE SECRET'), false);
});
void test('client revocation prevents new downloads', async () => {
  const p = setup();
  const e = await p.enroll('alice', 'Alice', {
    name: 'Agent',
    environmentIds: ['development'],
  });
  await p.db
    .prepare('UPDATE clients SET revoked=1 WHERE id = ?')
    .bind(e.clientId)
    .run();
  await assert.rejects(() => p.authorizeClient(e.token), /revoked/);
});
void test('parallel workspace edits use compare-and-swap and one loses cleanly', async () => {
  const p = setup();
  const s = await p.state('alice');
  const results = await Promise.allSettled(
    ['One', 'Two'].map((name) =>
      p.mutation('alice', 'Alice', {
        revision: s.revision,
        kind: 'environment',
        item: { name, parentId: 'organization' },
      }),
    ),
  );
  assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
  assert.equal((await p.state('alice')).environments.length, 5);
});
void test('new environments are immediately enrollable and inherit published policies and modes', async () => {
  const p = setup();
  const s = await p.state('alice');
  const id = s.policies[0].id;
  await mutate(p, { kind: 'policy', operation: 'publish', item: { id } });
  const created = await mutate(p, {
    kind: 'environment',
    item: { name: 'PCI', parentId: 'development' },
  });
  assert.equal(
    (
      await p.enroll('alice', 'Alice', {
        name: 'PCI agent',
        environmentIds: [created.id],
      })
    ).environment,
    created.id,
  );
  assert.equal((await bundle(p, created.id)).policies[0].id, id);
  await mutate(p, {
    kind: 'environment',
    operation: 'mode',
    item: { id: created.id },
    mode: 'CUSTOM',
  });
  await mutate(p, {
    kind: 'environment',
    operation: 'policy-mode',
    item: { id: created.id },
    policyId: id,
    mode: 'ENFORCE',
  });
  let snapshot = await bundle(p, created.id);
  assert.equal(effectivePolicies(snapshot, created.id)[0].mode, 'ENFORCE');
  await mutate(p, {
    kind: 'environment',
    operation: 'mode',
    item: { id: created.id },
    mode: 'AUDIT',
  });
  snapshot = await bundle(p, created.id);
  assert.equal(effectivePolicies(snapshot, created.id)[0].mode, 'AUDIT');
  assert.equal(
    snapshot.environments.find((e) => e.id === created.id)!.mode,
    'AUDIT',
  );
  await mutate(p, {
    kind: 'environment',
    operation: 'policy-mode',
    item: { id: created.id },
    policyId: id,
    mode: 'ENFORCE',
  });
  assert.equal(
    effectivePolicies(await bundle(p, created.id), created.id)[0].mode,
    'ENFORCE',
  );
});
void test('manage policies locks inherited rules and handles distinct draft assignments', async () => {
  const p = setup();
  const s = await p.state('alice');
  const policy = s.policies[0];
  const inheritedIds = effectivePolicies(s, 'development').map((p) => p.id);
  await mutate(p, {
    kind: 'policy',
    operation: 'publish',
    item: { id: policy.id },
  });
  await assert.rejects(
    () =>
      mutate(p, {
        kind: 'environment',
        operation: 'policies',
        item: { id: 'development' },
        policyIds: [],
      }),
    /Inherited policies cannot be deselected/,
  );
  assert.equal((await bundle(p)).policies.length, 1);
  assert.ok(
    (await bundle(p, 'production')).policies.some((x) => x.id === policy.id),
  );
  const child = await mutate(p, {
    kind: 'environment',
    item: { name: 'Nested', parentId: 'development' },
  });
  assert.equal((await bundle(p, child.id)).policies.length, 1);
  await mutate(p, {
    kind: 'environment',
    operation: 'policies',
    item: { id: child.id },
    policyIds: inheritedIds,
  });
  assert.equal((await bundle(p, child.id)).policies.length, 1);
  // Pending draft uses production, active version still uses organization.
  await mutate(p, {
    kind: 'policy',
    item: { ...policy, environmentIds: ['production'] },
  });
  await mutate(p, {
    kind: 'environment',
    operation: 'policies',
    item: { id: 'development' },
    policyIds: inheritedIds,
  });
  assert.equal((await bundle(p)).policies.length, 1);
  const current = (await p.state('alice')).policies.find(
    (x) => x.id === policy.id,
  )!;
  assert.ok(current.environmentIds.includes('development'));
  assert.equal(
    current.published!.environmentIds.includes('development'),
    false,
  );
});
void test('create and publish immediately; simulator can choose saved draft or published version', async () => {
  const p = setup();
  const seed = (await p.state('alice')).policies[0];
  const created = await mutate(p, {
    kind: 'policy',
    publish: true,
    item: {
      ...seed,
      id: undefined,
      name: 'Immediate',
      environmentIds: ['development'],
      cedar:
        'permit(principal, action == Cleopatr::Action::"process.execute", resource);',
      rule: undefined,
    },
  });
  const live = (await p.state('alice')).policies.find(
    (x) => x.id === created.id,
  )!;
  assert.equal(live.status, 'PUBLISHED');
  await mutate(p, {
    kind: 'policy',
    item: {
      ...live,
      cedar:
        'forbid(principal, action == Cleopatr::Action::"process.execute", resource);',
    },
  });
  for (const source of ['DRAFT', 'PUBLISHED']) {
    const response = await p.handle(
      new Request('https://cleo.example/api/v1/simulate', {
        method: 'POST',
        headers: {
          origin: 'https://cleo.example',
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          source,
          request: {
            environmentId: 'development',
            sessionId: 'sim',
            action: 'process.execute',
            resource: { type: 'Process', id: 'x' },
            context: {},
          },
        }),
      }),
      { id: 'alice', name: 'Alice' },
    );
    assert.equal(response.status, 200);
    assert.equal(
      ((await response.json()) as { decision: string }).decision,
      source === 'PUBLISHED' ? 'ALLOW' : 'DENY',
    );
  }
  const removed = await p.handle(
    new Request('https://cleo.example/api/v1/publish', {
      method: 'POST',
      headers: { origin: 'https://cleo.example' },
      body: '{}',
    }),
    { id: 'alice', name: 'Alice' },
  );
  assert.equal(removed.status, 404);
});
void test('history keeps the latest 50 previous publications and concurrent publishes stay atomic', async () => {
  const p = setup();
  const policy = (await p.state('alice')).policies[0];
  for (let i = 1; i <= 53; i++)
    await mutate(p, {
      kind: 'policy',
      publish: true,
      item: { ...policy, name: `Version ${i}` },
    });
  const history = await p.history('alice', policy.id);
  assert.equal(history.current!.version, 53);
  assert.equal(history.previous.length, 50);
  assert.equal(history.previous[0].version, 52);
  assert.equal(history.previous.at(-1)!.version, 3);
  const revision = (await p.state('alice')).revision;
  const results = await Promise.allSettled(
    ['A', 'B'].map((name) =>
      p.mutation('alice', 'Alice', {
        revision,
        kind: 'policy',
        publish: true,
        item: { ...policy, name },
      }),
    ),
  );
  assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
  assert.equal((await p.history('alice', policy.id)).current!.version, 54);
});
void test('environment activity returns the latest 50 scoped events with authenticated client name', async () => {
  const p = setup();
  const client = await p.enroll('alice', 'Alice', {
    name: 'Verified agent',
    environmentIds: ['development'],
  });
  const events = Array.from({ length: 60 }, (_, i) => ({
    id: `event-${i}`,
    time: new Date(Date.now() - (60 - i) * 1000).toISOString(),
    environmentId: 'development',
    policyId: 'one',
    policyName: 'Read files',
    action: 'file.read',
    decision: 'ALLOW',
    clientName: 'spoofed',
    mode: 'AUDIT',
  }));
  await p.ingest('alice', client.clientId, { events });
  await p.ingest('alice', client.clientId, { events }); // Idempotent upload.
  const rows = await p.environmentActivity('alice', 'development');
  assert.equal(rows.length, 50);
  assert.equal(rows[0].id, 'event-59');
  assert.equal(rows.at(-1).id, 'event-10');
  assert.ok(rows.every((e) => e.clientName === 'Verified agent'));
  assert.equal((await p.environmentActivity('alice', 'production')).length, 0);
  assert.equal((await p.environmentActivity('bob', 'development')).length, 0);
  await assert.rejects(
    () =>
      p.ingest('alice', client.clientId, {
        events: [{ ...events[0], id: 'outside', environmentId: 'production' }],
      }),
    /outside/,
  );
});
void test('legacy storage upgrades once and preserves active versions, draft edits, and history', async () => {
  const p = setup();
  await p.state('alice');
  const first = createSeed();
  const second = structuredClone(first);
  second.policies[0].name = 'Published change';
  const draft = structuredClone(second);
  draft.policies[0].name = 'Unpublished edit';
  draft.policies.pop(); // A draft deletion must not erase the live policy on upgrade.
  await p.db
    .prepare(
      'UPDATE workspaces SET snapshot = ?, model_version = 1, sequence = 8 WHERE id = ?',
    )
    .bind(JSON.stringify(draft), 'alice')
    .run();
  for (const [i, snapshot] of [first, second].entries())
    await p.db
      .prepare(
        'INSERT INTO releases (id,tenant,sequence,body) VALUES (?,?,?,?)',
      )
      .bind(
        `old-${i}`,
        'alice',
        i + 1,
        JSON.stringify({
          snapshot,
          mode: 'ENFORCE',
          createdAt: `2026-09-${10 + i}T00:00:00.000Z`,
        }),
      )
      .run();
  const state = await p.state('alice');
  assert.equal(state.sequence, 9);
  assert.equal(state.policies.length, first.policies.length);
  assert.equal(state.policies[0].name, 'Unpublished edit');
  assert.equal(state.policies[0].published!.name, 'Published change');
  assert.equal(state.environments[0].mode, 'ENFORCE');
  assert.equal(
    (await p.history('alice', first.policies[0].id)).previous[0].name,
    first.policies[0].name,
  );
  assert.equal((await p.state('alice')).sequence, 9);
  assert.equal(publishedSnapshot(state).policies[0].name, 'Published change');
  assert.equal(policyContent(state.policies[0]).name, 'Unpublished edit');
});
