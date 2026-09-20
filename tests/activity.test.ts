import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as cedar from '@cedar-policy/cedar-wasm/nodejs';
import { SQLiteDatabase } from '../control-plane/sqlite.ts';
import { ControlPlane } from '../control-plane/service.ts';
import { queryActivity } from '../control-plane/activity.ts';
import type { ApiInput } from '../core/api-types.ts';
const start = Date.parse('2026-09-10T12:00:00Z');
async function setup() {
  const p = new ControlPlane(new SQLiteDatabase(':memory:', 'drizzle'), cedar);
  const a = await p.enroll('alice', 'Alice', {
    name: 'Agent A',
    environmentIds: ['organization'],
  });
  const b = await p.enroll('alice', 'Alice', {
    name: 'Agent B',
    environmentIds: ['organization'],
  });
  const policies = (await p.state('alice')).policies;
  for (const policy of policies)
    await mutate(p, {
      kind: 'policy',
      operation: 'publish',
      item: { id: policy.id },
    });
  return { p, a, b, policies };
}
async function mutate(p: ControlPlane, input: ApiInput) {
  return p.mutation('alice', 'Alice', {
    revision: (await p.state('alice')).revision,
    ...input,
  });
}
const query = (
  p: ControlPlane,
  params: Record<string, string | string[]> = {},
  tenant = 'alice',
) => {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries({ type: 'decision', ...params }))
    for (const item of Array.isArray(value) ? value : [value])
      search.append(key, item);
  return queryActivity(p.db, tenant, search);
};
const event = (id: string, patch: Record<string, unknown> = {}) => ({
  id,
  time: new Date(start).toISOString(),
  environmentId: 'development',
  policyId: 'policy-a',
  policyName: 'Read files',
  action: 'file.read',
  decision: 'ALLOW',
  mode: 'AUDIT',
  ...patch,
});
void test('activity combines filters with OR within a category and AND across categories', async () => {
  const { p, a, b } = await setup();
  await p.ingest('alice', a.clientId, {
    events: [
      event('one'),
      event('two', {
        environmentId: 'production',
        action: 'database.query',
        policyId: 'policy-b',
      }),
      event('three', {
        environmentId: 'development',
        action: 'http.request',
        policyId: 'policy-b',
      }),
    ],
  });
  await p.ingest('alice', b.clientId, {
    events: [event('four'), event('five', { environmentId: 'production' })],
  });
  assert.equal(
    (await query(p, { environment: ['development', 'production'] })).total,
    5,
  );
  assert.equal((await query(p, { resource: ['File', 'Database'] })).total, 4);
  const selected = await query(p, {
    environment: ['development', 'production'],
    resource: ['Database', 'File'],
    policy: 'policy-a',
    principal: 'Agent A',
  });
  assert.deepEqual(
    selected.events.map((e) => e.id),
    ['one'],
  );
  assert.deepEqual((await query(p)).principals, ['Agent A', 'Agent B']);
  const platform = await query(p, { type: 'platform' });
  assert.ok(platform.total > 0);
  assert.ok(platform.events.every((e) => e.kind === 'administration'));
  assert.ok((await query(p)).events.every((e) => e.kind === 'decision'));
});
void test('filtering searches beyond the old 150-row window and keyset pages handle equal timestamps', async () => {
  const { p, a } = await setup();
  for (let batch = 0; batch < 3; batch++)
    await p.ingest('alice', a.clientId, {
      events: Array.from({ length: 65 }, (_, i) =>
        event(`page-${batch}-${i}`, {
          policyId: batch === 0 && i === 0 ? 'old-match' : 'other',
          time: new Date(start + batch * 60000).toISOString(),
        }),
      ),
    });
  assert.equal((await query(p, { policy: 'old-match' })).total, 1);
  const ids: string[] = [];
  let cursor: string | null = null;
  do {
    const page = await query(p, cursor ? { cursor } : {});
    assert.equal(page.total, 195);
    assert.ok(page.events.length <= 50);
    ids.push(...page.events.map((e) => e.recordId!));
    cursor = page.nextCursor;
  } while (cursor);
  assert.equal(ids.length, 195);
  assert.equal(new Set(ids).size, 195);
});
void test('date ranges honor time zones and inclusive boundaries; invalid ranges are rejected', async () => {
  const { p, a } = await setup();
  await p.ingest('alice', a.clientId, {
    events: [-1, 0, 1].map((offset) =>
      event(`date-${offset}`, {
        time: new Date(start + offset * 1000).toISOString(),
      }),
    ),
  });
  const selected = await query(p, {
    from: '2026-09-10T08:00:00-04:00',
    to: '2026-09-10T12:00:00Z',
  });
  assert.deepEqual(
    selected.events.map((e) => e.id),
    ['date-0'],
  );
  assert.equal((await query(p, { from: '2026-09-10T12:00:00Z' })).total, 2);
  assert.equal((await query(p, { to: '2026-09-10T12:00:00Z' })).total, 2);
  await assert.rejects(() => query(p, { from: 'bad' }), /date/);
  await assert.rejects(
    () =>
      query(p, { from: '2026-09-10T12:00:01Z', to: '2026-09-10T12:00:00Z' }),
    /before/,
  );
  await assert.rejects(() => query(p, { cursor: 'oops' }), /cursor/);
  await assert.rejects(
    () => query(p, { resource: 'Not a resource' }),
    /resource/,
  );
});
void test('principals use recorded server names, include historical clients, and remain tenant isolated', async () => {
  const { p, a } = await setup();
  const same = await p.enroll('alice', 'Alice', {
    name: 'Agent A',
    environmentIds: ['development'],
  });
  const other = await p.enroll('bob', 'Bob', {
    name: 'Private client',
    environmentIds: ['development'],
  });
  await p.ingest('alice', a.clientId, {
    events: [
      event('same-id', { clientName: 'spoofed', resourceType: 'Database' }),
    ],
  });
  await p.ingest('alice', same.clientId, { events: [event('same-id')] });
  await p.ingest('bob', other.clientId, { events: [event('private')] });
  await p.db
    .prepare('UPDATE clients SET name = ?, revoked = 1 WHERE id = ?')
    .bind('Renamed client', a.clientId)
    .run();
  const rows = await query(p, { principal: 'Agent A' });
  assert.equal(rows.total, 2);
  assert.notEqual(rows.events[0].recordId, rows.events[1].recordId);
  assert.deepEqual(rows.principals, ['Agent A']);
  assert.ok(rows.events.every((e) => e.resourceType === 'File'));
  assert.equal((await query(p, {}, 'bob')).total, 1);
  assert.equal((await query(p, { principal: "' OR 1=1 --" })).total, 0);
  assert.equal((await query(p, { environment: "' OR 1=1 --" })).total, 0);
  assert.equal(
    (await query(p, { type: 'platform', principal: 'Agent A' })).total,
    2,
  );
});
void test('platform policy history remains filterable after reassignment and deletion', async () => {
  const { p, policies } = await setup();
  const created = await mutate(p, {
    kind: 'policy',
    publish: true,
    item: {
      ...policies[0],
      id: undefined,
      name: 'Scoped rule',
      environmentIds: ['development'],
    },
  });
  const current = (await p.state('alice')).policies.find(
    (x) => x.id === created.id,
  )!;
  await mutate(p, {
    kind: 'policy',
    publish: true,
    item: { ...current, environmentIds: ['production'] },
  });
  await mutate(p, {
    kind: 'policy',
    operation: 'delete',
    item: { id: created.id },
  });
  assert.equal(
    (await query(p, { type: 'platform', policy: created.id })).total,
    3,
  );
  assert.equal(
    (
      await query(p, {
        type: 'platform',
        environment: 'development',
        policy: created.id,
      })
    ).total,
    2,
  );
  assert.equal(
    (
      await query(p, {
        type: 'platform',
        environment: 'customer-platform',
        policy: created.id,
      })
    ).total,
    2,
  );
  const resource = await mutate(p, {
    kind: 'resource',
    item: {
      name: 'Events test DB',
      type: 'Database',
      environmentId: 'development',
      locator: 'test-db',
    },
  });
  await mutate(p, {
    kind: 'resource',
    operation: 'delete',
    item: { id: resource.id },
  });
  assert.equal(
    (
      await query(p, {
        type: 'platform',
        resource: 'Database',
        environment: 'development',
      })
    ).events.filter((e) => e.objectId === resource.id).length,
    2,
  );
});
void test('older decision records can filter using action type, determining policies, and enrolled client identity', async () => {
  const { p, a } = await setup();
  const body = {
    id: 'legacy',
    time: new Date(start).toISOString(),
    kind: 'decision',
    clientId: a.clientId,
    action: 'database.query',
    determiningPolicies: ['legacy-policy'],
    environmentId: 'development',
  };
  await p.db
    .prepare('INSERT INTO events(id,tenant,time,kind,body) VALUES (?,?,?,?,?)')
    .bind('legacy-record', 'alice', body.time, 'decision', JSON.stringify(body))
    .run();
  const rows = await query(p, {
    resource: 'Database',
    policy: 'legacy-policy',
    principal: 'Agent A',
    environment: 'development',
  });
  assert.equal(rows.total, 1);
  assert.equal(rows.events[0].clientName, 'Agent A');
  assert.equal(rows.events[0].resourceType, 'Database');
});
void test('activity endpoint is browser-only and validates filter requests', async () => {
  const { p, a } = await setup();
  const request = (path: string, token?: string) =>
    new Request(
      'https://cleo.example/api/v1/' + path,
      token ? { headers: { authorization: 'Bearer ' + token } } : {},
    );
  assert.equal((await p.handle(request('activity'), null)).status, 401);
  assert.equal(
    (await p.handle(request('activity', a.token), null)).status,
    403,
  );
  assert.equal(
    (
      await p.handle(request('activity?type=unknown'), {
        id: 'alice',
        name: 'Alice',
      })
    ).status,
    400,
  );
  assert.equal(
    (
      await p.handle(request('activity?type=platform'), {
        id: 'alice',
        name: 'Alice',
      })
    ).status,
    200,
  );
});
