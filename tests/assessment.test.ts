import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as cedar from '@cedar-policy/cedar-wasm/nodejs';
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createSeed, type ActionRequest } from '../core/model.ts';
import { evaluate, type CedarEngine } from '../core/engine.ts';
import {
  captureAssessment,
  validateAssessment,
  MAX_AUDIT_BATCH_BYTES,
  jsonBytes,
  type AssessedPayload,
} from '../core/assessment.ts';
import { SQLiteDatabase } from '../control-plane/sqlite.ts';
import { ControlPlane } from '../control-plane/service.ts';
import { queryActivity } from '../control-plane/activity.ts';
import { activate, atomicJson } from '../cli/cache.ts';
import { authorize, flushAudit, spool } from '../cli/runtime.ts';
import type { EventRecord } from '../core/api-types.ts';

const request: ActionRequest = {
  environmentId: 'development',
  sessionId: 'distinct-session',
  principal: 'Test agent',
  action: 'file.read',
  resource: { type: 'File', id: 'project-workspace' },
  workspace: '/workspace',
  context: {
    withinWorkspace: true,
    path: '/workspace/example.txt',
    argv: ['space value', '--flag'],
    confidence: 'configured',
  },
};
const payload = () => {
  const result = evaluate(cedar, createSeed(), structuredClone(request));
  assert.equal(result.assessment.status, 'captured');
  return result.assessment.payload;
};
const event = (id: string, assessed = payload()): EventRecord => ({
  id,
  kind: 'decision',
  time: new Date().toISOString(),
  action: request.action,
  environmentId: request.environmentId,
  resource: request.resource.id,
  decision: 'ALLOW',
  assessment: captureAssessment(assessed),
  policyId: 'pol_workspace_read',
  policyName: 'Allow workspace reads',
  policyVersion: 1,
});
async function client(t: import('node:test').TestContext) {
  const p = new ControlPlane(new SQLiteDatabase(':memory:', 'migrations'), cedar);
  const enrollment = await p.enroll('alice', 'Alice', {
    name: 'Test agent',
    environmentIds: ['development'],
  });
  const state = await p.state('alice');
  await p.mutation('alice', 'Alice', {
    revision: state.revision,
    kind: 'policy',
    operation: 'publish',
    item: { id: 'pol_workspace_read' },
  });
  const dir = await mkdtemp(join(tmpdir(), 'cleo-assessment-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  await atomicJson(join(dir, 'config'), {
    ...enrollment,
    server: 'http://127.0.0.1:1',
  });
  await activate(
    await p.bundle('alice', ['development'], {
      id: enrollment.clientId,
      name: enrollment.clientName,
    }),
    dir,
  );
  return { p, dir, enrollment };
}

void test('captured input equals the actual Cedar request and remains immutable after caller edits', () => {
  let observed: Parameters<CedarEngine['isAuthorized']>[0] | undefined;
  const engine: CedarEngine = {
    ...cedar,
    isAuthorized(input) {
      observed = structuredClone(input);
      return cedar.isAuthorized(input);
    },
  };
  const snapshot = createSeed();
  const input = structuredClone(request);
  const result = evaluate(engine, snapshot, input);
  assert.equal(result.assessment.status, 'captured');
  const { principal, action, resource, context, entities } = observed!;
  assert.deepEqual(result.assessment.payload, {
    principal,
    action,
    resource,
    context,
    entities,
  });
  input.context.argv = ['changed'];
  snapshot.resources.find((r) => r.id === 'project-workspace')!.name =
    'Renamed later';
  assert.deepEqual(result.assessment.payload.context.argv, [
    'space value',
    '--flag',
  ]);
  assert.equal(
    result.assessment.payload.entities[1].attrs.name,
    'Project workspace',
  );
});

void test('CLI pins the principal and persists the exact assessment through both activity views', async (t) => {
  const { p, dir, enrollment } = await client(t);
  const result = await authorize(
    { ...request, principal: 'Forged agent' },
    { dir, refresh: false },
  );
  assert.equal(result.assessment.status, 'captured');
  assert.equal(result.assessment.payload.principal.id, 'Test agent');
  const files = await readdir(join(dir, 'spool'));
  const records = await Promise.all(
    files
      .filter((f) => f.endsWith('.json'))
      .map(async (f) =>
        JSON.parse(await readFile(join(dir, 'spool', f), 'utf8')),
      ),
  );
  assert.ok(records.length > 0);
  assert.ok(records.every((e) => e.assessment.status === 'captured'));
  await p.ingest('alice', enrollment.clientId, { events: records });
  const resource = (await p.state('alice')).resources.find(
    (r) => r.id === 'project-workspace',
  )!;
  await p.mutation('alice', 'Alice', {
    revision: (await p.state('alice')).revision,
    kind: 'resource',
    item: {
      ...resource,
      name: 'Changed after the event',
      locator: '/another-workspace',
    },
  });
  const environment = await p.environmentActivity('alice', 'development');
  const activity = await queryActivity(
    p.db,
    'alice',
    new URLSearchParams({ type: 'decision', principal: 'Test agent' }),
  );
  assert.equal(environment.length, records.length);
  assert.deepEqual(environment[0].assessment, result.assessment);
  assert.deepEqual(activity.events[0].assessment, result.assessment);
  assert.equal(
    (
      await queryActivity(
        p.db,
        'bob',
        new URLSearchParams({ type: 'decision' }),
      )
    ).total,
    0,
  );
  await p.ingest('alice', enrollment.clientId, {
    events: [
      {
        ...event('legacy'),
        assessment: undefined,
        context: { password: 'raw secret' },
        sql: 'raw SQL',
      },
    ],
  });
  const legacy = (await p.environmentActivity('alice', 'development')).find(
    (e) => e.id === 'legacy',
  );
  assert.equal(legacy.assessment, undefined);
  assert.ok(!JSON.stringify(legacy).includes('raw secret'));
  assert.ok(!JSON.stringify(legacy).includes('raw SQL'));
});

void test('ingestion rejects spoofed identities, mismatched events and arbitrary extra payload fields', async (t) => {
  const { p, enrollment } = await client(t);
  for (const change of [
    (x: AssessedPayload) => {
      x.principal.id = 'Other agent';
    },
    (x: AssessedPayload) => {
      x.action.id = 'file.write';
    },
    (x: AssessedPayload) => {
      x.resource.id = 'another-resource';
    },
    (x: AssessedPayload) => {
      x.entities[0].attrs.environment = 'production';
    },
    (x: AssessedPayload) => {
      x.context.password = 'not a Cedar context field';
    },
    (x: AssessedPayload) => {
      x.entities[1].attrs.secret = 'unexpected';
    },
  ]) {
    const input = payload();
    change(input);
    await assert.rejects(
      () =>
        p.ingest('alice', enrollment.clientId, {
          events: [event(crypto.randomUUID(), input)],
        }),
      /Invalid assessed payload/,
    );
  }
  const valid = event('valid');
  await p.ingest('alice', enrollment.clientId, { events: [valid] });
  assert.equal((await p.environmentActivity('alice', 'development')).length, 1);
});

void test('oversized captures explicitly report unavailability without truncating or changing authorization', async (t) => {
  const { dir } = await client(t);
  const result = await authorize(
    {
      ...request,
      context: { withinWorkspace: true, argv: ['é'.repeat(70000)] },
    },
    { dir, refresh: false, mode: 'ENFORCE' },
  );
  assert.equal(result.allowed, true);
  assert.equal(result.assessment.status, 'unavailable');
  assert.equal(result.assessment.reason, 'too_large');
  assert.ok(!('payload' in result.assessment));
  assert.deepEqual(
    validateAssessment(result.assessment, {
      principal: 'Test agent',
      action: request.action,
      resource: request.resource.id,
      environment: 'development',
    }),
    result.assessment,
  );
  const invalid = await authorize(
    { ...request, context: { unknown: true } },
    { dir, refresh: false, mode: 'ENFORCE' },
  );
  assert.equal(invalid.allowed, false);
  assert.deepEqual(invalid.assessment, {
    version: 1,
    status: 'unavailable',
    reason: 'not_evaluated',
  });
});

void test('audit upload batches by encoded bytes and retains unsent full payloads', async (t) => {
  const { dir } = await client(t);
  const input = payload();
  input.context.argv = ['x'.repeat(70000)];
  for (let i = 0; i < 3; i++) await spool(event('large-' + i, input), dir);
  const received: EventRecord[] = [];
  t.mock.method(
    globalThis,
    'fetch',
    async (_url: unknown, options: RequestInit) => {
      assert.ok(typeof options.body === 'string');
      assert.ok(
        new TextEncoder().encode(options.body).length <=
          MAX_AUDIT_BATCH_BYTES,
      );
      const body = JSON.parse(options.body);
      received.push(...body.events);
      return Response.json({ accepted: body.events.length });
    },
  );
  assert.equal(await flushAudit(dir), 2);
  assert.equal((await readdir(join(dir, 'spool'))).length, 1);
  assert.equal(await flushAudit(dir), 1);
  assert.equal(received.length, 3);
  assert.ok(received.every((e) => jsonBytes(e.assessment) > 70000));
  for (const record of received) {
    assert.equal(record.assessment?.status, 'captured');
    assert.deepEqual(
      record.assessment.payload.context.argv,
      input.context.argv,
    );
  }
});
