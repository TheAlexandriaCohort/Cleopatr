import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { spawn } from 'node:child_process';
import {
  mkdtemp,
  mkdir,
  readdir,
  readFile,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import * as cedar from '@cedar-policy/cedar-wasm/nodejs';
import { atomicJson, activate } from '../cli/cache.ts';
import {
  auditStatus,
  flushAudit,
  spool,
  startAuditUploader,
} from '../cli/audit.ts';
import { importVmEvents } from '../cli/vm-events.ts';
import { SQLiteDatabase } from '../control-plane/sqlite.ts';
import { ControlPlane } from '../control-plane/service.ts';
import { queryActivity } from '../control-plane/activity.ts';
import type { EventRecord } from '../core/api-types.ts';

const event = (id: string): EventRecord => ({
  id,
  kind: 'decision',
  time: new Date().toISOString(),
  environmentId: 'development',
  action: 'file.read',
  resource: 'project-workspace',
  decision: 'ALLOW',
  policyId: 'pol_workspace_read',
  policyName: 'Allow workspace reads',
  effectiveResult: 'ALLOWED',
  mode: 'AUDIT',
});
async function fixture(t: import('node:test').TestContext) {
  const dir = await mkdtemp(join(tmpdir(), 'cleo-delivery-'));
  const control = new ControlPlane(
    new SQLiteDatabase(':memory:', 'drizzle'),
    cedar,
  );
  const enrollment = await control.enroll('alice', 'Alice', {
    name: 'Delivery client',
    environmentIds: ['development'],
  });
  let available = true;
  let receiptMatches = true;
  let calls = 0;
  const server = http.createServer(async (request, response) => {
    calls++;
    if (!available) {
      response.writeHead(503).end();
      return;
    }
    let text = '';
    for await (const chunk of request) text += chunk;
    const input = JSON.parse(text);
    const result = await control.ingest('alice', enrollment.clientId, input);
    response.setHeader('Content-Type', 'application/json');
    response.end(JSON.stringify(receiptMatches ? result : { accepted: 0 }));
  });
  await new Promise<void>((done) => server.listen(0, '127.0.0.1', done));
  await atomicJson(join(dir, 'config'), {
    ...enrollment,
    server: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
  });
  t.after(async () => {
    server.closeAllConnections();
    await new Promise<void>((done) => server.close(() => done()));
    await rm(dir, { recursive: true, force: true });
  });
  return {
    dir,
    control,
    enrollment,
    get calls() {
      return calls;
    },
    set available(value: boolean) {
      available = value;
    },
    set receiptMatches(value: boolean) {
      receiptMatches = value;
    },
  };
}

void test('automatic upload retains offline events, reports the error, retries, and reaches both activity views', async (t) => {
  const f = await fixture(t);
  await spool(event('offline-event'), f.dir);
  f.available = false;
  await assert.rejects(flushAudit(f.dir), /503/);
  assert.equal((await auditStatus(f.dir)).pending, 1);
  assert.match((await auditStatus(f.dir)).lastError!, /503/);
  f.available = true;
  const uploader = startAuditUploader(f.dir, 20);
  try {
    for (let i = 0; i < 100 && (await auditStatus(f.dir)).pending; i++)
      await new Promise((done) => setTimeout(done, 20));
    assert.equal((await auditStatus(f.dir)).pending, 0);
    assert.equal((await auditStatus(f.dir)).lastError, null);
    const activity = await queryActivity(
      f.control.db,
      'alice',
      new URLSearchParams({ type: 'decision' }),
    );
    const environment = await f.control.environmentActivity(
      'alice',
      'development',
    );
    assert.equal(activity.events[0].id, 'offline-event');
    assert.equal(environment[0].id, 'offline-event');
    assert.equal(activity.events[0].clientName, 'Delivery client');
  } finally {
    await uploader.stop();
  }
});

void test('concurrent uploads coalesce and a multi-batch drain stores every event once', async (t) => {
  const f = await fixture(t);
  for (let i = 0; i < 205; i++) await spool(event('batch-' + i), f.dir);
  const [first, second] = await Promise.all([
    flushAudit(f.dir, { maxBatches: 20 }),
    flushAudit(f.dir, { maxBatches: 20 }),
  ]);
  assert.equal(first, 205);
  assert.equal(second, 205);
  assert.equal(f.calls, 3);
  assert.equal((await auditStatus(f.dir)).pending, 0);
  const activity = await queryActivity(
    f.control.db,
    'alice',
    new URLSearchParams({ type: 'decision' }),
  );
  assert.equal(activity.total, 205);
});

void test('an incomplete server receipt retains records for an idempotent retry', async (t) => {
  const f = await fixture(t);
  await spool(event('receipt'), f.dir);
  f.receiptMatches = false;
  await assert.rejects(flushAudit(f.dir), /acknowledge every event/);
  assert.equal((await auditStatus(f.dir)).pending, 1);
  f.receiptMatches = true;
  assert.equal(await flushAudit(f.dir), 1);
  const activity = await queryActivity(
    f.control.db,
    'alice',
    new URLSearchParams({ type: 'decision' }),
  );
  assert.equal(activity.total, 1);
});

void test('final VM import drains more than one batch and preserves guest records when host persistence fails', async (t) => {
  const f = await fixture(t);
  const shared = join(f.dir, 'vm');
  await mkdir(join(shared, 'events'), { recursive: true });
  for (let i = 0; i < 205; i++)
    await writeFile(
      join(shared, 'events', i + '.json'),
      JSON.stringify(event('vm-' + i)),
    );
  assert.equal(await importVmEvents(shared, f.dir), 100);
  assert.equal(
    await importVmEvents(shared, f.dir, Number.MAX_SAFE_INTEGER),
    105,
  );
  assert.equal((await readdir(join(shared, 'events'))).length, 0);
  assert.equal((await auditStatus(f.dir)).pending, 205);
  const source = join(shared, 'events', 'retained.json');
  await writeFile(source, JSON.stringify(event('retained')));
  const badDestination = join(f.dir, 'not-a-directory');
  await writeFile(badDestination, 'occupied');
  await assert.rejects(importVmEvents(shared, badDestination));
  assert.equal(JSON.parse(await readFile(source, 'utf8')).id, 'retained');
});

void test('a short CLI launch uploads its assessed decision even when policy refresh is not due', async (t) => {
  const f = await fixture(t);
  const state = await f.control.state('alice');
  await f.control.mutation('alice', 'Alice', {
    revision: state.revision,
    kind: 'policy',
    publish: true,
    item: {
      name: 'Permit test launch',
      description: '',
      cedar:
        'permit(principal, action == Cleopatr::Action::"process.execute", resource);',
      environmentIds: ['development'],
      enabled: true,
    },
  });
  await activate(
    await f.control.bundle('alice', ['development'], {
      id: f.enrollment.clientId,
      name: f.enrollment.clientName,
    }),
    f.dir,
    Date.now(),
  );
  const child = spawn(
    process.execPath,
    [
      '--import',
      'tsx',
      resolve('cli/main.ts'),
      '--backend=cooperative',
      '--enforce',
      '--',
      process.execPath,
      '-e',
      '',
    ],
    {
      env: { ...process.env, CLEO_HOME: f.dir },
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );
  let errors = '';
  child.stderr.on('data', (chunk) => {
    errors += chunk;
  });
  const status = await new Promise((resolve) => child.once('close', resolve));
  assert.equal(status, 0, errors);
  assert.equal((await auditStatus(f.dir)).pending, 0);
  const activity = await queryActivity(
    f.control.db,
    'alice',
    new URLSearchParams({ type: 'decision' }),
  );
  assert.equal(activity.events[0].policyName, 'Permit test launch');
  assert.equal(activity.events[0].assessment?.status, 'captured');
});
