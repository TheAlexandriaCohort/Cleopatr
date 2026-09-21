import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import * as cedar from '@cedar-policy/cedar-wasm/nodejs';
import {
  effectivePolicies,
  publishedSnapshot,
  SCHEMA,
  type Snapshot,
  type Policy,
  type Bundle,
  type ActionRequest,
} from '../core/model.ts';
import { evaluateWithModes } from '../core/engine.ts';
import { ControlPlane } from '../control-plane/service.ts';
import { SQLiteDatabase } from '../control-plane/sqlite.ts';
import type { ApiInput } from '../core/api-types.ts';
import { makeKeys, signBundle, verifyBundle } from '../core/crypto.ts';
import { activate, atomicJson } from '../cli/cache.ts';
import { compileProfile, rights } from '../runtime/profile.ts';

function policy(id: string, code: string, environmentIds = ['root']): Policy {
  return {
    id,
    name: id,
    description: '',
    cedar: code,
    environmentIds,
    enabled: true,
    revision: 1,
    updatedAt: '2026-09-01T00:00:00.000Z',
    status: 'PUBLISHED',
  };
}
function snapshot(): Snapshot {
  return {
    environments: [
      {
        id: 'root',
        name: 'Root',
        description: '',
        kind: 'group',
        parentId: null,
        mode: 'CUSTOM',
        policyModes: { permit: 'ENFORCE', deny: 'ENFORCE' },
      },
      {
        id: 'child',
        name: 'Child',
        description: '',
        kind: 'environment',
        parentId: 'root',
        mode: 'CUSTOM',
        policyModes: { permit: 'AUDIT', deny: 'AUDIT' },
        excludedPolicyIds: ['deny'],
      },
      {
        id: 'leaf',
        name: 'Leaf',
        description: '',
        kind: 'environment',
        parentId: 'child',
        mode: 'AUDIT',
        excludedPolicyIds: ['permit', 'deny', 'audit'],
      },
    ],
    policies: [
      policy('permit', 'permit(principal, action, resource);'),
      // A duplicate assignment must not reset inherited source/mode.
      policy(
        'deny',
        'forbid(principal, action == Cleopatr::Action::"process.execute", resource);',
        ['root', 'leaf'],
      ),
      policy(
        'audit',
        'forbid(principal, action == Cleopatr::Action::"file.delete", resource);',
      ),
      policy(
        'local',
        'permit(principal, action == Cleopatr::Action::"file.read", resource);',
        ['child'],
      ),
    ],
    resources: [
      {
        id: 'node',
        name: 'Node',
        type: 'Process',
        environmentId: 'root',
        locator: '/usr/local/bin/node',
        description: '',
      },
      {
        id: 'workspace',
        name: 'Workspace',
        type: 'File',
        environmentId: 'root',
        locator: '/workspace',
        description: '',
      },
    ],
  };
}
const request: ActionRequest = {
  environmentId: 'leaf',
  sessionId: 'test',
  principal: 'client',
  action: 'process.execute',
  resource: { type: 'Process', id: 'node' },
  context: {},
};
async function setup(t: import('node:test').TestContext) {
  const db = new SQLiteDatabase(':memory:', 'migrations');
  t.after(() => db.close());
  const p = new ControlPlane(db, cedar);
  await p.state('alice');
  await db
    .prepare('UPDATE workspaces SET snapshot = ? WHERE id = ?')
    .bind(JSON.stringify(snapshot()), 'alice')
    .run();
  return p;
}
async function mutate(p: ControlPlane, input: ApiInput) {
  return p.mutation('alice', 'Alice', {
    revision: (await p.state('alice')).revision,
    ...input,
  });
}

void test('ancestor enforcement survives every descendant mode, stale exclusions and duplicate assignments', () => {
  const s = snapshot();
  for (const childMode of ['AUDIT', 'CUSTOM', 'ENFORCE'] as const) {
    for (const leafMode of ['AUDIT', 'CUSTOM', 'ENFORCE'] as const) {
      s.environments[1].mode = childMode;
      s.environments[2].mode = leafMode;
      s.environments[2].policyModes = { permit: 'AUDIT', deny: 'AUDIT' };
      const effective = effectivePolicies(s, 'leaf');
      assert.equal(effective.length, 4);
      assert.equal(
        effective.find((p) => p.id === 'deny')!.sourceEnvironmentId,
        'root',
      );
      assert.equal(effective.find((p) => p.id === 'deny')!.mode, 'ENFORCE');
      assert.equal(evaluateWithModes(cedar, s, request).allowed, false);
    }
  }
  // Ancestor modes only govern policies already present at that ancestor.
  s.environments[1].mode = 'AUDIT';
  s.environments[2].mode = 'AUDIT';
  assert.equal(
    effectivePolicies(s, 'child').find((p) => p.id === 'local')!.mode,
    'AUDIT',
  );
});

void test('API rejects inherited deselection and per-policy Audit without mutating state; bulk Audit preserves enforcement', async (t) => {
  const p = await setup(t);
  const before = await p.state('alice');
  for (const input of [
    { operation: 'policies', policyIds: ['permit', 'audit', 'local'] },
    { operation: 'policies', policyIds: ['permit', 'deny', 'local'] }, // Audit inheritance is mandatory too.
    { operation: 'policy-mode', policyId: 'deny', mode: 'AUDIT' },
  ]) {
    const response = await p.handle(
      new Request('https://cleo.example/api/v1/mutate', {
        method: 'POST',
        headers: {
          origin: 'https://cleo.example',
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          revision: before.revision,
          kind: 'environment',
          item: { id: 'child' },
          ...input,
        }),
      }),
      { id: 'alice', name: 'Alice' },
    );
    assert.equal(response.status, 400);
    assert.match(
      ((await response.json()) as { error: string }).error,
      /Inherited/,
    );
    assert.equal((await p.state('alice')).revision, before.revision);
  }
  await mutate(p, {
    kind: 'environment',
    operation: 'mode',
    item: { id: 'child' },
    mode: 'AUDIT',
  });
  const signed = await p.bundle('alice', ['leaf'], {
    id: 'test-client',
    name: 'Test client',
  });
  const bundle = await verifyBundle(signed, before.publicKey, 'alice');
  assert.equal(bundle.minimumClientVersion, '0.6.1');
  assert.equal(evaluateWithModes(cedar, bundle, request).allowed, false);
  const simulation = await p.handle(
    new Request('https://cleo.example/api/v1/simulate', {
      method: 'POST',
      headers: {
        origin: 'https://cleo.example',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        controlType: 'ENVIRONMENT',
        controlId: 'leaf',
        request,
      }),
    }),
    { id: 'alice', name: 'Alice' },
  );
  assert.equal(simulation.status, 200);
  assert.equal(
    ((await simulation.json()) as { allowed: boolean }).allowed,
    false,
  );
});

void test('inherited Audit can be strengthened; descendants keep that Enforce while direct assignments remain editable', async (t) => {
  const p = await setup(t);
  await mutate(p, {
    kind: 'environment',
    operation: 'policy-mode',
    item: { id: 'child' },
    policyId: 'audit',
    mode: 'ENFORCE',
  });
  assert.equal(
    effectivePolicies(await p.state('alice'), 'leaf').find(
      (p) => p.id === 'audit',
    )!.mode,
    'ENFORCE',
  );
  await mutate(p, {
    kind: 'environment',
    operation: 'mode',
    item: { id: 'leaf' },
    mode: 'CUSTOM',
  });
  await assert.rejects(
    () =>
      mutate(p, {
        kind: 'environment',
        operation: 'policy-mode',
        item: { id: 'leaf' },
        policyId: 'audit',
        mode: 'AUDIT',
      }),
    /Inherited Enforce/,
  );
  await mutate(p, {
    kind: 'environment',
    operation: 'policy-mode',
    item: { id: 'child' },
    policyId: 'audit',
    mode: 'AUDIT',
  });
  await mutate(p, {
    kind: 'environment',
    operation: 'policies',
    item: { id: 'child' },
    policyIds: ['permit', 'deny', 'audit'],
  });
  assert.ok(
    !effectivePolicies(await p.state('alice'), 'leaf').some(
      (p) => p.id === 'local',
    ),
  );
  // A parent may remove its own assignment; no child exclusion is needed.
  await mutate(p, {
    kind: 'environment',
    operation: 'policies',
    item: { id: 'root' },
    policyIds: ['permit', 'deny'],
  });
  assert.ok(
    !effectivePolicies(await p.state('alice'), 'leaf').some(
      (p) => p.id === 'audit',
    ),
  );
});

void test('inheritance upgrade clears legacy exclusions once without recreating deleted defaults', async (t) => {
  const p = await setup(t);
  await p.db
    .prepare('UPDATE workspaces SET model_version = 4 WHERE id = ?')
    .bind('alice')
    .run();
  const upgraded = await p.state('alice');
  assert.equal(upgraded.sequence, 2);
  assert.equal(upgraded.policies.length, 4);
  assert.ok(
    upgraded.environments.every(
      (environment) => environment.excludedPolicyIds === undefined,
    ),
  );
  assert.equal(
    evaluateWithModes(cedar, publishedSnapshot(upgraded), request).allowed,
    false,
  );
  assert.equal((await p.state('alice')).sequence, upgraded.sequence);
});

void test('offline CLI and kernel compiler enforce ancestry even for previously cached weak child settings', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'cleo-inheritance-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const keys = await makeKeys();
  await atomicJson(join(dir, 'config'), {
    server: 'http://127.0.0.1:1',
    token: 'test-only',
    tenant: 'alice',
    publicKey: keys.publicKey,
    environmentIds: ['leaf'],
    clientId: 'test-client',
    clientName: 'client',
  });
  const bundle: Bundle = {
    ...snapshot(),
    schema: SCHEMA,
    schemaVersion: '3.0',
    minimumClientVersion: '0.4.1',
    tenant: 'alice',
    sequence: 1,
    bundleId: 'cached-1',
    createdAt: new Date().toISOString(),
    environmentIds: ['leaf'],
    client: { id: 'test-client', name: 'client' },
  };
  await activate(await signBundle(bundle, keys.privateKey), dir);
  const file = join(dir, 'request.json');
  await writeFile(file, JSON.stringify(request));
  const packaged = process.env.CLEO_TEST_CLI;
  const command = packaged
    ? [packaged]
    : ['--import', 'tsx', resolve('cli/main.ts')];
  const result = spawnSync(
    process.execPath,
    [...command, 'authorize', '--request', file],
    {
      env: { ...process.env, CLEO_HOME: dir },
      encoding: 'utf8',
    },
  );
  assert.equal(result.status, 2, result.stderr);
  const decision = JSON.parse(result.stdout);
  assert.equal(decision.allowed, false);
  assert.equal(
    decision.policyDecisions.find(
      (policy: { policyId: string }) => policy.policyId === 'deny',
    ).mode,
    'ENFORCE',
  );
  const profile = compileProfile(bundle, 'leaf', 'client', false);
  assert.ok(profile.grants.every((grant) => !(grant.access & rights.execute)));
  const audit = spawnSync(
    process.execPath,
    [...command, 'authorize', '--audit', '--request', file],
    {
      env: { ...process.env, CLEO_HOME: dir },
      encoding: 'utf8',
    },
  );
  assert.equal(audit.status, 0, audit.stderr);
  const audited = JSON.parse(audit.stdout);
  assert.equal(audited.decision, 'DENY');
  assert.equal(audited.effectiveResult, 'ALLOWED_AUDIT');
  assert.ok(
    audited.policyDecisions.every(
      (policy: { mode: string }) => policy.mode === 'AUDIT',
    ),
  );
});
