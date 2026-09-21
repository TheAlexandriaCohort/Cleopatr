import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as cedar from '@cedar-policy/cedar-wasm/nodejs';
import { ControlPlane } from '../control-plane/service.ts';
import { SQLiteDatabase } from '../control-plane/sqlite.ts';
import { verifyBundle } from '../core/crypto.ts';
import {
  assignmentSnapshot,
  effectivePolicies,
  summarizePolicyModes,
  type EnvironmentMode,
} from '../core/model.ts';
import type { ApiInput } from '../core/api-types.ts';

const ids = [
  'pol_default_file_read',
  'pol_default_file_write',
  'pol_default_file_delete',
];
async function setup(t: import('node:test').TestContext) {
  const db = new SQLiteDatabase(':memory:', 'migrations');
  t.after(() => db.close());
  const p = new ControlPlane(db, cedar);
  const mutate = async (input: ApiInput) =>
    p.mutation('alice', 'Alice', {
      revision: (await p.state('alice')).revision,
      ...input,
    });
  const { id } = await mutate({
    kind: 'environment',
    item: { name: 'Mode test', parentId: null },
  });
  await mutate({
    kind: 'environment',
    operation: 'policies',
    item: { id },
    policyIds: ids,
  });
  const mode = (value: EnvironmentMode, environment = id) =>
    mutate({
      kind: 'environment',
      operation: 'mode',
      item: { id: environment },
      mode: value,
    });
  const row = (policyId: string, value: EnvironmentMode, environment = id) =>
    mutate({
      kind: 'environment',
      operation: 'policy-mode',
      item: { id: environment },
      policyId,
      mode: value,
    });
  async function check(expected: EnvironmentMode, values: string[]) {
    const state = await p.state('alice');
    const environment = state.environments.find((env) => env.id === id)!;
    const effective = effectivePolicies(assignmentSnapshot(state), id);
    assert.equal(environment.mode, expected);
    assert.equal(summarizePolicyModes(effective, environment.mode), expected);
    assert.deepEqual(
      ids.map((id) => effective.find((policy) => policy.id === id)!.mode),
      values,
    );
    // The signed policies consumed by existing CLI 0.4.2 have the same modes.
    const bundle = await verifyBundle(
      await p.bundle('alice', [id], { id: 'test-client', name: 'Test client' }),
      state.publicKey,
      'alice',
    );
    const live = effectivePolicies(bundle, id);
    assert.deepEqual(
      ids.map((id) => live.find((policy) => policy.id === id)!.mode),
      values,
    );
  }
  return { p, id, mutate, mode, row, check };
}

void test('row edits from either bulk mode preserve other policies and automatically select Audit, Custom or Enforce', async (t) => {
  const { row, check } = await setup(t);
  await check('AUDIT', ['AUDIT', 'AUDIT', 'AUDIT']);
  await row(ids[1], 'ENFORCE');
  await check('CUSTOM', ['AUDIT', 'ENFORCE', 'AUDIT']);
  await row(ids[0], 'ENFORCE');
  await check('CUSTOM', ['ENFORCE', 'ENFORCE', 'AUDIT']);
  await row(ids[2], 'ENFORCE');
  await check('ENFORCE', ['ENFORCE', 'ENFORCE', 'ENFORCE']);
  await row(ids[0], 'AUDIT');
  await check('CUSTOM', ['AUDIT', 'ENFORCE', 'ENFORCE']);
  await row(ids[1], 'AUDIT');
  await row(ids[2], 'AUDIT');
  await check('AUDIT', ['AUDIT', 'AUDIT', 'AUDIT']);
});

void test('bulk choices replace the entire editable mode set and old Custom overrides never reappear', async (t) => {
  const { row, mode, check, p, id } = await setup(t);
  await row(ids[0], 'ENFORCE');
  await mode('ENFORCE');
  await check('ENFORCE', ['ENFORCE', 'ENFORCE', 'ENFORCE']);
  await row(ids[2], 'AUDIT');
  await check('CUSTOM', ['ENFORCE', 'ENFORCE', 'AUDIT']);
  await mode('AUDIT');
  await check('AUDIT', ['AUDIT', 'AUDIT', 'AUDIT']);
  await row(ids[2], 'ENFORCE');
  await check('CUSTOM', ['AUDIT', 'AUDIT', 'ENFORCE']);
  await mode('ENFORCE');
  // Older API callers may still explicitly enter Custom; this must preserve rows.
  await mode('CUSTOM');
  const effective = effectivePolicies(await p.state('alice'), id);
  assert.ok(effective.every((policy) => policy.mode === 'ENFORCE'));
  assert.equal(summarizePolicyModes(effective), 'ENFORCE');
});

void test('editable child rows auto-switch the aggregate while inherited Enforce locks survive row and bulk changes', async (t) => {
  const { p, id, mutate, row, mode } = await setup(t);
  await mode('ENFORCE');
  const { id: child } = await mutate({
    kind: 'environment',
    item: { name: 'Child', parentId: id },
  });
  const local = 'pol_default_http_request';
  await mutate({
    kind: 'environment',
    operation: 'policies',
    item: { id: child },
    policyIds: [...ids, local],
  });
  const effective = async () =>
    effectivePolicies(assignmentSnapshot(await p.state('alice')), child);
  assert.equal(summarizePolicyModes(await effective()), 'CUSTOM');
  await row(local, 'ENFORCE', child);
  assert.equal(summarizePolicyModes(await effective()), 'ENFORCE');
  await row(local, 'AUDIT', child);
  assert.equal(summarizePolicyModes(await effective()), 'CUSTOM');
  await assert.rejects(() => row(ids[0], 'AUDIT', child), /Inherited Enforce/);
  await mode('AUDIT', child);
  assert.equal(summarizePolicyModes(await effective()), 'CUSTOM');
  assert.ok(
    (await effective())
      .filter((policy) => ids.includes(policy.id))
      .every((policy) => policy.mode === 'ENFORCE'),
  );
  assert.equal(
    (await effective()).find((policy) => policy.id === local)!.mode,
    'AUDIT',
  );
});

void test('aggregate display follows parent mode and policy membership changes without overriding child settings', async (t) => {
  const { p, id, mutate, row, mode } = await setup(t);
  const { id: child } = await mutate({
    kind: 'environment',
    item: { name: 'Child', parentId: id },
  });
  const summary = async () =>
    summarizePolicyModes(
      effectivePolicies(assignmentSnapshot(await p.state('alice')), child),
    );
  assert.equal(await summary(), 'AUDIT');
  await row(ids[0], 'ENFORCE');
  assert.equal(await summary(), 'CUSTOM');
  await mode('ENFORCE');
  assert.equal(await summary(), 'ENFORCE');
  await mode('AUDIT');
  assert.equal(await summary(), 'AUDIT');
  await row(ids[0], 'ENFORCE');
  await mutate({
    kind: 'environment',
    operation: 'policies',
    item: { id },
    policyIds: [ids[0]],
  });
  assert.equal(await summary(), 'ENFORCE');
});

void test('empty environments retain their bulk mode and invalid row edits leave state unchanged', async (t) => {
  const { p, id, mutate, row, mode } = await setup(t);
  await mutate({
    kind: 'environment',
    operation: 'policies',
    item: { id },
    policyIds: [],
  });
  await mode('ENFORCE');
  const before = await p.state('alice');
  assert.equal(
    summarizePolicyModes(
      [],
      before.environments.find((env) => env.id === id)!.mode,
    ),
    'ENFORCE',
  );
  await assert.rejects(() => row('missing', 'AUDIT'), /not effective/);
  assert.equal((await p.state('alice')).revision, before.revision);
  await mutate({
    kind: 'environment',
    operation: 'policies',
    item: { id },
    policyIds: ids,
  });
  await assert.rejects(() => row(ids[0], 'CUSTOM'), /Audit or Enforce/);
});
