import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as cedar from '@cedar-policy/cedar-wasm/nodejs';
import { ControlPlane } from '../control-plane/service.ts';
import { SQLiteDatabase } from '../control-plane/sqlite.ts';
import type { ApiInput, Simulation } from '../core/api-types.ts';
import { verifyBundle } from '../core/crypto.ts';
async function setup() {
  const p = new ControlPlane(new SQLiteDatabase(':memory:', 'drizzle'), cedar);
  const mutation = async (input: ApiInput) =>
    p.mutation('alice', 'Alice', {
      revision: (await p.state('alice')).revision,
      ...input,
    });
  const policy = await mutation({
    kind: 'policy',
    publish: true,
    item: {
      name: 'Named principal',
      cedar:
        'permit(principal == Cleopatr::AgentSession::"My agent", action == Cleopatr::Action::"process.execute", resource);',
      environmentIds: ['organization'],
    },
  });
  return { p, mutation, id: policy.id };
}
const request = {
  environmentId: 'development',
  sessionId: 'sim-session',
  principal: 'My agent',
  action: 'process.execute',
  resource: { type: 'Process' as const, id: 'unregistered' },
  context: {},
};
async function simulate(p: ControlPlane, input: ApiInput, tenant = 'alice') {
  const response = await p.handle(
    new Request('https://cleo.example/api/v1/simulate', {
      method: 'POST',
      headers: {
        origin: 'https://cleo.example',
        'content-type': 'application/json',
      },
      body: JSON.stringify(input),
    }),
    { id: tenant, name: tenant },
  );
  const data = (await response.json()) as Simulation & { error?: string };
  return { response, data };
}
void test('Policy control evaluates just the selected policy using an exact client-name principal', async () => {
  const { p, id, mutation } = await setup();
  await mutation({
    kind: 'policy',
    publish: true,
    item: {
      name: 'Broad allow',
      cedar: 'permit(principal, action, resource);',
      environmentIds: ['organization'],
    },
  });
  const input: ApiInput = {
    controlType: 'POLICY',
    controlId: id,
    source: 'PUBLISHED',
    request,
  };
  const allowed = await simulate(p, input);
  assert.equal(allowed.response.status, 200);
  assert.equal(allowed.data.decision, 'ALLOW');
  assert.equal(allowed.data.policyCount, 1);
  assert.equal(allowed.data.parc.principal.id, 'My agent');
  assert.equal(allowed.data.mode, undefined);
  const denied = await simulate(p, {
    ...input,
    request: { ...request, principal: 'my agent' },
  });
  assert.equal(denied.data.decision, 'DENY');
  assert.equal(denied.data.policyCount, 1);
});
void test('Draft and Published controls preserve their own content; Environment uses published inherited rules', async () => {
  const { p, id, mutation } = await setup();
  const original = (await p.state('alice')).policies.find(
    (policy) => policy.id === id,
  )!;
  await mutation({
    kind: 'policy',
    item: {
      ...original,
      name: 'Draft edits',
      cedar: 'forbid(principal, action, resource);',
    },
  });
  const draft = await simulate(p, {
    controlType: 'POLICY',
    controlId: id,
    source: 'DRAFT',
    request,
  });
  assert.equal(draft.data.decision, 'DENY');
  assert.equal(draft.data.controlName, 'Draft edits');
  const live = await simulate(p, {
    controlType: 'POLICY',
    controlId: id,
    source: 'PUBLISHED',
    request,
  });
  assert.equal(live.data.decision, 'ALLOW');
  assert.equal(live.data.controlName, 'Named principal');
  await mutation({
    kind: 'environment',
    operation: 'mode',
    item: { id: 'development' },
    mode: 'ENFORCE',
  });
  const environment = await simulate(p, {
    controlType: 'ENVIRONMENT',
    controlId: 'development',
    source: 'DRAFT',
    request,
  });
  assert.equal(environment.data.source, 'PUBLISHED');
  assert.equal(environment.data.mode, 'ENFORCE');
  assert.equal(environment.data.effectiveResult, 'ALLOWED');
  assert.ok(environment.data.determiningPolicies.includes(id));
  const denied = await simulate(p, {
    controlType: 'ENVIRONMENT',
    controlId: 'development',
    request: { ...request, principal: 'Other agent' },
  });
  assert.equal(denied.data.effectiveResult, 'BLOCKED');
});
void test('isolated policy tests work without assignments and clearly identify catalog environment context', async () => {
  const { p, id, mutation } = await setup();
  await mutation({
    kind: 'environment',
    operation: 'policies',
    item: { id: 'organization' },
    policyIds: [],
  });
  const result = await simulate(p, {
    controlType: 'POLICY',
    controlId: id,
    source: 'PUBLISHED',
    request,
  });
  assert.equal(result.response.status, 200);
  assert.equal(result.data.decision, 'ALLOW');
  assert.ok(result.data.environmentName);
  const catalog = await simulate(p, {
    controlType: 'POLICY',
    controlId: id,
    source: 'PUBLISHED',
    request: {
      ...request,
      action: 'database.query',
      resource: { type: 'Database', id: 'customer-db' },
    },
  });
  assert.equal(catalog.data.environmentName, 'Customer platform');
  assert.equal(catalog.data.contextSource, 'resource');
});
void test('simulation rejects nonexistent controls, unavailable versions, and blank principals', async () => {
  const { p, id } = await setup();
  const input: ApiInput = {
    controlType: 'POLICY',
    controlId: id,
    source: 'PUBLISHED',
    request,
  };
  assert.equal(
    (await simulate(p, { ...input, source: 'DRAFT' })).response.status,
    400,
  );
  assert.equal(
    (await simulate(p, { ...input, request: { ...request, principal: ' ' } }))
      .response.status,
    400,
  );
  assert.equal(
    (await simulate(p, { ...input, controlId: 'missing' })).response.status,
    404,
  );
  assert.equal(
    (
      await simulate(p, {
        ...input,
        controlType: 'ENVIRONMENT',
        controlId: 'missing',
      })
    ).response.status,
    404,
  );
  assert.equal((await simulate(p, input, 'bob')).response.status, 404);
});
void test('bundle principal identity comes from authenticated enrollment and upgrade advances the sequence once', async () => {
  const { p } = await setup();
  const initial = await p.state('alice');
  const client = await p.enroll('alice', 'Alice', {
    name: 'My agent',
    environmentIds: ['development'],
  });
  assert.equal(client.clientName, 'My agent');
  await p.db
    .prepare('UPDATE workspaces SET model_version = 2 WHERE id = ?')
    .bind('alice')
    .run();
  const request = new Request('https://cleo.example/api/v1/bundles', {
    headers: { authorization: `Bearer ${client.token}` },
  });
  const response = await p.handle(request, null);
  assert.equal(response.status, 200);
  const bundle = await verifyBundle(
    (await response.json()) as Parameters<typeof verifyBundle>[0],
    initial.publicKey,
    'alice',
  );
  assert.deepEqual(bundle.client, { id: client.clientId, name: 'My agent' });
  // Inheritance semantics require a client that cannot downgrade ancestor enforcement.
  assert.equal(bundle.minimumClientVersion, '0.4.2');
  assert.equal(bundle.sequence, initial.sequence + 1);
  assert.equal((await p.state('alice')).sequence, initial.sequence + 1);
});
