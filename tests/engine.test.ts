import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as cedar from '@cedar-policy/cedar-wasm/nodejs';
import {
  createSeed,
  ancestors,
  policiesFor,
  generateCedar,
  type ActionRequest,
} from '../core/model.ts';
import {
  evaluate,
  evaluateWithModes,
  validatePolicies,
} from '../core/engine.ts';
const request = (context: Record<string, unknown> = {}): ActionRequest => ({
  environmentId: 'customer-platform',
  sessionId: 'test',
  action: 'database.query',
  resource: { type: 'Database', id: 'customer-db' },
  context,
});
void test('starter policies validate against the shared Cedar schema', () => {
  const result = validatePolicies(cedar, createSeed().policies);
  assert.equal(result.valid, true, JSON.stringify(result));
});
void test('descendants inherit policies while siblings do not', () => {
  const seed = createSeed();
  assert.deepEqual(ancestors(seed.environments, 'customer-platform'), [
    'customer-platform',
    'production',
    'organization',
  ]);
  assert.equal(policiesFor(seed, 'development').length, 2);
  assert.equal(policiesFor(seed, 'customer-platform').length, 3);
});
void test('cycles and missing parents are rejected', () => {
  const seed = createSeed();
  seed.environments[0].parentId = 'customer-platform';
  assert.throws(() => ancestors(seed.environments, 'production'), /cycle/);
  assert.throws(() => ancestors(seed.environments, 'missing'), /Unknown/);
});
void test('Cedar forbid overrides an applicable broad permit', () => {
  const s = createSeed();
  s.policies.push({
    ...s.policies[0],
    id: 'permit_all',
    cedar: 'permit(principal, action, resource);',
  });
  const r = evaluate(cedar, s, request({ operation: 'DELETE' }));
  assert.equal(r.decision, 'DENY');
  assert.deepEqual(r.determiningPolicies, ['pol_protect_production']);
  assert.equal(
    evaluate(cedar, s, request({ operation: 'SELECT' })).decision,
    'ALLOW',
  );
});
void test('missing semantics trigger conservative forbid without evaluation errors', () => {
  const s = createSeed();
  s.policies.push({
    ...s.policies[0],
    id: 'permit_all',
    cedar: 'permit(principal, action, resource);',
  });
  const r = evaluate(cedar, s, request());
  assert.equal(r.decision, 'DENY');
  assert.equal(r.errors.length, 0);
  assert.ok(r.determiningPolicies.includes('pol_protect_production'));
});
void test('no matching permit means default deny', () =>
  assert.equal(
    evaluate(cedar, createSeed(), request({ operation: 'SELECT' })).decision,
    'DENY',
  ));
void test('context types, resource types, and unknown fields are rejected', () => {
  assert.throws(
    () => evaluate(cedar, createSeed(), request({ operation: 4 })),
    /Invalid/,
  );
  assert.throws(
    () => evaluate(cedar, createSeed(), request({ secret: 'x' })),
    /Unsupported/,
  );
  assert.throws(
    () =>
      evaluate(cedar, createSeed(), {
        ...request(),
        resource: { type: 'File', id: 'customer-db' },
      }),
    /do not match/,
  );
});
void test('builder escapes untrusted literals without widening permission', () => {
  const cedarText = generateCedar(
    {
      effect: 'permit',
      action: 'http.request',
      resourceId: '',
      field: 'host',
      operator: 'equals',
      value: 'evil"}; permit(principal,action,resource); //',
    },
    [],
  );
  assert.equal(
    validatePolicies(cedar, [{ id: 'test', cedar: cedarText }]).valid,
    true,
  );
});
void test('invalid Cedar and nonexistent schema attributes are rejected', () => {
  assert.equal(
    validatePolicies(cedar, [{ id: 'x', cedar: 'allow everyone' }]).valid,
    false,
  );
  assert.equal(
    validatePolicies(cedar, [
      {
        id: 'x',
        cedar:
          'permit(principal, action, resource) when {context.nonexistent};',
      },
    ]).valid,
    false,
  );
});
void test('Custom separates audit forbids from enforced permits, and --enforce strengthens both', () => {
  const s = createSeed();
  s.policies = [
    {
      ...s.policies[0],
      id: 'permit',
      cedar: 'permit(principal, action, resource);',
    },
    {
      ...s.policies[0],
      id: 'forbid',
      cedar: 'forbid(principal, action, resource);',
    },
  ];
  const env = s.environments.find((e) => e.id === 'customer-platform')!;
  env.mode = 'CUSTOM';
  env.policyModes = { permit: 'ENFORCE', forbid: 'AUDIT' };
  let result = evaluateWithModes(cedar, s, request());
  assert.equal(result.decision, 'DENY');
  assert.equal(result.enforcementDecision, 'ALLOW');
  assert.equal(result.allowed, true);
  assert.equal(result.effectiveResult, 'ALLOWED_AUDIT');
  assert.deepEqual(
    result.policyDecisions.map((p) => [p.policyId, p.mode, p.decision]),
    [
      ['permit', 'ENFORCE', 'ALLOW'],
      ['forbid', 'AUDIT', 'DENY'],
    ],
  );
  result = evaluateWithModes(cedar, s, request(), true);
  assert.equal(result.allowed, false);
  env.policyModes = { permit: 'AUDIT', forbid: 'ENFORCE' };
  assert.equal(evaluateWithModes(cedar, s, request()).allowed, false);
  const saved = JSON.stringify(s);
  const audit = evaluateWithModes(cedar, s, request(), false, true);
  assert.equal(audit.allowed, true);
  assert.equal(audit.decision, 'DENY');
  assert.equal(audit.effectiveResult, 'ALLOWED_AUDIT');
  assert.ok(audit.policyDecisions.every((p) => p.mode === 'AUDIT'));
  assert.equal(audit.enforcementDecision, undefined);
  assert.equal(JSON.stringify(s), saved);
  assert.throws(
    () => evaluateWithModes(cedar, s, request(), true, true),
    /Conflicting/,
  );
  // An audit permit cannot authorize an enforced subset with no matching permit.
  s.policies[1].cedar = 'forbid(principal, action, resource) when { false };';
  result = evaluateWithModes(cedar, s, request());
  assert.equal(result.decision, 'ALLOW');
  assert.equal(result.allowed, false);
  assert.ok(
    result.policyDecisions.some((p) => p.policyName.startsWith('Default deny')),
  );
});
void test('global environment modes override custom settings; empty Enforce defaults to deny', () => {
  const s = createSeed();
  const env = s.environments.find((e) => e.id === 'customer-platform')!;
  env.mode = 'AUDIT';
  env.policyModes = { pol_protect_production: 'ENFORCE' };
  assert.equal(evaluateWithModes(cedar, s, request()).allowed, true);
  env.mode = 'ENFORCE';
  assert.equal(evaluateWithModes(cedar, s, request()).allowed, false);
  s.policies = [];
  assert.equal(evaluateWithModes(cedar, s, request()).allowed, false);
  env.mode = 'CUSTOM';
  assert.equal(evaluateWithModes(cedar, s, request()).allowed, true);
});
