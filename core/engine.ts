import type * as Cedar from '@cedar-policy/cedar-wasm/nodejs';
import { captureAssessment, type AssessedPayload } from './assessment.ts';
import {
  ACTIONS,
  CONTEXT_FIELDS,
  SCHEMA,
  policiesFor,
  effectivePolicies,
  type Mode,
  type Snapshot,
  type ActionRequest,
} from './model.ts';
export type CedarEngine = Pick<
  typeof Cedar,
  | 'validate'
  | 'isAuthorized'
  | 'getCedarVersion'
  | 'formatPolicies'
  | 'checkParsePolicySet'
>;
export function validatePolicies(
  engine: CedarEngine,
  policies: { id: string; cedar: string }[],
) {
  const answer = engine.validate({
    schema: SCHEMA as Cedar.Schema,
    policies: {
      staticPolicies: Object.fromEntries(policies.map((p) => [p.id, p.cedar])),
    },
  });
  return answer.type === 'failure'
    ? {
        valid: false,
        errors: answer.errors.map((e) => e.message),
        warnings: answer.warnings.map((e) => e.message),
      }
    : {
        valid: !answer.validationErrors.length,
        errors: answer.validationErrors.map(
          (e) => `${e.policyId}: ${e.error.message}`,
        ),
        warnings: answer.validationWarnings.map(
          (e) => `${e.policyId}: ${e.error.message}`,
        ),
      };
}

export function evaluateWithModes(
  engine: CedarEngine,
  snapshot: Snapshot,
  request: ActionRequest,
  forceEnforce = false,
  forceAudit = false,
) {
  if (forceEnforce && forceAudit)
    throw new Error('Conflicting execution modes');
  const start = performance.now();
  const policies = effectivePolicies(snapshot, request.environmentId);
  const environment = snapshot.environments.find(
    (e) => e.id === request.environmentId,
  )!;
  const mode = forceAudit
    ? ('AUDIT' as const)
    : forceEnforce
      ? ('ENFORCE' as const)
      : (environment.mode ?? 'AUDIT');
  const full = evaluate(engine, snapshot, request);
  const enforced = forceAudit
    ? []
    : policies.filter((p) => forceEnforce || p.mode === 'ENFORCE');
  const mustEnforce =
    !forceAudit && (forceEnforce || mode === 'ENFORCE' || enforced.length > 0);
  const blocking = mustEnforce
    ? evaluate(engine, { ...snapshot, policies: enforced }, request)
    : undefined;
  const effectiveResult = blocking?.errors.length
    ? 'ERROR'
    : blocking?.decision === 'DENY'
      ? 'BLOCKED'
      : full.decision === 'DENY'
        ? 'ALLOWED_AUDIT'
        : 'ALLOWED';
  const policyDecisions: {
    policyId: string;
    policyName: string;
    policyVersion: number;
    decision: 'ALLOW' | 'DENY' | 'ERROR';
    mode: Mode;
  }[] = [];
  for (const policy of policies) {
    const single = evaluate(
      engine,
      { ...snapshot, policies: [policy] },
      request,
    );
    if (single.determiningPolicies.includes(policy.id) || single.errors.length)
      policyDecisions.push({
        policyId: policy.id,
        policyName: policy.name,
        policyVersion: policy.published?.version ?? policy.revision,
        decision: single.errors.length ? 'ERROR' : single.decision,
        mode: forceAudit ? 'AUDIT' : forceEnforce ? 'ENFORCE' : policy.mode,
      });
  }
  if (
    !policyDecisions.length ||
    (blocking?.decision === 'DENY' && !blocking.determiningPolicies.length)
  )
    policyDecisions.push({
      policyId: '',
      policyName: 'Default deny (no permit matched)',
      policyVersion: 0,
      decision: 'DENY',
      mode: mustEnforce ? 'ENFORCE' : 'AUDIT',
    });
  return {
    ...full,
    mode,
    policyDecisions,
    effectiveResult,
    allowed:
      effectiveResult === 'ALLOWED' || effectiveResult === 'ALLOWED_AUDIT',
    enforcementDecision: blocking?.decision,
    enforcementErrors: blocking?.errors ?? [],
    latencyUs: Math.round((performance.now() - start) * 1000),
  };
}
export function evaluate(
  engine: CedarEngine,
  snapshot: Snapshot,
  request: ActionRequest,
) {
  const start = performance.now();
  if (
    !ACTIONS[request.action] ||
    ACTIONS[request.action] !== request.resource.type
  )
    throw new Error('Action and resource type do not match the schema');
  for (const [key, value] of Object.entries(request.context)) {
    const type = CONTEXT_FIELDS[key];
    if (!type) throw new Error(`Unsupported context field: ${key}`);
    if (
      (type === 'String' && typeof value !== 'string') ||
      (type === 'Long' && !Number.isSafeInteger(value)) ||
      (type === 'Boolean' && typeof value !== 'boolean') ||
      (type === 'Set' &&
        (!Array.isArray(value) || !value.every((x) => typeof x === 'string')))
    )
      throw new Error(`Invalid value for context.${key}`);
  }
  const policies = policiesFor(snapshot, request.environmentId);
  const known = snapshot.resources.find((r) => r.id === request.resource.id);
  if (known && known.type !== request.resource.type)
    throw new Error('Resource type conflicts with the catalog');
  const principalName = request.principal ?? request.sessionId;
  if (
    typeof principalName !== 'string' ||
    !principalName.trim() ||
    principalName.length > 200
  )
    throw new Error('A principal name of 1–200 characters is required');
  const principal = { type: 'Cleopatr::AgentSession', id: principalName };
  const resource = {
    type: `Cleopatr::${request.resource.type}`,
    id: request.resource.id,
  };
  const parc = {
    principal,
    action: { type: 'Cleopatr::Action', id: request.action },
    resource,
    context: request.context,
  };
  const entities: AssessedPayload['entities'] = [
    {
      uid: principal,
      attrs: {
        environment: request.environmentId,
        workspace: request.workspace ?? '',
        humanId: request.humanId ?? 'local',
      },
      parents: [],
    },
    {
      uid: resource,
      attrs: {
        name: known?.name ?? request.resource.id,
        environment: known?.environmentId ?? request.environmentId,
        locator: known?.locator ?? request.resource.id,
      },
      parents: [],
    },
  ];
  const payload = { ...parc, entities };
  const assessment = captureAssessment(payload);
  const answer = engine.isAuthorized({
    ...payload,
    context: request.context as Cedar.Context,
    entities,
    policies: {
      staticPolicies: Object.fromEntries(policies.map((p) => [p.id, p.cedar])),
    },
    schema: SCHEMA as Cedar.Schema,
    validateRequest: true,
  });
  if (answer.type === 'failure')
    return {
      decision: 'DENY' as const,
      determiningPolicies: [],
      errors: answer.errors.map((e) => e.message),
      latencyUs: Math.round((performance.now() - start) * 1000),
      parc,
      assessment,
      policyCount: policies.length,
    };
  // A policy evaluation error is fail-closed, even if a separate permit matched.
  return {
    decision: answer.response.diagnostics.errors.length
      ? ('DENY' as const)
      : (answer.response.decision.toUpperCase() as 'ALLOW' | 'DENY'),
    determiningPolicies: answer.response.diagnostics.reason,
    errors: answer.response.diagnostics.errors.map(
      (e) => `${e.policyId}: ${e.error.message}`,
    ),
    latencyUs: Math.round((performance.now() - start) * 1000),
    parc,
    assessment,
    policyCount: policies.length,
  };
}
