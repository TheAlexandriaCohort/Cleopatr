import type { ApiInput, Simulation } from '../core/api-types.ts';
import {
  evaluate,
  evaluateWithModes,
  type CedarEngine,
} from '../core/engine.ts';
import {
  policyContent,
  publishedSnapshot,
  type Snapshot,
} from '../core/model.ts';
import { assert, bounded } from './lifecycle.ts';

export function simulateControl(
  cedar: CedarEngine,
  snapshot: Snapshot,
  input: ApiInput,
): Simulation {
  assert(input.request, 'A canonical request is required');
  assert(
    input.controlType === 'POLICY' || input.controlType === 'ENVIRONMENT',
    'Choose Policy or Environment',
  );
  const id = bounded(input.controlId);
  const principal = bounded(input.request.principal);
  const request = {
    ...input.request,
    principal,
    sessionId: input.request.sessionId || 'simulation',
  };
  if (input.controlType === 'ENVIRONMENT') {
    const environment = snapshot.environments.find((e) => e.id === id);
    assert(environment, 'Environment not found', 404);
    const live = publishedSnapshot(snapshot);
    return {
      ...evaluateWithModes(cedar, live, { ...request, environmentId: id }),
      controlType: 'ENVIRONMENT',
      controlId: id,
      controlName: environment.name,
      environmentName: environment.name,
      source: 'PUBLISHED',
      engine: cedar.getCedarVersion(),
      policyNames: Object.fromEntries(live.policies.map((p) => [p.id, p.name])),
    };
  }
  const saved = snapshot.policies.find((p) => p.id === id);
  assert(saved, 'Policy not found', 404);
  assert(
    input.source === 'DRAFT' || input.source === 'PUBLISHED',
    'Choose a draft or published policy',
  );
  if (input.source === 'PUBLISHED')
    assert(
      saved.published || saved.status === 'PUBLISHED',
      'This policy has not been published',
    );
  else assert(saved.status !== 'PUBLISHED', 'This policy has no saved draft');
  const policy =
    input.source === 'PUBLISHED' && saved.published
      ? {
          ...saved,
          ...policyContent(saved.published),
          revision: saved.published.version,
          published: undefined,
        }
      : saved;
  // A policy is evaluated in isolation; use catalog/assignment context for entity attributes.
  const known = snapshot.resources.find((r) => r.id === request.resource.id);
  const environment =
    snapshot.environments.find((e) => e.id === known?.environmentId) ??
    snapshot.environments.find((e) => policy.environmentIds.includes(e.id)) ??
    snapshot.environments[0];
  const environmentId = environment?.id ?? 'simulation';
  const isolated: Snapshot = {
    ...snapshot,
    environments: [
      {
        id: environmentId,
        name: environment?.name ?? 'Simulation',
        description: '',
        kind: 'environment',
        parentId: null,
      },
    ],
    policies: [{ ...policy, enabled: true, environmentIds: [environmentId] }],
  };
  return {
    ...evaluate(cedar, isolated, { ...request, environmentId }),
    controlType: 'POLICY',
    controlId: id,
    controlName: policy.name,
    environmentName: environment?.name ?? 'Simulation',
    contextSource: known
      ? 'resource'
      : environment
        ? 'policy assignment or workspace'
        : 'simulation',
    source: input.source,
    engine: cedar.getCedarVersion(),
    policyNames: { [id]: policy.name },
  };
}
