import {
  ancestors,
  effectivePolicies,
  inheritedPolicies,
  summarizePolicyModes,
  publishedSnapshot,
  assignmentSnapshot,
  policyContent,
  RESOURCE_TYPES,
  type Snapshot,
  type Policy,
  type PolicyHistory,
  type PolicyVersion,
  type EnvironmentMode,
} from '../core/model.ts';
import type { ApiInput } from '../core/api-types.ts';
import { validatePolicies, type CedarEngine } from '../core/engine.ts';

export class ApiError extends Error {
  constructor(
    message: string,
    public status = 400,
  ) {
    super(message);
  }
}
export function assert(ok: unknown, message: string, status = 400): asserts ok {
  if (!ok) throw new ApiError(message, status);
}
export function bounded(value: unknown, max = 200): string {
  assert(
    typeof value === 'string' && value.trim().length > 0 && value.length <= max,
    `A nonempty text value under ${max} characters is required`,
  );
  return value.trim();
}
const uid = (prefix: string) => `${prefix}_${crypto.randomUUID()}`;
export const HISTORY_LIMIT = 50;

export function changeSnapshot(
  original: Snapshot,
  input: ApiInput,
  cedar: CedarEngine,
  previous?: PolicyHistory,
) {
  const snapshot = structuredClone(original);
  const item = input.item ?? {};
  const time = new Date().toISOString();
  let history: PolicyHistory | undefined;
  const objectId =
    item.id ??
    uid(
      input.kind === 'policy'
        ? 'pol'
        : input.kind === 'environment'
          ? 'env'
          : 'res',
    );
  let name = item.name ?? objectId;
  function validateAssignments(ids: unknown): asserts ids is string[] {
    assert(
      Array.isArray(ids) &&
        ids.every((id) => snapshot.environments.some((e) => e.id === id)),
      'Choose existing environments or leave the policy unassigned',
    );
  }
  if (input.kind === 'environment') {
    const existing = snapshot.environments.find((e) => e.id === objectId);
    if (input.operation === 'delete') {
      assert(existing, 'Environment not found', 404);
      assert(
        !snapshot.environments.some((e) => e.parentId === objectId) &&
          !snapshot.resources.some((r) => r.environmentId === objectId) &&
          !snapshot.policies.some(
            (p) =>
              p.environmentIds.includes(objectId) ||
              p.published?.environmentIds.includes(objectId),
          ),
        'Remove children, resources, and policy assignments first',
      );
      snapshot.environments = snapshot.environments.filter(
        (e) => e.id !== objectId,
      );
    } else if (
      input.operation === 'mode' ||
      input.operation === 'policy-mode' ||
      input.operation === 'policies'
    ) {
      assert(existing, 'Environment not found', 404);
      name = existing.name;
      if (input.operation === 'mode') {
        assert(
          ['AUDIT', 'CUSTOM', 'ENFORCE'].includes(String(input.mode)),
          'Choose Audit, Custom, or Enforce',
        );
        // Entering Custom preserves the current rows; bulk choices replace any
        // old per-policy settings so they cannot reappear on the next row edit.
        existing.policyModes =
          input.mode === 'CUSTOM'
            ? Object.fromEntries(
                effectivePolicies(assignmentSnapshot(snapshot), objectId).map(
                  (policy) => [policy.id, policy.mode],
                ),
              )
            : {};
        existing.mode = input.mode as EnvironmentMode;
      } else if (input.operation === 'policy-mode') {
        const current = effectivePolicies(
          assignmentSnapshot(snapshot),
          objectId,
        );
        assert(
          input.policyId && current.some((p) => p.id === input.policyId),
          'Policy is not effective in this environment',
        );
        assert(
          input.mode === 'AUDIT' || input.mode === 'ENFORCE',
          'Choose Audit or Enforce',
        );
        assert(
          input.mode !== 'AUDIT' ||
            !inheritedPolicies(assignmentSnapshot(snapshot), objectId).some(
              (policy) =>
                policy.id === input.policyId && policy.mode === 'ENFORCE',
            ),
          'Inherited Enforce policies cannot be changed to Audit in a child environment',
        );
        // Snapshot every row before leaving a bulk mode. Editing one policy
        // must not change any other policy or revive older Custom overrides.
        existing.policyModes = {
          ...Object.fromEntries(
            current.map((policy) => [policy.id, policy.mode]),
          ),
          [input.policyId]: input.mode,
        };
        existing.mode = 'CUSTOM';
        existing.mode = summarizePolicyModes(
          effectivePolicies(assignmentSnapshot(snapshot), objectId),
        );
      } else {
        assert(
          Array.isArray(input.policyIds) &&
            input.policyIds.every((id) =>
              snapshot.policies.some((p) => p.id === id),
            ),
          'Choose existing policies',
        );
        const selected = new Set(input.policyIds);
        const inherited = inheritedPolicies(
          assignmentSnapshot(snapshot),
          objectId,
        );
        assert(
          inherited.every((policy) => selected.has(policy.id)),
          'Inherited policies cannot be deselected in a child environment',
        );
        const parentPolicies = new Set(
          existing.parentId
            ? effectivePolicies(snapshot, existing.parentId).map((p) => p.id)
            : [],
        );
        const publishedParents = new Set(
          existing.parentId
            ? effectivePolicies(
                publishedSnapshot(snapshot),
                existing.parentId,
              ).map((p) => p.id)
            : [],
        );
        for (const p of snapshot.policies) {
          const update = (
            version: Pick<Policy, 'environmentIds'>,
            parents: Set<string>,
          ) => {
            if (!selected.has(p.id))
              version.environmentIds = version.environmentIds.filter(
                (id) => id !== objectId,
              );
            else if (
              !parents.has(p.id) &&
              !version.environmentIds.includes(objectId)
            )
              version.environmentIds.push(objectId);
          };
          update(p, parentPolicies);
          if (p.published) update(p.published, publishedParents);
          if (selected.has(p.id)) {
            p.enabled = true;
            if (p.published) p.published.enabled = true;
          }
        }
        delete existing.excludedPolicyIds;
      }
    } else {
      const env = {
        id: objectId,
        name: bounded(item.name),
        description: String(item.description ?? '').slice(0, 1000),
        parentId: item.parentId || null,
        kind:
          item.kind === 'group' ? ('group' as const) : ('environment' as const),
        mode: existing?.mode ?? ('AUDIT' as const),
      };
      if (existing) Object.assign(existing, env);
      else snapshot.environments.push(env);
      for (const e of snapshot.environments)
        ancestors(snapshot.environments, e.id);
    }
  } else if (input.kind === 'resource') {
    const existing = snapshot.resources.find((r) => r.id === objectId);
    if (input.operation === 'delete') {
      assert(existing, 'Resource not found', 404);
      assert(
        !snapshot.policies.some(
          (p) =>
            p.cedar.includes(JSON.stringify(objectId)) ||
            p.published?.cedar.includes(JSON.stringify(objectId)),
        ),
        'Remove policy references to this resource first',
      );
      snapshot.resources = snapshot.resources.filter((r) => r.id !== objectId);
    } else {
      assert(
        item.type && RESOURCE_TYPES.includes(item.type),
        'Invalid resource type',
      );
      assert(
        snapshot.environments.some((e) => e.id === item.environmentId),
        'Choose an existing environment',
      );
      const resource = {
        id: objectId,
        name: bounded(item.name),
        description: String(item.description ?? '').slice(0, 1000),
        type: item.type,
        environmentId: bounded(item.environmentId),
        locator: bounded(item.locator, 2000),
      };
      if (existing) Object.assign(existing, resource);
      else snapshot.resources.push(resource);
    }
  } else if (input.kind === 'policy') {
    const existing = snapshot.policies.find((p) => p.id === objectId);
    if (input.operation === 'delete') {
      assert(existing, 'Policy not found', 404);
      snapshot.policies = snapshot.policies.filter((p) => p.id !== objectId);
      for (const env of snapshot.environments) {
        env.excludedPolicyIds = env.excludedPolicyIds?.filter(
          (id) => id !== objectId,
        );
        if (env.policyModes) delete env.policyModes[objectId];
      }
    } else {
      let policy: Policy;
      if (input.operation === 'publish' || input.operation === 'rollback') {
        assert(existing, 'Policy not found', 404);
        policy = existing;
        name = existing.name;
      } else {
        validateAssignments(item.environmentIds);
        policy = {
          id: objectId,
          name: bounded(item.name),
          description: String(item.description ?? '').slice(0, 1000),
          cedar: bounded(item.cedar, 30000),
          environmentIds: [...new Set(item.environmentIds)],
          enabled: true,
          revision: existing?.revision ?? 0,
          updatedAt: time,
          status: 'DRAFT',
          ...(existing?.published ? { published: existing.published } : {}),
          ...(item.rule ? { rule: item.rule } : {}),
          requirement: String(item.requirement ?? '').slice(0, 4000),
        };
      }
      const isPublishing =
        input.publish === true ||
        input.operation === 'publish' ||
        input.operation === 'rollback';
      if (isPublishing) {
        if (input.operation === 'rollback')
          assert(
            previous && existing?.published,
            'No previous published version to restore',
            404,
          );
        const content =
          input.operation === 'rollback'
            ? {
                ...policyContent(previous!),
                environmentIds: [...policy.published!.environmentIds],
              }
            : policyContent(policy);
        validateAssignments(content.environmentIds);
        const check = validatePolicies(cedar, [
          { id: objectId, cedar: content.cedar },
        ]);
        assert(check.valid, check.errors.join('\n'));
        if (policy.published)
          history = {
            ...policy.published,
            id: uid('history'),
            policyId: objectId,
            supersededAt: time,
          };
        const published: PolicyVersion = {
          ...content,
          version: (policy.published?.version ?? 0) + 1,
          publishedAt: time,
        };
        const keepDraft =
          input.operation === 'rollback' && policy.status === 'DRAFT';
        policy = {
          ...policy,
          ...(keepDraft ? {} : content),
          published,
          status: keepDraft ? 'DRAFT' : 'PUBLISHED',
        };
      } else {
        const check = validatePolicies(cedar, [policy]);
        assert(check.valid, check.errors.join('\n'));
      }
      policy.revision++;
      policy.updatedAt = time;
      if (existing)
        snapshot.policies[snapshot.policies.indexOf(existing)] = policy;
      else snapshot.policies.push(policy);
    }
  } else throw new ApiError('Unknown object kind');
  assert(
    snapshot.environments.length <= 500 &&
      snapshot.resources.length <= 2000 &&
      snapshot.policies.length <= 500,
    'Workspace size limit reached',
  );
  return { snapshot, history, objectId, name, time };
}
