import {
  CONFIGURATION_FORMAT,
  CONFIGURATION_VERSION,
  type Configuration,
  type ImportPreview,
} from '../core/configuration.ts';
import {
  ACTIONS,
  RESOURCE_TYPES,
  ancestors,
  policyContent,
  type Environment,
  type Resource,
  type Rule,
  type Policy,
  type Snapshot,
  type PolicyHistory,
} from '../core/model.ts';
import { validatePolicies, type CedarEngine } from '../core/engine.ts';
import { assert } from './lifecycle.ts';

type ObjectValue = Record<string, unknown>;
function object(value: unknown, label: string, keys: string[]): ObjectValue {
  assert(
    value !== null && typeof value === 'object' && !Array.isArray(value),
    `${label} must be an object`,
  );
  const result = value as ObjectValue;
  assert(
    Object.keys(result).every((key) => keys.includes(key)),
    `${label} contains unsupported fields`,
  );
  return result;
}
function text(
  value: unknown,
  label: string,
  max: number,
  empty = false,
): string {
  assert(
    typeof value === 'string' &&
      value.length <= max &&
      (empty || value.trim().length > 0),
    `Invalid ${label}`,
  );
  return value;
}
function identifier(value: unknown): string {
  const id = text(value, 'ID', 200);
  assert(
    !['__proto__', 'constructor', 'prototype'].includes(id) &&
      !Array.from(id).some((character) => character.charCodeAt(0) < 32),
    'Invalid ID',
  );
  return id;
}
function ids(value: unknown): string[] {
  assert(
    Array.isArray(value) && value.length <= 500,
    'Invalid environment assignments',
  );
  const result = value.map(identifier);
  assert(
    new Set(result).size === result.length,
    'Duplicate environment assignments',
  );
  return result;
}
function list<T extends { id: string }>(
  value: unknown,
  label: string,
  max: number,
  parse: (entry: unknown) => T,
): T[] {
  assert(
    Array.isArray(value) && value.length <= max,
    `Invalid ${label} list (maximum ${max})`,
  );
  const result = value.map(parse);
  assert(
    new Set(result.map((entry) => entry.id)).size === result.length,
    `Duplicate IDs in ${label}`,
  );
  return result;
}
function rule(value: unknown): Rule {
  const r = object(value, 'Rule', [
    'effect',
    'principal',
    'action',
    'resourceId',
    'field',
    'operator',
    'value',
  ]);
  assert(r.effect === 'permit' || r.effect === 'forbid', 'Invalid rule effect');
  assert(
    typeof r.action === 'string' && Object.hasOwn(ACTIONS, r.action),
    'Invalid rule action',
  );
  assert(
    ['equals', 'notEquals', 'in', 'lessThan'].includes(String(r.operator)),
    'Invalid rule operator',
  );
  return {
    effect: r.effect,
    action: r.action,
    resourceId: text(r.resourceId, 'rule resource', 200, true),
    field: text(r.field, 'rule field', 200, true),
    operator: r.operator as Rule['operator'],
    value: text(r.value, 'rule value', 4000, true),
    ...(r.principal !== undefined
      ? { principal: text(r.principal, 'principal', 200, true) }
      : {}),
  };
}
const CONTENT_KEYS = [
  'name',
  'description',
  'cedar',
  'environmentIds',
  'enabled',
  'rule',
  'requirement',
];
function content(value: ObjectValue) {
  assert(
    typeof value.enabled === 'boolean',
    'Policy enabled must be true or false',
  );
  return {
    name: text(value.name, 'policy name', 200),
    description: text(value.description ?? '', 'description', 1000, true),
    cedar: text(value.cedar, 'Cedar policy', 30000),
    environmentIds: ids(value.environmentIds),
    enabled: value.enabled,
    ...(value.rule !== undefined ? { rule: rule(value.rule) } : {}),
    ...(value.requirement !== undefined
      ? { requirement: text(value.requirement, 'requirement', 4000, true) }
      : {}),
  };
}

export function parseConfiguration(value: unknown): Configuration {
  const root = object(value, 'Configuration', [
    'format',
    'version',
    'exportedAt',
    'environments',
    'resources',
    'policies',
  ]);
  assert(
    root.format === CONFIGURATION_FORMAT &&
      root.version === CONFIGURATION_VERSION,
    'Unsupported configuration format or version',
  );
  const environments = list(
    root.environments,
    'Environments',
    500,
    (entry): Environment => {
      const e = object(entry, 'Environment', [
        'id',
        'name',
        'description',
        'parentId',
        'kind',
        'mode',
        'policyModes',
      ]);
      assert(
        e.kind === 'group' || e.kind === 'environment',
        'Invalid environment kind',
      );
      assert(
        ['AUDIT', 'ENFORCE', 'CUSTOM'].includes(String(e.mode)),
        'Invalid environment mode',
      );
      const modes = e.policyModes ?? {};
      assert(
        modes !== null && typeof modes === 'object' && !Array.isArray(modes),
        'Invalid policy modes',
      );
      const policyModes = Object.fromEntries(
        Object.entries(modes).map(([key, mode]) => {
          identifier(key);
          assert(mode === 'AUDIT' || mode === 'ENFORCE', 'Invalid policy mode');
          return [key, mode];
        }),
      ) as Environment['policyModes'];
      return {
        id: identifier(e.id),
        name: text(e.name, 'environment name', 200),
        description: text(e.description ?? '', 'description', 1000, true),
        parentId: e.parentId === null ? null : identifier(e.parentId),
        kind: e.kind,
        mode: e.mode as Environment['mode'],
        policyModes,
      };
    },
  );
  const resources = list(
    root.resources,
    'Resources',
    2000,
    (entry): Resource => {
      const r = object(entry, 'Resource', [
        'id',
        'name',
        'type',
        'description',
        'environmentId',
        'locator',
      ]);
      assert(
        RESOURCE_TYPES.includes(r.type as Resource['type']),
        'Invalid resource type',
      );
      return {
        id: identifier(r.id),
        name: text(r.name, 'resource name', 200),
        type: r.type as Resource['type'],
        description: text(r.description ?? '', 'description', 1000, true),
        environmentId: identifier(r.environmentId),
        locator: text(r.locator, 'locator', 2000),
      };
    },
  );
  const policies = list(root.policies, 'Policies', 500, (entry) => {
    const p = object(entry, 'Policy', ['id', ...CONTENT_KEYS, 'published']);
    return {
      id: identifier(p.id),
      ...content(p),
      ...(p.published !== undefined
        ? {
            published: content(
              object(p.published, 'Published policy', CONTENT_KEYS),
            ),
          }
        : {}),
    };
  });
  return {
    format: CONFIGURATION_FORMAT,
    version: CONFIGURATION_VERSION,
    environments,
    resources,
    policies,
  };
}

// Explicit projection: never serialize AppState, database rows, client records,
// keys, activity, arbitrary extra properties, or policy history into exports.
export function exportConfiguration(snapshot: Snapshot): Configuration {
  const policyFields = (p: ReturnType<typeof policyContent>) => ({
    name: p.name,
    description: p.description,
    cedar: p.cedar,
    environmentIds: p.environmentIds,
    enabled: p.enabled,
    ...(p.rule
      ? {
          rule: {
            effect: p.rule.effect,
            principal: p.rule.principal,
            action: p.rule.action,
            resourceId: p.rule.resourceId,
            field: p.rule.field,
            operator: p.rule.operator,
            value: p.rule.value,
          },
        }
      : {}),
    ...(p.requirement !== undefined ? { requirement: p.requirement } : {}),
  });
  return {
    format: CONFIGURATION_FORMAT,
    version: CONFIGURATION_VERSION,
    exportedAt: new Date().toISOString(),
    environments: snapshot.environments.map((e) => ({
      id: e.id,
      name: e.name,
      description: e.description,
      parentId: e.parentId,
      kind: e.kind,
      mode: e.mode ?? 'AUDIT',
      policyModes: Object.fromEntries(
        Object.entries(e.policyModes ?? {}).map(([id, mode]) => [id, mode]),
      ),
    })),
    resources: snapshot.resources.map((r) => ({
      id: r.id,
      name: r.name,
      type: r.type,
      environmentId: r.environmentId,
      locator: r.locator,
      description: r.description,
    })),
    policies: snapshot.policies.map((p) => ({
      id: p.id,
      ...policyFields(p),
      ...(p.published ? { published: policyFields(p.published) } : {}),
    })),
  };
}

export function prepareImport(
  original: Snapshot,
  value: unknown,
  cedar: CedarEngine,
) {
  const config = parseConfiguration(value);
  const snapshot = structuredClone(original);
  const time = new Date().toISOString();
  const histories: PolicyHistory[] = [];
  const changes: ImportPreview['changes'] = {
    environments: { added: 0, updated: 0 },
    resources: { added: 0, updated: 0 },
    policies: { added: 0, updated: 0 },
  };
  function merge<T extends { id: string }>(
    target: T[],
    incoming: T[],
    kind: keyof typeof changes,
  ) {
    for (const item of incoming) {
      const index = target.findIndex((old) => old.id === item.id);
      if (index < 0) {
        target.push(item);
        changes[kind].added++;
      } else {
        target[index] = item;
        changes[kind].updated++;
      }
    }
  }
  merge(snapshot.environments, config.environments, 'environments');
  merge(snapshot.resources, config.resources, 'resources');
  const policies: Policy[] = config.policies.map((incoming) => {
    const existing = snapshot.policies.find((p) => p.id === incoming.id);
    let published = existing?.published;
    if (
      incoming.published &&
      (!published ||
        JSON.stringify(content(incoming.published)) !==
          JSON.stringify(content(published)))
    ) {
      if (published)
        histories.push({
          ...published,
          id: `history_${crypto.randomUUID()}`,
          policyId: incoming.id,
          supersededAt: time,
        });
      published = {
        ...incoming.published,
        version: (published?.version ?? 0) + 1,
        publishedAt: time,
      };
    }
    return {
      ...content(incoming),
      id: incoming.id,
      revision: (existing?.revision ?? 0) + 1,
      updatedAt: time,
      status:
        published &&
        JSON.stringify(content(incoming)) === JSON.stringify(content(published))
          ? 'PUBLISHED'
          : 'DRAFT',
      ...(published ? { published } : {}),
    };
  });
  merge(snapshot.policies, policies, 'policies');
  assert(
    snapshot.environments.length <= 500 &&
      snapshot.resources.length <= 2000 &&
      snapshot.policies.length <= 500,
    'Workspace size limit reached',
  );
  try {
    for (const e of snapshot.environments)
      ancestors(snapshot.environments, e.id);
  } catch (error) {
    assert(false, (error as Error).message);
  }
  const environmentIds = new Set(snapshot.environments.map((e) => e.id));
  const policyIds = new Set(snapshot.policies.map((p) => p.id));
  const resourceIds = new Set(snapshot.resources.map((r) => r.id));
  for (const r of snapshot.resources)
    assert(
      environmentIds.has(r.environmentId),
      `Resource ${r.name} references an unknown Environment`,
    );
  for (const e of snapshot.environments)
    assert(
      Object.keys(e.policyModes ?? {}).every((id) => policyIds.has(id)),
      `Environment ${e.name} references an unknown policy`,
    );
  for (const p of snapshot.policies)
    for (const version of [p, ...(p.published ? [p.published] : [])]) {
      assert(
        version.environmentIds.every((id) => environmentIds.has(id)),
        `Policy ${p.name} references an unknown Environment`,
      );
      if (version.rule?.resourceId && version.rule.resourceId !== '*')
        assert(
          resourceIds.has(version.rule.resourceId),
          `Policy ${p.name} references an unknown Resource`,
        );
    }
  // Validate both drafts and active content before any database writes.
  for (const policiesToCheck of [
    snapshot.policies,
    snapshot.policies
      .filter((p) => p.published)
      .map((p) => ({ id: p.id, cedar: p.published!.cedar })),
  ]) {
    const check = validatePolicies(cedar, policiesToCheck);
    assert(check.valid, 'Invalid Cedar: ' + check.errors.join('; '));
  }
  return {
    snapshot,
    histories,
    time,
    changes,
    publishedPolicies: config.policies.filter((p) => p.published).length,
  };
}
