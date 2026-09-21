export const VERSION = '0.6.1';
// Telemetry-only CLI updates must not change signed policy contents at the
// same sequence. Raise this only when the bundle contract requires it.
export const BUNDLE_MINIMUM_CLIENT_VERSION = '0.6.1';
export const SCHEMA_VERSION = '3.0';
export type Mode = 'AUDIT' | 'ENFORCE';
export type EnvironmentMode = Mode | 'CUSTOM';
export type Environment = {
  id: string;
  name: string;
  description: string;
  parentId: string | null;
  kind: 'group' | 'environment';
  mode?: EnvironmentMode;
  policyModes?: Record<string, Mode>;
  /** Legacy field, ignored: descendants cannot exclude inherited policies. */
  excludedPolicyIds?: string[];
};
export type Resource = {
  id: string;
  name: string;
  type: ResourceType;
  environmentId: string;
  locator: string;
  description: string;
};
export const RESOURCE_TYPES = [
  'Database',
  'File',
  'Endpoint',
  'MCPTool',
  'Process',
  'Network',
] as const;
export type ResourceType = (typeof RESOURCE_TYPES)[number];
export type Rule = {
  effect: 'permit' | 'forbid';
  /** Empty or absent matches all clients; otherwise the enrolled client name. */
  principal?: string;
  action: string;
  resourceId: string;
  field: string;
  operator: 'equals' | 'notEquals' | 'in' | 'lessThan';
  value: string;
};
export type Policy = {
  id: string;
  name: string;
  description: string;
  cedar: string;
  environmentIds: string[];
  enabled: boolean;
  revision: number;
  updatedAt: string;
  rule?: Rule;
  requirement?: string;
  status?: 'DRAFT' | 'PUBLISHED';
  published?: PolicyVersion;
};
export type PolicyVersion = Pick<
  Policy,
  | 'name'
  | 'description'
  | 'cedar'
  | 'environmentIds'
  | 'enabled'
  | 'rule'
  | 'requirement'
> & {
  version: number;
  publishedAt: string;
};
export type PolicyHistory = PolicyVersion & {
  id: string;
  policyId: string;
  supersededAt: string;
};
export type Snapshot = {
  environments: Environment[];
  resources: Resource[];
  policies: Policy[];
};
export type Bundle = Snapshot & {
  schemaVersion: string;
  tenant: string;
  sequence: number;
  bundleId: string;
  createdAt: string;
  environmentIds: string[];
  minimumClientVersion: string;
  client?: { id: string; name: string };
  schema: Record<string, unknown>;
};
export type SignedBundle = {
  payload: string;
  signature: string;
  keyId: string;
  digest: string;
  algorithm: 'Ed25519';
};
export type ActionRequest = {
  environmentId: string;
  sessionId: string;
  principal?: string;
  action: string;
  resource: { type: ResourceType; id: string };
  context: Record<string, unknown>;
  workspace?: string;
  humanId?: string;
};
export const ACTIONS: Record<string, ResourceType> = {
  'process.execute': 'Process',
  'process.signal': 'Process',
  'process.privilege_attempt': 'Process',
  'file.read': 'File',
  'file.write': 'File',
  'file.create': 'File',
  'file.delete': 'File',
  'file.rename': 'File',
  'file.metadata': 'File',
  'network.connect': 'Network',
  'network.listen': 'Network',
  'dns.query': 'Network',
  'http.request': 'Endpoint',
  'mcp.tool.invoke': 'MCPTool',
  'mcp.resource.read': 'MCPTool',
  'mcp.prompt.get': 'MCPTool',
  'database.connect': 'Database',
  'database.query': 'Database',
  'database.transaction': 'Database',
};
export const CONTEXT_FIELDS: Record<
  string,
  'String' | 'Long' | 'Boolean' | 'Set'
> = {
  operation: 'String',
  method: 'String',
  host: 'String',
  path: 'String',
  executable: 'String',
  cwd: 'String',
  protocol: 'String',
  port: 'Long',
  tool: 'String',
  server: 'String',
  amount: 'Long',
  confidence: 'String',
  tables: 'Set',
  argv: 'Set',
  resolvedPath: 'String',
  encrypted: 'Boolean',
  semanticAvailable: 'Boolean',
  withinWorkspace: 'Boolean',
};
export function ancestors(environments: Environment[], id: string): string[] {
  const result: string[] = [];
  let cursor: string | null = id;
  while (cursor) {
    if (result.includes(cursor))
      throw new Error('Environment hierarchy contains a cycle');
    const e = environments.find((x) => x.id === cursor);
    if (!e) throw new Error(`Unknown environment: ${cursor}`);
    result.push(cursor);
    cursor = e.parentId;
  }
  return result;
}
export function descendants(environments: Environment[], id: string) {
  return environments
    .filter((e) => ancestors(environments, e.id).includes(id))
    .map((e) => e.id);
}
export function effectivePolicies(snapshot: Snapshot, id: string) {
  const lineage = ancestors(snapshot.environments, id).reverse();
  const applicable = new Map<
    string,
    { policy: Policy; sourceEnvironmentId: string; mode: Mode }
  >();
  for (const envId of lineage) {
    const environment = snapshot.environments.find((e) => e.id === envId)!;
    for (const policy of snapshot.policies)
      if (
        policy.enabled &&
        policy.environmentIds.includes(envId) &&
        !applicable.has(policy.id)
      )
        applicable.set(policy.id, {
          policy,
          sourceEnvironmentId: envId,
          mode: 'AUDIT',
        });
    for (const entry of applicable.values()) {
      const requested =
        environment.mode === 'CUSTOM'
          ? (environment.policyModes?.[entry.policy.id] ?? entry.mode)
          : (environment.mode ?? 'AUDIT');
      // Enforcement only strengthens down a lineage. A second assignment and
      // legacy exclusion metadata cannot reset a parent's effective decision mode.
      if (requested === 'ENFORCE') entry.mode = 'ENFORCE';
    }
  }
  return [...applicable.values()].map(
    ({ policy, sourceEnvironmentId, mode }) => ({
      ...policy,
      mode,
      sourceEnvironmentId,
    }),
  );
}
export function inheritedPolicies(snapshot: Snapshot, id: string) {
  const parent = snapshot.environments.find(
    (environment) => environment.id === id,
  )?.parentId;
  return parent ? effectivePolicies(snapshot, parent) : [];
}
export function summarizePolicyModes(
  policies: { mode: Mode }[],
  emptyMode: EnvironmentMode = 'AUDIT',
): EnvironmentMode {
  if (!policies.length) return emptyMode;
  const first = policies[0].mode;
  return policies.every((policy) => policy.mode === first) ? first : 'CUSTOM';
}
export function policiesFor(snapshot: Snapshot, id: string) {
  return effectivePolicies(snapshot, id);
}
export function publishedSnapshot(snapshot: Snapshot): Snapshot {
  return {
    ...snapshot,
    policies: snapshot.policies.flatMap((p) =>
      p.published
        ? [
            {
              id: p.id,
              ...policyContent(p.published),
              revision: p.published.version,
              updatedAt: p.published.publishedAt,
              status: 'PUBLISHED' as const,
            },
          ]
        : p.status === 'PUBLISHED'
          ? [p]
          : [],
    ),
  };
}
// Assignment management includes saved drafts and the still-active published copy.
export function assignmentSnapshot(snapshot: Snapshot): Snapshot {
  return {
    ...snapshot,
    policies: snapshot.policies.map((p) =>
      p.published
        ? {
            ...p,
            ...policyContent(p.published),
            environmentIds: [
              ...new Set([...p.environmentIds, ...p.published.environmentIds]),
            ],
            enabled: p.enabled || p.published.enabled,
          }
        : p,
    ),
  };
}
export function policyContent(
  policy: Pick<
    Policy,
    | 'name'
    | 'description'
    | 'cedar'
    | 'environmentIds'
    | 'enabled'
    | 'rule'
    | 'requirement'
  >,
): Omit<PolicyVersion, 'version' | 'publishedAt'> {
  const {
    name,
    description,
    cedar,
    environmentIds,
    enabled,
    rule,
    requirement,
  } = policy;
  return {
    name,
    description,
    cedar,
    environmentIds: [...environmentIds],
    enabled,
    rule,
    requirement,
  };
}
export function policyResourceTypes(policy: Policy): ResourceType[] {
  if (policy.rule?.action) return [ACTIONS[policy.rule.action]];
  const actions = [...policy.cedar.matchAll(/Cleopatr::Action::"([^"]+)"/g)]
    .map((m) => ACTIONS[m[1]])
    .filter(Boolean);
  const resources = RESOURCE_TYPES.filter((type) =>
    policy.cedar.includes(`Cleopatr::${type}::`),
  );
  const types = new Set([...actions, ...resources]);
  return types.size ? [...types] : [...RESOURCE_TYPES];
}
export function generateCedar(rule: Rule, resources: Resource[]): string {
  if (!['permit', 'forbid'].includes(rule.effect) || !ACTIONS[rule.action])
    throw new Error('Choose a valid action and effect');
  const selected = rule.resourceId
    ? resources.find((r) => r.id === rule.resourceId)
    : undefined;
  if (rule.resourceId && !selected)
    throw new Error('Choose an existing resource');
  if (selected && selected.type !== ACTIONS[rule.action])
    throw new Error('Resource type does not match the action');
  const literal = (v: string) => JSON.stringify(v);
  let condition = '';
  if (rule.field) {
    const t = CONTEXT_FIELDS[rule.field];
    if (!t) throw new Error('Unknown context field');
    const attr = `context.${rule.field}`;
    let v = literal(rule.value);
    if (t === 'Long') {
      const n = Number(rule.value);
      if (!Number.isSafeInteger(n)) throw new Error('Enter a whole number');
      v = String(n);
    }
    if (t === 'Boolean') {
      if (!['true', 'false'].includes(rule.value))
        throw new Error('Enter true or false');
      v = rule.value;
    }
    if (t === 'Set') throw new Error('Use the Cedar editor for set conditions');
    let expr = '';
    if (rule.operator === 'in') {
      if (t !== 'String')
        throw new Error('List matching requires a text field');
      expr = `[${rule.value
        .split(',')
        .map((v) => literal(v.trim()))
        .join(', ')}].contains(${attr})`;
    } else if (rule.operator === 'lessThan') {
      if (t !== 'Long') throw new Error('Less than requires a numeric field');
      expr = `${attr} < ${v}`;
    } else if (['equals', 'notEquals'].includes(rule.operator)) {
      expr = `${attr} ${rule.operator === 'equals' ? '==' : '!='} ${v}`;
    } else throw new Error('Unknown operator');
    // Missing facts never satisfy a permit; a forbid is conservative when facts are absent.
    condition = `\nwhen { ${rule.effect === 'forbid' ? `if context has ${rule.field} then (${expr}) else true` : `context has ${rule.field} && (${expr})`} }`;
  }
  if (rule.principal !== undefined && typeof rule.principal !== 'string')
    throw new Error('Choose a valid principal');
  const principal = rule.principal
    ? `principal == Cleopatr::AgentSession::${literal(rule.principal)}`
    : 'principal';
  return `${rule.effect}(\n  ${principal},\n  action == Cleopatr::Action::${literal(rule.action)},\n  ${selected ? `resource == Cleopatr::${selected.type}::${literal(selected.id)}` : 'resource'}\n)${condition};`;
}

export function createDefaultPolicies(
  time = new Date().toISOString(),
): Policy[] {
  return Object.keys(ACTIONS).map((action) => {
    const rule: Rule = {
      effect: 'permit',
      principal: '',
      action,
      resourceId: '',
      field: '',
      operator: 'equals',
      value: '',
    };
    const policy: Policy = {
      id: `pol_default_${action.replaceAll('.', '_')}`,
      name: `Default - ${action}`,
      description: `Allow ${action} for any principal and resource. Assign to an Environment to apply.`,
      cedar: generateCedar(rule, []),
      environmentIds: [],
      enabled: true,
      revision: 1,
      updatedAt: time,
      status: 'PUBLISHED',
      rule,
    };
    policy.published = {
      ...policyContent(policy),
      version: 1,
      publishedAt: time,
    };
    return policy;
  });
}

// Called only at workspace creation or a versioned upgrade; deleted defaults stay deleted.
export function addDefaultPolicies(snapshot: Snapshot, time: string) {
  const ids = new Set(snapshot.policies.map((policy) => policy.id));
  snapshot.policies.push(
    ...createDefaultPolicies(time).filter((policy) => !ids.has(policy.id)),
  );
}
export function buildSchema() {
  const shape = {
    type: 'Record',
    attributes: {
      name: { type: 'String' },
      environment: { type: 'String' },
      locator: { type: 'String' },
    },
  };
  const entityTypes: Record<string, unknown> = {
    AgentSession: {
      shape: {
        type: 'Record',
        attributes: {
          environment: { type: 'String' },
          workspace: { type: 'String' },
          humanId: { type: 'String' },
        },
      },
    },
  };
  for (const type of RESOURCE_TYPES) entityTypes[type] = { shape };
  const attributes = Object.fromEntries(
    Object.entries(CONTEXT_FIELDS).map(([k, type]) => [
      k,
      type === 'Set'
        ? { type, element: { type: 'String' }, required: false }
        : { type, required: false },
    ]),
  );
  return {
    Cleopatr: {
      entityTypes,
      actions: Object.fromEntries(
        Object.entries(ACTIONS).map(([name, type]) => [
          name,
          {
            appliesTo: {
              principalTypes: ['AgentSession'],
              resourceTypes: [type],
              context: { type: 'Record', attributes },
            },
          },
        ]),
      ),
    },
  };
}
export const SCHEMA = buildSchema();
export function createSeed(): Snapshot {
  const environments: Environment[] = [
    {
      id: 'organization',
      name: 'Organization',
      description: 'Rules inherited by every environment.',
      parentId: null,
      kind: 'group',
    },
    {
      id: 'development',
      name: 'Development',
      description: 'Local workspaces and experimental agents.',
      parentId: 'organization',
      kind: 'environment',
    },
    {
      id: 'production',
      name: 'Production',
      description: 'Customer-facing systems and live data.',
      parentId: 'organization',
      kind: 'group',
    },
    {
      id: 'customer-platform',
      name: 'Customer platform',
      description: 'Production services for customer operations.',
      parentId: 'production',
      kind: 'environment',
    },
  ];
  const resources: Resource[] = [
    {
      id: 'customer-db',
      name: 'Customer database',
      type: 'Database',
      environmentId: 'customer-platform',
      locator: 'postgresql://db.example.internal/customers',
      description: 'Example production PostgreSQL database.',
    },
    {
      id: 'project-workspace',
      name: 'Project workspace',
      type: 'File',
      environmentId: 'development',
      locator: '/workspace',
      description: 'Example agent project directory.',
    },
    {
      id: 'support-refund',
      name: 'Support refund tool',
      type: 'MCPTool',
      environmentId: 'customer-platform',
      locator: 'support/refund',
      description: 'Example MCP tool.',
    },
  ];
  const now = new Date().toISOString();
  const base = {
    revision: 1,
    enabled: true,
    updatedAt: now,
    status: 'DRAFT' as const,
  };
  const read: Rule = {
    effect: 'permit',
    action: 'file.read',
    resourceId: '',
    field: 'withinWorkspace',
    operator: 'equals',
    value: 'true',
  };
  const db: Rule = {
    effect: 'forbid',
    action: 'database.query',
    resourceId: '',
    field: 'operation',
    operator: 'in',
    value: 'INSERT,UPDATE,DELETE,DDL,COPY,CALL,UNKNOWN',
  };
  const sudo: Rule = {
    effect: 'forbid',
    action: 'process.execute',
    resourceId: '',
    field: 'executable',
    operator: 'in',
    value: '/usr/bin/sudo,/bin/su,/usr/bin/su',
  };
  return {
    environments,
    resources,
    policies: [
      {
        ...base,
        id: 'pol_workspace_read',
        name: 'Allow workspace reads',
        description: 'Read files within the agent’s workspace.',
        environmentIds: ['organization'],
        rule: read,
        cedar: generateCedar(read, resources),
      },
      {
        ...base,
        id: 'pol_protect_production',
        name: 'Protect production data',
        description: 'Prevent destructive database operations.',
        environmentIds: ['production'],
        rule: db,
        cedar: generateCedar(db, resources),
      },
      {
        ...base,
        id: 'pol_no_privilege',
        name: 'Block privilege escalation',
        description: 'Keep agent processes unprivileged.',
        environmentIds: ['organization'],
        rule: sudo,
        cedar: generateCedar(sudo, resources),
      },
      ...createDefaultPolicies(now),
    ],
  };
}
