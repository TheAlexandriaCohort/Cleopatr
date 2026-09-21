import * as cedar from '@cedar-policy/cedar-wasm/nodejs';
import { posix } from 'node:path';
import {
  effectivePolicies,
  ancestors,
  type Bundle,
  type ActionRequest,
} from '../core/model.ts';
import { evaluateWithModes } from '../core/engine.ts';
import { networkIdentity } from './network.ts';
import { httpPath } from './url.ts';
import { databaseTarget } from './adapters/database.ts';

// Linux UAPI bit positions. No file grant includes execute implicitly.
export const rights = {
  execute: 1,
  write: 2,
  read: 4 | 8,
  delete: 16 | 32,
  create: 128 | 256 | 4096,
  rename: 8192,
  truncate: 16384,
};
const semanticActions = new Set([
  'process.signal',
  'process.privilege_attempt',
  'file.metadata',
  'network.listen',
  'http.request',
  'network.connect',
  'dns.query',
  'mcp.tool.invoke',
  'mcp.resource.read',
  'mcp.prompt.get',
  'database.connect',
  'database.query',
  'database.transaction',
]);
type Json = null | string | number | boolean | Json[] | { [key: string]: Json };
const supportedActions = new Set([
  ...semanticActions,
  'process.execute',
  'file.read',
  'file.write',
  'file.create',
  'file.delete',
  'file.rename',
  'network.connect',
  'http.request',
  'mcp.tool.invoke',
  'mcp.resource.read',
  'mcp.prompt.get',
]);
function variable(node: Json, name: string): boolean {
  if (!node || typeof node !== 'object') return false;
  if (!Array.isArray(node) && node.Var === name) return true;
  return Object.values(node).some((v) => variable(v, name));
}
function onlySemantic(scope: Record<string, unknown>) {
  const entity = scope.entity as { type?: string; id?: string } | undefined;
  const entities = scope.entities as
    | { type?: string; id?: string }[]
    | undefined;
  const values =
    scope.op === '==' && entity
      ? [entity]
      : scope.op === 'in' && entities
        ? entities
        : [];
  return (
    values.length > 0 &&
    values.every(
      (e) => e.type === 'Cleopatr::Action' && semanticActions.has(e.id ?? ''),
    )
  );
}

// Directory membership in the fixed /workspace mount is constant for this
// capability compiler. Other OS context still requires per-operation mediation.
function staticFileContext(ast: Record<string, Json>) {
  const scope = ast.action as Record<string, Json>;
  const selected = scope.entity
    ? [scope.entity]
    : Array.isArray(scope.entities)
      ? scope.entities
      : [];
  if (
    !selected.length ||
    !selected.every(
      (e) =>
        e &&
        typeof e === 'object' &&
        !Array.isArray(e) &&
        typeof e.id === 'string' &&
        e.id.startsWith('file.'),
    )
  )
    return false;
  const walk = (node: Json): boolean => {
    if (!node || typeof node !== 'object') return true;
    if (!Array.isArray(node)) {
      if (node.Var === 'context') return false;
      for (const op of ['.', 'has']) {
        const value = node[op];
        if (
          value &&
          typeof value === 'object' &&
          !Array.isArray(value) &&
          value.attr === 'withinWorkspace' &&
          value.left &&
          typeof value.left === 'object' &&
          !Array.isArray(value.left) &&
          value.left.Var === 'context'
        )
          return true;
      }
    }
    return Object.values(node).every(walk);
  };
  return walk(ast.conditions);
}

export function compileProfile(
  bundle: Bundle,
  environmentId: string,
  principal: string,
  enforce: boolean,
  audit = false,
) {
  if (enforce && audit) throw new Error('Conflicting execution modes');
  const lineage = new Set(ancestors(bundle.environments, environmentId));
  const resources = bundle.resources.filter((r) =>
    lineage.has(r.environmentId),
  );
  const policies = effectivePolicies(bundle, environmentId);
  const auditOnly =
    audit ||
    (!enforce &&
      bundle.environments.find((e) => e.id === environmentId)?.mode !==
        'ENFORCE' &&
      policies.every((policy) => policy.mode === 'AUDIT'));
  // Audit keeps the resource/isolation boundary, but no policy is compiled
  // into a deny. Unsupported policy semantics do not prevent an audit launch.
  for (const policy of audit ? [] : policies) {
    const parsed = cedar.policyToJson(policy.cedar);
    if (parsed.type !== 'success')
      throw new Error(`Cannot parse policy ${policy.name}`);
    const ast = parsed.json as unknown as Record<string, Json>;
    const checkReferences = (value: Json): void => {
      if (!value || typeof value !== 'object') return;
      if (
        !Array.isArray(value) &&
        typeof value.type === 'string' &&
        ['Cleopatr::File', 'Cleopatr::Process'].includes(value.type) &&
        !resources.some(
          (r) => r.id === value.id && `Cleopatr::${r.type}` === value.type,
        )
      )
        throw new Error(
          `Policy "${policy.name}" references an OS resource outside this environment's catalog`,
        );
      Object.values(value).forEach(checkReferences);
    };
    checkReferences(ast);
    const scope = ast.action as Record<string, Json>;
    const selected = scope.entity
      ? [scope.entity]
      : Array.isArray(scope.entities)
        ? scope.entities
        : [];
    if (
      selected.some(
        (entity) =>
          entity &&
          typeof entity === 'object' &&
          !Array.isArray(entity) &&
          (typeof entity.id !== 'string' || !supportedActions.has(entity.id)),
      )
    )
      throw new Error(
        `Policy "${policy.name}" requires an action this Linux backend cannot mediate`,
      );
    // Arbitrary context-dependent Cedar cannot be faithfully compiled into path/inode rules.
    // Without an explicit audit override, refuse rules the kernel cannot represent.
    if (
      !onlySemantic(ast.action as Record<string, unknown>) &&
      ((variable(ast.conditions, 'context') && !staticFileContext(ast)) ||
        variable(ast.conditions, 'action'))
    )
      throw new Error(
        `Policy "${policy.name}" needs per-operation OS context. This Landlock backend supports context-free OS policies only; no session was started.`,
      );
  }
  if (resources.filter((r) => r.type === 'Database').length > 128)
    throw new Error('At most 128 Database endpoints are supported per enclave');
  const databaseEndpoints = new Set<string>();
  for (const resource of resources.filter((r) => r.type === 'Database')) {
    const target = databaseTarget(resource);
    const endpoint = `${target.host}:${target.port}`;
    if (databaseEndpoints.has(endpoint))
      throw new Error('Only one Database resource per host/port is supported');
    databaseEndpoints.add(endpoint);
  }
  for (const resource of resources.filter((r) => r.type === 'MCPTool')) {
    let url: URL;
    try {
      url = new URL(resource.locator);
    } catch {
      throw new Error(
        `MCP resource ${resource.name} requires an HTTP transport URL for this backend`,
      );
    }
    if (
      !['http:', 'https:'].includes(url.protocol) ||
      url.username ||
      url.password
    )
      throw new Error(`Unsupported MCP transport for ${resource.name}`);
  }
  for (const resource of resources.filter(
    (r) => r.type === 'Endpoint' || r.type === 'Network',
  )) {
    let url: URL;
    try {
      url = new URL(resource.locator);
    } catch {
      throw new Error(
        `${resource.name} requires an absolute HTTP(S) URL in this backend`,
      );
    }
    if (
      resource.type === 'Network' &&
      ['dns:', 'tcp:', 'udp:'].includes(url.protocol)
    ) {
      if (
        url.username ||
        url.password ||
        url.search ||
        url.hash ||
        !url.hostname ||
        url.hostname.includes('*') ||
        !['', '/'].includes(url.pathname) ||
        (url.protocol === 'dns:' && url.port)
      )
        throw new Error(`Invalid Network locator: ${resource.name}`);
      continue;
    }
    if (
      !['http:', 'https:'].includes(url.protocol) ||
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      url.hostname.includes('*') ||
      (resource.type === 'Network' && url.pathname !== '/')
    )
      throw new Error(
        `Unsupported ${resource.type} locator for ${resource.name}; use an origin${resource.type === 'Endpoint' ? ' and optional path' : ''}`,
      );
    httpPath(url);
  }
  const grants = new Map<string, number>();
  const identities = new Set<string>();
  for (const resource of resources.filter((r) =>
    ['Endpoint', 'Network', 'MCPTool'].includes(r.type),
  )) {
    const url = new URL(resource.locator);
    const key = JSON.stringify([
      resource.type,
      resource.type === 'Network'
        ? networkIdentity(resource.locator)
        : url.origin,
      resource.type === 'Network' ? '' : httpPath(url),
      resource.type === 'MCPTool' ? url.search : '',
      resource.type === 'MCPTool' ? decodeURIComponent(url.hash.slice(1)) : '',
    ]);
    if (identities.has(key))
      throw new Error(
        `Ambiguous duplicate protocol resource: ${resource.name}`,
      );
    identities.add(key);
  }
  const add = (path: string, access: number) =>
    grants.set(path, (grants.get(path) ?? 0) | access);
  const decide = (action: string, type: 'File' | 'Process', id: string) => {
    if (audit) return true;
    const request: ActionRequest = {
      environmentId,
      sessionId: 'profile',
      principal,
      action,
      resource: { type, id },
      workspace: '/workspace',
      context:
        type === 'File'
          ? {
              withinWorkspace: resources.some(
                (r) =>
                  r.id === id &&
                  (r.locator === '/workspace' ||
                    r.locator.startsWith('/workspace/')),
              ),
            }
          : {},
    };
    const result = evaluateWithModes(cedar, bundle, request, enforce);
    if (result.errors.length || result.enforcementErrors.length)
      throw new Error(
        `OS profile evaluation failed for ${id}: ${[...result.errors, ...result.enforcementErrors].join('; ')}`,
      );
    return result.allowed;
  };
  const fileResources = resources.filter((r) => r.type === 'File');
  // Landlock grants combine by union. A parent grant cannot contain a child exception.
  // Disallow overlapping catalog paths instead of silently widening a deny.
  const pathFor = (value: string) => {
    if (
      !value.startsWith('/') ||
      posix.normalize(value) !== value ||
      value === '/' ||
      value.includes('\0')
    )
      throw new Error(
        `Use a normalized, absolute, non-root sandbox resource path: ${value}`,
      );
    if (
      ![
        '/workspace',
        '/usr',
        '/bin',
        '/lib',
        '/lib64',
        '/etc',
        '/tmp',
        '/dev',
      ].some((p) => value === p || value.startsWith(p + '/'))
    )
      throw new Error(
        `Resource path is outside the supported sandbox roots: ${value}`,
      );
    return value;
  };
  for (const resource of fileResources) {
    const path = pathFor(resource.locator);
    if (
      fileResources.some(
        (other) =>
          other.id !== resource.id &&
          (other.locator === path ||
            other.locator.startsWith(path + '/') ||
            path.startsWith(other.locator + '/')),
      )
    )
      throw new Error(
        `Overlapping File resources cannot be safely compiled: ${path}`,
      );
    let access = 0;
    const create = decide('file.create', 'File', resource.id);
    const remove = decide('file.delete', 'File', resource.id);
    const rename = decide('file.rename', 'File', resource.id);
    if ((create && remove) !== rename)
      throw new Error(
        `Landlock cannot independently represent rename versus create/delete for ${path}; align these permissions or use another backend.`,
      );
    if (decide('file.read', 'File', resource.id)) access |= rights.read;
    if (decide('file.write', 'File', resource.id))
      access |= rights.write | rights.truncate;
    if (create) access |= rights.create;
    if (remove) access |= rights.delete;
    if (rename) access |= rights.rename;
    if (access) add(path, access);
  }
  for (const resource of resources.filter((r) => r.type === 'Process')) {
    if (decide('process.execute', 'Process', resource.id))
      add(pathFor(resource.locator), rights.execute);
  }
  return {
    principal,
    environmentId,
    auditOnly,
    boundaries: fileResources.map((r) => r.locator),
    grants: [...grants].map(([path, access]) => ({ path, access })),
    resources,
  };
}

export function requireExecutableGrant(
  profile: ReturnType<typeof compileProfile>,
) {
  const identity = `Cleopatr::AgentSession::${JSON.stringify(profile.principal)}`;
  if (!profile.resources.some((resource) => resource.type === 'Process'))
    throw new Error(
      `No executable is permitted: Environment ${JSON.stringify(profile.environmentId)} has no Process resources in its catalog or parent Environments. The principal is ${identity}. Register the agent, interpreters/tools and ELF loader as Process resources; a process.execute permit alone cannot create the executable allowlist. Runtime directories also need File read permissions.`,
    );
  if (!profile.grants.some((grant) => (grant.access & rights.execute) !== 0))
    throw new Error(
      `No executable is permitted for ${identity} in Environment ${JSON.stringify(profile.environmentId)}. No effective process.execute permit allows the registered Process resources, or a forbid blocks them. Check principal/resource scopes and Enforce modes. Runtime directories also need File read permissions. Network policies are evaluated only after the process can start.`,
    );
}
