import type { ApiInput, AppState, ClientRecord } from '../core/api-types.ts';
import {
  createSeed,
  addDefaultPolicies,
  ancestors,
  descendants,
  SCHEMA,
  ACTIONS,
  BUNDLE_MINIMUM_CLIENT_VERSION,
  SCHEMA_VERSION,
  publishedSnapshot,
  policyContent,
  effectivePolicies,
  type PolicyHistory,
  type PolicyVersion,
  type Snapshot,
  type Policy,
  type Bundle,
} from '../core/model.ts';
import {
  validatePolicies,
  evaluateWithModes,
  type CedarEngine,
} from '../core/engine.ts';
import { digest, makeKeys, signBundle } from '../core/crypto.ts';
import {
  ApiError,
  assert,
  bounded,
  changeSnapshot,
  HISTORY_LIMIT,
} from './lifecycle.ts';
import { normalizeEvent, platformScope, queryActivity } from './activity.ts';
import { simulateControl } from './simulation.ts';
import { validateAssessment } from '../core/assessment.ts';
import { exportConfiguration, prepareImport } from './configuration.ts';
import { CONFIGURATION_MAX_BYTES } from '../core/configuration.ts';
import { requestOrigin } from './http.ts';
export { ApiError } from './lifecycle.ts';
type WorkspaceRow = {
  id: string;
  snapshot: string;
  revision: number;
  sequence: number;
  mutation: string;
  public_key: string;
  private_key: string;
  model_version: number;
  updated_at: string;
};
type BodyRow = { body: string };
type ClientRow = ClientRecord & { tenant: string; token_hash: string };
export type DbValue = string | number | null;
export type DbResult = { meta: { changes: number } };
export type Database = {
  prepare: (sql: string) => Statement;
  batch: (statements: Statement[]) => Promise<DbResult[]>;
};
export type Statement = {
  bind: (...values: DbValue[]) => Statement;
  first: <T = BodyRow>() => Promise<T | null>;
  all: <T = BodyRow>() => Promise<{ results: T[] }>;
  run: () => Promise<DbResult>;
};
const now = () => new Date().toISOString();
const uid = (prefix: string) => `${prefix}_${crypto.randomUUID()}`;
export class ControlPlane {
  constructor(
    public db: Database,
    public cedar: CedarEngine,
    public signingKey?: JsonWebKey,
    public authoring?: { endpoint: string; token?: string },
  ) {}
  async workspace(tenant: string): Promise<
    Omit<WorkspaceRow, 'snapshot'> & {
      snapshot: Snapshot;
      publicKey: JsonWebKey;
    }
  > {
    let row = await this.db
      .prepare('SELECT * FROM workspaces WHERE id = ?')
      .bind(tenant)
      .first<WorkspaceRow>();
    if (!row) {
      const keys = this.signingKey
        ? {
            privateKey: this.signingKey,
            publicKey: (({ d: _d, ...rest }) => ({
              ...rest,
              key_ops: ['verify'],
            }))(this.signingKey),
          }
        : await makeKeys();
      await this.db
        .prepare(
          'INSERT OR IGNORE INTO workspaces (id,snapshot,revision,sequence,mutation,public_key,private_key,model_version,updated_at) VALUES (?,?,1,1,?,?,?,6,?)',
        )
        .bind(
          tenant,
          JSON.stringify(createSeed()),
          uid('init'),
          JSON.stringify(keys.publicKey),
          this.signingKey ? 'external' : JSON.stringify(keys.privateKey),
          now(),
        )
        .run();
      row = await this.db
        .prepare('SELECT * FROM workspaces WHERE id = ?')
        .bind(tenant)
        .first<WorkspaceRow>();
    }
    assert(row, 'Workspace initialization failed', 500);
    if (row.model_version < 2) {
      // Read-only legacy archive: migrate the last published policy content once.
      const records = await this.db
        .prepare(
          'SELECT body FROM releases WHERE tenant = ? ORDER BY sequence DESC LIMIT 1000',
        )
        .bind(tenant)
        .all();
      const saved = records.results.reverse().map(
        (x) =>
          JSON.parse(x.body) as {
            snapshot: Snapshot;
            mode: 'AUDIT' | 'ENFORCE';
            createdAt: string;
          },
      );
      const latest = saved.at(-1);
      const snapshot = JSON.parse(row.snapshot) as Snapshot;
      // Objects deleted only in the old draft must not erase still-published content.
      for (const policy of latest?.snapshot.policies ?? [])
        if (!snapshot.policies.some((p) => p.id === policy.id))
          snapshot.policies.push(structuredClone(policy));
      for (const env of latest?.snapshot.environments ?? [])
        if (!snapshot.environments.some((e) => e.id === env.id))
          snapshot.environments.push(structuredClone(env));
      for (const resource of latest?.snapshot.resources ?? [])
        if (!snapshot.resources.some((r) => r.id === resource.id))
          snapshot.resources.push(structuredClone(resource));
      const history: PolicyHistory[] = [];
      for (const env of snapshot.environments) {
        env.mode = latest?.mode ?? 'AUDIT';
        env.policyModes = {};
        delete env.excludedPolicyIds;
      }
      for (const policy of snapshot.policies) {
        let active: PolicyVersion | undefined;
        for (const record of saved) {
          const old = record.snapshot.policies.find((p) => p.id === policy.id);
          if (!old) continue;
          const content = policyContent(old);
          if (
            active &&
            JSON.stringify(policyContent(active)) === JSON.stringify(content)
          )
            continue;
          if (active)
            history.push({
              ...active,
              id: uid('history'),
              policyId: policy.id,
              supersededAt: record.createdAt,
            });
          active = {
            ...content,
            version: (active?.version ?? 0) + 1,
            publishedAt: record.createdAt,
          };
        }
        const live = latest?.snapshot.policies.find((p) => p.id === policy.id);
        policy.published = live ? active : undefined;
        policy.status =
          active &&
          live &&
          JSON.stringify(policyContent(policy)) ===
            JSON.stringify(policyContent(active))
            ? 'PUBLISHED'
            : 'DRAFT';
      }
      const marker = uid('upgrade');
      addDefaultPolicies(snapshot, now());
      const statements = [
        this.db
          .prepare(
            'UPDATE workspaces SET snapshot = ?, model_version = 6, sequence = sequence + 1, revision = revision + 1, mutation = ?, updated_at = ? WHERE id = ? AND model_version = 1 AND revision = ?',
          )
          .bind(JSON.stringify(snapshot), marker, now(), tenant, row.revision),
      ];
      for (const entry of history.filter(
        (h) =>
          history.filter(
            (x) => x.policyId === h.policyId && x.version > h.version,
          ).length < HISTORY_LIMIT,
      ))
        statements.push(this.historyInsert(tenant, marker, entry));
      await this.db.batch(statements);
      return this.workspace(tenant);
    }

    if (row.model_version < 6) {
      // Upgrade once, preserving edits and assignments. Advance signed snapshot provenance.
      // Version 6 requires client-bound bundles and CLI 0.6.1. Advancing the
      // sequence lets old caches upgrade without weakening rollback protection.
      const snapshot = JSON.parse(row.snapshot) as Snapshot;
      const time = now();
      if (row.model_version < 4) addDefaultPolicies(snapshot, time);
      for (const environment of snapshot.environments)
        delete environment.excludedPolicyIds;
      await this.db
        .prepare(
          'UPDATE workspaces SET snapshot = ?, model_version = 6, sequence = sequence + 1, revision = revision + 1, mutation = ?, updated_at = ? WHERE id = ? AND model_version = ? AND revision = ?',
        )
        .bind(
          JSON.stringify(snapshot),
          uid('defaults'),
          time,
          tenant,
          row.model_version,
          row.revision,
        )
        .run();
      return this.workspace(tenant);
    }
    return {
      ...row,
      snapshot: JSON.parse(row.snapshot) as Snapshot,
      publicKey: JSON.parse(row.public_key) as JsonWebKey,
    };
  }
  async state(tenant: string): Promise<AppState> {
    const w = await this.workspace(tenant);
    const [events, clients] = await Promise.all([
      this.db
        .prepare(
          'SELECT body FROM events WHERE tenant = ? ORDER BY time DESC LIMIT 150',
        )
        .bind(tenant)
        .all(),
      this.db
        .prepare(
          'SELECT id,name,environment_ids,created_at,expires_at,last_seen,revoked FROM clients WHERE tenant = ? ORDER BY created_at DESC, id DESC',
        )
        .bind(tenant)
        .all<ClientRecord>(),
    ]);
    return {
      ...w.snapshot,
      revision: w.revision,
      tenant,
      publicKey: w.publicKey,
      sequence: w.sequence,
      events: events.results.map((x) => normalizeEvent(JSON.parse(x.body))),
      clients: clients.results,
      engine: this.cedar.getCedarVersion(),
    };
  }
  historyInsert(tenant: string, mutation: string, entry: PolicyHistory) {
    return this.db
      .prepare(
        'INSERT INTO policy_history (id,tenant,policy_id,version,body,superseded_at) SELECT ?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM workspaces WHERE id = ? AND mutation = ?)',
      )
      .bind(
        entry.id,
        tenant,
        entry.policyId,
        entry.version,
        JSON.stringify(entry),
        entry.supersededAt,
        tenant,
        mutation,
      );
  }
  async history(tenant: string, policyId: string) {
    const workspace = await this.workspace(tenant);
    const policy = workspace.snapshot.policies.find((p) => p.id === policyId);
    assert(policy, 'Policy not found', 404);
    const rows = await this.db
      .prepare(
        'SELECT body FROM policy_history WHERE tenant = ? AND policy_id = ? ORDER BY version DESC LIMIT 50',
      )
      .bind(tenant, policyId)
      .all();
    return {
      current: policy.published,
      previous: rows.results.map((x) => JSON.parse(x.body) as PolicyHistory),
    };
  }
  async mutation(tenant: string, actor: string, input: ApiInput) {
    const workspace = await this.workspace(tenant);
    assert(
      input.revision === workspace.revision,
      'This workspace changed. Refresh and retry.',
      409,
    );
    const previous =
      input.operation === 'rollback'
        ? (await this.history(tenant, bounded(input.item?.id))).previous[0]
        : undefined;
    const changed = changeSnapshot(
      workspace.snapshot,
      input,
      this.cedar,
      previous,
    );
    const mutation = uid('mut');
    const event = {
      id: uid('evt'),
      time: changed.time,
      kind: 'administration',
      actor,
      operation: input.publish ? 'publish' : (input.operation ?? 'save'),
      objectType: input.kind,
      name: changed.name,
      ...platformScope(
        workspace.snapshot,
        changed.snapshot,
        input,
        changed.objectId,
      ),
      policyId: input.kind === 'policy' ? changed.objectId : input.policyId,
      environmentId:
        input.kind === 'environment' ? changed.objectId : undefined,
    };
    const statements = [
      this.db
        .prepare(
          'UPDATE workspaces SET snapshot = ?, revision = revision + 1, sequence = sequence + 1, mutation = ?, updated_at = ? WHERE id = ? AND revision = ?',
        )
        .bind(
          JSON.stringify(changed.snapshot),
          mutation,
          changed.time,
          tenant,
          workspace.revision,
        ),
      this.db
        .prepare(
          'INSERT INTO events (id,tenant,time,kind,body,environment_id) SELECT ?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM workspaces WHERE id = ? AND mutation = ?)',
        )
        .bind(
          event.id,
          tenant,
          event.time,
          event.kind,
          JSON.stringify(event),
          event.environmentId ?? null,
          tenant,
          mutation,
        ),
    ];
    if (changed.history) {
      statements.push(this.historyInsert(tenant, mutation, changed.history));
      statements.push(
        this.db
          .prepare(
            'DELETE FROM policy_history WHERE tenant = ? AND policy_id = ? AND id NOT IN (SELECT id FROM policy_history WHERE tenant = ? AND policy_id = ? ORDER BY version DESC LIMIT 50) AND EXISTS (SELECT 1 FROM workspaces WHERE id = ? AND mutation = ?)',
          )
          .bind(
            tenant,
            changed.objectId,
            tenant,
            changed.objectId,
            tenant,
            mutation,
          ),
      );
    }
    const results = await this.db.batch(statements);
    assert(
      results[0].meta.changes === 1,
      'Workspace changed. Refresh and retry.',
      409,
    );
    return { ok: true, revision: workspace.revision + 1, id: changed.objectId };
  }
  async importConfiguration(
    tenant: string,
    actor: string,
    input: ApiInput,
    preview = false,
  ) {
    const workspace = await this.workspace(tenant);
    assert(
      input.revision === workspace.revision,
      'This workspace changed. Review the import again.',
      409,
    );
    const prepared = prepareImport(
      workspace.snapshot,
      input.configuration,
      this.cedar,
    );
    const result = {
      revision: workspace.revision,
      changes: prepared.changes,
      publishedPolicies: prepared.publishedPolicies,
    };
    if (preview) return result;
    const marker = uid('import');
    const event = {
      id: uid('evt'),
      time: prepared.time,
      kind: 'administration',
      actor,
      operation: 'import',
      objectType: 'configuration',
      name: 'Configuration import',
      changes: prepared.changes,
      environmentIds: prepared.snapshot.environments.map((e) => e.id),
      policyIds: prepared.snapshot.policies.map((p) => p.id),
      resourceTypes: [
        ...new Set(prepared.snapshot.resources.map((r) => r.type)),
      ],
    };
    const statements = [
      this.db
        .prepare(
          'UPDATE workspaces SET snapshot = ?, revision = revision + 1, sequence = sequence + 1, mutation = ?, updated_at = ? WHERE id = ? AND revision = ?',
        )
        .bind(
          JSON.stringify(prepared.snapshot),
          marker,
          prepared.time,
          tenant,
          workspace.revision,
        ),
      this.db
        .prepare(
          'INSERT INTO events (id,tenant,time,kind,body) SELECT ?,?,?,?,? WHERE EXISTS (SELECT 1 FROM workspaces WHERE id = ? AND mutation = ?)',
        )
        .bind(
          event.id,
          tenant,
          event.time,
          event.kind,
          JSON.stringify(event),
          tenant,
          marker,
        ),
    ];
    for (const history of prepared.histories) {
      statements.push(this.historyInsert(tenant, marker, history));
      statements.push(
        this.db
          .prepare(
            'DELETE FROM policy_history WHERE tenant = ? AND policy_id = ? AND id NOT IN (SELECT id FROM policy_history WHERE tenant = ? AND policy_id = ? ORDER BY version DESC LIMIT 50) AND EXISTS (SELECT 1 FROM workspaces WHERE id = ? AND mutation = ?)',
          )
          .bind(
            tenant,
            history.policyId,
            tenant,
            history.policyId,
            tenant,
            marker,
          ),
      );
    }
    const committed = await this.db.batch(statements);
    assert(
      committed[0].meta.changes === 1,
      'This workspace changed. Review the import again.',
      409,
    );
    return { ...result, revision: workspace.revision + 1 };
  }
  async bundle(
    tenant: string,
    environmentIds: string[],
    client: { id: string; name: string },
  ) {
    assert(client?.id && client.name, 'A client identity is required');
    const workspace = await this.workspace(tenant);
    for (const id of environmentIds)
      ancestors(workspace.snapshot.environments, id);
    const allowed = [
      ...new Set(
        environmentIds.flatMap((id) =>
          descendants(workspace.snapshot.environments, id),
        ),
      ),
    ].sort();
    assert(allowed.length, 'Choose an existing environment');
    const snapshot = publishedSnapshot(workspace.snapshot);
    const policyIds = new Set(
      allowed.flatMap((id) => effectivePolicies(snapshot, id).map((p) => p.id)),
    );
    const bundle: Bundle = {
      ...snapshot,
      policies: snapshot.policies.filter((p) => policyIds.has(p.id)),
      schema: SCHEMA,
      schemaVersion: SCHEMA_VERSION,
      tenant,
      sequence: workspace.sequence,
      bundleId: `policies_${workspace.sequence}`,
      createdAt: workspace.updated_at,
      environmentIds: allowed,
      minimumClientVersion: BUNDLE_MINIMUM_CLIENT_VERSION,
      client,
    };
    return signBundle(
      bundle,
      this.signingKey ?? JSON.parse(workspace.private_key),
    );
  }
  async bundleForClient(tenant: string, clientId: string) {
    const client = await this.db
      .prepare('SELECT * FROM clients WHERE tenant = ? AND id = ?')
      .bind(tenant, clientId)
      .first<ClientRow>();
    assert(client, 'Client not found in this workspace', 404);
    assert(
      !client.revoked && (!client.expires_at || client.expires_at > now()),
      'Select an active client; this client is expired or revoked',
      403,
    );
    return this.bundle(tenant, JSON.parse(client.environment_ids), {
      id: client.id,
      name: client.name,
    });
  }
  async environmentActivity(tenant: string, environmentId: string) {
    ancestors(
      (await this.workspace(tenant)).snapshot.environments,
      environmentId,
    );
    const rows = await this.db
      .prepare(
        "SELECT body FROM events WHERE tenant = ? AND environment_id = ? AND kind = 'decision' ORDER BY time DESC, id DESC LIMIT 50",
      )
      .bind(tenant, environmentId)
      .all();
    return rows.results.map((x) => JSON.parse(x.body));
  }
  async enroll(tenant: string, actor: string, input: ApiInput) {
    const w = await this.workspace(tenant);
    const name = bounded(input.name);
    const nameConflict =
      'Client name already exists in this workspace. Choose a different name.';
    const existing = await this.db
      .prepare('SELECT id FROM clients WHERE tenant = ? AND name = ? LIMIT 1')
      .bind(tenant, name)
      .first();
    assert(!existing, nameConflict, 409);
    assert(
      Array.isArray(input.environmentIds) && input.environmentIds.length > 0,
      'Choose at least one environment',
    );
    for (const id of input.environmentIds)
      ancestors(w.snapshot.environments, id);
    const token = uid('cleo') + crypto.randomUUID().replaceAll('-', '');
    const id = uid('client');
    const created = now();
    let expiresAt: string | null = null;
    if (input.expiresAt !== undefined && input.expiresAt !== null) {
      assert(
        typeof input.expiresAt === 'string' &&
          Number.isFinite(Date.parse(input.expiresAt)) &&
          Date.parse(input.expiresAt) > Date.now(),
        'Expiration must be a future date and time',
      );
      expiresAt = new Date(input.expiresAt).toISOString();
    }
    try {
      await this.db.batch([
        this.db
          .prepare(
            'INSERT INTO clients (id,tenant,token_hash,name,environment_ids,created_at,expires_at,revoked) VALUES (?,?,?,?,?,?,?,0)',
          )
          .bind(
            id,
            tenant,
            await digest(token),
            name,
            JSON.stringify(input.environmentIds),
            created,
            expiresAt,
          ),
        this.db
          .prepare(
            'INSERT INTO events (id,tenant,time,kind,body) VALUES (?,?,?,?,?)',
          )
          .bind(
            uid('evt'),
            tenant,
            created,
            'administration',
            JSON.stringify({
              id: uid('evt'),
              time: created,
              kind: 'administration',
              actor,
              operation: 'enroll',
              name,
              clientId: id,
              clientName: name,
              environmentIds: [
                ...new Set(
                  input.environmentIds.flatMap((env) =>
                    descendants(w.snapshot.environments, env),
                  ),
                ),
              ],
            }),
          ),
      ]);
    } catch (error) {
      // The database guard is authoritative if another request wins the race.
      if (error instanceof Error && error.message === nameConflict)
        throw new ApiError(nameConflict, 409);
      throw error;
    }
    return {
      clientId: id,
      clientName: name,
      token,
      tenant,
      publicKey: w.publicKey,
      environmentIds: input.environmentIds,
      expiresAt,
      environment: input.environmentIds[0],
    };
  }
  async authorizeClient(token: string) {
    const client = await this.db
      .prepare(
        'SELECT * FROM clients WHERE token_hash = ? AND revoked = 0 AND (expires_at IS NULL OR expires_at > ?)',
      )
      .bind(await digest(token), now())
      .first<ClientRow>();
    assert(client, 'Client credential is invalid, expired, or revoked', 401);
    return {
      ...client,
      environmentIds: JSON.parse(client.environment_ids) as string[],
    };
  }
  async ingest(tenant: string, clientId: string, input: ApiInput) {
    assert(
      Array.isArray(input.events) && input.events.length <= 100,
      'Send at most 100 events',
    );
    const client = await this.db
      .prepare('SELECT * FROM clients WHERE tenant = ? AND id = ?')
      .bind(tenant, clientId)
      .first<ClientRow>();
    assert(client, 'Client not found', 404);
    const workspace = await this.workspace(tenant);
    const assigned = (JSON.parse(client.environment_ids) as string[]).filter(
      (id) => workspace.snapshot.environments.some((env) => env.id === id),
    );
    const allowed = new Set(
      assigned.flatMap((id) =>
        descendants(workspace.snapshot.environments, id),
      ),
    );
    const statements = input.events.map((e) => {
      const environmentId =
        typeof e.environmentId === 'string' ? e.environmentId : undefined;
      if (environmentId)
        assert(
          allowed.has(environmentId),
          'Event environment is outside this client assignment',
          403,
        );
      let assessment;
      try {
        assessment = validateAssessment(e.assessment, {
          principal: client.name,
          action: e.action,
          resource: e.resource,
          environment: environmentId,
        });
      } catch (error) {
        throw new ApiError((error as Error).message, 400);
      }
      // Preserve only the explicitly validated Cedar input; exclude unrelated raw event data.
      const event = {
        assessment,
        id: bounded(e.id, 150),
        time:
          typeof e.time === 'string' &&
          Number.isFinite(Date.parse(e.time)) &&
          Date.parse(e.time) <= Date.now() + 300000
            ? new Date(e.time).toISOString()
            : now(),
        receivedAt: now(),
        kind: 'decision',
        clientId,
        clientName: client.name,
        environmentId,
        policyId:
          typeof e.policyId === 'string' ? e.policyId.slice(0, 150) : undefined,
        policyName:
          typeof e.policyName === 'string'
            ? e.policyName.slice(0, 200)
            : undefined,
        policyVersion: Number.isSafeInteger(e.policyVersion)
          ? e.policyVersion
          : undefined,
        sessionId: (typeof e.sessionId === 'string' ? e.sessionId : '').slice(
          0,
          150,
        ),
        action:
          typeof e.action === 'string' && Object.hasOwn(ACTIONS, e.action)
            ? e.action
            : 'unknown',
        resourceType:
          typeof e.action === 'string' && Object.hasOwn(ACTIONS, e.action)
            ? ACTIONS[e.action]
            : undefined,
        resource: (typeof e.resource === 'string' ? e.resource : '').slice(
          0,
          250,
        ),
        decision:
          e.decision === 'ALLOW'
            ? 'ALLOW'
            : e.decision === 'ERROR'
              ? 'ERROR'
              : 'DENY',
        effectiveResult: [
          'ALLOWED',
          'ALLOWED_AUDIT',
          'BLOCKED',
          'ERROR',
        ].includes(String(e.effectiveResult))
          ? e.effectiveResult
          : 'ERROR',
        mode: e.mode === 'ENFORCE' ? 'ENFORCE' : 'AUDIT',
        bundleId: (typeof e.bundleId === 'string' ? e.bundleId : '').slice(
          0,
          100,
        ),
        sequence: Number.isSafeInteger(e.sequence) ? e.sequence : 0,
        determiningPolicies: Array.isArray(e.determiningPolicies)
          ? e.determiningPolicies
              .filter((x) => typeof x === 'string')
              .slice(0, 50)
          : [],
        adapter: (typeof e.adapter === 'string' ? e.adapter : 'explicit').slice(
          0,
          80,
        ),
        confidence: [
          'semantic',
          'configured',
          'unknown',
          'proxy-observed',
        ].includes(String(e.confidence))
          ? e.confidence
          : 'unknown',
      };
      return this.db
        .prepare(
          'INSERT OR IGNORE INTO events (id,tenant,time,kind,body,environment_id) VALUES (?,?,?,?,?,?)',
        )
        .bind(
          `${clientId}:${event.id}`,
          tenant,
          event.time,
          'decision',
          JSON.stringify(event),
          environmentId ?? null,
        );
    });
    statements.push(
      this.db
        .prepare('UPDATE clients SET last_seen = ? WHERE tenant = ? AND id = ?')
        .bind(now(), tenant, clientId),
    );
    await this.db.batch(statements);
    return { accepted: input.events.length };
  }
  async handle(
    request: Request,
    browserUser: { id: string; name: string } | null,
  ): Promise<Response> {
    try {
      const url = new URL(request.url);
      const route = url.pathname.replace(/^\/api\/v1\/?/, '');
      const token = request.headers
        .get('authorization')
        ?.replace(/^Bearer /, '');
      const client = token ? await this.authorizeClient(token) : null;
      assert(client || browserUser, 'Sign in to use this workspace', 401);
      const tenant = client?.tenant ?? browserUser!.id;
      const actor = client?.name ?? browserUser!.name;
      if (client)
        assert(
          ['bundles', 'audit', 'heartbeat'].includes(route),
          'Client credentials cannot administer policies',
          403,
        );
      if (request.method !== 'GET' && !client) {
        const origin = request.headers.get('origin');
        assert(
          origin && origin === requestOrigin(request),
          'Cross-origin mutation rejected',
          403,
        );
      }
      if (request.method === 'GET') {
        if (route === 'configuration') {
          const configuration = exportConfiguration(
            (await this.workspace(tenant)).snapshot,
          );
          const json = JSON.stringify(configuration, null, 2);
          assert(
            new TextEncoder().encode(json).length < CONFIGURATION_MAX_BYTES,
            'Configuration exceeds the 32 MiB transfer limit',
            413,
          );
          return new Response(json, {
            headers: {
              'content-type': 'application/json',
              'content-disposition':
                'attachment; filename="cleopatr-configuration.json"',
              'cache-control': 'no-store',
            },
          });
        }
        if (route === 'state') return Response.json(await this.state(tenant));
        if (route === 'activity')
          return Response.json(
            await queryActivity(this.db, tenant, url.searchParams),
          );
        if (route === 'bundles') {
          const clientId = client?.id ?? url.searchParams.get('clientId');
          assert(
            clientId,
            'Select a client before downloading a policy bundle',
          );
          const bundle = await this.bundleForClient(tenant, bounded(clientId));
          if (request.headers.get('if-none-match') === `"${bundle.digest}"`)
            return new Response(null, {
              status: 304,
              headers: {
                etag: `"${bundle.digest}"`,
                'cache-control': 'private, no-cache',
              },
            });
          return Response.json(bundle, {
            headers: {
              etag: `"${bundle.digest}"`,
              'cache-control': 'private, no-cache',
            },
          });
        }
        if (route === 'history')
          return Response.json(
            await this.history(tenant, bounded(url.searchParams.get('policy'))),
          );
        if (route === 'environment-activity')
          return Response.json(
            await this.environmentActivity(
              tenant,
              bounded(url.searchParams.get('environment')),
            ),
          );
      }
      assert(request.method === 'POST', 'Route not found', 404);
      const limit = ['configuration/import', 'configuration/preview'].includes(
        route,
      )
        ? CONFIGURATION_MAX_BYTES
        : 200000;
      const reader = request.body?.getReader();
      const chunks: Uint8Array[] = [];
      let size = 0;
      if (reader)
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          size += value.byteLength;
          if (size >= limit) {
            await reader.cancel();
            throw new ApiError('Request is too large', 413);
          }
          chunks.push(value);
        }
      const bytes = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
      }
      const body = new TextDecoder().decode(bytes);
      const input: ApiInput = JSON.parse(body || '{}');
      if (route === 'configuration/preview' || route === 'configuration/import')
        return Response.json(
          await this.importConfiguration(
            tenant,
            actor,
            input,
            route.endsWith('/preview'),
          ),
        );
      if (route === 'mutate')
        return Response.json(await this.mutation(tenant, actor, input));
      if (route === 'validate')
        return Response.json(
          validatePolicies(this.cedar, [
            { id: 'candidate', cedar: bounded(input.cedar, 30000) },
          ]),
        );
      if (route === 'simulate') {
        assert(input.request, 'A canonical request is required');
        const w = await this.workspace(tenant);
        if (input.controlType)
          return Response.json(simulateControl(this.cedar, w.snapshot, input));
        let snapshot: Snapshot =
          input.source === 'PUBLISHED'
            ? publishedSnapshot(w.snapshot)
            : w.snapshot;
        if (input.cedar) {
          const check = validatePolicies(this.cedar, [
            { id: 'candidate', cedar: input.cedar },
          ]);
          assert(check.valid, check.errors.join('\n'));
          snapshot = {
            ...snapshot,
            policies: [
              ...snapshot.policies.filter(
                (p: Policy) => p.id !== input.policyId,
              ),
              {
                id: 'candidate',
                name: 'Candidate',
                description: '',
                cedar: input.cedar,
                environmentIds: [input.request.environmentId],
                enabled: true,
                revision: 0,
                updatedAt: now(),
              },
            ],
          };
        }
        return Response.json({
          ...evaluateWithModes(this.cedar, snapshot, input.request),
          source: input.source === 'PUBLISHED' ? 'PUBLISHED' : 'DRAFT',
          engine: this.cedar.getCedarVersion(),
        });
      }
      if (route === 'generate') {
        assert(
          this.authoring?.endpoint,
          'AI drafting is not configured. Use the rule builder or Cedar editor, or configure CLEO_AUTHORING_ENDPOINT on the server.',
          503,
        );
        const requirement = bounded(input.requirement, 4000);
        const w = await this.workspace(tenant);
        const response = await fetch(this.authoring.endpoint, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            ...(this.authoring.token
              ? { authorization: `Bearer ${this.authoring.token}` }
              : {}),
          },
          body: JSON.stringify({
            requirement,
            schema: SCHEMA,
            resources: w.snapshot.resources,
            policies: w.snapshot.policies,
            contract: {
              cedar: 'string',
              assumptions: 'string[]',
              testCases: 'ActionRequest[]',
            },
          }),
          signal: AbortSignal.timeout(30000),
          redirect: 'error',
        });
        assert(
          response.ok,
          'The authoring provider failed; no policy was changed',
          502,
        );
        const candidate = (await response.json()) as {
          cedar: string;
          assumptions?: string[];
          model?: string;
          testCases?: unknown[];
        };
        const check = validatePolicies(this.cedar, [
          { id: 'candidate', cedar: bounded(candidate.cedar, 30000) },
        ]);
        assert(
          check.valid,
          'The generated draft failed Cedar validation: ' +
            check.errors.join('; '),
          422,
        );
        await this.db
          .prepare(
            'INSERT INTO events (id,tenant,time,kind,body) VALUES (?,?,?,?,?)',
          )
          .bind(
            uid('evt'),
            tenant,
            now(),
            'authoring',
            JSON.stringify({
              id: uid('evt'),
              time: now(),
              kind: 'authoring',
              actor,
              requirement,
              candidate: candidate.cedar,
              assumptions: candidate.assumptions ?? [],
              model: candidate.model ?? 'external provider',
              validation: check,
            }),
          )
          .run();
        return Response.json({ ...candidate, validation: check });
      }
      if (route === 'enroll')
        return Response.json(await this.enroll(tenant, actor, input));
      if (route === 'revoke') {
        const target = await this.db
          .prepare('SELECT * FROM clients WHERE tenant = ? AND id = ?')
          .bind(tenant, bounded(input.id))
          .first<ClientRow>();
        assert(target, 'Client not found', 404);
        const workspace = await this.workspace(tenant);
        const environmentIds = (JSON.parse(target.environment_ids) as string[])
          .filter((id) =>
            workspace.snapshot.environments.some((e) => e.id === id),
          )
          .flatMap((id) => descendants(workspace.snapshot.environments, id));
        await this.db
          .prepare('UPDATE clients SET revoked = 1 WHERE id = ? AND tenant = ?')
          .bind(bounded(input.id), tenant)
          .run();
        await this.db
          .prepare(
            'INSERT INTO events (id,tenant,time,kind,body) VALUES (?,?,?,?,?)',
          )
          .bind(
            uid('evt'),
            tenant,
            now(),
            'administration',
            JSON.stringify({
              id: uid('evt'),
              kind: 'administration',
              time: now(),
              actor,
              operation: 'revoke',
              name: target.name,
              clientId: target.id,
              clientName: target.name,
              environmentIds: [...new Set(environmentIds)],
            }),
          )
          .run();
        return Response.json({ ok: true });
      }
      if (route === 'audit') {
        assert(client, 'Use an enrolled client token', 403);
        return Response.json(await this.ingest(tenant, client.id, input));
      }
      if (route === 'heartbeat') {
        assert(client, 'Use an enrolled client token', 403);
        await this.db
          .prepare('UPDATE clients SET last_seen = ? WHERE id = ?')
          .bind(now(), client.id)
          .run();
        return Response.json({ ok: true });
      }
      throw new ApiError('Route not found', 404);
    } catch (error) {
      const status = error instanceof ApiError ? error.status : 400;
      return Response.json(
        { error: error instanceof Error ? error.message : 'Request failed' },
        { status, headers: { 'cache-control': 'no-store' } },
      );
    }
  }
}
