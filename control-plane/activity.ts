import type {
  ActivityResponse,
  ApiInput,
  EventRecord,
} from '../core/api-types.ts';
import {
  ACTIONS,
  RESOURCE_TYPES,
  assignmentSnapshot,
  descendants,
  effectivePolicies,
  policyResourceTypes,
  type Snapshot,
} from '../core/model.ts';
import type { Database, DbValue } from './service.ts';
import { assert } from './lifecycle.ts';

// Capture scope at the time of a platform change, including removed assignments.
export function platformScope(
  before: Snapshot,
  after: Snapshot,
  input: ApiInput,
  objectId: string,
) {
  const environmentIds = new Set<string>();
  const policyIds = new Set<string>(input.policyId ? [input.policyId] : []);
  const resourceTypes = new Set<string>();
  if (input.kind === 'policy') policyIds.add(objectId);
  for (const snapshot of [before, after]) {
    if (
      input.kind === 'environment' &&
      snapshot.environments.some((e) => e.id === objectId)
    ) {
      descendants(snapshot.environments, objectId).forEach((id) =>
        environmentIds.add(id),
      );
      if (!input.policyId)
        effectivePolicies(assignmentSnapshot(snapshot), objectId).forEach((p) =>
          policyIds.add(p.id),
        );
    }
    if (input.kind === 'resource') {
      const resource = snapshot.resources.find((r) => r.id === objectId);
      if (resource) {
        resourceTypes.add(resource.type);
        descendants(snapshot.environments, resource.environmentId).forEach(
          (id) => environmentIds.add(id),
        );
        snapshot.policies
          .filter(
            (p) =>
              p.cedar.includes(JSON.stringify(objectId)) ||
              p.published?.cedar.includes(JSON.stringify(objectId)),
          )
          .forEach((p) => policyIds.add(p.id));
      }
    }
  }
  for (const snapshot of [before, after]) {
    for (const policy of snapshot.policies.filter((p) => policyIds.has(p.id))) {
      if (input.kind !== 'resource') {
        policyResourceTypes(policy).forEach((type) => resourceTypes.add(type));
        if (policy.published)
          policyResourceTypes({
            ...policy,
            ...policy.published,
            rule: policy.published.rule,
          }).forEach((type) => resourceTypes.add(type));
      }
    }
    if (input.kind === 'policy') {
      const assigned = assignmentSnapshot(snapshot);
      for (const env of snapshot.environments)
        if (effectivePolicies(assigned, env.id).some((p) => p.id === objectId))
          environmentIds.add(env.id);
    }
  }
  return {
    objectId,
    environmentIds: [...environmentIds],
    policyIds: [...policyIds],
    resourceTypes: [...resourceTypes],
    ...(input.kind === 'resource' ? { resource: objectId } : {}),
  };
}

export function normalizeEvent(event: EventRecord): EventRecord {
  return event.kind === 'release'
    ? {
        ...event,
        kind: 'administration',
        operation: 'publish',
        objectType: 'policies',
        name: event.note,
      }
    : event;
}
const clientName =
  "COALESCE(NULLIF(json_extract(e.body, '$.clientName'), ''), c.name)";
const resourceType = `COALESCE(json_extract(e.body, '$.resourceType'), CASE json_extract(e.body, '$.action') ${Object.entries(
  ACTIONS,
)
  .map(([action, type]) => `WHEN '${action}' THEN '${type}'`)
  .join(' ')} END)`;
const from =
  "FROM events e LEFT JOIN clients c ON c.tenant = e.tenant AND c.id = json_extract(e.body, '$.clientId')";
const PAGE_SIZE = 50;
type Row = {
  id: string;
  time: string;
  body: string;
  client_name: string | null;
  resource_type: string | null;
};

export async function queryActivity(
  db: Database,
  tenant: string,
  params: URLSearchParams,
): Promise<ActivityResponse> {
  const type = params.get('type') ?? 'platform';
  assert(
    type === 'platform' || type === 'decision',
    'Choose Platform or Policy decisions',
  );
  const where = [
    'e.tenant = ?',
    type === 'decision'
      ? "e.kind = 'decision'"
      : "e.kind IN ('administration', 'release')",
  ];
  const values: DbValue[] = [tenant];
  const selection = (key: string, max = 500) => {
    const selected = [...new Set(params.getAll(key))];
    assert(
      selected.length <= max &&
        selected.every((value) => value.length > 0 && value.length <= 200),
      `Invalid ${key} filter`,
    );
    return selected;
  };
  const environments = selection('environment');
  const policies = selection('policy');
  const resources = selection('resource', RESOURCE_TYPES.length);
  const principals = selection('principal');
  assert(
    resources.every((r) => RESOURCE_TYPES.some((t) => t === r)),
    'Invalid resource type',
  );
  if (environments.length) {
    where.push(
      "(COALESCE(e.environment_id, json_extract(e.body, '$.environmentId')) IN (SELECT value FROM json_each(?)) OR EXISTS (SELECT 1 FROM json_each(e.body, '$.environmentIds') a WHERE a.value IN (SELECT value FROM json_each(?))))",
    );
    values.push(JSON.stringify(environments), JSON.stringify(environments));
  }
  if (policies.length) {
    where.push(
      "(json_extract(e.body, '$.policyId') IN (SELECT value FROM json_each(?)) OR EXISTS (SELECT 1 FROM json_each(e.body, '$.policyIds') a WHERE a.value IN (SELECT value FROM json_each(?))) OR EXISTS (SELECT 1 FROM json_each(e.body, '$.determiningPolicies') a WHERE a.value IN (SELECT value FROM json_each(?))))",
    );
    values.push(...Array.from({ length: 3 }, () => JSON.stringify(policies)));
  }
  if (resources.length) {
    where.push(
      `(${resourceType} IN (SELECT value FROM json_each(?)) OR EXISTS (SELECT 1 FROM json_each(e.body, '$.resourceTypes') a WHERE a.value IN (SELECT value FROM json_each(?))))`,
    );
    values.push(JSON.stringify(resources), JSON.stringify(resources));
  }
  if (principals.length) {
    where.push(`${clientName} IN (SELECT value FROM json_each(?))`);
    values.push(JSON.stringify(principals));
  }
  const date = (key: string) => {
    const value = params.get(key);
    if (!value) return undefined;
    assert(
      value.length <= 40 &&
        /T.*(?:Z|[+-]\d{2}:\d{2})$/i.test(value) &&
        Number.isFinite(Date.parse(value)),
      `Invalid ${key} date/time; include a time zone`,
    );
    return new Date(value).toISOString();
  };
  const start = date('from'),
    end = date('to');
  assert(
    !start || !end || start <= end,
    'Start must be before or equal to end',
  );
  if (start) {
    where.push('e.time >= ?');
    values.push(start);
  }
  if (end) {
    where.push('e.time <= ?');
    values.push(end);
  }
  const filter = where.join(' AND ');
  let cursorClause = '';
  const pageValues = [...values];
  if (params.has('cursor')) {
    const raw = params.get('cursor')!;
    assert(raw.length < 1000, 'Invalid activity cursor');
    let cursor: { time?: string; id?: string } | undefined;
    try {
      cursor = JSON.parse(raw);
    } catch {
      /* Report a bounded validation error. */
    }
    assert(
      cursor &&
        typeof cursor.time === 'string' &&
        Number.isFinite(Date.parse(cursor.time)) &&
        typeof cursor.id === 'string' &&
        cursor.id.length <= 400,
      'Invalid activity cursor',
    );
    cursorClause = ' AND (e.time < ? OR (e.time = ? AND e.id < ?))';
    pageValues.push(cursor.time, cursor.time, cursor.id);
  }
  const [rows, count, names] = await Promise.all([
    db
      .prepare(
        `SELECT e.id, e.time, e.body, ${clientName} AS client_name, ${resourceType} AS resource_type ${from} WHERE ${filter}${cursorClause} ORDER BY e.time DESC, e.id DESC LIMIT 51`,
      )
      .bind(...pageValues)
      .all<Row>(),
    db
      .prepare(`SELECT COUNT(*) AS total ${from} WHERE ${filter}`)
      .bind(...values)
      .first<{ total: number }>(),
    db
      .prepare(
        `SELECT DISTINCT ${clientName} AS name ${from} WHERE e.tenant = ? AND e.kind = 'decision' AND ${clientName} IS NOT NULL AND ${clientName} != '' ORDER BY name COLLATE NOCASE, name`,
      )
      .bind(tenant)
      .all<{ name: string }>(),
  ]);
  const page = rows.results.slice(0, PAGE_SIZE);
  const last = page.at(-1);
  return {
    events: page.map((row) => ({
      ...normalizeEvent(JSON.parse(row.body)),
      recordId: row.id,
      ...(row.client_name ? { clientName: row.client_name } : {}),
      ...(row.resource_type ? { resourceType: row.resource_type } : {}),
    })),
    total: count?.total ?? 0,
    nextCursor:
      rows.results.length > PAGE_SIZE && last
        ? JSON.stringify({ time: last.time, id: last.id })
        : null,
    principals: names.results.map((r) => r.name),
  };
}
