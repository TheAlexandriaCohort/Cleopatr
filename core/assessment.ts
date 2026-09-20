import { ACTIONS, CONTEXT_FIELDS, SCHEMA_VERSION } from './model.ts';

export type EntityId = { type: string; id: string };
export type AssessedPayload = {
  principal: EntityId;
  action: EntityId;
  resource: EntityId;
  context: Record<string, unknown>;
  entities: {
    uid: EntityId;
    attrs: Record<string, string>;
    parents: EntityId[];
  }[];
};
export type Assessment =
  | {
      version: 1;
      status: 'captured';
      schemaVersion: string;
      payload: AssessedPayload;
    }
  | { version: 1; status: 'unavailable'; reason: 'not_evaluated' }
  | { version: 1; status: 'unavailable'; reason: 'too_large'; bytes: number };

export const MAX_ASSESSMENT_BYTES = 128 * 1024;
export const MAX_AUDIT_EVENT_BYTES = 160 * 1024;
export const MAX_AUDIT_BATCH_BYTES = 180 * 1024;
export const jsonBytes = (value: unknown) =>
  new TextEncoder().encode(JSON.stringify(value)).length;

// Capture the engine input, never a reconstruction using today's catalog.
export function captureAssessment(payload: AssessedPayload): Assessment {
  const serialized = JSON.stringify(payload);
  const bytes = new TextEncoder().encode(serialized).length;
  if (bytes > MAX_ASSESSMENT_BYTES)
    return { version: 1, status: 'unavailable', reason: 'too_large', bytes };
  return {
    version: 1,
    status: 'captured',
    schemaVersion: SCHEMA_VERSION,
    payload: JSON.parse(serialized),
  };
}

function check(ok: unknown, message: string): asserts ok {
  if (!ok) throw new Error('Invalid assessed payload: ' + message);
}
function record(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}
function fields(value: Record<string, unknown>, names: string[]) {
  check(
    Object.keys(value).length === names.length &&
      names.every((name) => Object.hasOwn(value, name)),
    'unexpected fields',
  );
}
function entity(value: unknown): asserts value is EntityId {
  check(record(value), 'entity must be an object');
  fields(value, ['type', 'id']);
  check(
    typeof value.type === 'string' &&
      typeof value.id === 'string' &&
      value.type.length > 0,
    'entity identity is required',
  );
}

// This preserves the captured JSON exactly after validating its bounded shape.
// Other, arbitrary event fields remain excluded by the audit ingestion allowlist.
export function validateAssessment(
  value: unknown,
  expected: {
    principal: string;
    action: unknown;
    resource: unknown;
    environment: string | undefined;
  },
): Assessment | undefined {
  if (value === undefined) return undefined; // Old clients and historical events.
  check(record(value) && value.version === 1, 'unsupported format');
  if (value.status === 'unavailable') {
    if (value.reason === 'not_evaluated')
      fields(value, ['version', 'status', 'reason']);
    else {
      fields(value, ['version', 'status', 'reason', 'bytes']);
      check(
        value.reason === 'too_large' &&
          Number.isSafeInteger(value.bytes) &&
          Number(value.bytes) > MAX_ASSESSMENT_BYTES,
        'invalid capture limit',
      );
    }
    return value as Assessment;
  }
  fields(value, ['version', 'status', 'schemaVersion', 'payload']);
  check(
    value.status === 'captured' && value.schemaVersion === SCHEMA_VERSION,
    'unsupported schema',
  );
  const payload = value.payload;
  check(
    record(payload) && jsonBytes(payload) <= MAX_ASSESSMENT_BYTES,
    'payload is too large',
  );
  fields(payload, ['principal', 'action', 'resource', 'context', 'entities']);
  entity(payload.principal);
  entity(payload.action);
  entity(payload.resource);
  check(
    payload.principal.type === 'Cleopatr::AgentSession' &&
      payload.principal.id === expected.principal,
    'principal must match the enrolled client name',
  );
  check(
    payload.action.type === 'Cleopatr::Action' &&
      payload.action.id === expected.action &&
      Object.hasOwn(ACTIONS, payload.action.id),
    'action differs from event',
  );
  check(
    payload.resource.type === `Cleopatr::${ACTIONS[payload.action.id]}` &&
      payload.resource.id === expected.resource,
    'resource differs from event',
  );
  check(record(payload.context), 'context must be an object');
  for (const [key, item] of Object.entries(payload.context)) {
    const type = CONTEXT_FIELDS[key];
    check(
      type &&
        ((type === 'String' && typeof item === 'string') ||
          (type === 'Long' && Number.isSafeInteger(item)) ||
          (type === 'Boolean' && typeof item === 'boolean') ||
          (type === 'Set' &&
            Array.isArray(item) &&
            item.every((x) => typeof x === 'string'))),
      `unsupported context.${key}`,
    );
  }
  check(
    Array.isArray(payload.entities) && payload.entities.length === 2,
    'expected principal and resource entities',
  );
  for (const [index, item] of payload.entities.entries()) {
    check(record(item), 'invalid entity');
    fields(item, ['uid', 'attrs', 'parents']);
    entity(item.uid);
    const uid = index === 0 ? payload.principal : payload.resource;
    check(
      item.uid.type === uid.type && item.uid.id === uid.id,
      'entity identity differs from request',
    );
    check(record(item.attrs), 'entity attributes are required');
    fields(
      item.attrs,
      index === 0
        ? ['environment', 'workspace', 'humanId']
        : ['name', 'environment', 'locator'],
    );
    check(
      Object.values(item.attrs).every((x) => typeof x === 'string'),
      'invalid entity attribute',
    );
    check(
      Array.isArray(item.parents) && item.parents.length === 0,
      'unexpected entity parents',
    );
    if (index === 0)
      check(
        item.attrs.environment === expected.environment,
        'environment differs from event',
      );
  }
  return JSON.parse(JSON.stringify(value)) as Assessment;
}
