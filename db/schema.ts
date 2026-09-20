import {
  sqliteTable,
  text,
  integer,
  index,
  uniqueIndex,
} from 'drizzle-orm/sqlite-core';
export const workspaces = sqliteTable('workspaces', {
  id: text('id').primaryKey(),
  snapshot: text('snapshot').notNull(),
  revision: integer('revision').notNull().default(1),
  sequence: integer('sequence').notNull().default(0),
  mutation: text('mutation').notNull(),
  publicKey: text('public_key').notNull(),
  privateKey: text('private_key').notNull(),
  modelVersion: integer('model_version').notNull().default(1),
  updatedAt: text('updated_at').notNull().default('1970-01-01T00:00:00.000Z'),
});
// Retained only as a read-once migration archive for pre-0.2 workspaces.
export const legacySnapshots = sqliteTable(
  'releases',
  {
    id: text('id').primaryKey(),
    tenant: text('tenant').notNull(),
    sequence: integer('sequence').notNull(),
    body: text('body').notNull(),
  },
  (t) => [uniqueIndex('releases_tenant_sequence').on(t.tenant, t.sequence)],
);
export const revisions = sqliteTable(
  'revisions',
  {
    id: text('id').primaryKey(),
    tenant: text('tenant').notNull(),
    policyId: text('policy_id').notNull(),
    body: text('body').notNull(),
    time: text('time').notNull(),
  },
  (t) => [index('revisions_tenant_policy').on(t.tenant, t.policyId)],
);
export const policyHistory = sqliteTable(
  'policy_history',
  {
    id: text('id').primaryKey(),
    tenant: text('tenant').notNull(),
    policyId: text('policy_id').notNull(),
    version: integer('version').notNull(),
    body: text('body').notNull(),
    supersededAt: text('superseded_at').notNull(),
  },
  (t) => [
    uniqueIndex('policy_history_version').on(t.tenant, t.policyId, t.version),
  ],
);
export const clients = sqliteTable(
  'clients',
  {
    id: text('id').primaryKey(),
    tenant: text('tenant').notNull(),
    tokenHash: text('token_hash').notNull(),
    name: text('name').notNull(),
    environmentIds: text('environment_ids').notNull(),
    createdAt: text('created_at').notNull(),
    expiresAt: text('expires_at'),
    lastSeen: text('last_seen'),
    revoked: integer('revoked').notNull().default(0),
  },
  (t) => [
    uniqueIndex('clients_token').on(t.tokenHash),
    index('clients_tenant').on(t.tenant),
  ],
);
export const events = sqliteTable(
  'events',
  {
    id: text('id').primaryKey(),
    tenant: text('tenant').notNull(),
    time: text('time').notNull(),
    kind: text('kind').notNull(),
    body: text('body').notNull(),
    environmentId: text('environment_id'),
  },
  (t) => [
    index('events_tenant_time').on(t.tenant, t.time),
    index('events_environment_time').on(
      t.tenant,
      t.environmentId,
      t.kind,
      t.time,
    ),
  ],
);
