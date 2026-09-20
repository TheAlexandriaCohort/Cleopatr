import type {
  Snapshot,
  Policy,
  Environment,
  Resource,
  EnvironmentMode,
  PolicyHistory,
  ActionRequest,
} from './model';
import type { evaluate } from './engine';
import type { Assessment } from './assessment';
export type DraftItem = Partial<Policy & Environment & Resource>;
export type ApiInput = {
  revision?: number;
  kind?: string;
  operation?: string;
  item?: DraftItem;
  mode?: EnvironmentMode;
  publish?: boolean;
  policyIds?: string[];
  source?: 'DRAFT' | 'PUBLISHED';
  controlType?: 'POLICY' | 'ENVIRONMENT';
  controlId?: string;
  name?: string;
  note?: string;
  environmentIds?: string[];
  expiresAt?: string | null;
  events?: Record<string, unknown>[];
  request?: ActionRequest;
  cedar?: string;
  policyId?: string;
  id?: string;
  requirement?: string;
};
export type EventRecord = {
  assessment?: Assessment;
  id: string;
  time: string;
  kind: string;
  sessionId?: string;
  action?: string;
  resource?: string;
  resourceType?: string;
  resourceTypes?: string[];
  environmentIds?: string[];
  policyIds?: string[];
  objectId?: string;
  recordId?: string;
  decision?: string;
  effectiveResult?: string;
  mode?: EnvironmentMode;
  bundleId?: string;
  environmentId?: string;
  clientId?: string;
  clientName?: string;
  policyId?: string;
  policyName?: string;
  policyVersion?: number;
  sequence?: number;
  determiningPolicies?: string[];
  adapter?: string;
  confidence?: unknown;
  actor?: string;
  operation?: string;
  objectType?: string;
  name?: string;
  note?: string;
};
export type ClientRecord = {
  id: string;
  name: string;
  environment_ids: string;
  created_at: string;
  expires_at: string | null;
  last_seen: string | null;
  revoked: number;
};
export type Enrollment = {
  clientId: string;
  clientName: string;
  token: string;
  tenant: string;
  publicKey: JsonWebKey;
  environmentIds: string[];
  expiresAt: string | null;
  environment?: string;
  server?: string;
};
export type AppState = Snapshot & {
  revision: number;
  tenant: string;
  publicKey: JsonWebKey;
  sequence: number;
  events: EventRecord[];
  clients: ClientRecord[];
  engine: string;
};
export type Simulation = ReturnType<typeof evaluate> & {
  controlType?: 'POLICY' | 'ENVIRONMENT';
  controlId?: string;
  controlName?: string;
  environmentName?: string;
  contextSource?: string;
  policyNames?: Record<string, string>;
  mode?: EnvironmentMode;
  effectiveResult?: string;
  source: string;
  engine: string;
};
export type HistoryResponse = {
  current?: Policy['published'];
  previous: PolicyHistory[];
};

export type ActivityResponse = {
  events: EventRecord[];
  total: number;
  nextCursor: string | null;
  principals: string[];
};
