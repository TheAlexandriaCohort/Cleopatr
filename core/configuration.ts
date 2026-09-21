import type { Environment, Resource, PolicyVersion } from './model';

export const CONFIGURATION_FORMAT = 'cleopatr-configuration';
export const CONFIGURATION_VERSION = 1;
export const CONFIGURATION_MAX_BYTES = 32 * 1024 * 1024;
export type PolicyConfiguration = Omit<
  PolicyVersion,
  'version' | 'publishedAt'
> & {
  id: string;
  published?: Omit<PolicyVersion, 'version' | 'publishedAt'>;
};
export type Configuration = {
  format: typeof CONFIGURATION_FORMAT;
  version: typeof CONFIGURATION_VERSION;
  exportedAt?: string;
  environments: Environment[];
  resources: Resource[];
  policies: PolicyConfiguration[];
};
export type ImportPreview = {
  revision: number;
  changes: Record<
    'environments' | 'resources' | 'policies',
    { added: number; updated: number }
  >;
  publishedPolicies: number;
};
