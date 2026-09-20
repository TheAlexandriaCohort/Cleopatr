import { mkdir, writeFile } from 'node:fs/promises';
import {
  SCHEMA,
  type Bundle,
  type Policy,
  type Resource,
} from '../../core/model.ts';
import { signBundle } from '../../core/crypto.ts';
import * as cedar from '@cedar-policy/cedar-wasm/nodejs';
import { validatePolicies } from '../../core/engine.ts';
const output = process.argv[2];
if (!output) throw new Error('Provide a fixture output directory');
await mkdir(output, { recursive: true });
const key = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
  'sign',
  'verify',
]);
const publicKey = await crypto.subtle.exportKey('jwk', key.publicKey);
const privateKey = await crypto.subtle.exportKey('jwk', key.privateKey);
const resources: Resource[] = [
  ['bin', 'File', '/bin'],
  ['shell-stdin', 'File', '/dev'],
  ['temporary', 'File', '/tmp'],
  ['readonly', 'File', '/workspace/readonly'],
  ['writable', 'File', '/workspace/writable'],
  ['busybox', 'Process', '/bin/busybox'],
  ['origin', 'Endpoint', 'http://127.0.0.1:19090'],
  ['syscall-probe', 'Process', '/bin/syscall-probe'],
  ['test-db', 'Database', 'postgres://127.0.0.1:19091/test?tls=disable'],
  ['dns-alias', 'Database', 'postgres://blocked.test/test'],
].map(([id, type, locator]) => ({
  id,
  type: type as Resource['type'],
  locator,
  name: id,
  description: '',
  environmentId: 'test',
}));
const policy = (id: string, cedar: string): Policy => ({
  id,
  name: id,
  cedar,
  enabled: true,
  description: '',
  environmentIds: ['test'],
  revision: 1,
  updatedAt: '',
  status: 'PUBLISHED',
});
const bundle: Bundle = {
  tenant: 'kernel-test',
  sequence: 1,
  schemaVersion: '3.0',
  minimumClientVersion: '0.3.0',
  bundleId: 'kernel-test-1',
  createdAt: new Date().toISOString(),
  schema: SCHEMA,
  environmentIds: ['test'],
  client: { id: 'test-client', name: 'Kernel test agent' },
  resources,
  environments: [
    {
      id: 'test',
      name: 'Test',
      kind: 'environment',
      parentId: null,
      description: '',
      mode: 'ENFORCE',
    },
  ],
  policies: [
    policy(
      'deny-metadata',
      'forbid(principal, action == Cleopatr::Action::"file.metadata", resource == Cleopatr::File::"readonly") when { context has operation && context.operation == "chmod" };',
    ),
    policy(
      'deny-signal',
      'forbid(principal, action == Cleopatr::Action::"process.signal", resource) when { context has amount && context.amount == 12 };',
    ),
    policy(
      'deny-privilege',
      'forbid(principal, action == Cleopatr::Action::"process.privilege_attempt", resource) when { context has operation && context.operation == "setuid" && context has amount && context.amount == 0 };',
    ),
    policy(
      'deny-listen',
      'forbid(principal, action == Cleopatr::Action::"network.listen", resource) when { context has port && context.port == 23456 };',
    ),
    policy(
      'deny-dns',
      'forbid(principal, action == Cleopatr::Action::"dns.query", resource) when { context has host && context.host == "blocked.test" };',
    ),
    policy(
      'deny-query',
      'forbid(principal, action == Cleopatr::Action::"database.query", resource) when { context has argv && context.argv.contains("SELECT \'blocked\'") };',
    ),
    policy(
      'deny-transaction',
      'forbid(principal, action == Cleopatr::Action::"database.transaction", resource);',
    ),
    policy(
      'allow',
      'permit(principal == Cleopatr::AgentSession::"Kernel test agent", action, resource);',
    ),
    policy(
      'protect',
      'forbid(principal, action in [Cleopatr::Action::"file.write", Cleopatr::Action::"file.create", Cleopatr::Action::"file.delete", Cleopatr::Action::"file.rename"], resource == Cleopatr::File::"readonly");',
    ),
    policy(
      'deny-http',
      'forbid(principal, action == Cleopatr::Action::"http.request", resource) when { context has path && context.path == "/denied" };',
    ),
  ],
};
const validation = validatePolicies(cedar, bundle.policies);
if (!validation.valid) throw new Error(validation.errors.join('; '));
const signed = await signBundle(bundle, privateKey);
await writeFile(
  output + '/config',
  JSON.stringify({
    tenant: bundle.tenant,
    server: 'http://127.0.0.1:19999',
    token: 'test-only-offline',
    publicKey,
    environmentIds: ['test'],
    clientId: 'test-client',
    clientName: 'Kernel test agent',
    environment: 'test',
  }),
);
await writeFile(
  output + '/bundle.json',
  JSON.stringify({
    signed,
    checkedAt: 0,
    activatedAt: Date.now(),
    highWater: 1,
    etag: `"${signed.digest}"`,
  }),
);
