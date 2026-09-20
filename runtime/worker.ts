import { Buffer } from 'node:buffer';
import { createInterface } from 'node:readline';
import {
  loadBundle,
  requestRefresh,
  refreshWorker,
  dataDir,
} from '../cli/cache.ts';
import { resolveEnvironment } from '../cli/options.ts';
import { createPinnedAuthorizer, flushAudit } from '../cli/runtime.ts';
import { compileProfile, requireExecutableGrant } from './profile.ts';
import { createDnsAdapter, startDnsTcp } from './adapters/dns.ts';
import { startDatabaseProxy, databaseTarget } from './adapters/database.ts';
import { networkResource } from './network.ts';
import { isIP } from 'node:net';
import type { ActionRequest } from '../core/model.ts';
import type { Decide } from './adapters/http.ts';
import { startHttpProxy } from './adapters/http.ts';

if (process.getuid?.() !== 0 || process.env.CLEO_SUPERVISOR !== '1')
  throw new Error('Policy worker must be started by the privileged supervisor');
if (process.argv[2] === '__refresh') {
  await refreshWorker();
  await flushAudit().catch(() => {});
  process.exit(0);
}
const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
const output = (value: unknown) =>
  process.stdout.write(JSON.stringify(value) + '\n');
const closers: (() => void)[] = [];
let decide!: Decide;
let dns!: (packet: Buffer) => Promise<Buffer>;
let resources: ReturnType<typeof compileProfile>['resources'] = [];
let sequence: number | undefined;
try {
  for await (const line of lines) {
    if (line.length > 65536) throw new Error('Supervisor message too large');
    const message = JSON.parse(line);
    if (message.op === 'start' && sequence === undefined) {
      const loaded = await loadBundle(dataDir());
      const { bundle, config } = loaded;
      const environmentId = resolveEnvironment(
        bundle,
        message.request.environment ??
          config.environment ??
          config.environmentIds[0],
      );
      const principal = bundle.client?.name ?? config.clientName;
      if (!principal) throw new Error('Signed client identity is required');
      const sessionId = 'agt_' + crypto.randomUUID();
      if (message.request.audit && message.request.enforce)
        throw new Error('Conflicting execution modes');
      const mode =
        message.request.audit === true
          ? 'AUDIT'
          : message.request.enforce === true
            ? 'ENFORCE'
            : undefined;
      const profile = compileProfile(
        bundle,
        environmentId,
        principal,
        message.request.enforce === true,
        message.request.audit === true,
      );
      requireExecutableGrant(profile);
      resources = profile.resources;
      const pinned = createPinnedAuthorizer(loaded, {
        mode,
        entry: process.argv[1],
        adapter: 'enclave',
        expectedSequence: bundle.sequence,
      });
      decide = async (action, resource, context) => {
        if (action === 'network.connect') {
          const catalog = networkResource(resources, resource.id);
          if (catalog) resource = { type: 'Network', id: catalog.id };
          if (
            typeof context.host === 'string' &&
            !isIP(context.host.replace(/^\[|\]$/g, ''))
          ) {
            const dnsResource = networkResource(
              resources,
              `dns://${context.host}`,
            );
            if (
              !(await decide(
                'dns.query',
                {
                  type: 'Network',
                  id: dnsResource?.id ?? `dns://${context.host}`,
                },
                {
                  host: context.host,
                  operation: 'LOOKUP',
                  protocol: 'dns',
                  confidence: 'adapter-observed',
                  semanticAvailable: true,
                },
              ))
            )
              return false;
          }
        }
        const result = await pinned(
          {
            environmentId,
            sessionId,
            action,
            resource,
            context,
            workspace: '/workspace',
          },
          action.startsWith('mcp.')
            ? 'mcp-http'
            : action.startsWith('database.')
              ? 'database-wire'
              : action === 'dns.query'
                ? 'dns-wire'
                : ['http.request', 'network.connect'].includes(action)
                  ? 'http-proxy'
                  : 'seccomp',
        );
        const names = result.determiningPolicies.map((id) =>
          JSON.stringify(
            bundle.policies.find((policy) => policy.id === id)?.name ?? id,
          ),
        );
        process.stderr.write(
          `cleo: ${result.mode} · ${action} · ${result.effectiveResult} · ${names.join(', ') || 'default deny'}\n`,
        );
        return result.allowed;
      };
      const proxy = await startHttpProxy(profile.resources, decide, {
        auditOnly: profile.auditOnly,
        onDiagnostic: (message) => process.stderr.write(`cleo: ${message}\n`),
      });
      closers.push(proxy.close);
      const routes: { host: string; port: number; proxyPort: number }[] = [];
      const aliases = new Map<string, string>();
      for (const resource of profile.resources.filter(
        (r) => r.type === 'Database',
      )) {
        const target = databaseTarget(resource);
        const address = isIP(target.host)
          ? target.host
          : (aliases.get(target.host) ??
            `198.18.${Math.floor(aliases.size / 250)}.${(aliases.size % 250) + 1}`);
        if (!isIP(target.host)) aliases.set(target.host, address);
        if (
          routes.some(
            (route) => route.host === address && route.port === target.port,
          )
        )
          throw new Error(
            'Database route collides with a reserved DNS alias; use distinct endpoint addresses',
          );
        const adapter = await startDatabaseProxy(resource, decide);
        closers.push(adapter.close);
        routes.push({
          host: address,
          port: target.port,
          proxyPort: adapter.port,
        });
      }
      dns = createDnsAdapter(resources, decide, aliases);
      const dnsTcp = await startDnsTcp(dns);
      closers.push(dnsTcp.close);
      sequence = bundle.sequence;
      output({
        sessionId,
        sequence,
        environmentId,
        grants: profile.grants,
        boundaries: profile.boundaries,
        proxyPort: proxy.port,
        dnsPort: dnsTcp.port,
        routes,
      });
    } else if (message.op === 'authorize' && sequence !== undefined) {
      const { action, locator, context } = message;
      const type: ActionRequest['resource']['type'] = action.startsWith(
        'process.',
      )
        ? 'Process'
        : action === 'file.metadata'
          ? 'File'
          : 'Network';
      if (
        ![
          'process.signal',
          'process.privilege_attempt',
          'file.metadata',
          'network.listen',
          'network.connect',
        ].includes(action) ||
        typeof locator !== 'string'
      )
        throw new Error('Invalid kernel action');
      const resource =
        type === 'Network'
          ? networkResource(resources, locator)
          : resources.find(
              (r) =>
                r.type === type &&
                (r.locator === locator ||
                  (type === 'File' && locator.startsWith(r.locator + '/'))),
            );
      output({
        allowed: await decide(
          action,
          { type, id: resource?.id ?? locator },
          context,
        ),
      });
    } else if (message.op === 'dns' && sequence !== undefined) {
      if (
        typeof message.packet !== 'string' ||
        message.packet.length > 8192 ||
        !/^[0-9a-f]+$/.test(message.packet) ||
        message.packet.length % 2
      )
        throw new Error('Invalid DNS packet');
      output({
        packet: Buffer.from(
          await dns(Buffer.from(message.packet, 'hex')),
        ).toString('hex'),
      });
    } else if (message.op === 'check' && sequence !== undefined) {
      await requestRefresh(dataDir()).catch(() => {});
      output({
        current: (await loadBundle(dataDir())).bundle.sequence === sequence,
      });
    } else throw new Error('Invalid supervisor request');
  }
} catch (error) {
  process.stderr.write(`cleo policy worker: ${(error as Error).message}\n`);
  process.exitCode = 1;
} finally {
  for (const close of closers) close();
  lines.close();
  process.stdin.destroy();
}
