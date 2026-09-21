import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net, { type AddressInfo } from 'node:net';
import * as cedar from '@cedar-policy/cedar-wasm/nodejs';
import { evaluateWithModes } from '../core/engine.ts';
import {
  compileProfile,
  requireExecutableGrant,
  rights,
} from '../runtime/profile.ts';
import { startHttpProxy, type Decide } from '../runtime/adapters/http.ts';
import { authorizeMcpBody } from '../runtime/adapters/mcp-http.ts';
import {
  SCHEMA,
  type Bundle,
  type Policy,
  type Resource,
} from '../core/model.ts';

function fixture(): Bundle {
  return {
    schemaVersion: '3.0',
    tenant: 't',
    sequence: 1,
    bundleId: 'b',
    createdAt: new Date().toISOString(),
    minimumClientVersion: '0.3.0',
    environmentIds: ['child'],
    schema: SCHEMA,
    environments: [
      {
        id: 'root',
        name: 'Root',
        parentId: null,
        kind: 'group',
        description: '',
        mode: 'ENFORCE',
      },
      {
        id: 'child',
        name: 'Child',
        parentId: 'root',
        kind: 'environment',
        description: '',
        mode: 'ENFORCE',
      },
    ],
    resources: [
      resource('workspace', 'File', '/workspace'),
      resource('python', 'Process', '/usr/bin/python3'),
    ],
    policies: [policy('permit', 'permit(principal, action, resource);')],
  };
}
function resource(
  id: string,
  type: Resource['type'],
  locator: string,
): Resource {
  return {
    id,
    type,
    locator,
    name: id,
    description: '',
    environmentId: 'root',
  };
}
function policy(id: string, cedar: string): Policy {
  return {
    id,
    cedar,
    name: id,
    enabled: true,
    description: '',
    environmentIds: ['root'],
    revision: 1,
    updatedAt: '',
    status: 'PUBLISHED',
  };
}
void test('opaque tunnels are enabled only when the entire effective session audits', () => {
  const bundle = fixture();
  const profile = (enforce = false, audit = false) =>
    compileProfile(bundle, 'child', 'client', enforce, audit);
  assert.equal(profile().auditOnly, false);
  bundle.environments[1].mode = 'AUDIT';
  assert.equal(
    profile().auditOnly,
    false,
    'ancestor Enforce must remain effective',
  );
  bundle.environments[0].mode = 'AUDIT';
  assert.equal(profile().auditOnly, true);
  assert.equal(profile(true).auditOnly, false);
  bundle.environments[1].mode = 'CUSTOM';
  bundle.environments[1].policyModes = { permit: 'ENFORCE' };
  assert.equal(profile().auditOnly, false);
  assert.equal(profile(false, true).auditOnly, true);
  bundle.policies = [];
  bundle.environments[1].mode = 'ENFORCE';
  assert.equal(
    profile().auditOnly,
    false,
    'empty Enforce must not open tunnels',
  );
});
void test('kernel profile preserves inherited denies and keeps execute separate from file access', () => {
  const bundle = fixture();
  bundle.policies.push(
    policy(
      'delete',
      'forbid(principal, action in [Cleopatr::Action::"file.delete", Cleopatr::Action::"file.rename"], resource);',
    ),
  );
  const profile = compileProfile(bundle, 'child', 'named-client', false);
  const file = profile.grants.find((g) => g.path === '/workspace')!;
  assert.equal(file.access & rights.delete, 0);
  assert.equal(file.access & rights.execute, 0);
  assert.equal(file.access & rights.read, rights.read);
  assert.equal(
    profile.grants.find((g) => g.path === '/usr/bin/python3')?.access,
    rights.execute,
  );
});
void test('kernel profile uses client-name principal and never downgrades environment enforcement', () => {
  const bundle = fixture();
  bundle.policies = [
    policy(
      'named',
      'permit(principal == Cleopatr::AgentSession::"client", action, resource);',
    ),
  ];
  assert.equal(
    compileProfile(bundle, 'child', 'other', false).grants.length,
    0,
  );
  assert.ok(compileProfile(bundle, 'child', 'client', false).grants.length);
  bundle.environments[1].mode = 'AUDIT';
  assert.equal(
    compileProfile(bundle, 'child', 'other', false).grants.length,
    0,
  );
  assert.equal(compileProfile(bundle, 'child', 'other', true).grants.length, 0);
});
void test('explicit audit lifts inherited OS policy denies within the catalog and retains isolation boundaries', () => {
  const bundle = fixture();
  bundle.policies = [policy('deny', 'forbid(principal, action, resource);')];
  assert.equal(
    compileProfile(bundle, 'child', 'client', false).grants.length,
    0,
  );
  bundle.policies.push(
    policy(
      'unsupported',
      'forbid(principal, action == Cleopatr::Action::"process.signal", resource);',
    ),
  );
  const saved = JSON.stringify(bundle);
  const profile = compileProfile(bundle, 'child', 'client', false, true);
  const access = profile.grants.find((g) => g.path === '/workspace')!.access;
  assert.equal(access & rights.write, rights.write);
  assert.equal(access & rights.delete, rights.delete);
  assert.equal(access & rights.execute, 0);
  assert.equal(
    profile.grants.find((g) => g.path === '/usr/bin/python3')?.access,
    rights.execute,
  );
  assert.equal(profile.grants.length, 2);
  assert.equal(JSON.stringify(bundle), saved);
  assert.throws(
    () => compileProfile(bundle, 'child', 'client', true, true),
    /Conflicting/,
  );
  bundle.resources.push(resource('outside', 'File', '/var/lib/cleopatr'));
  assert.throws(
    () => compileProfile(bundle, 'child', 'client', false, true),
    /outside.*sandbox roots/,
  );
});
void test('OS compiler refuses context-dependent permissions and accepts separately scoped semantic policies', () => {
  const bundle = fixture();
  bundle.policies.push(
    policy(
      'argv',
      'forbid(principal, action == Cleopatr::Action::"process.execute", resource) when { context has argv };',
    ),
  );
  assert.throws(
    () => compileProfile(bundle, 'child', 'client', false),
    /per-operation OS context/,
  );
  bundle.policies.pop();
  bundle.policies.push(
    policy(
      'post',
      'forbid(principal, action == Cleopatr::Action::"http.request", resource) when { context.method == "POST" };',
    ),
  );
  assert.ok(compileProfile(bundle, 'child', 'client', false));
});
void test('kernel profile rejects parent/child exceptions, duplicate paths, path traversal and host roots', () => {
  for (const path of [
    '/workspace/private',
    '/workspace',
    '/',
    '/workspace/../etc',
    '/proc',
    '/var/lib/cleopatr',
  ]) {
    const bundle = fixture();
    bundle.resources.push(resource('exception', 'File', path));
    assert.throws(() => compileProfile(bundle, 'child', 'client', false));
  }
});
void test('kernel profile refuses independent rename denial when create and delete would permit it', () => {
  const bundle = fixture();
  bundle.policies.push(
    policy(
      'rename',
      'forbid(principal, action == Cleopatr::Action::"file.rename", resource);',
    ),
  );
  assert.throws(
    () => compileProfile(bundle, 'child', 'client', true),
    /cannot independently represent rename/,
  );
});
void test('admission accepts dynamically mediated actions and refuses undeclared OS resource identities', () => {
  for (const action of [
    'process.signal',
    'file.metadata',
    'dns.query',
    'database.query',
    'database.connect',
    'database.transaction',
    'process.privilege_attempt',
    'network.listen',
  ]) {
    const bundle = fixture();
    bundle.policies.push(
      policy(
        'unsupported',
        `forbid(principal, action == Cleopatr::Action::"${action}", resource);`,
      ),
    );
    assert.ok(compileProfile(bundle, 'child', 'client', true));
  }
  const bundle = fixture();
  bundle.policies.push(
    policy(
      'unknown-file',
      'forbid(principal, action, resource == Cleopatr::File::"unregistered-secret");',
    ),
  );
  assert.throws(
    () => compileProfile(bundle, 'child', 'client', true),
    /outside this environment/,
  );
});

async function httpFixture(
  t: import('node:test').TestContext,
  decide: Decide,
  extra: (origin: string) => Resource[] = () => [],
) {
  const received: {
    url: string;
    headers: http.IncomingHttpHeaders;
    body: string;
  }[] = [];
  const origin = http.createServer(async (req, res) => {
    let body = '';
    for await (const chunk of req) body += chunk;
    received.push({ url: req.url!, headers: req.headers, body });
    res.end('forwarded');
  });
  await new Promise<void>((resolve) => origin.listen(0, '127.0.0.1', resolve));
  const target = `http://127.0.0.1:${(origin.address() as AddressInfo).port}`;
  const proxy = await startHttpProxy(
    [resource('api', 'Endpoint', target), ...extra(target)],
    decide,
  );
  t.after(() => {
    proxy.close();
    origin.closeAllConnections();
    origin.close();
  });
  const request = (
    path = '/test',
    method = 'GET',
    body?: string,
    headers: Record<string, string> = {},
  ) =>
    new Promise<{ status: number; body: string }>((resolve, reject) => {
      const req = http.request(
        {
          host: '127.0.0.1',
          port: proxy.port,
          path: target + path,
          method,
          headers,
        },
        (res) => {
          let body = '';
          res.on('data', (chunk) => (body += chunk));
          res.on('end', () => resolve({ status: res.statusCode!, body }));
        },
      );
      req.on('error', reject);
      req.end(body);
    });
  return { received, target, proxy, request };
}
void test('HTTP decisions happen before effects; network authorization is independently required', async (t) => {
  const decisions: string[] = [];
  const f = await httpFixture(t, async (action, _resource, context) => {
    decisions.push(action);
    return (
      context.method !== 'DELETE' &&
      !(action === 'network.connect' && decisions.length > 3)
    );
  });
  assert.equal((await f.request()).status, 200);
  assert.equal((await f.request('/test', 'DELETE')).status, 403);
  assert.equal((await f.request()).status, 403);
  assert.equal(f.received.length, 1);
  assert.deepEqual(decisions, [
    'http.request',
    'network.connect',
    'http.request',
    'http.request',
    'network.connect',
  ]);
});
void test('audit forwards supported HTTP requests while retaining their DENY decision', async (t) => {
  const bundle = fixture();
  bundle.policies = [policy('deny', 'forbid(principal, action, resource);')];
  let audit = false;
  const seen: ReturnType<typeof evaluateWithModes>[] = [];
  const f = await httpFixture(t, async (action, resource, context) => {
    const result = evaluateWithModes(
      cedar,
      bundle,
      {
        environmentId: 'child',
        sessionId: 'test',
        principal: 'client',
        action,
        resource,
        context,
      },
      false,
      audit,
    );
    seen.push(result);
    return result.allowed;
  });
  assert.equal((await f.request()).status, 403);
  assert.equal(f.received.length, 0);
  audit = true;
  assert.equal((await f.request()).status, 200);
  assert.equal(f.received.length, 1);
  assert.equal(seen.length, 3);
  assert.ok(
    seen
      .slice(1)
      .every(
        (result) =>
          result.decision === 'DENY' &&
          result.effectiveResult === 'ALLOWED_AUDIT',
      ),
  );
});
void test('network origin spelling retains the catalog identity for enforcement', async (t) => {
  const f = await httpFixture(
    t,
    async (_action, resource) => resource.id !== 'blocked-network',
    (origin) => [resource('blocked-network', 'Network', origin + '/')],
  );
  assert.equal((await f.request()).status, 403);
  assert.equal(f.received.length, 0);
});
void test('proxy strips proxy credentials and hop headers and preserves request bodies', async (t) => {
  const f = await httpFixture(t, async () => true);
  assert.equal(
    (
      await f.request('/post', 'POST', 'same bytes', {
        'proxy-authorization': 'secret',
        connection: 'x-private',
        'x-private': 'secret',
      })
    ).status,
    200,
  );
  assert.equal(f.received[0].body, 'same bytes');
  assert.equal(f.received[0].headers['proxy-authorization'], undefined);
  assert.equal(f.received[0].headers['x-private'], undefined);
});
void test('URI spelling cannot bypass a more-specific resource or a path deny', async (t) => {
  const f = await httpFixture(
    t,
    async (_action, resource, context) =>
      resource.id !== 'private' && context.path !== '/denied',
    (origin) => [resource('private', 'Endpoint', origin + '/private')],
  );
  for (const path of [
    '/private',
    '/%70rivate',
    '/%64enied',
    '/private%2fsecret',
    '/%2570rivate',
  ])
    assert.notEqual((await f.request(path)).status, 200);
  assert.equal(f.received.length, 0);
});
void test('opaque CONNECT tunnels in enforced sessions are rejected before opening an upstream connection', async (t) => {
  const f = await httpFixture(t, async () => true);
  const response = await new Promise<string>((resolve, reject) => {
    const socket = net.connect(f.proxy.port, '127.0.0.1', () =>
      socket.write(
        `CONNECT ${new URL(f.target).host} HTTP/1.1\r\nHost: ${new URL(f.target).host}\r\n\r\n`,
      ),
    );
    let data = '';
    socket.on('data', (chunk) => (data += chunk));
    socket.on('end', () => resolve(data));
    socket.on('error', reject);
  });
  assert.match(response, /^HTTP\/1.1 501/);
  assert.equal(f.received.length, 0);
});
void test('MCP HTTP inspects the exact forwarded body and blocks forbidden tools, batches and unknown methods', async (t) => {
  const seen: string[] = [];
  const f = await httpFixture(
    t,
    async (action, _resource, context) => {
      seen.push(action);
      return context.tool !== 'destroy';
    },
    (origin) => [resource('mcp', 'MCPTool', origin + '/mcp')],
  );
  const body = (method: string, name = 'safe') =>
    JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: { name } });
  const good = body('tools/call');
  assert.equal((await f.request('/mcp', 'POST', good)).status, 200);
  assert.equal(f.received[0].body, good);
  assert.equal(
    (await f.request('/mcp', 'POST', body('tools/call', 'destroy'))).status,
    403,
  );
  assert.equal((await f.request('/mcp', 'POST', `[${good}]`)).status, 403);
  assert.equal(
    (await f.request('/mcp?uninspected=1', 'POST', good)).status,
    403,
  );
  assert.equal((await f.request('/%6dcp', 'POST', good)).status, 403);
  assert.equal(
    (await f.request('/mcp', 'POST', body('experimental/exec'))).status,
    403,
  );
  assert.equal(f.received.length, 1);
  assert.ok(seen.includes('mcp.tool.invoke'));
});
void test('MCP semantic facts enforce integer amount typing and resource identity', async () => {
  const target = new URL('https://example.test/mcp');
  const resources = [resource('refund', 'MCPTool', target.href + '#refund')];
  const facts: unknown[] = [];
  const decide: Decide = async (_action, resource, context) => {
    facts.push({ resource, context });
    return true;
  };
  for (const amount of ['100', 1.5, 1e100]) {
    assert.equal(
      await authorizeMcpBody(
        Buffer.from(
          JSON.stringify({
            jsonrpc: '2.0',
            method: 'tools/call',
            params: { name: 'refund', arguments: { amount } },
          }),
        ),
        target,
        resources,
        decide,
      ),
      false,
    );
  }
  assert.equal(facts.length, 0);
  assert.equal(
    await authorizeMcpBody(
      Buffer.from(
        JSON.stringify({
          jsonrpc: '2.0',
          method: 'tools/call',
          params: { name: 'refund', arguments: { amount: 100 } },
        }),
      ),
      target,
      resources,
      decide,
    ),
    true,
  );
  assert.equal(facts.length, 1);
});

void test('fixed workspace membership is supported only for scoped file policies', () => {
  const bundle = fixture();
  bundle.resources.push(resource('runtime', 'File', '/usr'));
  bundle.policies = [
    policy(
      'workspace',
      'permit(principal, action == Cleopatr::Action::"file.read", resource) when { context has withinWorkspace && context.withinWorkspace };',
    ),
  ];
  const grants = compileProfile(bundle, 'child', 'client', true).grants;
  assert.equal(
    grants.find((g) => g.path === '/workspace')?.access,
    rights.read,
  );
  assert.equal(
    grants.find((g) => g.path === '/usr'),
    undefined,
  );
  for (const cedar of [
    'permit(principal, action, resource) when { context.withinWorkspace };',
    'permit(principal, action == Cleopatr::Action::"file.read", resource) when { context.withinWorkspace && context.path == "/workspace" };',
  ]) {
    bundle.policies = [policy('dynamic', cedar)];
    assert.throws(
      () => compileProfile(bundle, 'child', 'client', true),
      /per-operation OS context/,
    );
  }
});
void test('HTTPS tunnel attempts invoke the broad HTTP forbid without inventing an encrypted GET or path', async (t) => {
  const decisions: {
    action: string;
    resource: unknown;
    context: Record<string, unknown>;
  }[] = [];
  const proxy = await startHttpProxy([], async (action, resource, context) => {
    decisions.push({ action, resource, context });
    return false;
  });
  t.after(() => proxy.close());
  const response = await new Promise<string>((resolve, reject) => {
    const socket = net.connect(proxy.port, '127.0.0.1', () =>
      socket.write(
        'CONNECT www.google.com:443 HTTP/1.1\r\nHost: www.google.com:443\r\n\r\n',
      ),
    );
    let data = '';
    socket.on('data', (chunk) => (data += chunk));
    socket.on('end', () => resolve(data));
    socket.on('error', reject);
  });
  assert.match(response, /^HTTP\/1.1 403/);
  assert.equal(decisions.length, 1);
  assert.equal(decisions[0].action, 'http.request');
  assert.deepEqual(decisions[0].resource, {
    type: 'Endpoint',
    id: 'https://www.google.com',
  });
  assert.equal(decisions[0].context.method, 'CONNECT');
  assert.equal(decisions[0].context.path, undefined);
  assert.equal(decisions[0].context.semanticAvailable, false);
});

void test('type-scoped process permit matches the client name but still needs registered executables', () => {
  const bundle = fixture();
  bundle.resources = bundle.resources.filter((r) => r.type !== 'Process');
  bundle.policies = [
    policy(
      'launch',
      'permit(principal is Cleopatr::AgentSession, action == Cleopatr::Action::"process.execute", resource);',
    ),
  ];
  const missing = compileProfile(bundle, 'child', 'curl-agent', true);
  assert.throws(() => requireExecutableGrant(missing), /no Process resources/);
  assert.throws(
    () => requireExecutableGrant(missing),
    /Cleopatr::AgentSession::"curl-agent"/,
  );
  bundle.resources.push(resource('node', 'Process', '/usr/local/bin/node'));
  const ready = compileProfile(bundle, 'child', 'curl-agent', true);
  assert.doesNotThrow(() => requireExecutableGrant(ready));
  assert.equal(ready.grants[0].access, rights.execute);
  bundle.policies[0].cedar =
    'permit(principal == Cleopatr::AgentSession::"someone-else", action == Cleopatr::Action::"process.execute", resource);';
  assert.throws(
    () =>
      requireExecutableGrant(
        compileProfile(bundle, 'child', 'curl-agent', true),
      ),
    /No effective process.execute permit/,
  );
});
