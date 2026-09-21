import { test } from 'node:test';
import assert from 'node:assert/strict';
import net, { type AddressInfo } from 'node:net';
import { execFile } from 'node:child_process';
import { startHttpProxy } from '../runtime/adapters/http.ts';
import { tlsFixture } from '../runtime/tests/tls-fixture.ts';

function connectRequest(port: number, authority: string, head = '') {
  return new Promise<string>((resolve, reject) => {
    const socket = net.connect(port, '127.0.0.1', () =>
      socket.write(
        `CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n${head}`,
      ),
    );
    let data = '';
    socket.on('data', (chunk) => (data += chunk));
    socket.on('end', () => resolve(data));
    socket.on('error', reject);
    socket.setTimeout(3000, () => {
      socket.destroy();
      reject(new Error('CONNECT timed out'));
    });
  });
}
void test('audit tunnels preserve early bytes and wait for both authorizations before connecting', async (t) => {
  let connections = 0;
  const origin = net.createServer((socket) => {
    connections++;
    socket.once('data', (chunk) => socket.end('echo:' + chunk.toString()));
  });
  await new Promise<void>((resolve) => origin.listen(0, '127.0.0.1', resolve));
  t.after(() => origin.close());
  const authority = `127.0.0.1:${(origin.address() as AddressInfo).port}`;
  const seen: string[] = [];
  const proxy = await startHttpProxy(
    [],
    async (action) => {
      seen.push(action);
      assert.equal(connections, 0);
      return true;
    },
    { auditOnly: true },
  );
  t.after(() => proxy.close());
  const response = await connectRequest(proxy.port, authority, 'EARLY');
  assert.match(response, /^HTTP\/1.1 200 Connection Established/);
  assert.match(response, /echo:EARLY$/);
  assert.deepEqual(seen, ['http.request', 'network.connect']);
  assert.equal(connections, 1);
});
void test('policy denials, enforced sessions, and invalid authorities never contact the destination', async (t) => {
  let connections = 0;
  const origin = net.createServer((socket) => {
    connections++;
    socket.destroy();
  });
  await new Promise<void>((resolve) => origin.listen(0, '127.0.0.1', resolve));
  t.after(() => origin.close());
  const authority = `127.0.0.1:${(origin.address() as AddressInfo).port}`;
  for (const [denyAction, auditOnly, expected] of [
    ['http.request', true, 403],
    ['network.connect', true, 403],
    ['', false, 501],
  ] as const) {
    const proxy = await startHttpProxy(
      [],
      async (action) => action !== denyAction,
      { auditOnly },
    );
    t.after(() => proxy.close());
    const response = await connectRequest(proxy.port, authority);
    assert.match(response, new RegExp(`^HTTP/1.1 ${expected}`));
    assert.match(
      response,
      expected === 501 ? /https-inspection-required/ : /policy-deny/,
    );
  }
  const proxy = await startHttpProxy(
    [],
    async () => {
      throw new Error('must not evaluate malformed input');
    },
    { auditOnly: true },
  );
  t.after(() => proxy.close());
  assert.match(
    await connectRequest(proxy.port, 'example.com:0'),
    /^HTTP\/1.1 400/,
  );
  assert.equal(connections, 0);
});
void test('real HTTPS traverses audit tunnel with client TLS verification and no invented GET payload', async (t) => {
  const origin = await tlsFixture();
  t.after(() => origin.close());
  const facts: { action: string; context: Record<string, unknown> }[] = [];
  const proxy = await startHttpProxy(
    [],
    async (action, _resource, context) => {
      facts.push({ action, context });
      return true;
    },
    { auditOnly: true },
  );
  t.after(() => proxy.close());
  const curl = (trusted: boolean) =>
    new Promise<{ code: number; out: string; err: string }>((resolve) => {
      execFile(
        'curl',
        [
          '--silent',
          '--show-error',
          '--fail',
          '--max-time',
          '5',
          '--noproxy',
          '',
          '--proxy',
          `http://127.0.0.1:${proxy.port}`,
          ...(trusted ? ['--cacert', origin.cert] : []),
          `https://127.0.0.1:${origin.port}/test?q=value`,
        ],
        (error, out, err) =>
          resolve({ code: error ? Number(error.code) : 0, out, err }),
      );
    });
  const denied = await curl(false);
  assert.equal(denied.code, 60, denied.err);
  assert.equal(origin.received.length, 0);
  const allowed = await curl(true);
  assert.equal(allowed.code, 0, allowed.err);
  assert.equal(
    allowed.out,
    'x'.repeat(256 * 1024) + 'HTTPS reached destination',
  );
  assert.deepEqual(origin.received, ['/test?q=value']);
  assert.equal(facts.length, 4);
  assert.ok(
    facts.every(
      (fact) =>
        fact.context.semanticAvailable === false &&
        fact.context.path === undefined,
    ),
  );
  assert.ok(
    facts
      .filter((fact) => fact.action === 'http.request')
      .every((fact) => fact.context.method === 'CONNECT'),
  );
});
