import { u16be } from '../runtime/adapters/wire.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import net, { type AddressInfo } from 'node:net';
import { once } from 'node:events';
import { sqlOperation } from '../runtime/adapters/sql.ts';
import {
  createDnsAdapter,
  dnsQuestion,
  startDnsTcp,
} from '../runtime/adapters/dns.ts';
import {
  databaseTarget,
  startDatabaseProxy,
} from '../runtime/adapters/database.ts';
import type { Resource } from '../core/model.ts';

function question(host: string, type = 1) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(1234);
  header.writeUInt16BE(0x100, 2);
  header.writeUInt16BE(1, 4);
  const tail = Buffer.alloc(5);
  tail.writeUInt16BE(type, 1);
  tail.writeUInt16BE(1, 3);
  return Buffer.concat([
    header,
    ...host
      .split('.')
      .map((label) =>
        Buffer.concat([Buffer.from([label.length]), Buffer.from(label)]),
      ),
    tail,
  ]);
}
void test('DNS records exact questions, refuses policy denials and malformed wire messages', async () => {
  const calls: unknown[] = [];
  const adapter = createDnsAdapter([], async (...args) => {
    calls.push(args);
    return false;
  });
  const packet = question('example.com');
  const denied = await adapter(packet);
  assert.equal(u16be(denied, 2) & 15, 5);
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0], [
    'dns.query',
    { type: 'Network', id: 'dns://example.com' },
    {
      host: 'example.com',
      operation: '1',
      protocol: 'dns',
      semanticAvailable: true,
      confidence: 'wire-observed',
    },
  ]);
  for (const malformed of [
    Buffer.alloc(0),
    Buffer.from([1]),
    Buffer.concat([packet, Buffer.from('trailing')]),
  ])
    assert.equal(u16be(await adapter(malformed), 2) & 15, 1);
  const compressed = Buffer.from(packet);
  compressed[12] = 0xc0;
  assert.throws(() => dnsQuestion(compressed));
  assert.equal(
    calls.length,
    1,
    'Malformed questions never reach policy/upstream',
  );
});
void test('database DNS aliases are authorized and TCP DNS handles fragmented frames', async () => {
  let allowed = true;
  const answer = createDnsAdapter(
    [],
    async () => allowed,
    new Map([['db.example', '198.18.0.1']]),
  );
  const packet = question('db.example');
  const reply = await answer(packet);
  assert.deepEqual([...reply.subarray(-4)], [198, 18, 0, 1]);
  allowed = false;
  assert.equal(u16be(await answer(packet), 2) & 15, 5);
  allowed = true;
  const server = await startDnsTcp(answer);
  const socket = net.createConnection(server.port, '127.0.0.1');
  try {
    await once(socket, 'connect');
    const length = Buffer.alloc(2);
    length.writeUInt16BE(packet.length);
    const response = once(socket, 'data');
    socket.write(length.subarray(0, 1));
    socket.write(Buffer.concat([length.subarray(1), packet]));
    const [bytes] = (await response) as [Buffer];
    assert.equal(u16be(bytes, 0), reply.length);
    assert.deepEqual(bytes.subarray(2), reply);
  } finally {
    socket.destroy();
    server.close();
  }
});
void test('SQL classification keeps explicit transactions separate and rejects protocol/multiple-statement escapes', () => {
  for (const dialect of ['postgres', 'mysql'] as const) {
    assert.deepEqual(
      sqlOperation("/* comment */ SELECT 'semicolon;here'; -- done\n", dialect),
      { action: 'database.query', operation: 'SELECT' },
    );
    for (const text of ['BEGIN', 'START TRANSACTION', 'COMMIT', 'ROLLBACK'])
      assert.equal(sqlOperation(text, dialect).action, 'database.transaction');
    for (const text of [
      'SELECT 1; COMMIT',
      'SELECT 1 /*!50000 ;COMMIT */',
      'COPY x TO STDOUT',
      'PREPARE x AS SELECT 1',
      'EXECUTE x',
      'SET autocommit=0',
      'USE other',
      'SELECT $$x$$',
      "SELECT 'unterminated",
      "SELECT 'a\\' ;COMMIT",
      'CALL my_proc()',
      'DO something',
    ])
      assert.throws(() => sqlOperation(text, dialect), text);
  }
  assert.throws(() =>
    sqlOperation('SELECT 1 /* a /* b */ ; COMMIT */', 'mysql'),
  );
});
const resource = (locator: string): Resource => ({
  id: 'db',
  name: 'DB',
  type: 'Database',
  locator,
  environmentId: 'env',
  description: '',
});
void test('database catalog requires explicit identities and verified TLS for remote hosts', () => {
  assert.equal(
    databaseTarget(resource('postgres://db.example/app')).encrypted,
    true,
  );
  for (const locator of [
    'postgres://user:password@db.example/app',
    'mysql://db.example/',
    'mysql://db.example/app?tls=disable',
    'postgres://db.example/app?sslmode=disable',
  ])
    assert.throws(() => databaseTarget(resource(locator)));
});
void test('database.connect denial has no upstream side effect', async () => {
  let connects = 0;
  const upstream = net.createServer((socket) => {
    connects++;
    socket.destroy();
  });
  await new Promise<void>((resolve) =>
    upstream.listen(0, '127.0.0.1', resolve),
  );
  const port = (upstream.address() as AddressInfo).port;
  const adapter = await startDatabaseProxy(
    resource(`mysql://127.0.0.1:${port}/app?tls=disable`),
    async () => false,
  );
  const socket = net.createConnection(adapter.port, '127.0.0.1');
  try {
    const [bytes] = (await once(socket, 'data')) as [Buffer];
    assert.equal(bytes[4], 255);
    assert.equal(connects, 0);
  } finally {
    socket.destroy();
    adapter.close();
    upstream.close();
  }
});
