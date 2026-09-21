// Real-server adapter compatibility tests. Clients are test-only and may live
// outside the application dependency tree: CLEO_TEST_CLIENTS=/path/to/package.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { readFile } from 'node:fs/promises';
import { tlsFixture } from './tls-fixture.ts';
import { resolve, dirname } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { startDatabaseProxy } from '../adapters/database.ts';
import type { Resource } from '../../core/model.ts';

const require = createRequire(
  resolve(process.env.CLEO_TEST_CLIENTS ?? '.', 'package.json'),
);
const { Client } = require('pg');
const mysql = require('mysql2/promise');
const names: string[] = [];
function docker(args: string[]) {
  const result = spawnSync('docker', args, {
    encoding: 'utf8',
    timeout: 180000,
  });
  if (result.status !== 0)
    throw new Error(`docker ${args[0]} failed: ${result.stderr.slice(-1500)}`);
  return result.stdout.trim();
}
const r = (locator: string): Resource => ({
  id: 'test-db',
  name: 'Test database',
  type: 'Database',
  environmentId: 'test',
  description: '',
  locator,
});
async function ready(connect: () => Promise<unknown>) {
  for (let i = 0; i < 90; i++) {
    try {
      return await connect();
    } catch {
      await delay(1000);
    }
  }
  throw new Error('Database did not become ready');
}
const certificate = await tlsFixture();
const ca = await readFile(certificate.cert, 'utf8');
try {
  for (const protocol of ['postgres', 'mysql'] as const) {
    const name = `cleo-${protocol}-protocol-${process.pid}`;
    names.push(name);
    const port = protocol === 'postgres' ? 5432 : 3306;
    docker([
      'run',
      '-d',
      '--rm',
      '--name',
      name,
      '-p',
      `127.0.0.1::${port}`,
      '-v',
      `${dirname(certificate.cert)}:/tls-fixture:ro`,
      '--entrypoint',
      'sh',
      ...(protocol === 'postgres'
        ? [
            '-e',
            'POSTGRES_HOST_AUTH_METHOD=trust',
            '-e',
            'POSTGRES_DB=cleo_test',
            'postgres:17',
            '-c',
            'cp /tls-fixture/cert.pem /tmp/server-cert.pem; cp /tls-fixture/key.pem /tmp/server-key.pem; chown postgres:postgres /tmp/server-key.pem; chmod 600 /tmp/server-key.pem; exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/server-cert.pem -c ssl_key_file=/tmp/server-key.pem',
          ]
        : [
            '-e',
            'MYSQL_ALLOW_EMPTY_PASSWORD=yes',
            '-e',
            'MYSQL_DATABASE=cleo_test',
            'mysql:8.4',
            '-c',
            'cp /tls-fixture/cert.pem /tmp/server-cert.pem; cp /tls-fixture/key.pem /tmp/server-key.pem; chown mysql:mysql /tmp/server-key.pem; chmod 600 /tmp/server-key.pem; exec docker-entrypoint.sh mysqld --ssl-cert=/tmp/server-cert.pem --ssl-key=/tmp/server-key.pem',
          ]),
    ]);
    const upstreamPort = Number(
      docker(['port', name, String(port)])
        .split(':')
        .at(-1),
    );
    const direct = async (port: number) => {
      if (protocol === 'postgres') {
        const client = new Client({
          host: '127.0.0.1',
          port,
          user: 'postgres',
          database: 'cleo_test',
          connectionTimeoutMillis: 3000,
        });
        await client.connect();
        client.on('error', () => {});
        return client;
      }
      const client = await mysql.createConnection({
        host: '127.0.0.1',
        port,
        user: 'root',
        database: 'cleo_test',
        connectTimeout: 3000,
      });
      client.on('error', () => {});
      return client;
    };
    const admin = (await ready(() => direct(upstreamPort))) as Awaited<
      ReturnType<typeof direct>
    >;
    await admin.query('CREATE TABLE checks (value VARCHAR(30))');
    const events: { action: string; context: Record<string, unknown> }[] = [];
    let deny = '';
    const adapter = await startDatabaseProxy(
      r(`${protocol}://127.0.0.1:${upstreamPort}/cleo_test`),
      async (action, _resource, context) => {
        events.push({ action, context });
        return (
          action !== deny &&
          !JSON.stringify(context.argv ?? []).includes('blocked')
        );
      },
      { ca },
    );
    try {
      const untrusted = await startDatabaseProxy(
        r(`${protocol}://127.0.0.1:${upstreamPort}/cleo_test`),
        async () => true,
      );
      try {
        await assert.rejects(
          direct(untrusted.port),
          /certificate|self.signed|issuer/i,
        );
      } finally {
        untrusted.close();
      }
      const client = await direct(adapter.port);
      const tlsState = await client.query(
        protocol === 'postgres'
          ? 'SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()'
          : "SHOW STATUS LIKE 'Ssl_cipher'",
      );
      assert.ok(
        protocol === 'postgres' ? tlsState.rows[0].ssl : tlsState[0][0].Value,
        'upstream transport uses TLS',
      );
      await client.query("INSERT INTO checks VALUES ('allowed')");
      await client.query('SELECT * FROM checks');
      await client.query('BEGIN');
      await client.query("INSERT INTO checks VALUES ('rolled-back')");
      await client.query('ROLLBACK');
      await client.query('BEGIN');
      await client.query('COMMIT');
      await assert.rejects(
        client.query("INSERT INTO checks VALUES ('blocked')"),
        /Cleopatr|policy/i,
      );
      await client.end().catch(() => {});
      const result = await admin.query('SELECT * FROM checks');
      assert.deepEqual(protocol === 'postgres' ? result.rows : result[0], [
        { value: 'allowed' },
      ]);
      assert.ok(events.some((e) => e.action === 'database.connect'));
      assert.ok(
        events.some(
          (e) =>
            e.action === 'database.query' && e.context.operation === 'INSERT',
        ),
      );
      assert.ok(
        events.some(
          (e) =>
            e.action === 'database.transaction' &&
            e.context.operation === 'ROLLBACK',
        ),
      );
      deny = 'database.transaction';
      const transaction = await direct(adapter.port);
      await assert.rejects(transaction.query('BEGIN'), /Cleopatr|policy/i);
      await transaction.end().catch(() => {});
      deny = 'database.connect';
      await assert.rejects(direct(adapter.port), /Cleopatr|policy/i);
      deny = '';
      const prepared = await direct(adapter.port);
      await assert.rejects(
        protocol === 'postgres'
          ? prepared.query('SELECT $1::text', ['x'])
          : prepared.execute('SELECT ?', ['x']),
        /supported|prepared/i,
      );
      await prepared.end().catch(() => {});
      console.log(
        `[PASS] ${protocol}: real client/server verified TLS, untrusted certificate rejection, connect, queries, BEGIN/COMMIT/ROLLBACK, policy denial before side effects, unsupported prepared protocol rejected`,
      );
    } finally {
      adapter.close();
      await admin.end();
    }
  }
} finally {
  await certificate.close();
  for (const name of names)
    spawnSync('docker', ['rm', '-f', name], {
      stdio: 'ignore',
      timeout: 10000,
    });
}
