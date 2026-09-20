import { createServer } from 'node:http';
import { mkdirSync } from 'node:fs';
import { resolve, join } from 'node:path';
import * as cedar from '@cedar-policy/cedar-wasm/nodejs';
import { ControlPlane } from './service.ts';
import { SQLiteDatabase } from './sqlite.ts';
const dir = resolve(process.env.CLEO_SERVER_DATA ?? '.local');
mkdirSync(dir, { recursive: true, mode: 0o700 });
const db = new SQLiteDatabase(join(dir, 'cleopatr.sqlite'), resolve('drizzle'));
const plane = new ControlPlane(
  db,
  cedar,
  process.env.CLEO_SIGNING_JWK
    ? JSON.parse(process.env.CLEO_SIGNING_JWK)
    : undefined,
);
const adminToken = process.env.CLEO_ADMIN_TOKEN;
const port = Number(process.env.CLEO_PORT ?? 4318);
const server = createServer(async (req, res) => {
  try {
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of req) {
      size += chunk.length;
      if (size > 200000) {
        res.writeHead(413);
        res.end('Too large');
        return;
      }
      chunks.push(chunk);
    }
    const url = `http://127.0.0.1:${port}${req.url}`;
    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers))
      if (v) headers.set(k, Array.isArray(v) ? v.join(',') : v);
    // This separate endpoint never trusts browser identity headers. Admin access requires a local secret.
    const admin =
      adminToken && headers.get('x-cleo-admin-token') === adminToken
        ? { id: 'local-workspace', name: 'Local administrator' }
        : null;
    if (admin) headers.set('origin', new URL(url).origin);
    const request = new Request(url, {
      method: req.method,
      headers,
      ...(req.method === 'GET' || req.method === 'HEAD'
        ? {}
        : { body: Buffer.concat(chunks) }),
    });
    const response = await plane.handle(request, admin);
    res.writeHead(response.status, Object.fromEntries(response.headers));
    res.end(Buffer.from(await response.arrayBuffer()));
  } catch (e) {
    res.writeHead(500, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: (e as Error).message }));
  }
});
server.listen(port, '127.0.0.1', () =>
  process.stdout.write(
    `Cleopatr local API http://127.0.0.1:${port}/api/v1\nSet CLEO_ADMIN_TOKEN to administer this local instance.\n`,
  ),
);
