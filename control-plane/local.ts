import { createServer } from 'node:http';
import { existsSync } from 'node:fs';
import { nodeControlPlane } from './node.ts';
import { validAdminToken } from './auth.ts';
if (existsSync('.env')) process.loadEnvFile('.env');
const { plane, workspaceId } = nodeControlPlane();
const port = Number(process.env.CLEO_PORT ?? 4318);
const server = createServer(async (req, res) => {
  try {
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of req) {
      size += chunk.length;
      if (size > 32 * 1024 * 1024) {
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
    const admin = validAdminToken(headers.get('x-cleo-admin-token') ?? '')
      ? { id: workspaceId, name: 'Administrator' }
      : null;
    if (admin) headers.set('origin', new URL(url).origin);
    const response = await plane.handle(
      new Request(url, {
        method: req.method,
        headers,
        ...(req.method === 'GET' || req.method === 'HEAD'
          ? {}
          : { body: Buffer.concat(chunks) }),
      }),
      admin,
    );
    res.writeHead(response.status, Object.fromEntries(response.headers));
    res.end(Buffer.from(await response.arrayBuffer()));
  } catch (e) {
    res.writeHead(500, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: (e as Error).message }));
  }
});
server.listen(port, '127.0.0.1', () =>
  process.stdout.write(
    `Cleopatr API http://127.0.0.1:${port}/api/v1\nShares the web app SQLite database. Set CLEO_ADMIN_TOKEN to administer this endpoint.\n`,
  ),
);
