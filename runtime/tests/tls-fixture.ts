import { createSecureServer } from 'node:http2';
import type { Socket } from 'node:net';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';

// Disposable test certificate, trusted only by the test's curl invocation.
export async function tlsFixture(host = '127.0.0.1') {
  const dir = await mkdtemp(join(tmpdir(), 'cleo-test-tls-'));
  const cert = join(dir, 'cert.pem');
  try {
    await promisify(execFile)('openssl', [
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-days',
      '1',
      '-subj',
      '/CN=localhost',
      '-addext',
      'subjectAltName=DNS:localhost,DNS:host.docker.internal,IP:127.0.0.1',
      '-keyout',
      join(dir, 'key.pem'),
      '-out',
      cert,
    ]);
    const received: string[] = [];
    const server = createSecureServer(
      {
        key: await readFile(join(dir, 'key.pem')),
        allowHTTP1: true,
        cert: await readFile(cert),
      },
      (req, res) => {
        received.push(req.url!);
        res.end('x'.repeat(256 * 1024) + 'HTTPS reached destination');
      },
    );
    const sockets = new Set<Socket>();
    server.on('connection', (socket) => {
      sockets.add(socket);
      socket.on('close', () => sockets.delete(socket));
    });
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, host, resolve);
    });
    return {
      cert,
      received,
      port: (server.address() as AddressInfo).port,
      close: async () => {
        for (const socket of sockets) socket.destroy();
        await new Promise<void>((resolve) => server.close(() => resolve()));
        await rm(dir, { recursive: true, force: true });
      },
    };
  } catch (error) {
    await rm(dir, { recursive: true, force: true });
    throw error;
  }
}
