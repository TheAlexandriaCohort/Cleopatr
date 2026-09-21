import http, { type IncomingMessage, type ServerResponse } from 'node:http';
import { Buffer } from 'node:buffer';
import https from 'node:https';
import net, { type AddressInfo } from 'node:net';
import type { ActionRequest, Resource } from '../../core/model.ts';
import { mcpResources, authorizeMcpBody } from './mcp-http.ts';
import { httpPath } from '../url.ts';

export type Decide = (
  action: string,
  resource: ActionRequest['resource'],
  context: ActionRequest['context'],
) => Promise<boolean>;
const hop = new Set([
  'connection',
  'proxy-connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);
function headers(message: IncomingMessage) {
  const exclude = new Set([
    ...hop,
    ...(message.headers.connection ?? '')
      .toLowerCase()
      .split(',')
      .map((v) => v.trim()),
  ]);
  return Object.fromEntries(
    Object.entries(message.headers).filter(([key]) => !exclude.has(key)),
  );
}
function match(resources: Resource[], url: URL) {
  const path = httpPath(url);
  return resources
    .filter((r) => r.type === 'Endpoint')
    .map((resource) => {
      try {
        const url = new URL(resource.locator);
        return { resource, url, path: httpPath(url) };
      } catch {
        return undefined;
      }
    })
    .filter(
      (r): r is { resource: Resource; url: URL; path: string } =>
        !!r &&
        r.url.origin === url.origin &&
        (r.path === '/' ||
          path === r.path ||
          path.startsWith(r.path.replace(/\/$/, '') + '/')),
    )
    .sort((a, b) => b.path.length - a.path.length)[0]?.resource;
}
export async function startHttpProxy(
  resources: Resource[],
  decide: Decide,
  options: {
    auditOnly?: boolean;
    onDiagnostic?: (message: string) => void;
  } = {},
) {
  const sockets = new Set<import('node:net').Socket>();
  const server = http.createServer(
    { maxHeaderSize: 16384, requestTimeout: 30000, headersTimeout: 10000 },
    (req, res) => {
      void forward(req, res).catch(() => {
        if (!res.headersSent) res.writeHead(502);
        res.end('Cleopatr adapter failed closed');
      });
    },
  );
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => socket.destroy());
    socket.setTimeout(30000, () => socket.destroy());
  });
  server.maxConnections = 128;
  server.maxRequestsPerSocket = 128;
  server.keepAliveTimeout = 5000;
  // CONNECT exposes the destination, not the encrypted HTTP method/path.
  // Only a session with no effective Enforce policies may pass opaque traffic.
  // The worker derives this flag from the verified bundle, never agent input.
  server.on('connect', (req, socket, head) => {
    socket.pause();
    const refuse = (status: number, reason: string, message: string) => {
      options.onDiagnostic?.(message);
      if (socket.destroyed || socket.writableEnded) return;
      const body = message + '\n';
      socket.end(
        `HTTP/1.1 ${status} ${http.STATUS_CODES[status]}\r\nConnection: close\r\nX-Cleopatr-Reason: ${reason}\r\nContent-Type: text/plain\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`,
        () => socket.destroy(),
      );
    };
    void (async () => {
      const authority = req.url ?? '';
      if (
        !/^(?:\[[0-9a-fA-F:]+\]|[a-zA-Z0-9.-]+):[0-9]{1,5}$/.test(authority)
      ) {
        refuse(400, 'invalid-connect', 'Invalid CONNECT authority');
        return;
      }
      let url: URL;
      try {
        url = new URL(`https://${authority}`);
      } catch {
        refuse(400, 'invalid-connect', 'Invalid CONNECT authority');
        return;
      }
      const port = Number(url.port || 443);
      if (port < 1 || port > 65535) {
        refuse(400, 'invalid-connect', 'Invalid CONNECT port');
        return;
      }
      const endpoint = match(resources, url);
      if (
        !(await decide(
          'http.request',
          { type: 'Endpoint', id: endpoint?.id ?? url.origin },
          {
            method: 'CONNECT',
            host: url.hostname,
            port,
            protocol: 'https',
            encrypted: true,
            semanticAvailable: false,
            confidence: 'proxy-observed',
          },
        ))
      ) {
        refuse(403, 'policy-deny', 'CONNECT blocked by Cleopatr policy');
        return;
      }
      const network = resources.find((r) => {
        try {
          return (
            r.type === 'Network' && new URL(r.locator).origin === url.origin
          );
        } catch {
          return false;
        }
      });
      if (
        !(await decide(
          'network.connect',
          { type: 'Network', id: network?.id ?? url.origin },
          {
            host: url.hostname,
            port,
            protocol: 'tcp',
            semanticAvailable: false,
            confidence: 'proxy-observed',
          },
        ))
      ) {
        refuse(
          403,
          'policy-deny',
          'CONNECT network connection blocked by Cleopatr policy',
        );
        return;
      }
      if (!options.auditOnly) {
        refuse(
          501,
          'https-inspection-required',
          'HTTPS inspection is not implemented for sessions containing Enforce policies; the tunnel was not opened',
        );
        return;
      }
      if (socket.destroyed) return;
      const upstream = net.createConnection({
        host: url.hostname.replace(/^\[|\]$/g, ''),
        port,
      });
      sockets.add(upstream);
      let connected = false;
      const deadline = setTimeout(
        () => upstream.destroy(new Error('connect timeout')),
        10000,
      );
      deadline.unref();
      upstream.on('close', () => {
        clearTimeout(deadline);
        sockets.delete(upstream);
        if (connected && !upstream.readableEnded) socket.destroy();
      });
      socket.once('close', () => upstream.destroy());
      socket.once('error', () => upstream.destroy());
      upstream.on('error', () => {
        if (connected) socket.destroy();
        else
          refuse(
            502,
            'upstream-unavailable',
            'CONNECT destination unavailable',
          );
      });
      upstream.once('connect', () => {
        clearTimeout(deadline);
        if (socket.destroyed) {
          upstream.destroy();
          return;
        }
        connected = true;
        upstream.setTimeout(30000, () => upstream.destroy());
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        options.onDiagnostic?.(
          `audit tunnel opened to ${url.host}; encrypted requests are not inspected`,
        );
        if (head.length) upstream.write(head);
        upstream.pipe(socket);
        socket.pipe(upstream);
        socket.resume();
      });
    })().catch(() =>
      refuse(
        503,
        'authorization-unavailable',
        'CONNECT authorization unavailable',
      ),
    );
  });
  server.on('upgrade', (_req, socket) => socket.destroy());
  server.on('clientError', (_error, socket) => socket.destroy());
  async function forward(req: IncomingMessage, res: ServerResponse) {
    const url = new URL(req.url ?? '');
    if (
      !['http:', 'https:'].includes(url.protocol) ||
      url.username ||
      url.password ||
      url.hash
    )
      throw new Error('Invalid proxy target');
    const resource = match(resources, url);
    const context = {
      method: req.method ?? '',
      host: url.hostname,
      path: httpPath(url),
      port: Number(url.port || (url.protocol === 'https:' ? 443 : 80)),
      protocol: url.protocol.slice(0, -1),
      encrypted: url.protocol === 'https:',
      semanticAvailable: true,
      confidence: 'proxy-observed',
    };
    if (
      !(await decide(
        'http.request',
        { type: 'Endpoint', id: resource?.id ?? url.origin },
        context,
      ))
    ) {
      res.writeHead(403).end('Blocked by Cleopatr policy');
      return;
    }
    if (!resource) {
      res
        .writeHead(403)
        .end('Destination is not in the signed resource catalog');
      return;
    }
    const network = resources.find((r) => {
      if (r.type !== 'Network') return false;
      try {
        return new URL(r.locator).origin === url.origin;
      } catch {
        return false;
      }
    });
    if (
      !(await decide(
        'network.connect',
        { type: 'Network', id: network?.id ?? url.origin },
        {
          host: context.host,
          port: context.port,
          protocol: 'tcp',
          confidence: 'proxy-observed',
          semanticAvailable: true,
        },
      ))
    ) {
      res.writeHead(403).end('Connection blocked by Cleopatr policy');
      return;
    }
    const outgoing = { ...headers(req), host: url.host };
    let body: Buffer | undefined;
    const mcp = mcpResources(resources, url);
    const mcpOrigin = resources.some((r) => {
      if (r.type !== 'MCPTool') return false;
      try {
        return new URL(r.locator).origin === url.origin;
      } catch {
        return false;
      }
    });
    if (mcpOrigin && !mcp.length) {
      // A changed path/query cannot downgrade an MCP call to uninspected generic HTTP.
      res
        .writeHead(403)
        .end('MCP origin requires an exact registered transport endpoint');
      return;
    }
    if (mcp.length) {
      if (req.method === 'POST') {
        const chunks: Buffer[] = [];
        let length = 0;
        for await (const chunk of req) {
          length += chunk.length;
          if (length > 1024 * 1024) throw new Error('MCP body exceeds one MiB');
          chunks.push(Buffer.from(chunk));
        }
        const complete = Buffer.concat(chunks);
        body = complete;
        if (!(await authorizeMcpBody(complete, url, mcp, decide))) {
          res.writeHead(403).end('MCP operation blocked by Cleopatr');
          return;
        }
      } else if (!['GET', 'DELETE'].includes(req.method ?? '')) {
        res.writeHead(405).end();
        return;
      }
    }
    const upstream = (url.protocol === 'https:' ? https : http).request(
      url,
      {
        method: req.method,
        headers: outgoing,
        timeout: 10000,
        agent: false,
        // Node validates upstream TLS hostname/certificate; no redirect following or tunnel fallback.
      },
      (response) => {
        res.writeHead(response.statusCode ?? 502, headers(response));
        response.pipe(res);
      },
    );
    upstream.on('timeout', () =>
      upstream.destroy(new Error('upstream timeout')),
    );
    upstream.on('error', () => {
      if (!res.headersSent) res.writeHead(502);
      res.end('Upstream unavailable');
    });
    res.on('close', () => upstream.destroy());
    if (body) upstream.end(body);
    else req.pipe(upstream);
  }
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return {
    port: (server.address() as AddressInfo).port,
    close: () => {
      for (const socket of sockets) socket.destroy();
      server.close();
    },
  };
}
