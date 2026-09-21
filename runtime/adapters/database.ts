import { u16le, u32be, u32le, uintle } from './wire.ts';
import { Buffer } from 'node:buffer';
import net, { type AddressInfo, type Socket } from 'node:net';
import tls from 'node:tls';
import { once } from 'node:events';
import type { Resource } from '../../core/model.ts';
import type { Decide } from './http.ts';
import { sqlOperation } from './sql.ts';

const MAX_FRAME = 65536;
export function databaseTarget(resource: Resource) {
  const url = new URL(resource.locator);
  if (
    !['postgres:', 'postgresql:', 'mysql:'].includes(url.protocol) ||
    url.username ||
    url.password ||
    url.hash ||
    !/^\/[a-zA-Z0-9_.-]+$/.test(url.pathname) ||
    [...url.searchParams.keys()].some((k) => k !== 'tls') ||
    url.searchParams.getAll('tls').length > 1
  )
    throw new Error(
      `Database ${resource.name}: use postgres://host:port/database or mysql://host:port/database without credentials`,
    );
  const protocol = url.protocol === 'mysql:' ? 'mysql' : 'postgres';
  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  const encrypted = url.searchParams.get('tls') !== 'disable';
  if (
    !host ||
    host.includes('*') ||
    url.port === '0' ||
    (url.searchParams.has('tls') &&
      !['require', 'disable'].includes(url.searchParams.get('tls')!))
  )
    throw new Error('Invalid database transport');
  if (
    !encrypted &&
    !['127.0.0.1', '::1', 'localhost', 'host.docker.internal'].includes(host)
  )
    throw new Error(
      'Plaintext database upstream is limited to loopback/test host',
    );
  return {
    protocol: protocol as 'postgres' | 'mysql',
    host,
    port: Number(url.port || (protocol === 'mysql' ? 3306 : 5432)),
    database: url.pathname.slice(1),
    encrypted,
  };
}

// Bound both queued bytes and each frame. Readers pause sockets between frames;
// protocol authorization is serialized before any application frame is sent.
class Reader {
  buffer = Buffer.alloc(0);
  failure?: Error;
  wake?: () => void;
  constructor(readonly socket: Socket) {
    socket.on('data', this.data);
    socket.on('end', this.end);
    socket.on('error', this.error);
    socket.on('close', this.end);
    socket.pause();
  }
  data = (chunk: Buffer) => {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    this.socket.pause();
    if (this.buffer.length > MAX_FRAME * 2)
      this.failure = new Error('Database frame buffer exceeded');
    this.wake?.();
  };
  end = () => {
    this.failure ??= new Error('Database connection ended');
    this.wake?.();
  };
  error = (error: Error) => {
    this.failure = error;
    this.wake?.();
  };
  async read(length: number): Promise<Buffer> {
    if (length < 0 || length > MAX_FRAME)
      throw new Error('Database frame too large');
    while (this.buffer.length < length) {
      if (this.failure) throw this.failure;
      await new Promise<void>((resolve) => {
        this.wake = resolve;
        this.socket.resume();
      });
      this.wake = undefined;
    }
    const out = this.buffer.subarray(0, length);
    this.buffer = this.buffer.subarray(length);
    return out;
  }
  detach() {
    if (this.buffer.length) throw new Error('Unexpected bytes before TLS');
    this.socket.removeListener('data', this.data);
    this.socket.removeListener('end', this.end);
    this.socket.removeListener('close', this.end);
    this.socket.removeListener('error', this.error);
  }
}
function pgFrame(type: string, body: Buffer) {
  const header = Buffer.alloc(5);
  header[0] = type.charCodeAt(0);
  header.writeUInt32BE(body.length + 4, 1);
  return Buffer.concat([header, body]);
}
async function pgRead(reader: Reader) {
  const header = await reader.read(5);
  const size = u32be(header, 1);
  if (size < 4) throw new Error('Invalid PostgreSQL frame');
  const body = await reader.read(size - 4);
  return {
    type: String.fromCharCode(header[0]),
    body,
    wire: Buffer.concat([header, body]),
  };
}
function pgError(message: string) {
  return pgFrame('E', Buffer.from(`SFATAL\0C42501\0M${message}\0\0`));
}
function mysqlFrame(body: Buffer, sequence: number) {
  const header = Buffer.alloc(4);
  header.writeUIntLE(body.length, 0, 3);
  header[3] = sequence & 255;
  return Buffer.concat([header, body]);
}
async function mysqlRead(reader: Reader) {
  const header = await reader.read(4);
  const body = await reader.read(uintle(header, 0, 3));
  return { body, sequence: header[3] };
}
function mysqlError(message: string, seq = 1) {
  const prefix = Buffer.from([255, 0x76, 0x04, 35, 52, 50, 48, 48, 48]);
  return mysqlFrame(Buffer.concat([prefix, Buffer.from(message)]), seq);
}
function utf8(buffer: Buffer) {
  return new TextDecoder('utf-8', { fatal: true }).decode(buffer);
}
async function send(socket: Socket, bytes: Buffer) {
  if (!socket.write(bytes)) await once(socket, 'drain');
}

export async function startDatabaseProxy(
  resource: Resource,
  decide: Decide,
  options: { ca?: string } = {},
) {
  const target = databaseTarget(resource);
  const sockets = new Set<Socket>();
  const errorSequence = new WeakMap<Socket, number>();
  const track = (socket: Socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => {});
    socket.setTimeout(30000, () =>
      socket.destroy(new Error('Database transport timeout')),
    );
    return socket;
  };
  const context = {
    host: target.host,
    port: target.port,
    protocol: target.protocol,
    server: target.database,
    encrypted: target.encrypted,
    confidence: 'wire-observed',
    semanticAvailable: true,
  };
  const check = (action: string, extra = {}) =>
    decide(
      action,
      { type: 'Database', id: resource.id },
      { ...context, ...extra },
    );
  const query = async (sql: string) => {
    const operation = sqlOperation(sql, target.protocol);
    if (
      !(await check(operation.action, {
        operation: operation.operation,
        argv: [sql],
      }))
    )
      throw new Error('Blocked by Cleopatr policy');
  };
  const connect = async () => {
    if (!(await check('database.connect', { operation: 'CONNECT' })))
      throw new Error('Database connection blocked by Cleopatr policy');
    if (
      !(await decide(
        'network.connect',
        { type: 'Network', id: `tcp://${target.host}:${target.port}` },
        { ...context, protocol: 'tcp' },
      ))
    )
      throw new Error('Database network connection blocked by Cleopatr policy');
    const socket = track(
      net.createConnection({ host: target.host, port: target.port }),
    );
    await once(socket, 'connect');
    return socket;
  };
  const secure = async (socket: Socket) => {
    const secured = track(
      tls.connect({
        socket,
        ca: options.ca,
        servername: net.isIP(target.host) ? undefined : target.host,
        rejectUnauthorized: true,
        minVersion: 'TLSv1.2',
        checkServerIdentity: (_host, cert) =>
          tls.checkServerIdentity(target.host, cert),
      }),
    );
    await once(secured, 'secureConnect');
    return secured;
  };
  const server = net.createServer((socket) => {
    track(socket);
    void (
      target.protocol === 'postgres' ? postgres(socket) : mysql(socket)
    ).catch((error) => {
      if (!socket.destroyed)
        socket.end(
          target.protocol === 'postgres'
            ? pgError((error as Error).message)
            : mysqlError(
                (error as Error).message,
                errorSequence.get(socket) ?? 0,
              ),
        );
    });
  });
  server.maxConnections = 64;
  async function postgres(client: Socket) {
    const downstream = new Reader(client);
    let length = u32be(await downstream.read(4));
    let startup = await downstream.read(length - 4);
    if (length === 8 && u32be(startup, 0) === 80877103) {
      await send(client, Buffer.from('N'));
      length = u32be(await downstream.read(4));
      startup = await downstream.read(length - 4);
    }
    if (
      startup.length < 5 ||
      u32be(startup, 0) !== 196608 ||
      startup.at(-1) !== 0
    )
      throw new Error('Only PostgreSQL protocol 3.0 startup is supported');
    const fields = utf8(startup.subarray(4)).split('\0');
    if (fields.at(-1) !== '' || fields.at(-2) !== '')
      throw new Error('Invalid PostgreSQL startup');
    const params = new Map<string, string>();
    for (let i = 0; i < fields.length - 2; i += 2) {
      if (
        !['user', 'database', 'application_name', 'client_encoding'].includes(
          fields[i],
        ) ||
        params.has(fields[i])
      )
        throw new Error('Unsupported PostgreSQL startup parameter');
      params.set(fields[i], fields[i + 1]);
    }
    if (
      params.get('database') !== target.database ||
      !params.get('user') ||
      (params.has('client_encoding') &&
        !/^UTF-?8$/i.test(params.get('client_encoding')!))
    )
      throw new Error('Database identity/encoding differs from catalog');
    let upstream = await connect();
    client.once('close', () => upstream.destroy());
    try {
      let reader = new Reader(upstream);
      if (target.encrypted) {
        await send(upstream, Buffer.from([0, 0, 0, 8, 4, 210, 22, 47]));
        if ((await reader.read(1))[0] !== 83)
          throw new Error('PostgreSQL upstream TLS required');
        reader.detach();
        upstream = await secure(upstream);
        reader = new Reader(upstream);
      }
      const header = Buffer.alloc(4);
      header.writeUInt32BE(length);
      await send(upstream, Buffer.concat([header, startup]));
      for (;;) {
        const frame = await pgRead(reader);
        await send(client, frame.wire);
        if (frame.type === 'E') return;
        if (frame.type === 'Z') break;
        if (frame.type === 'R') {
          const auth = u32be(frame.body, 0);
          if ([3, 5, 10, 11].includes(auth)) {
            const reply = await pgRead(downstream);
            if (reply.type !== 'p')
              throw new Error('Expected PostgreSQL authentication');
            await send(upstream, reply.wire);
          } else if (![0, 12].includes(auth))
            throw new Error('Unsupported PostgreSQL authentication');
        } else if (!['S', 'K', 'N'].includes(frame.type))
          throw new Error('Unexpected PostgreSQL startup response');
      }
      for (;;) {
        const frame = await pgRead(downstream);
        if (frame.type === 'X' && !frame.body.length) return;
        if (
          frame.type !== 'Q' ||
          frame.body.at(-1) !== 0 ||
          frame.body.subarray(0, -1).includes(0)
        )
          throw new Error(
            'Only PostgreSQL simple-query messages are supported; prepared/COPY/replication protocols are blocked',
          );
        await query(utf8(frame.body.subarray(0, -1)));
        await send(upstream, frame.wire);
        for (;;) {
          const reply = await pgRead(reader);
          if (!['T', 'D', 'C', 'E', 'N', 'S', 'I', 'Z'].includes(reply.type))
            throw new Error('Unsupported PostgreSQL response');
          await send(client, reply.wire);
          if (reply.type === 'Z') break;
        }
      }
    } finally {
      upstream.destroy();
    }
  }
  async function mysql(client: Socket) {
    // MySQL sends a greeting before database identity arrives. The connection
    // is authorized for this catalog endpoint before contacting that endpoint.
    let upstream = await connect();
    client.once('close', () => upstream.destroy());
    try {
      let reader = new Reader(upstream);
      const downstream = new Reader(client);
      const greeting = await mysqlRead(reader);
      if (greeting.sequence !== 0 || greeting.body[0] !== 10)
        throw new Error('Only MySQL protocol 10 is supported');
      const versionEnd = greeting.body.indexOf(0, 1),
        lowOffset = versionEnd + 14,
        highOffset = lowOffset + 5;
      if (versionEnd < 0 || greeting.body.length < highOffset + 2)
        throw new Error('Invalid MySQL greeting');
      const original =
        u16le(greeting.body, lowOffset) |
        (u16le(greeting.body, highOffset) << 16);
      // Disable TLS to the private enclave endpoint (upstream TLS is separate),
      // compression, local infile, multi-statements/results and EOF deprecation.
      const forbidden =
        0x800 |
        0x20 |
        0x80 |
        0x10000 |
        0x20000 |
        0x40000 |
        0x1000000 |
        0x4000000;
      const capabilities = original & ~forbidden;
      const body = Buffer.from(greeting.body);
      body.writeUInt16LE(capabilities & 65535, lowOffset);
      body.writeUInt16LE((capabilities >>> 16) & 65535, highOffset);
      await send(client, mysqlFrame(body, 0));
      const login = await mysqlRead(downstream);
      errorSequence.set(client, 2);
      if (login.sequence !== 1 || login.body.length < 34)
        throw new Error('Invalid MySQL handshake');
      const clientFlags = u32le(login.body, 0);
      const flags = clientFlags & ~forbidden;
      if (
        clientFlags & (0x800 | 0x20 | 0x1000000 | 0x4000000) ||
        !(flags & 0x200) ||
        !(flags & 8) ||
        !(flags & 0x8000)
      )
        throw new Error(
          'Unsupported MySQL capabilities; select a database and use text queries',
        );
      if (![33, 45, 46, 83, 224, 255].includes(login.body[8]))
        throw new Error('MySQL client must use UTF-8');
      let offset = login.body.indexOf(0, 32) + 1;
      if (offset <= 32) throw new Error('Invalid MySQL username');
      let authLength = login.body[offset++];
      if (flags & 0x200000) {
        if (authLength === 252) {
          authLength = u16le(login.body, offset);
          offset += 2;
        } else if (authLength === 253) {
          authLength = uintle(login.body, offset, 3);
          offset += 3;
        } else if (authLength >= 251)
          throw new Error('Unsupported MySQL authentication length');
      }
      offset += authLength;
      if (offset >= login.body.length)
        throw new Error('Truncated MySQL authentication');
      const dbEnd = login.body.indexOf(0, offset);
      if (
        dbEnd < 0 ||
        utf8(login.body.subarray(offset, dbEnd)) !== target.database
      )
        throw new Error('Database identity differs from catalog');
      let delta = 0;
      if (target.encrypted) {
        if (!(original & 0x800)) throw new Error('MySQL upstream TLS required');
        const ssl = Buffer.from(login.body.subarray(0, 32));
        ssl.writeUInt32LE(flags | 0x800, 0);
        await send(upstream, mysqlFrame(ssl, 1));
        reader.detach();
        upstream = await secure(upstream);
        reader = new Reader(upstream);
        delta = 1;
      }
      const auth = Buffer.from(login.body);
      auth.writeUInt32LE(flags | (delta ? 0x800 : 0), 0);
      await send(upstream, mysqlFrame(auth, 1 + delta));
      for (let count = 0; ; count++) {
        if (count > 8)
          throw new Error('MySQL authentication exchange exceeded limit');
        const response = await mysqlRead(reader);
        await send(
          client,
          mysqlFrame(response.body, response.sequence - delta),
        );
        if (response.body[0] === 0) break;
        if (response.body[0] === 255) return;
        // caching_sha2 fast-auth success does not expect another client packet.
        if (response.body[0] === 1 && response.body[1] === 3) continue;
        if (![1, 254].includes(response.body[0]))
          throw new Error('Unsupported MySQL authentication');
        const reply = await mysqlRead(downstream);
        await send(upstream, mysqlFrame(reply.body, reply.sequence + delta));
      }
      errorSequence.set(client, 1);
      for (;;) {
        const request = await mysqlRead(downstream);
        if (request.sequence !== 0 || !request.body.length)
          throw new Error('Invalid MySQL command');
        const command = request.body[0];
        if (command === 1 && request.body.length === 1) return;
        if (command !== 3)
          throw new Error(
            'Only MySQL COM_QUERY is supported; prepared statements, database switches and other commands are blocked',
          );
        await query(utf8(request.body.subarray(1)));
        await send(upstream, mysqlFrame(request.body, 0));
        let response = await mysqlRead(reader);
        if ([0, 255].includes(response.body[0])) {
          await send(client, mysqlFrame(response.body, response.sequence));
          continue;
        }
        // Single result set, bounded column count; legacy EOF separates metadata
        // from rows. LOCAL INFILE (0xfb) is never relayed to the client.
        const columns = response.body[0];
        if (columns < 1 || columns >= 251 || response.body.length !== 1)
          throw new Error('Unsupported MySQL result');
        await send(client, mysqlFrame(response.body, response.sequence));
        for (let i = 0; i < columns; i++) {
          response = await mysqlRead(reader);
          await send(client, mysqlFrame(response.body, response.sequence));
        }
        response = await mysqlRead(reader);
        if (response.body[0] !== 254 || response.body.length >= 9)
          throw new Error('Expected MySQL metadata EOF');
        await send(client, mysqlFrame(response.body, response.sequence));
        for (;;) {
          response = await mysqlRead(reader);
          if (response.body[0] === 254 && response.body.length < 9) {
            if (response.body.length < 5 || u16le(response.body, 3) & 8)
              throw new Error('Multiple MySQL results unsupported');
            await send(client, mysqlFrame(response.body, response.sequence));
            break;
          }
          await send(client, mysqlFrame(response.body, response.sequence));
          if (response.body[0] === 255) break;
        }
      }
    } finally {
      upstream.destroy();
    }
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
