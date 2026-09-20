import { u16be, u32be } from './wire.ts';
import { Buffer } from 'node:buffer';
import dgram from 'node:dgram';
import net, { type AddressInfo } from 'node:net';
import { getServers } from 'node:dns';
import { networkResource } from '../network.ts';
import type { Resource } from '../../core/model.ts';
import type { Decide } from './http.ts';

// One uncompressed IN question per datagram. Compression in questions and
// extra sections are deliberately refused rather than interpreted differently
// from the upstream resolver. Replies are bounded and correlated by the socket.
export function dnsQuestion(packet: Buffer) {
  if (
    packet.length < 17 ||
    packet.length > 4096 ||
    u16be(packet, 2) & 0xf800 ||
    u16be(packet, 4) !== 1 ||
    u16be(packet, 6) ||
    u16be(packet, 8)
  )
    throw new Error('Unsupported DNS message');
  let offset = 12;
  const labels: string[] = [];
  while (packet[offset]) {
    const length = packet[offset++];
    if (length > 63 || offset + length >= packet.length)
      throw new Error('Invalid DNS name');
    const label = new TextDecoder('utf-8', { fatal: true }).decode(
      packet.subarray(offset, offset + length),
    );
    if (!/^[a-zA-Z0-9_-]+$/.test(label)) throw new Error('Invalid DNS label');
    labels.push(label.toLowerCase());
    offset += length;
  }
  offset++;
  if (
    !labels.length ||
    labels.join('.').length > 253 ||
    offset + 4 > packet.length ||
    u16be(packet, offset + 2) !== 1
  )
    throw new Error('Invalid DNS question');
  const type = u16be(packet, offset);
  // Accept only a single, empty EDNS0 OPT record after the question.
  const end = offset + 4;
  const additional = u16be(packet, 10);
  if (
    additional === 0
      ? end !== packet.length
      : additional !== 1 ||
        packet.length !== end + 11 ||
        packet[end] !== 0 ||
        u16be(packet, end + 1) !== 41 ||
        u32be(packet, end + 5) !== 0 ||
        u16be(packet, end + 9) !== 0
  )
    throw new Error('Unsupported DNS additional records');
  return { host: labels.join('.'), type, end };
}
export function dnsReply(packet: Buffer, code: number, address?: string) {
  let end = 12;
  try {
    end = dnsQuestion(packet).end;
  } catch {
    /* FORMERR has no question */
  }
  const out = Buffer.alloc(end + (address ? 16 : 0));
  out.set(packet.subarray(0, end));
  out.writeUInt16BE(
    0x8080 | (packet.length >= 4 ? u16be(packet, 2) & 0x100 : 0) | code,
    2,
  );
  out.writeUInt16BE(end > 12 ? 1 : 0, 4);
  out.writeUInt16BE(address ? 1 : 0, 6);
  out.writeUInt32BE(0, 8);
  if (address) {
    out.writeUInt16BE(0xc00c, end);
    out.writeUInt16BE(1, end + 2);
    out.writeUInt16BE(1, end + 4);
    out.writeUInt32BE(5, end + 6);
    out.writeUInt16BE(4, end + 10);
    Buffer.from(address.split('.').map(Number)).copy(out, end + 12);
  }
  return out;
}
export function createDnsAdapter(
  resources: Resource[],
  decide: Decide,
  aliases: Map<string, string> = new Map(),
  resolver = getServers()[0],
) {
  return async (packet: Buffer): Promise<Buffer> => {
    let question: ReturnType<typeof dnsQuestion>;
    try {
      question = dnsQuestion(packet);
    } catch {
      return dnsReply(packet, 1);
    }
    const { host, type } = question;
    const resource = networkResource(resources, `dns://${host}`);
    if (
      !(await decide(
        'dns.query',
        { type: 'Network', id: resource?.id ?? `dns://${host}` },
        {
          host,
          operation: String(type),
          protocol: 'dns',
          semanticAvailable: true,
          confidence: 'wire-observed',
        },
      ))
    )
      return dnsReply(packet, 5);
    const alias = aliases.get(host);
    if (alias) return dnsReply(packet, 0, type === 1 ? alias : undefined);
    if (!resolver || !net.isIP(resolver)) return dnsReply(packet, 2);
    return new Promise((resolve) => {
      const socket = dgram.createSocket(
        net.isIP(resolver) === 6 ? 'udp6' : 'udp4',
      );
      let done = false;
      const finish = (answer: Buffer) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        socket.close();
        resolve(answer);
      };
      const timer = setTimeout(() => finish(dnsReply(packet, 2)), 2000);
      socket.on('error', () => finish(dnsReply(packet, 2)));
      socket.on('message', (answer) => {
        if (
          answer.length < 12 ||
          answer.length > 4096 ||
          u16be(answer, 0) !== u16be(packet, 0) ||
          !(u16be(answer, 2) & 0x8000) ||
          u16be(answer, 4) !== 1 ||
          answer.length < question.end ||
          !answer
            .subarray(12, question.end)
            .every((v, i) => v === packet[12 + i])
        )
          return;
        finish(answer);
      });
      socket.connect(53, resolver, () => socket.send(packet));
    });
  };
}
export async function startDnsTcp(answer: (packet: Buffer) => Promise<Buffer>) {
  const sockets = new Set<net.Socket>();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => socket.destroy());
    socket.setTimeout(10000, () => socket.destroy());
    let buffer = Buffer.alloc(0),
      busy = false;
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length > 8192) return void socket.destroy();
      void pump();
    });
    async function pump() {
      if (busy) return;
      busy = true;
      try {
        while (buffer.length >= 2) {
          const length = u16be(buffer, 0);
          if (length < 12 || length > 4096) throw new Error('DNS frame limit');
          if (buffer.length < length + 2) break;
          const packet = buffer.subarray(2, length + 2);
          buffer = buffer.subarray(length + 2);
          const response = await answer(packet);
          const header = Buffer.alloc(2);
          header.writeUInt16BE(response.length);
          socket.write(Buffer.concat([header, response]));
        }
      } catch {
        socket.destroy();
      } finally {
        busy = false;
      }
    }
  });
  server.maxConnections = 64;
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
