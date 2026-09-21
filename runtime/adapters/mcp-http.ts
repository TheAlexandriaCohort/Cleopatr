import type { Resource } from '../../core/model.ts';
import { Buffer } from 'node:buffer';
import type { Decide } from './http.ts';

const calls: Record<string, string> = {
  'tools/call': 'mcp.tool.invoke',
  'resources/read': 'mcp.resource.read',
  'prompts/get': 'mcp.prompt.get',
};
const administration = new Set([
  'initialize',
  'ping',
  'tools/list',
  'resources/list',
  'resources/templates/list',
  'prompts/list',
  'notifications/initialized',
  'notifications/cancelled',
  'notifications/progress',
]);

export function mcpResources(resources: Resource[], target: URL) {
  return resources.filter((resource) => {
    if (resource.type !== 'MCPTool') return false;
    try {
      const url = new URL(resource.locator);
      return (
        url.origin === target.origin &&
        url.pathname === target.pathname &&
        url.search === target.search
      );
    } catch {
      return false;
    }
  });
}

export async function authorizeMcpBody(
  body: Buffer,
  target: URL,
  resources: Resource[],
  decide: Decide,
) {
  // One immutable body is parsed, authorized and forwarded. Batches/unknown extensions fail closed.
  const message: unknown = JSON.parse(
    new TextDecoder('utf-8', { fatal: true }).decode(body),
  );
  if (!message || typeof message !== 'object' || Array.isArray(message))
    return false;
  const msg = message as Record<string, unknown>;
  if (msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') return false;
  if (administration.has(msg.method)) return true;
  const action = calls[msg.method];
  if (
    !action ||
    !msg.params ||
    typeof msg.params !== 'object' ||
    Array.isArray(msg.params)
  )
    return false;
  const params = msg.params as Record<string, unknown>;
  const name = msg.method === 'resources/read' ? params.uri : params.name;
  if (typeof name !== 'string' || !name || name.length > 2048) return false;
  const resource =
    resources.find(
      (r) => decodeURIComponent(new URL(r.locator).hash.slice(1)) === name,
    ) ?? resources.find((r) => !new URL(r.locator).hash);
  if (!resource) return false;
  const args = params.arguments;
  const amount =
    args && typeof args === 'object' && !Array.isArray(args)
      ? (args as Record<string, unknown>).amount
      : undefined;
  if (amount !== undefined && !Number.isSafeInteger(amount)) return false;
  return decide(
    action,
    { type: 'MCPTool', id: resource.id },
    {
      tool: name,
      server: target.origin,
      operation: msg.method,
      protocol: 'mcp-http',
      semanticAvailable: true,
      confidence: 'proxy-observed',
      ...(amount === undefined ? {} : { amount }),
    },
  );
}
