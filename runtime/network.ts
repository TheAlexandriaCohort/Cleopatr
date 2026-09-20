import type { Resource } from '../core/model.ts';

export function networkIdentity(value: string) {
  try {
    const url = new URL(value);
    return `${url.protocol}//${url.hostname.toLowerCase()}:${url.port || (url.protocol === 'https:' ? 443 : url.protocol === 'http:' ? 80 : '')}`;
  } catch {
    return value;
  }
}
export function networkResource(resources: Resource[], locator: string) {
  const target = networkIdentity(locator);
  return resources.find(
    (resource) =>
      resource.type === 'Network' &&
      networkIdentity(resource.locator) === target,
  );
}
