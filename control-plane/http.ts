/** Next.js may use its internal hostname in request.url. Match browser origins
 * against the incoming Host, never an untrusted forwarded-host header. */
export function requestOrigin(request: Request): string | null {
  const url = new URL(request.url);
  const host = request.headers.get('host') ?? url.host;
  if (/[\s/@?#\\]/.test(host)) return null;
  try {
    return new URL(`${url.protocol}//${host}`).origin;
  } catch {
    return null;
  }
}
