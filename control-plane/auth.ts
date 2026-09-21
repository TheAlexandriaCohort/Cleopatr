import { createHmac, timingSafeEqual } from 'node:crypto';

export const SESSION_COOKIE = 'cleo_admin_session';
const SESSION_SECONDS = 12 * 60 * 60;
function same(a: string, b: string) {
  const left = Buffer.from(a),
    right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}
export function validAdminToken(
  value: string,
  token = process.env.CLEO_ADMIN_TOKEN,
) {
  return !!token && same(value, token);
}
export function createSession(token: string, now = Date.now()) {
  const expires = String(Math.floor(now / 1000) + SESSION_SECONDS);
  return (
    expires +
    '.' +
    createHmac('sha256', token)
      .update('cleopatr-admin:' + expires)
      .digest('hex')
  );
}
export function isAdministrator(
  headers: Headers,
  token = process.env.CLEO_ADMIN_TOKEN,
  now = Date.now(),
) {
  if (!token) {
    // Local mode is paired with the loopback-only server launcher. Do not trust
    // forwarded identity/host headers or permit DNS rebinding to another host.
    const host = headers.get('host') ?? '';
    return /^(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/.test(host);
  }
  if (validAdminToken(headers.get('x-cleo-admin-token') ?? '', token))
    return true;
  const session = headers
    .get('cookie')
    ?.split(';')
    .map((part) => part.trim())
    .find((part) => part.startsWith(SESSION_COOKIE + '='))
    ?.slice(SESSION_COOKIE.length + 1);
  if (!session) return false;
  const [expires, signature, extra] = session.split('.');
  if (
    extra !== undefined ||
    !/^\d+$/.test(expires) ||
    !signature ||
    Number(expires) <= now / 1000 ||
    Number(expires) > now / 1000 + SESSION_SECONDS
  )
    return false;
  const expected = createHmac('sha256', token)
    .update('cleopatr-admin:' + expires)
    .digest('hex');
  return same(signature, expected);
}
export function sessionCookie(value: string, secure: boolean, clear = false) {
  return `${SESSION_COOKIE}=${value}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${clear ? 0 : SESSION_SECONDS}${secure ? '; Secure' : ''}`;
}
