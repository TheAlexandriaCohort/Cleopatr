import {
  createSession,
  sessionCookie,
  validAdminToken,
} from '../../../control-plane/auth';
import { requestOrigin } from '../../../control-plane/http';
export async function POST(request: Request) {
  const url = new URL(request.url);
  const origin = request.headers.get('origin');
  if (!origin || origin !== requestOrigin(request))
    return Response.json(
      { error: 'Cross-origin request rejected' },
      { status: 403 },
    );
  const reader = request.body?.getReader();
  const bytes: number[] = [];
  if (reader)
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (bytes.length + value.byteLength > 4096) {
        await reader.cancel();
        return Response.json({ error: 'Request too large' }, { status: 413 });
      }
      bytes.push(...value);
    }
  const text = new TextDecoder().decode(new Uint8Array(bytes));
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    return Response.json({ error: 'Invalid JSON' }, { status: 400 });
  }
  if (body?.logout === true)
    return Response.json(
      { ok: true },
      {
        headers: {
          'set-cookie': sessionCookie('', url.protocol === 'https:', true),
          'cache-control': 'no-store',
        },
      },
    );
  if (typeof body?.token !== 'string' || !validAdminToken(body.token))
    return Response.json(
      { error: 'Invalid administrator token' },
      { status: 401, headers: { 'cache-control': 'no-store' } },
    );
  return Response.json(
    { ok: true },
    {
      headers: {
        'set-cookie': sessionCookie(
          createSession(process.env.CLEO_ADMIN_TOKEN!),
          url.protocol === 'https:',
        ),
        'cache-control': 'no-store',
      },
    },
  );
}
