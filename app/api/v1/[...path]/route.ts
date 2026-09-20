import { env } from 'cloudflare:workers';
import { getChatGPTUser } from '../../../chatgpt-auth';
import { ControlPlane, type Database } from '../../../../control-plane/service';
import cedar from '../../../../control-plane/cedar';
export const dynamic = 'force-dynamic';
async function handle(request: Request) {
  const user = await getChatGPTUser();
  const secrets = env as unknown as {
    CLEO_SIGNING_JWK?: string;
    CLEO_AUTHORING_ENDPOINT?: string;
    CLEO_AUTHORING_TOKEN?: string;
  };
  const key = secrets.CLEO_SIGNING_JWK;
  return new ControlPlane(
    env.DB as unknown as Database,
    cedar,
    key ? JSON.parse(key) : undefined,
    secrets.CLEO_AUTHORING_ENDPOINT
      ? {
          endpoint: secrets.CLEO_AUTHORING_ENDPOINT,
          token: secrets.CLEO_AUTHORING_TOKEN,
        }
      : undefined,
  ).handle(request, user ? { id: user.userId, name: user.displayName } : null);
}
export const GET = handle;
export const POST = handle;
