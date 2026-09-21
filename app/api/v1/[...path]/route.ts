import { nodeControlPlane } from '../../../../control-plane/node';
import { isAdministrator } from '../../../../control-plane/auth';
export const dynamic = 'force-dynamic';
async function handle(request: Request) {
  const { plane, workspaceId } = nodeControlPlane();
  const response = await plane.handle(
    request,
    isAdministrator(request.headers)
      ? { id: workspaceId, name: 'Administrator' }
      : null,
  );
  if (!response.headers.has('cache-control'))
    response.headers.set('cache-control', 'no-store');
  return response;
}
export const GET = handle;
export const POST = handle;
