import Console from './console';
import { headers } from 'next/headers';
import { redirect } from 'next/navigation';
import { isAdministrator } from '../control-plane/auth';
export const dynamic = 'force-dynamic';
export default async function Page() {
  if (!isAdministrator(new Headers(await headers()))) redirect('/login');
  return <Console canSignOut={!!process.env.CLEO_ADMIN_TOKEN} />;
}
