import { lstat, readFile, readdir, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import type { EventRecord } from '../core/api-types.ts';
import { MAX_AUDIT_EVENT_BYTES } from '../core/assessment.ts';
import { spool } from './audit.ts';

export async function importVmEvents(shared: string, dir: string, limit = 100) {
  const files = (await readdir(join(shared, 'events')))
    .filter((file) => file.endsWith('.json'))
    .sort()
    .slice(0, limit);
  for (const file of files) {
    const path = join(shared, 'events', file);
    const metadata = await lstat(path);
    if (!metadata.isFile() || metadata.size > MAX_AUDIT_EVENT_BYTES)
      throw new Error('Invalid VM audit record');
    const event = JSON.parse(await readFile(path, 'utf8')) as EventRecord;
    await spool(event, dir);
    // Remove the guest copy only after the host has durably queued it.
    await unlink(path);
  }
  return files.length;
}
