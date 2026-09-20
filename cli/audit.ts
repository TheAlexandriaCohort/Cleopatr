import {
  appendFile,
  mkdir,
  readFile,
  readdir,
  rename,
  unlink,
  writeFile,
} from 'node:fs/promises';
import { join, resolve } from 'node:path';
import type { EventRecord } from '../core/api-types.ts';
import { MAX_AUDIT_BATCH_BYTES, jsonBytes } from '../core/assessment.ts';
import { atomicJson, dataDir, readConfig } from './cache.ts';

export async function spool(event: EventRecord, dir = dataDir()) {
  const spoolDir = join(dir, 'spool');
  await mkdir(spoolDir, { recursive: true, mode: 0o700 });
  const files = await readdir(spoolDir);
  if (files.length >= 10000) {
    const allows = files.filter((f) => f.endsWith('.allow.json')).sort();
    if (allows.length) await unlink(join(spoolDir, allows[0])).catch(() => {});
    else {
      await appendFile(
        join(dir, 'audit-overflow.log'),
        `${new Date().toISOString()} spool full; ${event.decision} event not persisted\n`,
        { mode: 0o600 },
      );
      throw new Error('Audit spool is full');
    }
  }
  const name = `${Date.now()}-${crypto.randomUUID()}.${event.decision === 'ALLOW' ? 'allow' : 'deny'}.json`;
  const tmp = join(spoolDir, name + '.tmp');
  await writeFile(tmp, JSON.stringify(event), { mode: 0o600 });
  await rename(tmp, join(spoolDir, name));
}

type UploadStatus = {
  lastAttempt?: string;
  lastSuccess?: string;
  lastError?: string | null;
};
async function savedStatus(dir: string): Promise<UploadStatus> {
  return readFile(join(dir, 'audit-status.json'), 'utf8')
    .then(JSON.parse)
    .catch(() => ({}));
}
export async function auditStatus(dir = dataDir()) {
  const files = await readdir(join(dir, 'spool')).catch(() => []);
  return {
    ...(await savedStatus(dir)),
    pending: files.filter((f) => f.endsWith('.json')).length,
  };
}

const activeUploads = new Map<string, Promise<number>>();
export function flushAudit(
  dir = dataDir(),
  options: { maxBatches?: number } = {},
) {
  dir = resolve(dir);
  const active = activeUploads.get(dir);
  if (active) return active;
  const operation = upload(dir, options.maxBatches ?? 1).finally(() =>
    activeUploads.delete(dir),
  );
  activeUploads.set(dir, operation);
  return operation;
}

async function upload(dir: string, maxBatches: number) {
  const path = join(dir, 'spool');
  const previous = await savedStatus(dir);
  const deadline = Date.now() + 4000;
  let uploaded = 0;
  let attempted = false;
  try {
    for (let batch = 0; batch < maxBatches && Date.now() < deadline; batch++) {
      const files = (await readdir(path).catch(() => []))
        .filter((f) => f.endsWith('.json'))
        .sort()
        .slice(0, 100);
      if (!files.length) break;
      attempted = true;
      const events: EventRecord[] = [];
      const selected: string[] = [];
      let bytes = jsonBytes({ events: [] });
      for (const file of files) {
        let text: string;
        try {
          text = await readFile(join(path, file), 'utf8');
        } catch (error) {
          // Another CLI process may have already uploaded this exact record.
          if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue;
          throw error;
        }
        const event = JSON.parse(text) as EventRecord;
        const size = jsonBytes(event) + (events.length ? 1 : 0);
        if (bytes + size > MAX_AUDIT_BATCH_BYTES) break;
        bytes += size;
        selected.push(file);
        events.push(event);
      }
      if (!events.length) {
        if (
          !selected.length &&
          !(await readdir(path)).some((f) => files.includes(f))
        )
          continue;
        throw new Error('Audit record exceeds upload size limit');
      }
      const config = await readConfig(dir);
      const response = await fetch(new URL('/api/v1/audit', config.server), {
        method: 'POST',
        headers: {
          authorization: `Bearer ${config.token}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ events }),
        signal: AbortSignal.timeout(Math.max(1, deadline - Date.now())),
        redirect: 'error',
      });
      if (!response.ok)
        throw new Error(`Audit upload failed (${response.status})`);
      const receipt = (await response.json()) as { accepted?: number };
      if (receipt.accepted !== events.length)
        throw new Error('Audit server did not acknowledge every event');
      // Concurrent uploads are harmless: the server deduplicates by client and event ID.
      for (const file of selected)
        await unlink(join(path, file)).catch(() => {});
      uploaded += selected.length;
    }
    if (attempted)
      await atomicJson(join(dir, 'audit-status.json'), {
        ...previous,
        lastAttempt: new Date().toISOString(),
        ...(uploaded ? { lastSuccess: new Date().toISOString() } : {}),
        lastError: null,
      });
    return uploaded;
  } catch (error) {
    await atomicJson(join(dir, 'audit-status.json'), {
      ...previous,
      lastAttempt: new Date().toISOString(),
      lastError: (error as Error).message,
    }).catch(() => {});
    throw error;
  }
}

/** Upload independently of the five-minute policy refresh, without delaying authorization. */
export function startAuditUploader(dir: string, intervalMs = 5000) {
  let errorReported = '';
  let current: Promise<void> | undefined;
  const tick = () => {
    if (current) return current;
    current = flushAudit(dir, { maxBatches: 20 })
      .then(() => {
        errorReported = '';
      })
      .catch((error: Error) => {
        if (errorReported !== error.message) {
          process.stderr.write(
            `cleo: ${error.message}; events retained locally for retry. Inspect cleo status or run cleo audit flush.\n`,
          );
          errorReported = error.message;
        }
      })
      .finally(() => {
        current = undefined;
      });
    return current;
  };
  void tick();
  const timer = setInterval(() => void tick(), intervalMs);
  timer.unref();
  return {
    async stop() {
      clearInterval(timer);
      await current;
      // Include events produced after an in-flight batch was selected.
      await tick();
    },
  };
}
