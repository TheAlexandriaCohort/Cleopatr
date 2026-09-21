import {
  mkdir,
  readFile,
  writeFile,
  rename,
  stat,
  unlink,
  lstat,
  chmod,
} from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { homedir } from 'node:os';
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import * as cedar from '@cedar-policy/cedar-wasm/nodejs';
import { verifyBundle } from '../core/crypto.ts';
import { validatePolicies } from '../core/engine.ts';
import {
  ancestors,
  SCHEMA,
  type SignedBundle,
  type Bundle,
} from '../core/model.ts';
export const REFRESH_INTERVAL_MS = 300000;
export type Config = {
  server: string;
  token: string;
  tenant: string;
  publicKey: JsonWebKey;
  environmentIds: string[];
  clientId: string;
  clientName?: string;
  expiresAt?: string | null;
  environment?: string;
};
export type Cache = {
  signed: SignedBundle;
  checkedAt: number;
  activatedAt: number;
  highWater: number;
  etag: string;
};
export function dataDir() {
  if (process.env.CLEO_HOME) return resolve(process.env.CLEO_HOME);
  const project = resolve('.cleo');
  const previous = join(homedir(), '.config', 'cleopatr');
  return existsSync(join(project, 'config')) ||
    existsSync(join(project, 'config.json')) ||
    !existsSync(join(previous, 'config.json'))
    ? project
    : previous;
}
export async function ensureDir(dir: string) {
  await mkdir(dir, { recursive: true, mode: 0o700 });
  if ((await lstat(dir)).isSymbolicLink())
    throw new Error('Refusing a symbolic-link Cleopatr directory');
  await chmod(dir, 0o700);
}
export async function atomicJson(path: string, value: unknown) {
  const temp = path + '.' + crypto.randomUUID() + '.tmp';
  await writeFile(temp, JSON.stringify(value, null, 2), {
    mode: 0o600,
    flag: 'wx',
  });
  try {
    await rename(temp, path);
  } catch (e) {
    await unlink(temp).catch(() => {});
    throw e;
  }
}
export async function readConfig(dir = dataDir()): Promise<Config> {
  const config = JSON.parse(
    await readFile(join(dir, 'config'), 'utf8').catch(
      (error: NodeJS.ErrnoException) => {
        if (error.code !== 'ENOENT') throw error;
        return readFile(join(dir, 'config.json'), 'utf8');
      },
    ),
  );
  validateConfig(config);
  return config;
}
export function validateConfig(config: Config) {
  const url = new URL(config.server);
  if (
    url.username ||
    url.password ||
    !['http:', 'https:'].includes(url.protocol) ||
    (url.protocol === 'http:' &&
      !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))
  )
    throw new Error(
      'Control plane must use HTTPS (HTTP is allowed only on loopback)',
    );
  if (
    !config.tenant ||
    !config.token ||
    !config.clientId ||
    (config.clientName !== undefined &&
      (typeof config.clientName !== 'string' ||
        !config.clientName.trim() ||
        config.clientName.length > 200)) ||
    !config.publicKey?.x ||
    !Array.isArray(config.environmentIds) ||
    !config.environmentIds.length ||
    config.environmentIds.some((x) => typeof x !== 'string') ||
    (config.environment !== undefined &&
      (typeof config.environment !== 'string' || !config.environment.trim()))
  )
    throw new Error('Invalid enrollment configuration');
}
export async function readCache(dir = dataDir()): Promise<Cache | null> {
  try {
    return JSON.parse(await readFile(join(dir, 'bundle.json'), 'utf8'));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw new Error(
      'Policy cache is unreadable; run cleo sync or import a verified bundle',
    );
  }
}
export async function loadBundle(dir = dataDir()) {
  const config = await readConfig(dir);
  const cache = await readCache(dir);
  if (!cache)
    throw new Error(
      'No verified policy bundle. Run cleo sync or import a signed bundle before authorizing.',
    );
  const bundle = await verifyBundle(
    cache.signed,
    config.publicKey,
    config.tenant,
    cache.highWater,
  );
  verifyScope(bundle, config);
  const validation = validatePolicies(cedar, bundle.policies);
  if (!validation.valid)
    throw new Error(
      'Cached policy validation failed: ' + validation.errors.join('; '),
    );
  return { config, cache, bundle };
}
function verifyScope(
  bundle: Bundle,
  config: Config,
): asserts bundle is Bundle & { client: { id: string; name: string } } {
  if (!bundle.client)
    throw new Error(
      'Policy bundle has no signed client identity. Run cleo sync or download a bundle for this client from Deploy, then import it.',
    );
  if (bundle.client.id !== config.clientId)
    throw new Error('Signed client identity does not match this enrollment');
  if (JSON.stringify(bundle.schema) !== JSON.stringify(SCHEMA))
    throw new Error('Bundle schema does not match this client');
  const expected = bundle.environments
    .filter((e) =>
      ancestors(bundle.environments, e.id).some((id) =>
        config.environmentIds.includes(id),
      ),
    )
    .map((e) => e.id)
    .sort();
  if (
    JSON.stringify([...bundle.environmentIds].sort()) !==
    JSON.stringify(expected)
  )
    throw new Error('Bundle assignment does not match this client enrollment');
}
async function withActivationLock<T>(
  dir: string,
  work: () => Promise<T>,
): Promise<T> {
  const lock = join(dir, 'activation.lock');
  const started = Date.now();
  while (true) {
    try {
      await writeFile(lock, String(Date.now()), { flag: 'wx', mode: 0o600 });
      break;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
      try {
        if (Date.now() - (await stat(lock)).mtimeMs > 30000) await unlink(lock);
      } catch {}
      if (Date.now() - started > 3000)
        throw new Error('Policy activation is busy; retry');
      await new Promise((r) => setTimeout(r, 10));
    }
  }
  try {
    return await work();
  } finally {
    await unlink(lock).catch(() => {});
  }
}
export async function activate(
  signed: SignedBundle,
  dir = dataDir(),
  checkedAt = Date.now(),
) {
  return withActivationLock(dir, () =>
    activateUnlocked(signed, dir, checkedAt),
  );
}
async function activateUnlocked(
  signed: SignedBundle,
  dir: string,
  checkedAt: number,
) {
  const config = await readConfig(dir);
  const cache = await readCache(dir);
  const bundle = await verifyBundle(
    signed,
    config.publicKey,
    config.tenant,
    cache?.highWater ?? 0,
  );
  verifyScope(bundle, config);
  const validation = validatePolicies(cedar, bundle.policies);
  if (!validation.valid)
    throw new Error(
      'Policy schema validation failed: ' + validation.errors.join('; '),
    );
  if (cache) {
    const old = await verifyBundle(
      cache.signed,
      config.publicKey,
      config.tenant,
      cache.highWater,
    );
    if (
      old.sequence === bundle.sequence &&
      cache.signed.digest !== signed.digest
    )
      throw new Error('Policy bundle contents changed without a new sequence');
  }
  const next: Cache = {
    signed,
    checkedAt,
    activatedAt: Date.now(),
    highWater: Math.max(cache?.highWater ?? 0, bundle.sequence),
    etag: `"${signed.digest}"`,
  };
  await atomicJson(join(dir, 'bundle.json'), next);
  return bundle;
}
export function needsRefresh(cache: Cache | null, at = Date.now()) {
  return !cache || at - cache.checkedAt >= REFRESH_INTERVAL_MS;
}
export async function requestRefresh(dir = dataDir(), entry = process.argv[1]) {
  // The caller never waits for network I/O or for this child to complete.
  const cache = await readCache(dir);
  if (!needsRefresh(cache)) return false;
  const lock = join(dir, 'refresh.lock');
  try {
    await writeFile(lock, String(Date.now()), { flag: 'wx', mode: 0o600 });
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
    const age = Date.now() - (await stat(lock)).mtimeMs;
    if (age > 60000) {
      await unlink(lock).catch(() => {});
    }
    return false;
  }
  try {
    const args = entry.endsWith('.ts')
      ? ['--import', 'tsx', entry, '__refresh']
      : [entry, '__refresh'];
    const child = spawn(process.execPath, args, {
      detached: true,
      stdio: 'ignore',
      env: { ...process.env, CLEO_HOME: dir },
    });
    child.on('error', () => {
      void unlink(lock).catch(() => {});
    });
    child.unref();
    return true;
  } catch (e) {
    await unlink(lock).catch(() => {});
    throw e;
  }
}
export async function sync(dir = dataDir(), fetcher: typeof fetch = fetch) {
  const config = await readConfig(dir);
  const cache = await readCache(dir);
  const response = await fetcher(new URL('/api/v1/bundles', config.server), {
    headers: {
      authorization: `Bearer ${config.token}`,
      ...(cache ? { 'if-none-match': cache.etag } : {}),
    },
    signal: AbortSignal.timeout(4000),
    redirect: 'error',
  });
  if (response.status === 304) {
    if (!cache) throw new Error('Server returned 304 without a local bundle');
    await withActivationLock(dir, async () => {
      await loadBundle(dir);
      const current = await readCache(dir);
      if (current?.etag === cache.etag)
        await atomicJson(join(dir, 'bundle.json'), {
          ...current,
          checkedAt: Date.now(),
        });
    });
    return { changed: false, sequence: cache.highWater };
  }
  if (!response.ok)
    throw new Error(
      `Policy refresh failed (${response.status}); the previous verified bundle is retained`,
    );
  const text = await response.text();
  if (text.length > 5000000) throw new Error('Policy bundle is too large');
  const bundle = await activate(JSON.parse(text), dir);
  return { changed: true, sequence: bundle.sequence };
}
export async function refreshWorker(dir = dataDir()) {
  try {
    await sync(dir);
    await atomicJson(join(dir, 'refresh-status.json'), {
      ok: true,
      time: new Date().toISOString(),
    });
  } catch (e) {
    await atomicJson(join(dir, 'refresh-status.json'), {
      ok: false,
      time: new Date().toISOString(),
      error: (e as Error).message,
    });
  } finally {
    await unlink(join(dir, 'refresh.lock')).catch(() => {});
  }
}
