import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { makeKeys, signBundle } from '../core/crypto.ts';
import {
  createSeed,
  publishedSnapshot,
  SCHEMA,
  type Bundle,
} from '../core/model.ts';
import {
  activate,
  atomicJson,
  readCache,
  sync,
  needsRefresh,
  requestRefresh,
  loadBundle,
} from '../cli/cache.ts';
import { authorize, createPinnedAuthorizer } from '../cli/runtime.ts';
async function fixture() {
  const dir = await mkdtemp(join(tmpdir(), 'cleo-test-'));
  const keys = await makeKeys();
  await atomicJson(join(dir, 'config.json'), {
    server: 'https://offline.example',
    token: 'test-token',
    tenant: 'test',
    publicKey: keys.publicKey,
    environmentIds: ['development'],
    clientId: 'test-client',
    clientName: 'Test client',
  });
  const seed = createSeed();
  seed.policies.forEach((p) => (p.status = 'PUBLISHED'));
  const bundle: Bundle = {
    ...publishedSnapshot(seed),
    schema: SCHEMA,
    schemaVersion: '3.0',
    tenant: 'test',
    sequence: 1,
    bundleId: 'one',
    createdAt: new Date().toISOString(),
    environmentIds: ['development'],
    minimumClientVersion: '0.3.0',
  };
  const signed = await signBundle(bundle, keys.privateKey);
  return { dir, keys, bundle, signed };
}
const action = {
  environmentId: 'development',
  sessionId: 'test',
  action: 'file.read',
  resource: { type: 'File' as const, id: 'project-workspace' },
  context: { withinWorkspace: true },
};
void test('pinned supervisor authorizer preserves identity and rejects changed cache bytes at the same sequence', async () => {
  const f = await fixture();
  await activate(f.signed, f.dir);
  const loaded = await loadBundle(f.dir);
  const pinned = createPinnedAuthorizer(loaded, {
    dir: f.dir,
    refresh: false,
    expectedSequence: 1,
  });
  const result = await pinned(
    { ...action, principal: 'spoofed client' },
    'seccomp',
  );
  assert.equal(result.parc.principal.id, 'Test client');
  const cache = (await readCache(f.dir))!;
  await atomicJson(join(f.dir, 'bundle.json'), {
    ...cache,
    checkedAt: Date.now(),
  });
  assert.equal(
    (await pinned(action)).sequence,
    1,
    '304 freshness updates do not replace policies',
  );
  await atomicJson(join(f.dir, 'bundle.json'), {
    ...cache,
    signed: { ...cache.signed, payload: cache.signed.payload + 'tampered' },
  });
  await assert.rejects(pinned(action), /snapshot changed/);
});
void test('supervisor cannot authorize against a snapshot different from its installed kernel profile', async () => {
  const f = await fixture();
  await activate(f.signed, f.dir);
  assert.equal(
    (
      await authorize(action, {
        dir: f.dir,
        refresh: false,
        expectedSequence: 1,
      })
    ).sequence,
    1,
  );
  await activate(
    await signBundle(
      { ...f.bundle, sequence: 2, bundleId: 'two' },
      f.keys.privateKey,
    ),
    f.dir,
  );
  await assert.rejects(
    () =>
      authorize(action, { dir: f.dir, refresh: false, expectedSequence: 1 }),
    /snapshot changed/,
  );
});
void test('five-minute threshold and successful 304 updates last checked time', async () => {
  const f = await fixture();
  await activate(f.signed, f.dir, 1000);
  const c = await readCache(f.dir);
  assert.equal(needsRefresh(c, 300999), false);
  assert.equal(needsRefresh(c, 301000), true);
  await sync(
    f.dir,
    (async () => new Response(null, { status: 304 })) as typeof fetch,
  );
  assert.equal(needsRefresh(await readCache(f.dir)), false);
});
void test('offline refresh retains the last-known verified policy set', async () => {
  const f = await fixture();
  await activate(f.signed, f.dir, 1000);
  await assert.rejects(
    () =>
      sync(f.dir, (async () => {
        throw new Error('offline');
      }) as typeof fetch),
    /offline/,
  );
  assert.equal((await loadBundle(f.dir)).bundle.sequence, 1);
  const decision = await authorize(action, { dir: f.dir, refresh: false });
  assert.equal(decision.allowed, true);
  assert.equal(decision.stale, true);
});
void test('tamper, wrong assignments, old sequence and changed equal-sequence bundle cannot replace cache', async () => {
  const f = await fixture();
  await activate(f.signed, f.dir);
  await assert.rejects(() =>
    activate({ ...f.signed, signature: f.signed.signature.slice(4) }, f.dir),
  );
  const next = await signBundle(
    { ...f.bundle, sequence: 2, bundleId: 'two' },
    f.keys.privateKey,
  );
  await activate(next, f.dir);
  await assert.rejects(() => activate(f.signed, f.dir), /rollback/);
  await assert.rejects(
    async () =>
      activate(
        await signBundle(
          { ...f.bundle, sequence: 3, environmentIds: ['production'] },
          f.keys.privateKey,
        ),
        f.dir,
      ),
    /assignment/,
  );
  await assert.rejects(
    async () =>
      activate(
        await signBundle(
          { ...f.bundle, sequence: 2, bundleId: 'changed' },
          f.keys.privateKey,
        ),
        f.dir,
      ),
    /without a new sequence/,
  );
  assert.equal((await loadBundle(f.dir)).bundle.sequence, 2);
});
void test('default follows environment modes and explicit audit records would-deny', async () => {
  const f = await fixture();
  await activate(f.signed, f.dir);
  const denied = { ...action, context: { withinWorkspace: false } };
  const audit = await authorize(denied, { dir: f.dir, refresh: false });
  assert.equal(audit.decision, 'DENY');
  assert.equal(audit.allowed, true);
  assert.equal(audit.effectiveResult, 'ALLOWED_AUDIT');
  await activate(
    await signBundle(
      {
        ...f.bundle,
        sequence: 2,
        environments: f.bundle.environments.map((e) => ({
          ...e,
          mode: 'ENFORCE',
        })),
      },
      f.keys.privateKey,
    ),
    f.dir,
  );
  const enforce = await authorize(denied, {
    dir: f.dir,
    refresh: false,
  });
  assert.equal(enforce.mode, 'ENFORCE');
  assert.equal(enforce.allowed, false);
  const override = await authorize(denied, {
    dir: f.dir,
    refresh: false,
    mode: 'AUDIT',
  });
  assert.equal(override.allowed, true);
  assert.equal(override.decision, 'DENY');
  assert.equal(override.effectiveResult, 'ALLOWED_AUDIT');
  assert.equal(
    (await authorize(denied, { dir: f.dir, refresh: false })).allowed,
    false,
  );
});
void test('cold start has no implicit allow and rejects unassigned environments', async () => {
  const f = await fixture();
  await assert.rejects(
    () => authorize(action, { dir: f.dir, refresh: false }),
    /No verified/,
  );
  await activate(f.signed, f.dir);
  await assert.rejects(
    () =>
      authorize(
        { ...action, environmentId: 'production' },
        { dir: f.dir, refresh: false },
      ),
    /not assigned/,
  );
});
void test('refresh is detached and concurrent action requests coalesce', async () => {
  const f = await fixture();
  await activate(f.signed, f.dir, 0);
  const entry = join(f.dir, 'slow-refresh.mjs');
  await writeFile(entry, 'setTimeout(()=>{}, 1500)');
  const before = performance.now();
  const result = await authorize(action, { dir: f.dir, entry });
  assert.equal(result.allowed, true);
  assert.ok(
    performance.now() - before < 1000,
    'authorization waited for background worker',
  );
  assert.equal(await requestRefresh(f.dir, entry), false);
});
void test('concurrent activations never regress the high-water sequence', async () => {
  const f = await fixture();
  await activate(f.signed, f.dir);
  const two = await signBundle(
    { ...f.bundle, sequence: 2, bundleId: 'two' },
    f.keys.privateKey,
  );
  const three = await signBundle(
    { ...f.bundle, sequence: 3, bundleId: 'three' },
    f.keys.privateKey,
  );
  await Promise.allSettled([activate(three, f.dir), activate(two, f.dir)]);
  assert.equal((await loadBundle(f.dir)).bundle.sequence, 3);
});
void test('new clients can still use verified legacy caches while offline', async () => {
  const f = await fixture();
  const legacy = {
    ...f.bundle,
    schemaVersion: '1.0',
    minimumClientVersion: '0.1.0',
    releaseId: 'legacy',
    mode: 'ENFORCE',
  };
  await activate(await signBundle(legacy, f.keys.privateKey), f.dir);
  const decision = await authorize(
    { ...action, context: { withinWorkspace: false } },
    { dir: f.dir, refresh: false },
  );
  assert.equal(decision.allowed, false);
  assert.equal(decision.mode, 'ENFORCE');
});
void test('signed drafts and invalid per-policy modes cannot enter the live cache', async () => {
  const f = await fixture();
  await assert.rejects(
    async () =>
      activate(
        await signBundle(
          {
            ...f.bundle,
            policies: f.bundle.policies.map((p) => ({ ...p, status: 'DRAFT' })),
          },
          f.keys.privateKey,
        ),
        f.dir,
      ),
    /unpublished/,
  );
  await assert.rejects(
    async () =>
      activate(
        await signBundle(
          {
            ...f.bundle,
            environments: f.bundle.environments.map((e) => ({
              ...e,
              policyModes: { invalid: 'MAYBE' as 'AUDIT' },
            })),
          },
          f.keys.privateKey,
        ),
        f.dir,
      ),
    /modes/,
  );
});
void test('Custom audit-only malformed requests remain audit, while enforced policies fail closed', async () => {
  const f = await fixture();
  f.bundle.environments.forEach((e) => {
    e.mode = 'CUSTOM';
    e.policyModes = {};
  });
  await activate(await signBundle(f.bundle, f.keys.privateKey), f.dir);
  const malformed = { ...action, context: { unsupported: true } };
  assert.equal(
    (await authorize(malformed, { dir: f.dir, refresh: false })).allowed,
    true,
  );
  f.bundle.environments.find((e) => e.id === 'development')!.policyModes = {
    [f.bundle.policies[0].id]: 'ENFORCE',
  };
  f.bundle.sequence++;
  await activate(await signBundle(f.bundle, f.keys.privateKey), f.dir);
  assert.equal(
    (await authorize(malformed, { dir: f.dir, refresh: false })).allowed,
    false,
  );
});
void test('authorization pins the enrolled principal and cannot accept a forged request principal', async () => {
  const f = await fixture();
  f.bundle.client = { id: 'test-client', name: 'Signed agent' };
  f.bundle.policies = [
    {
      ...f.bundle.policies[0],
      cedar:
        'permit(principal == Cleopatr::AgentSession::"Signed agent", action, resource);',
    },
  ];
  await activate(await signBundle(f.bundle, f.keys.privateKey), f.dir);
  const result = await authorize(
    { ...action, sessionId: 'distinct-session', principal: 'Forged agent' },
    { dir: f.dir, mode: 'ENFORCE', refresh: false },
  );
  assert.equal(result.allowed, true);
  assert.equal(result.parc.principal.id, 'Signed agent');
  await assert.rejects(
    async () =>
      activate(
        await signBundle(
          {
            ...f.bundle,
            sequence: 2,
            client: { id: 'another-client', name: 'Signed agent' },
          },
          f.keys.privateKey,
        ),
        f.dir,
      ),
    /identity/,
  );
});
void test('legacy enrollment gains a signed client name on sync, then works offline', async () => {
  const f = await fixture();
  await atomicJson(join(f.dir, 'config.json'), {
    server: 'https://offline.example',
    token: 'test-token',
    tenant: 'test',
    publicKey: f.keys.publicKey,
    environmentIds: ['development'],
    clientId: 'test-client',
  });
  await activate(
    await signBundle(
      { ...f.bundle, schemaVersion: '2.0', minimumClientVersion: '0.2.0' },
      f.keys.privateKey,
    ),
    f.dir,
  );
  await assert.rejects(
    () => authorize(action, { dir: f.dir, refresh: false }),
    /Client name is missing/,
  );
  const signed = await signBundle(
    {
      ...f.bundle,
      sequence: 2,
      client: { id: 'test-client', name: 'Recovered name' },
    },
    f.keys.privateKey,
  );
  await sync(f.dir, (async () => Response.json(signed)) as typeof fetch);
  const result = await authorize(action, { dir: f.dir, refresh: false });
  assert.equal(result.allowed, true);
  assert.equal(result.parc.principal.id, 'Recovered name');
});

void test('CLI 0.4 preserves signed 0.3 snapshots and rejects unknown minimum client versions', async () => {
  const f = await fixture();
  await activate(f.signed, f.dir);
  await activate(
    await signBundle(
      { ...f.bundle, sequence: 2, minimumClientVersion: '0.4.0' },
      f.keys.privateKey,
    ),
    f.dir,
  );
  const future = await signBundle(
    { ...f.bundle, sequence: 3, minimumClientVersion: '9.0.0' },
    f.keys.privateKey,
  );
  await assert.rejects(
    () => activate(future, f.dir),
    /different Cleopatr version/,
  );
});
