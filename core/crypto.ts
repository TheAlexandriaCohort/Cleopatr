import {
  SCHEMA_VERSION,
  VERSION,
  type Bundle,
  type SignedBundle,
} from './model.ts';
const enc = new TextEncoder();
export function base64(bytes: ArrayBuffer | Uint8Array) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}
export function unbase64(value: string) {
  return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
}
export async function digest(value: string) {
  return Array.from(
    new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(value))),
  )
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');
}
export async function makeKeys() {
  const keys = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  return {
    privateKey: await crypto.subtle.exportKey('jwk', keys.privateKey),
    publicKey: await crypto.subtle.exportKey('jwk', keys.publicKey),
  };
}
export async function signBundle(
  bundle: Bundle,
  key: JsonWebKey,
): Promise<SignedBundle> {
  const payload = JSON.stringify(bundle);
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    key,
    { name: 'Ed25519' },
    false,
    ['sign'],
  );
  return {
    payload,
    signature: base64(
      await crypto.subtle.sign('Ed25519', privateKey, enc.encode(payload)),
    ),
    digest: await digest(payload),
    keyId: await digest(key.x!),
    algorithm: 'Ed25519',
  };
}
export async function verifyBundle(
  signed: SignedBundle,
  publicKey: JsonWebKey,
  tenant: string,
  minSequence = 0,
): Promise<Bundle> {
  if (
    signed.algorithm !== 'Ed25519' ||
    (await digest(signed.payload)) !== signed.digest ||
    signed.keyId !== (await digest(publicKey.x!))
  )
    throw new Error('Bundle digest or signing key mismatch');
  const key = await crypto.subtle.importKey(
    'jwk',
    publicKey,
    { name: 'Ed25519' },
    false,
    ['verify'],
  );
  if (
    !(await crypto.subtle.verify(
      'Ed25519',
      key,
      unbase64(signed.signature),
      enc.encode(signed.payload),
    ))
  )
    throw new Error('Bundle signature verification failed');
  const bundle = JSON.parse(signed.payload) as Bundle;
  if (bundle.tenant !== tenant)
    throw new Error('Bundle belongs to a different tenant');
  if (
    !Number.isSafeInteger(bundle.sequence) ||
    bundle.sequence < 1 ||
    bundle.sequence < minSequence
  )
    throw new Error('Rejected policy rollback');
  const legacy = bundle as Bundle & {
    mode?: 'AUDIT' | 'ENFORCE';
    releaseId?: string;
  };
  const isLegacy =
    bundle.schemaVersion === '1.0' && bundle.minimumClientVersion === '0.1.0';
  if (
    !isLegacy &&
    !(
      bundle.schemaVersion === '2.0' && bundle.minimumClientVersion === '0.2.0'
    ) &&
    (bundle.schemaVersion !== SCHEMA_VERSION ||
      ![
        '0.3.0',
        '0.4.0',
        '0.4.1',
        '0.4.2',
        '0.4.3',
        '0.4.4',
        '0.5.0',
        '0.5.1',
        VERSION,
      ].includes(bundle.minimumClientVersion))
  )
    throw new Error('Bundle requires a different Cleopatr version');
  if (
    !Array.isArray(bundle.environmentIds) ||
    !bundle.environmentIds.length ||
    !Array.isArray(bundle.policies) ||
    !Array.isArray(bundle.resources) ||
    !Array.isArray(bundle.environments)
  )
    throw new Error('Invalid bundle manifest');
  if (isLegacy) {
    if (legacy.mode !== 'AUDIT' && legacy.mode !== 'ENFORCE')
      throw new Error('Invalid legacy bundle mode');
    bundle.environments = bundle.environments.map((e) => ({
      ...e,
      mode: legacy.mode,
    }));
    bundle.policies = bundle.policies.map((p) => ({
      ...p,
      status: 'PUBLISHED',
    }));
    bundle.bundleId = legacy.releaseId ?? `legacy_${bundle.sequence}`;
  }
  if (
    !bundle.bundleId ||
    bundle.environments.some(
      (e) =>
        !['AUDIT', 'CUSTOM', 'ENFORCE'].includes(e.mode ?? 'AUDIT') ||
        Object.values(e.policyModes ?? {}).some(
          (mode) => mode !== 'AUDIT' && mode !== 'ENFORCE',
        ),
    )
  )
    throw new Error('Invalid environment policy modes');
  if (
    !isLegacy &&
    bundle.policies.some((p) => p.status !== 'PUBLISHED' || p.published)
  )
    throw new Error('Bundle contains unpublished policy content');
  if (
    bundle.client &&
    (typeof bundle.client.id !== 'string' ||
      !bundle.client.id ||
      typeof bundle.client.name !== 'string' ||
      !bundle.client.name.trim() ||
      bundle.client.name.length > 200)
  )
    throw new Error('Invalid signed client identity');
  return bundle;
}
