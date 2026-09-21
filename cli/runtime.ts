import { spool } from './audit.ts';
export { spool, flushAudit } from './audit.ts';
import * as cedar from '@cedar-policy/cedar-wasm/nodejs';
import { loadBundle, readCache, requestRefresh, dataDir } from './cache.ts';
import { evaluateWithModes } from '../core/engine.ts';
import {
  effectivePolicies,
  type ActionRequest,
  type Mode,
} from '../core/model.ts';
type AuthorizationOptions = {
  dir?: string;
  mode?: Mode;
  refresh?: boolean;
  entry?: string;
  adapter?: string;
  expectedSequence?: number;
};
export async function authorize(
  request: ActionRequest,
  options: AuthorizationOptions = {},
) {
  const dir = options.dir ?? dataDir();
  return authorizeVerified(request, await loadBundle(dir), options);
}

// Only the protected worker holds this closure. It pins a previously verified
// snapshot and checks that the protected cache bytes are unchanged before each
// decision; changes terminate the session instead of hot-swapping OS grants.
export function createPinnedAuthorizer(
  loaded: Awaited<ReturnType<typeof loadBundle>>,
  options: AuthorizationOptions,
) {
  return async (request: ActionRequest, adapter = options.adapter) => {
    const cache = await readCache(options.dir ?? dataDir());
    if (
      !cache ||
      cache.signed.payload !== loaded.cache.signed.payload ||
      cache.signed.signature !== loaded.cache.signed.signature ||
      cache.highWater !== loaded.cache.highWater
    )
      throw new Error(
        'Policy snapshot changed; restart the supervisor session',
      );
    return authorizeVerified(
      request,
      { ...loaded, cache },
      { ...options, adapter },
    );
  };
}
async function authorizeVerified(
  request: ActionRequest,
  loaded: Awaited<ReturnType<typeof loadBundle>>,
  options: AuthorizationOptions,
) {
  const dir = options.dir ?? dataDir();
  const { bundle, cache } = loaded;
  if (
    options.expectedSequence !== undefined &&
    bundle.sequence !== options.expectedSequence
  )
    throw new Error(
      'Policy snapshot changed; this supervisor session must be restarted',
    );
  if (!bundle.environmentIds.includes(request.environmentId))
    throw new Error('This client is not assigned to the requested environment');
  if (options.refresh !== false)
    await requestRefresh(dir, options.entry).catch(() => {});
  const principal = bundle.client.name;
  // Adapter request JSON cannot choose another client's principal.
  request = { ...request, principal };
  let result;
  try {
    result = evaluateWithModes(
      cedar,
      bundle,
      request,
      options.mode === 'ENFORCE',
      options.mode === 'AUDIT',
    );
  } catch (e) {
    const mode =
      options.mode === 'AUDIT'
        ? 'AUDIT'
        : options.mode === 'ENFORCE'
          ? 'ENFORCE'
          : (bundle.environments.find((env) => env.id === request.environmentId)
              ?.mode ?? 'AUDIT');
    // Explicit audit also makes evaluation errors non-blocking for Enforce policies.
    const enforce =
      options.mode !== 'AUDIT' &&
      (mode === 'ENFORCE' ||
        effectivePolicies(bundle, request.environmentId).some(
          (p) => p.mode === 'ENFORCE',
        ));
    result = {
      decision: 'DENY' as const,
      determiningPolicies: [],
      errors: [(e as Error).message],
      latencyUs: 0,
      parc: {
        principal: { type: 'Cleopatr::AgentSession', id: principal },
        action: { type: 'Cleopatr::Action', id: request.action },
        resource: {
          type: `Cleopatr::${request.resource?.type ?? 'Unknown'}`,
          id: request.resource?.id ?? '',
        },
        context: request.context,
      },
      policyCount: 0,
      assessment: {
        version: 1 as const,
        status: 'unavailable' as const,
        reason: 'not_evaluated' as const,
      },
      mode,
      effectiveResult: enforce ? 'ERROR' : 'ALLOWED_AUDIT',
      allowed: !enforce,
      policyDecisions: [
        {
          policyId: '',
          policyName: 'Authorization error',
          policyVersion: 0,
          decision: 'ERROR',
          mode: enforce ? ('ENFORCE' as const) : ('AUDIT' as const),
        },
      ],
    };
  }
  const decision = {
    ...result,
    bundleId: bundle.bundleId,
    sequence: bundle.sequence,
    stale: Date.now() - cache.checkedAt >= 300000,
  };
  await Promise.all(
    decision.policyDecisions.map((policy) =>
      spool(
        {
          id: 'evt_' + crypto.randomUUID(),
          kind: 'decision',
          time: new Date().toISOString(),
          sessionId: request.sessionId,
          environmentId: request.environmentId,
          action: request.action,
          resource: request.resource?.id,
          assessment: decision.assessment,
          ...policy,
          effectiveResult:
            policy.decision === 'ALLOW'
              ? 'ALLOWED'
              : policy.mode === 'AUDIT'
                ? 'ALLOWED_AUDIT'
                : policy.decision === 'ERROR'
                  ? 'ERROR'
                  : 'BLOCKED',
          bundleId: bundle.bundleId,
          sequence: bundle.sequence,
          determiningPolicies: policy.policyId ? [policy.policyId] : [],
          adapter: options.adapter ?? 'explicit',
          confidence: request.context?.confidence ?? 'configured',
        },
        dir,
      ).catch((e) =>
        process.stderr.write(
          `cleo: audit spool error: ${(e as Error).message}\n`,
        ),
      ),
    ),
  );
  return decision;
}
