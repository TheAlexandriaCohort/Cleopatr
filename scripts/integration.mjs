import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
const origin = process.env.CLEO_TEST_URL ?? 'http://localhost:3000';
const clientName = 'Integration test client ' + crypto.randomUUID();
async function api(path, body) {
  const r = await fetch(origin + '/api/v1/' + path, {
    method: body ? 'POST' : 'GET',
    headers: {
      ...(process.env.CLEO_ADMIN_TOKEN
        ? { 'x-cleo-admin-token': process.env.CLEO_ADMIN_TOKEN }
        : {}),
      origin,
      ...(body ? { 'content-type': 'application/json' } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const data = await r.json();
  assert.equal(r.status, 200, JSON.stringify(data));
  return data;
}
async function mutate(body) {
  return api('mutate', { revision: (await api('state')).revision, ...body });
}
const dir = await mkdtemp(join(tmpdir(), 'cleopatr-integration-'));
function cli(args, expected = 0) {
  return new Promise((done, reject) => {
    const p = spawn(process.execPath, [resolve('dist-cli/cleo.js'), ...args], {
      env: { ...process.env, CLEO_HOME: dir },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '',
      err = '';
    p.stdout.on('data', (b) => (out += b));
    p.stderr.on('data', (b) => (err += b));
    p.on('error', reject);
    p.on('close', (code) => {
      if (code !== expected) reject(new Error(err || out));
      else {
        try {
          done(JSON.parse(out));
        } catch (error) {
          reject(error);
        }
      }
    });
  });
}
let environment, policy, enrollment;
try {
  environment = await mutate({
    kind: 'environment',
    item: { name: 'CLI integration check', parentId: null },
  });
  policy = await mutate({
    kind: 'policy',
    publish: true,
    item: {
      name: 'Integration file access',
      environmentIds: [environment.id],
      cedar: `permit(principal == Cleopatr::AgentSession::${JSON.stringify(clientName)}, action == Cleopatr::Action::"file.read", resource);`,
    },
  });
  enrollment = await api('enroll', {
    name: clientName,
    environmentIds: [environment.id],
  });
  await writeFile(
    join(dir, 'enrollment.json'),
    JSON.stringify({ ...enrollment, server: origin }),
    { mode: 0o600 },
  );
  await cli(['enroll', '--config', join(dir, 'enrollment.json')]);
  const synced = await cli(['sync']);
  assert.equal(synced.sequence, (await api('state')).sequence);
  const cachePath = join(dir, 'bundle.json');
  const cache = JSON.parse(await readFile(cachePath, 'utf8'));
  await writeFile(cachePath, JSON.stringify({ ...cache, checkedAt: 0 }));
  const path = join(dir, 'request.json');
  // Configuration supplies the environment without it being embedded in the request.
  await writeFile(
    path,
    JSON.stringify({
      sessionId: 'integration',
      action: 'file.read',
      resource: { type: 'File', id: 'integration-file' },
      context: {},
    }),
  );
  let decision = await cli(['authorize', '--request', path]);
  assert.equal(decision.decision, 'ALLOW');
  assert.equal(decision.parc.principal.id, enrollment.clientName);
  const simulatedRequest = {
    environmentId: environment.id,
    sessionId: 'simulator-check',
    principal: enrollment.clientName,
    action: 'file.read',
    resource: { type: 'File', id: 'integration-file' },
    context: {},
  };
  const simulated = await api('simulate', {
    controlType: 'POLICY',
    controlId: policy.id,
    source: 'PUBLISHED',
    request: simulatedRequest,
  });
  assert.equal(simulated.decision, decision.decision);
  assert.deepEqual(simulated.parc.principal, decision.parc.principal);
  const otherPrincipal = await api('simulate', {
    controlType: 'POLICY',
    controlId: policy.id,
    source: 'PUBLISHED',
    request: { ...simulatedRequest, principal: 'Different client' },
  });
  assert.equal(otherPrincipal.decision, 'DENY');
  assert.equal(decision.stale, true);
  let refreshed = false;
  for (let i = 0; i < 40; i++) {
    if (JSON.parse(await readFile(cachePath, 'utf8')).checkedAt > 0) {
      refreshed = true;
      break;
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  assert.ok(refreshed, 'Background refresh did not finish');
  const saved = (await api('state')).policies.find((p) => p.id === policy.id);
  await mutate({
    kind: 'policy',
    item: {
      ...saved,
      cedar:
        'forbid(principal, action == Cleopatr::Action::"file.read", resource);',
      rule: undefined,
    },
  });
  const draftSimulation = await api('simulate', {
    controlType: 'POLICY',
    controlId: policy.id,
    source: 'DRAFT',
    request: simulatedRequest,
  });
  assert.equal(draftSimulation.decision, 'DENY');
  const environmentSimulation = await api('simulate', {
    controlType: 'ENVIRONMENT',
    controlId: environment.id,
    request: simulatedRequest,
  });
  assert.equal(environmentSimulation.decision, 'ALLOW');
  await cli(['sync']);
  assert.equal((await cli(['authorize', '--request', path])).decision, 'ALLOW');
  await mutate({
    kind: 'policy',
    operation: 'publish',
    item: { id: policy.id },
  });
  await mutate({
    kind: 'environment',
    operation: 'mode',
    mode: 'ENFORCE',
    item: { id: environment.id },
  });
  await cli(['sync']);
  decision = await cli(['authorize', '--request', path], 2);
  assert.equal(decision.effectiveResult, 'BLOCKED');
  await mutate({
    kind: 'policy',
    operation: 'rollback',
    item: { id: policy.id },
  });
  await cli(['sync']);
  assert.equal((await cli(['authorize', '--request', path])).decision, 'ALLOW');
  await cli(['audit', 'flush']);
  const activity = await api(
    'environment-activity?environment=' + encodeURIComponent(environment.id),
  );
  assert.ok(
    activity.some(
      (e) => e.policyId === policy.id && e.clientName === enrollment.clientId,
    ) === false,
  );
  assert.ok(
    activity.some(
      (e) =>
        e.policyId === policy.id &&
        e.clientName === clientName &&
        e.decision === 'DENY',
    ),
  );
  const filters = new URLSearchParams({
    type: 'decision',
    environment: environment.id,
    policy: policy.id,
    resource: 'File',
    principal: clientName,
  });
  const filtered = await api('activity?' + filters.toString());
  assert.ok(filtered.total >= 3);
  assert.ok(
    filtered.events.every(
      (e) =>
        e.environmentId === environment.id &&
        e.policyId === policy.id &&
        e.clientName === clientName &&
        e.resourceType === 'File',
    ),
  );
  assert.ok(filtered.principals.includes(clientName));
  filters.set('resource', 'Database');
  assert.equal((await api('activity?' + filters.toString())).total, 0);
  const platformFilters = new URLSearchParams({
    type: 'platform',
    environment: environment.id,
    policy: policy.id,
    resource: 'File',
  });
  assert.ok((await api('activity?' + platformFilters.toString())).total >= 3);
  const history = await api('history?policy=' + encodeURIComponent(policy.id));
  assert.equal(history.current.version, 3);
  assert.equal(history.previous.length, 2);
  console.log(
    JSON.stringify({
      endToEnd: 'passed',
      directPublishing: 'verified',
      draftIsolation: 'verified',
      rollback: 'verified',
      configurationEnvironment: 'verified',
      backgroundRefresh: 'completed',
      environmentActivity: 'recorded',
      activityFilters: 'verified',
      simulatorControls: 'verified',
      clientNamePrincipal: 'verified',
    }),
  );
} finally {
  if (enrollment) await api('revoke', { id: enrollment.clientId });
  if (policy)
    await mutate({
      kind: 'policy',
      operation: 'delete',
      item: { id: policy.id },
    });
  if (environment)
    await mutate({
      kind: 'environment',
      operation: 'delete',
      item: { id: environment.id },
    });
}
