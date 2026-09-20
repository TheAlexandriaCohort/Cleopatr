import assert from 'node:assert/strict';
const origin = 'http://localhost:3000';
const sign = await fetch(origin + '/signin-with-chatgpt?return_to=%2F', {
  redirect: 'manual',
});
assert.equal(sign.status, 302);
const cookie = sign.headers.get('set-cookie').split(';')[0];
async function api(path, body) {
  const r = await fetch(origin + '/api/v1/' + path, {
    method: body ? 'POST' : 'GET',
    headers: {
      cookie,
      origin,
      ...(body ? { 'content-type': 'application/json' } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const data = await r.json();
  assert.equal(r.status, 200, JSON.stringify(data));
  return data;
}
const state = await api('state');
assert.ok(state.environments.length);
const validation = await api('validate', { cedar: state.policies[0].cedar });
assert.equal(validation.valid, true);
const simulation = await api('simulate', {
  request: {
    environmentId: 'customer-platform',
    sessionId: 'smoke-test',
    action: 'database.query',
    resource: { type: 'Database', id: 'customer-db' },
    context: { operation: 'DELETE' },
  },
});
assert.equal(simulation.decision, 'DENY');
console.log(
  JSON.stringify({
    api: 'passed',
    cedar: state.engine,
    environments: state.environments.length,
    resources: state.resources.length,
    validation: validation.valid,
    simulation: simulation.decision,
  }),
);
