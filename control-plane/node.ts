import cedar from './cedar.ts';
import { ControlPlane } from './service.ts';
import { openStorage } from './storage.ts';

function initialize() {
  const storage = openStorage();
  const key = process.env.CLEO_SIGNING_JWK;
  const endpoint = process.env.CLEO_AUTHORING_ENDPOINT;
  return {
    ...storage,
    plane: new ControlPlane(
      storage.db,
      cedar,
      key ? JSON.parse(key) : undefined,
      endpoint
        ? { endpoint, token: process.env.CLEO_AUTHORING_TOKEN }
        : undefined,
    ),
  };
}
// Development hot reload replaces server modules. Keep one database connection.
const scope = globalThis as typeof globalThis & {
  cleopatrStorage?: ReturnType<typeof initialize>;
};
export function nodeControlPlane() {
  return (scope.cleopatrStorage ??= initialize());
}
