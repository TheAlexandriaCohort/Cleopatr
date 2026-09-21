import { join, resolve } from 'node:path';
import { SQLiteDatabase } from './sqlite.ts';

export function openStorage(
  options: { dataDir?: string; workspaceId?: string } = {},
) {
  // Runtime state is supplied by the installation, never bundled at build time.
  const dataDir = resolve(
    /* turbopackIgnore: true */ options.dataDir ??
      process.env.CLEO_SERVER_DATA ??
      '.local',
  );
  const file = join(dataDir, 'cleopatr.sqlite');
  const db = new SQLiteDatabase(file, join(process.cwd(), 'migrations'));
  const ids = db.raw.prepare('SELECT id FROM workspaces').all();
  const configured =
    options.workspaceId || process.env.CLEO_WORKSPACE_ID || undefined;
  if (ids.length > 1 && !configured) {
    db.close();
    throw new Error(
      'Multiple workspaces found. Set CLEO_WORKSPACE_ID to choose the administrator workspace.',
    );
  }
  if (configured && ids.length && !ids.some((row) => row.id === configured)) {
    db.close();
    throw new Error('CLEO_WORKSPACE_ID does not match an existing workspace.');
  }
  return {
    db,
    file,
    workspaceId:
      configured ?? (ids[0]?.id as string | undefined) ?? 'local-workspace',
  };
}
