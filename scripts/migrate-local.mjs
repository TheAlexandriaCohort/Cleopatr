import {
  readdirSync,
  readFileSync,
  existsSync,
  mkdirSync,
  chmodSync,
} from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { join, resolve } from 'node:path';
const root = '.wrangler/state/v3/d1/miniflare-D1DatabaseObject';
const files = existsSync(root)
  ? readdirSync(root).filter(
      (f) => f.endsWith('.sqlite') && f !== 'metadata.sqlite',
    )
  : [];
if (!files.length) {
  console.error(
    'Open the app and sign in locally once to initialize the local D1 database, then rerun this command.',
  );
  process.exit(1);
}
for (const file of files) {
  const db = new DatabaseSync(join(root, file));
  db.exec('PRAGMA busy_timeout = 5000');
  db.exec(
    'CREATE TABLE IF NOT EXISTS _cleo_migrations (name TEXT PRIMARY KEY)',
  );
  const pending = readdirSync('drizzle')
    .filter((f) => f.endsWith('.sql'))
    .sort()
    .filter(
      (name) =>
        !db
          .prepare('SELECT name FROM _cleo_migrations WHERE name = ?')
          .get(name),
    );
  if (pending.length) {
    const backupDir = resolve('.local/backups');
    mkdirSync(backupDir, { recursive: true, mode: 0o700 });
    const backup = join(backupDir, `${Date.now()}-${file}`);
    db.prepare('VACUUM INTO ?').run(backup);
    chmodSync(backup, 0o600);
    console.log('Database backup: ' + backup);
    db.exec('BEGIN IMMEDIATE');
    try {
      for (const migration of pending) {
        db.exec(readFileSync(join('drizzle', migration), 'utf8'));
        db.prepare('INSERT INTO _cleo_migrations VALUES (?)').run(migration);
        console.log('Applied ' + migration);
      }
      db.exec('COMMIT');
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }
  }
  db.close();
}
