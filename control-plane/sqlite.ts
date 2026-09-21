import { DatabaseSync } from 'node:sqlite';
import {
  readFileSync,
  readdirSync,
  existsSync,
  mkdirSync,
  chmodSync,
} from 'node:fs';
import { join, dirname } from 'node:path';
import type { Database, Statement, DbValue } from './service.ts';
export class SQLiteDatabase implements Database {
  raw: DatabaseSync;
  private runners = new WeakMap<
    Statement,
    () => { meta: { changes: number } }
  >();
  constructor(path: string, migrations?: string) {
    if (path !== ':memory:')
      mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.raw = new DatabaseSync(path);
    if (path !== ':memory:') chmodSync(path, 0o600);
    this.raw.exec('PRAGMA journal_mode = WAL');
    this.raw.exec('PRAGMA busy_timeout = 5000');
    if (migrations) {
      this.raw.exec(
        'CREATE TABLE IF NOT EXISTS _cleo_migrations (name TEXT PRIMARY KEY)',
      );
      const files = readdirSync(migrations)
        .filter((f) => f.endsWith('.sql'))
        .sort();
      const pending = files.some(
        (file) =>
          !this.raw
            .prepare('SELECT name FROM _cleo_migrations WHERE name = ?')
            .get(file),
      );
      if (
        pending &&
        path !== ':memory:' &&
        existsSync(path) &&
        this.raw
          .prepare("SELECT name FROM sqlite_master WHERE name = 'workspaces'")
          .get()
      ) {
        const backups = join(dirname(path), 'backups');
        mkdirSync(backups, { recursive: true, mode: 0o700 });
        const backup = join(
          backups,
          `${Date.now()}-${crypto.randomUUID()}.sqlite`,
        );
        this.raw.prepare('VACUUM INTO ?').run(backup);
        chmodSync(backup, 0o600);
      }
      this.raw.exec('BEGIN IMMEDIATE');
      try {
        for (const file of files) {
          if (
            !this.raw
              .prepare('SELECT name FROM _cleo_migrations WHERE name = ?')
              .get(file)
          ) {
            this.raw.exec(readFileSync(join(migrations, file), 'utf8'));
            this.raw
              .prepare('INSERT INTO _cleo_migrations(name) VALUES (?)')
              .run(file);
          }
        }
        this.raw.exec('COMMIT');
      } catch (e) {
        this.raw.exec('ROLLBACK');
        this.raw.close();
        throw e;
      }
    }
  }
  prepare(sql: string): Statement {
    const raw = this.raw;
    let values: DbValue[] = [];
    const run = () => {
      const r = raw.prepare(sql).run(...values);
      return { meta: { changes: Number(r.changes) } };
    };
    const statement: Statement = {
      bind(...args: DbValue[]) {
        values = args;
        return this;
      },
      async first<T>() {
        return (raw.prepare(sql).get(...values) as T) ?? null;
      },
      async all<T>() {
        return { results: raw.prepare(sql).all(...values) as T[] };
      },
      async run() {
        return run();
      },
    };
    this.runners.set(statement, run);
    return statement;
  }
  async batch(statements: Statement[]) {
    // DatabaseSync transactions must not yield: unrelated async requests must
    // never execute statements inside another request's transaction.
    this.raw.exec('BEGIN IMMEDIATE');
    try {
      const results = [];
      for (const statement of statements) {
        const run = this.runners.get(statement);
        if (!run) throw new Error('Statement belongs to another database');
        results.push(run());
      }
      this.raw.exec('COMMIT');
      return results;
    } catch (e) {
      this.raw.exec('ROLLBACK');
      throw e;
    }
  }
  close() {
    this.raw.close();
  }
}
