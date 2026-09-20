import { DatabaseSync } from 'node:sqlite';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import type { Database, Statement, DbValue } from './service.ts';
export class SQLiteDatabase implements Database {
  raw: DatabaseSync;
  private queue: Promise<unknown> = Promise.resolve();
  constructor(path: string, migrations?: string) {
    this.raw = new DatabaseSync(path);
    this.raw.exec('PRAGMA journal_mode = WAL');
    this.raw.exec('PRAGMA busy_timeout = 5000');
    if (migrations) {
      this.raw.exec(
        'CREATE TABLE IF NOT EXISTS _cleo_migrations (name TEXT PRIMARY KEY)',
      );
      for (const file of readdirSync(migrations)
        .filter((f) => f.endsWith('.sql'))
        .sort()) {
        if (
          !this.raw
            .prepare('SELECT name FROM _cleo_migrations WHERE name = ?')
            .get(file)
        ) {
          this.raw.exec('BEGIN');
          try {
            this.raw.exec(readFileSync(join(migrations, file), 'utf8'));
            this.raw
              .prepare('INSERT INTO _cleo_migrations(name) VALUES (?)')
              .run(file);
            this.raw.exec('COMMIT');
          } catch (e) {
            this.raw.exec('ROLLBACK');
            throw e;
          }
        }
      }
    }
  }
  prepare(sql: string): Statement {
    const raw = this.raw;
    let values: DbValue[] = [];
    return {
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
        const r = raw.prepare(sql).run(...values);
        return { meta: { changes: Number(r.changes) } };
      },
    };
  }
  async batch(statements: Statement[]) {
    const work = this.queue.then(async () => {
      this.raw.exec('BEGIN IMMEDIATE');
      try {
        const results = [];
        for (const statement of statements) results.push(await statement.run());
        this.raw.exec('COMMIT');
        return results;
      } catch (e) {
        this.raw.exec('ROLLBACK');
        throw e;
      }
    });
    this.queue = work.catch(() => {});
    return work;
  }
  close() {
    this.raw.close();
  }
}
