import { Buffer } from 'node:buffer';
// The wire adapter exposes the exact statement in context.argv (one member),
// its leading command in context.operation, and database in context.server.
// It does not invent table names from a regex. Table-level SQL authorization
// requires a database-native parser and is deliberately not advertised here.
export function sqlOperation(sql: string, dialect: 'postgres' | 'mysql') {
  if (!sql.trim() || Buffer.byteLength(sql) > 32768 || sql.includes('\0'))
    throw new Error('SQL size or encoding unsupported');
  let plain = '',
    i = 0,
    ended = false;
  while (i < sql.length) {
    const c = sql[i];
    if (/\s/.test(c)) {
      plain += ' ';
      i++;
      continue;
    }
    if (
      (sql.startsWith('--', i) &&
        (dialect === 'postgres' || /\s/.test(sql[i + 2] ?? ' '))) ||
      (dialect === 'mysql' && c === '#')
    ) {
      const end = sql.indexOf('\n', i);
      i = end < 0 ? sql.length : end + 1;
      plain += ' ';
      continue;
    }
    if (sql.startsWith('/*', i)) {
      // MySQL executable/version comments and optimizer hints are not inert.
      if (sql[i + 2] === '!' || sql[i + 2] === '+')
        throw new Error('Executable SQL comments unsupported');
      let depth = 1;
      i += 2;
      while (i < sql.length && depth) {
        if (sql.startsWith('/*', i)) {
          if (dialect === 'mysql')
            throw new Error('Nested MySQL comments unsupported');
          depth++;
          i += 2;
        } else if (sql.startsWith('*/', i)) {
          depth--;
          i += 2;
        } else i++;
      }
      if (depth) throw new Error('Unterminated SQL comment');
      plain += ' ';
      continue;
    }
    if (ended) throw new Error('Multiple statements unsupported');
    if (c === ';') {
      ended = true;
      i++;
      continue;
    }
    if (c === "'" || c === '"' || c === '`') {
      const quote = c;
      i++;
      let closed = false;
      while (i < sql.length) {
        // Ambiguous escape modes are refused, never guessed.
        if (sql[i] === '\\')
          throw new Error('Backslash SQL escapes unsupported');
        if (sql[i++] === quote) {
          if (sql[i] === quote) {
            i++;
            continue;
          }
          closed = true;
          break;
        }
      }
      if (!closed) throw new Error('Unterminated SQL literal');
      plain += ' ? ';
      continue;
    }
    if (c === '$')
      throw new Error(
        'Dollar quoting and parameters require an unsupported prepared protocol',
      );
    plain += c;
    i++;
  }
  const normalized = plain.trim().replace(/\s+/g, ' ').toUpperCase();
  const command = normalized.split(' ')[0];
  if (
    ['BEGIN', 'COMMIT', 'ROLLBACK'].includes(command) &&
    /^(BEGIN(?: WORK| TRANSACTION)?|COMMIT(?: WORK)?|ROLLBACK(?: WORK)?)$/.test(
      normalized,
    )
  )
    return { action: 'database.transaction', operation: command };
  if (normalized === 'START TRANSACTION')
    return { action: 'database.transaction', operation: 'BEGIN' };
  if (!['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'SHOW'].includes(command))
    throw new Error(`Unsupported SQL command: ${command}`);
  // Reject commands that can change protocol framing, create server-side state,
  // or turn a query into a stored/remote program. Ordinary SQL semantics remain
  // the database's responsibility; permit(database.query) permits side effects.
  if (
    /\b(INTO\s+(OUTFILE|DUMPFILE)|LOAD_FILE|SLEEP|BENCHMARK)\b/.test(normalized)
  )
    throw new Error('Unsupported SQL operation');
  return { action: 'database.query', operation: command };
}
