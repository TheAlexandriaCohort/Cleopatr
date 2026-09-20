import { parseInvocation, selectedMode } from './options.ts';

export function shellQuote(value: string) {
  return "'" + value.replaceAll("'", "'\\''") + "'";
}

// Deliberately accepts literals only. It never evaluates shell expansions or
// hands an unparsed RHS to a shell after policy approval.
export function rewritePipeline(line: string) {
  if (!/^\s*cleo(?:\s|\||$)/.test(line) || !line.includes('|')) return line;
  if (line.includes('\n') || line.includes('\r'))
    throw new Error(
      'Cleo pipe syntax requires one line. Put shell logic in a script.',
    );
  const sides: string[][] = [[]];
  let word = '';
  let started = false;
  let quote = '';
  const finish = () => {
    if (started) sides[sides.length - 1].push(word);
    word = '';
    started = false;
  };
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote === "'") {
      if (c === "'") quote = '';
      else word += c;
      continue;
    }
    if (c === '\\') {
      const next = line[++i];
      if (next === undefined)
        throw new Error('Incomplete escape in Cleo command');
      if (quote === '"' && !['$', '`', '"', '\\'].includes(next)) word += '\\';
      word += next;
      started = true;
      continue;
    }
    if (c === '$' || c === '`')
      throw new Error(
        'Shell expansion is not supported by Cleo pipe syntax. Use literal arguments or a script.',
      );
    if (quote === '"') {
      if (c === '"') quote = '';
      else word += c;
      continue;
    }
    if (c === '"' || c === "'") {
      quote = c;
      started = true;
    } else if (/\s/.test(c)) finish();
    else if (c === '|') {
      finish();
      if (sides.length === 2)
        throw new Error(
          'Only one Cleo pipe is supported; use a script for pipelines or shell logic.',
        );
      sides.push([]);
    } else if (';&<>(){}*?[]~#!'.includes(c))
      throw new Error(
        'Shell operators, expansions and redirections are not supported by Cleo pipe syntax. Use a script.',
      );
    else {
      word += c;
      started = true;
    }
  }
  if (quote) throw new Error('Unclosed quote in Cleo command');
  finish();
  if (sides.length === 1) return line;
  const [left, right] = sides;
  if (left[0] !== 'cleo' || !right.length)
    throw new Error(
      'Use cleo [--audit] [--env=NAME_OR_ID] | command [args...]',
    );
  // No command, separator, or non-launch options are permitted on the LHS.
  const parsed = parseInvocation([...left.slice(1), '--', ...right]);
  if (
    (left[1] && !left[1].startsWith('-')) ||
    parsed.command !== 'run' ||
    parsed.positionals.length ||
    left.includes('--') ||
    [...parsed.options.keys()].some(
      (key) => !['--mode', '--environment', '--backend'].includes(key),
    )
  )
    throw new Error(
      'Only --audit, --enforce, --mode, --env and --backend options may precede the Cleo pipe.',
    );
  selectedMode(parsed.options.get('--mode'));
  if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(right[0]))
    throw new Error(
      'Put environment assignments inside an agent script, not after the Cleo pipe.',
    );
  return ['cleo', ...left.slice(1), '--', ...right].map(shellQuote).join(' ');
}

export function zshIntegration(cli: string[]) {
  const invoke = cli.map(shellQuote).join(' ');
  return `# Cleopatr: interactive zsh only. No shell startup files are modified.
if [[ -z "\${ZSH_VERSION-}" || ! -o interactive ]]; then
  print -u2 -- 'cleo: init zsh requires an interactive zsh shell'
  return 1
fi
_cleo_accept_line() {
  emulate -L zsh
  setopt extendedglob
  local cleo_line="\${BUFFER##[[:space:]]#}"
  local cleo_rewritten
  if [[ "$cleo_line" == cleo || "$cleo_line" == cleo[[:space:]\\|]* ]]; then
    if [[ -n "$PREBUFFER" ]]; then
      zle -M 'cleo: multiline input is unsupported; use a script'
      return 1
    fi
    cleo_rewritten=$(${invoke} __rewrite-zsh <<< "$BUFFER")
    if (( $? != 0 )); then
      zle -M 'cleo: command was not executed; correct the syntax or use a script'
      return 1
    fi
    BUFFER="$cleo_rewritten"
    CURSOR=\${#BUFFER}
  fi
  zle cleo-original-accept-line
}
if (( ! \${+widgets[cleo-original-accept-line]} )); then
  zle -A accept-line cleo-original-accept-line
fi
zle -N accept-line _cleo_accept_line
`;
}
