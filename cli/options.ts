import type { Bundle, Mode } from '../core/model.ts';

const valueOptions = new Set([
  '--config',
  '--file',
  '--request',
  '--environment',
  '--mode',
  '--server',
  '--resource',
  '--backend',
]);

export function parseInvocation(input: string[]) {
  const args = [...input];
  const first = args[0];
  const command = !first
    ? 'help'
    : first === '--help' || first === '--version'
      ? args.shift()!
      : first.startsWith('-')
        ? 'run'
        : args.shift()!;
  const options = new Map<string, string>();
  const positionals: string[] = [];
  let agent: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const token = args[i];
    if (token === '--') {
      agent = args.slice(i + 1);
      break;
    }
    if (!token.startsWith('-')) {
      positionals.push(token);
      continue;
    }
    const equals = token.indexOf('=');
    let key = equals < 0 ? token : token.slice(0, equals);
    if (key === '--env') key = '--environment';
    if (key === '--enforce' || key === '--audit') {
      if (equals >= 0) throw new Error(`${key} does not take a value`);
      if (options.has('--mode'))
        throw new Error('Specify only one mode option');
      options.set('--mode', key === '--audit' ? 'audit' : 'enforce');
      continue;
    }
    if (!valueOptions.has(key)) throw new Error(`Unknown option: ${key}`);
    if (options.has(key)) throw new Error(`Duplicate option: ${key}`);
    const value = equals < 0 ? args[++i] : token.slice(equals + 1);
    if (!value || (value.startsWith('--') && equals < 0))
      throw new Error(`Missing value for ${key}`);
    options.set(key, value);
  }
  return { command, options, positionals, agent };
}

export function selectedMode(value?: string): Mode | undefined {
  if (value === undefined) return undefined;
  const mode = value.toUpperCase();
  if (mode !== 'AUDIT' && mode !== 'ENFORCE')
    throw new Error('Mode must be audit or enforce');
  return mode;
}

export function resolveEnvironment(bundle: Bundle, selector: string) {
  const byId = bundle.environments.find((e) => e.id === selector);
  if (byId) {
    if (!bundle.environmentIds.includes(byId.id))
      throw new Error(
        `This client is not assigned to environment: ${selector}`,
      );
    return byId.id;
  }
  const matches = bundle.environments.filter(
    (e) =>
      bundle.environmentIds.includes(e.id) &&
      e.name.toLowerCase() === selector.toLowerCase(),
  );
  if (matches.length > 1)
    throw new Error(
      `Environment name is ambiguous: ${selector}. Use an environment ID.`,
    );
  if (!matches.length)
    throw new Error(
      `Environment not found in the assigned policy bundle: ${selector}. Run cleo sync to check for new environments.`,
    );
  return matches[0].id;
}
