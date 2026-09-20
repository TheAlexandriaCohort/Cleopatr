import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  parseInvocation,
  resolveEnvironment,
  selectedMode,
} from '../cli/options.ts';
import { rewritePipeline, zshIntegration } from '../cli/shell.ts';
import { createSeed, type Bundle } from '../core/model.ts';

void test('launch flags accept equals and separated values without consuming agent options', () => {
  const parsed = parseInvocation([
    '--enforce',
    '--env=PCI',
    '--',
    'node',
    '--mode',
    'agent-value',
  ]);
  assert.equal(parsed.command, 'run');
  assert.equal(selectedMode(parsed.options.get('--mode')), 'ENFORCE');
  assert.equal(parsed.options.get('--environment'), 'PCI');
  assert.deepEqual(parsed.agent, ['node', '--mode', 'agent-value']);
  assert.equal(
    parseInvocation(['run', '--env', 'PCI', '--', 'node']).options.get(
      '--environment',
    ),
    'PCI',
  );
  assert.equal(selectedMode(), undefined);
  assert.equal(
    selectedMode(parseInvocation(['--audit']).options.get('--mode')),
    'AUDIT',
  );
  for (const args of [
    ['--env'],
    ['--env='],
    ['--enforce=no'],
    ['--audit=false'],
    ['--audit', '--enforce'],
    ['--enforce', '--audit'],
    ['--mode=audit', '--audit'],
    ['--audit', '--mode=enforce'],
    ['--enforce', '--mode=audit'],
    ['--environment=a', '--env=b'],
    ['--typo'],
  ])
    assert.throws(() => parseInvocation(args));
});

void test('environment names resolve only within assignments and ambiguous names fail', () => {
  const bundle = { ...createSeed(), environmentIds: ['development'] } as Bundle;
  bundle.environments.find((e) => e.id === 'development')!.name = 'PCI';
  assert.equal(resolveEnvironment(bundle, 'PCI'), 'development');
  assert.equal(resolveEnvironment(bundle, 'pci'), 'development');
  assert.equal(resolveEnvironment(bundle, 'development'), 'development');
  assert.throws(() => resolveEnvironment(bundle, 'production'), /not assigned/);
  assert.throws(() => resolveEnvironment(bundle, 'missing'), /not found/);
  bundle.environments.push({
    id: 'pci-two',
    name: 'PCI',
    description: '',
    kind: 'environment',
    parentId: null,
  });
  bundle.environmentIds.push('pci-two');
  assert.throws(() => resolveEnvironment(bundle, 'PCI'), /ambiguous/);
  assert.equal(resolveEnvironment(bundle, 'pci-two'), 'pci-two');
});

void test('pipe examples become a single launcher and preserve literal argument boundaries in zsh', () => {
  const cases: [string, string[]][] = [
    [
      'cleo --audit --env=PCI | node agent.js',
      ['--audit', '--env=PCI', '--', 'node', 'agent.js'],
    ],
    ['cleo --env=PCI | node agent.js', ['--env=PCI', '--', 'node', 'agent.js']],
    [
      'cleo --backend linux --enforce --env PCI | python3 agent.py',
      [
        '--backend',
        'linux',
        '--enforce',
        '--env',
        'PCI',
        '--',
        'python3',
        'agent.py',
      ],
    ],
    ['cleo | python -m my-agent.py', ['--', 'python', '-m', 'my-agent.py']],
    [
      'cleo --enforce | ./agent-service.sh',
      ['--enforce', '--', './agent-service.sh'],
    ],
    [
      'cleo --enforce --env=PCI | npm run dev',
      ['--enforce', '--env=PCI', '--', 'npm', 'run', 'dev'],
    ],
    [
      String.raw`cleo --env "PCI Finance"|node 'space value' '' '$(touch never)' 'a|b' "a\\b" 'it'\''s'`,
      [
        '--env',
        'PCI Finance',
        '--',
        'node',
        'space value',
        '',
        '$(touch never)',
        'a|b',
        'a\\b',
        "it's",
      ],
    ],
  ];
  for (const [line, expected] of cases) {
    const rewritten = rewritePipeline(line);
    const result = spawnSync('zsh', [
      '-f',
      '-c',
      `function cleo { printf '%s\\0' "$@"; }\n${rewritten}`,
    ]);
    assert.equal(result.status, 0, result.stderr.toString());
    assert.deepEqual(
      result.stdout.toString().split('\0').slice(0, -1),
      expected,
    );
  }
});

void test('unsupported shell logic is rejected before any command can start', () => {
  for (const line of [
    'cleo | node | tee out',
    'cleo | node && echo bypass',
    'cleo | node; echo bypass',
    'cleo | node > out',
    'cleo | node $(touch marker)',
    'cleo | node "$(touch marker)"',
    'cleo | node `touch marker`',
    'cleo | node *.js',
    'cleo | (node)',
    'cleo | FOO=value node',
    'cleo | node\nother',
    'cleo | node "unclosed',
    'cleo || node',
    'cleo |',
    'cleo run | node',
    'cleo --request x | node',
    'cleo --env | node',
    'cleo --enforce=false | node',
  ])
    assert.throws(() => rewritePipeline(line), Error, line);
  assert.equal(rewritePipeline('git status | head'), 'git status | head');
  assert.equal(
    rewritePipeline('cleo --enforce -- node'),
    'cleo --enforce -- node',
  );
});

void test('zsh hook preserves prior widget, rewrites once, and stops execution on invalid input', () => {
  const source = zshIntegration([
    process.execPath,
    '--import',
    'tsx',
    process.cwd() + '/cli/main.ts',
  ]);
  const script = `${source}\n${source}
function zle {
  if [[ "$1" == cleo-original-accept-line ]]; then
    print -r -- "ACCEPT:$BUFFER"
  fi
}
BUFFER='  cleo --enforce --env=PCI|npm run dev'
PREBUFFER=''
_cleo_accept_line
BUFFER='cleo | node; echo must-not-run'
_cleo_accept_line
print -r -- "REJECT:$?"
BUFFER='cleo | node'
PREBUFFER='if true; then'
_cleo_accept_line
print -r -- "MULTILINE:$?"
BUFFER='echo untouched'
PREBUFFER=''
_cleo_accept_line
`;
  const result = spawnSync('zsh', ['-f', '-i', '-c', script], {
    encoding: 'utf8',
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(
    result.stdout,
    /ACCEPT:'cleo' '--enforce' '--env=PCI' '--' 'npm' 'run' 'dev'/,
  );
  assert.match(result.stdout, /REJECT:1/);
  assert.match(result.stdout, /MULTILINE:1/);
  assert.match(result.stdout, /ACCEPT:echo untouched/);
  assert.equal((result.stdout.match(/ACCEPT:/g) ?? []).length, 2);
});
