import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runManagedCommand } from '../cli/child-process.ts';

const options = {
  stage: 'Test helper',
  timeoutMs: 2000,
  timeoutMessage: 'Helper did not respond',
};
void test('managed command returns its exit status and bounded output, then removes signal listeners', async () => {
  const listeners = process.listenerCount('SIGINT');
  const result = await runManagedCommand(
    process.execPath,
    [
      '-e',
      'console.log("x".repeat(100000)); console.error("failure detail"); process.exitCode = 7;',
    ],
    options,
  );
  assert.equal(result.code, 7);
  assert.ok(result.output.length <= 65536);
  assert.match(result.output, /failure detail/);
  assert.equal(process.listenerCount('SIGINT'), listeners);
  await assert.rejects(
    runManagedCommand('/nonexistent/cleo-helper', [], options),
    /Test helper:.*ENOENT/,
  );
  assert.equal(process.listenerCount('SIGINT'), listeners);
});
void test('unresponsive helper that ignores TERM is killed and fails within its deadline plus grace', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'cleo-helper-test-'));
  const file = join(directory, 'pid');
  let pid: number | undefined;
  try {
    const start = performance.now();
    await assert.rejects(
      runManagedCommand(
        process.execPath,
        [
          '-e',
          'process.on("SIGTERM", () => {}); require("node:fs").writeFileSync(process.argv[1], String(process.pid)); setInterval(() => {}, 1000);',
          file,
        ],
        { ...options, timeoutMs: 500 },
      ),
      /Helper did not respond/,
    );
    assert.ok(performance.now() - start < 3000);
    pid = Number(await readFile(file, 'utf8'));
    // SIGKILL and reaping may finish one event-loop turn after the hard bound.
    for (let i = 0; i < 50; i++) {
      try {
        process.kill(pid, 0);
      } catch {
        pid = undefined;
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.equal(pid, undefined, 'helper must not survive cancellation');
  } finally {
    if (pid) process.kill(pid, 'SIGKILL');
    await rm(directory, { recursive: true, force: true });
  }
});
void test('VM readiness cancels only the startup deadline and leaves a running agent alive', async () => {
  let readyCalls = 0;
  const result = await runManagedCommand(
    process.execPath,
    ['-e', 'setTimeout(() => console.log("agent completed"), 500);'],
    {
      ...options,
      timeoutMs: 100,
      isReady: async () => true,
      onReady: () => {
        readyCalls++;
      },
    },
  );
  assert.equal(result.code, 0);
  assert.match(result.output, /agent completed/);
  assert.equal(readyCalls, 1);
});
void test('VM that never becomes ready is stopped, while an early failure keeps its exit status', async () => {
  await assert.rejects(
    runManagedCommand(
      process.execPath,
      ['-e', 'setInterval(() => {}, 1000);'],
      { ...options, timeoutMs: 200, isReady: async () => false },
    ),
    /Helper did not respond/,
  );
  const result = await runManagedCommand(
    process.execPath,
    ['-e', 'process.exit(125)'],
    {
      ...options,
      isReady: async () => false,
    },
  );
  assert.equal(result.code, 125);
});
void test('Ctrl-C interrupts a helper promptly without waiting for its normal deadline', async () => {
  const helper = new URL('../cli/child-process.ts', import.meta.url).href;
  const runner = spawn(
    process.execPath,
    [
      '--import',
      'tsx',
      '--input-type=module',
      '-e',
      `
    import { runManagedCommand } from ${JSON.stringify(helper)};
    const pending = runManagedCommand(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], {
      stage: 'Docker readiness check', timeoutMs: 10000, timeoutMessage: 'deadline',
    });
    console.log('ready');
    try { await pending; } catch (error) { console.error(error.message); process.exitCode = 1; }
  `,
    ],
    { stdio: ['ignore', 'pipe', 'pipe'] },
  );
  let output = '';
  runner.stdout!.once('data', () => runner.kill('SIGINT'));
  runner.stderr!.on('data', (data) => {
    output += data;
  });
  const watchdog = setTimeout(() => runner.kill('SIGKILL'), 4000);
  try {
    const code = await new Promise((resolve) => runner.once('close', resolve));
    assert.equal(code, 1);
    assert.match(output, /Docker readiness check cancelled \(SIGINT\)/);
    assert.doesNotMatch(output, /deadline/);
  } finally {
    clearTimeout(watchdog);
  }
});
