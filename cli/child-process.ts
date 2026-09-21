import { spawn } from 'node:child_process';

/** Bound a helper command, or only its startup when a readiness probe is supplied. */
export function runManagedCommand(
  command: string,
  args: string[],
  options: {
    stage: string;
    timeoutMs: number;
    timeoutMessage: string;
    env?: NodeJS.ProcessEnv;
    stdio?: 'capture' | 'output' | 'inherit';
    isReady?: () => Promise<boolean>;
    onReady?: () => void;
  },
): Promise<{ code: number | null; output: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      // Isolate helpers (including Docker build plugins) so cancellation can
      // terminate the entire helper group without signalling the user's shell.
      detached: process.platform !== 'win32',
      env: options.env,
      stdio:
        options.stdio === 'inherit'
          ? 'inherit'
          : options.stdio === 'output'
            ? ['ignore', 'inherit', 'inherit']
            : ['ignore', 'pipe', 'pipe'],
    });
    let output = '';
    let settled = false;
    let stopping: Error | undefined;
    let escalation: ReturnType<typeof setTimeout> | undefined;
    let probe: ReturnType<typeof setTimeout> | undefined;
    const handlers = new Map<NodeJS.Signals, () => void>();
    const collect = (data: Buffer) => {
      output = (output + data.toString()).slice(-65536);
    };
    child.stdout?.on('data', collect);
    child.stderr?.on('data', collect);

    function signalTree(signal: NodeJS.Signals) {
      try {
        if (process.platform !== 'win32' && child.pid)
          process.kill(-child.pid, signal);
        else child.kill(signal);
      } catch {
        child.kill(signal);
      }
    }
    function finish(error?: Error, code: number | null = null) {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      clearTimeout(escalation);
      clearTimeout(probe);
      for (const [signal, handler] of handlers) process.off(signal, handler);
      if (error) {
        child.stdout?.destroy();
        child.stderr?.destroy();
        child.unref();
        reject(error);
      } else resolve({ code, output });
    }
    function stop(error: Error, signal: NodeJS.Signals = 'SIGTERM') {
      if (settled || stopping) return;
      stopping = error;
      signalTree(signal);
      // A wedged client must not keep Cleo alive after its deadline, even if
      // its pipes or a subprocess fail to close after the initial signal.
      escalation = setTimeout(() => {
        signalTree('SIGKILL');
        finish(error);
      }, 500);
    }
    child.once('error', (error) =>
      finish(new Error(`${options.stage}: ${error.message}`)),
    );
    child.once('close', (code) => {
      if (stopping) signalTree('SIGKILL');
      finish(stopping, code);
    });
    for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP'] as const) {
      const handler = () =>
        stop(new Error(`${options.stage} cancelled (${signal})`), signal);
      handlers.set(signal, handler);
      process.on(signal, handler);
    }
    const deadline = setTimeout(
      () => stop(new Error(options.timeoutMessage)),
      options.timeoutMs,
    );
    async function checkReady() {
      try {
        const ready = await options.isReady!();
        if (settled || stopping) return;
        if (ready) {
          clearTimeout(deadline);
          options.onReady?.();
        } else probe = setTimeout(() => void checkReady(), 100);
      } catch (error) {
        stop(new Error(`${options.stage}: ${(error as Error).message}`));
      }
    }
    if (options.isReady) void checkReady();
  });
}
