#!/usr/bin/env node
import { readFile, realpath, access, stat } from 'node:fs/promises';
import { constants } from 'node:fs';
import { join, resolve, delimiter, basename } from 'node:path';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { platform, release } from 'node:os';
import {
  dataDir,
  ensureDir,
  readConfig,
  atomicJson,
  validateConfig,
  readCache,
  activate,
  sync,
  refreshWorker,
  loadBundle,
  requestRefresh,
} from './cache.ts';
import { authorize, flushAudit } from './runtime.ts';
import { VERSION, type ActionRequest } from '../core/model.ts';
import {
  parseInvocation,
  selectedMode,
  resolveEnvironment,
} from './options.ts';
import { rewritePipeline, zshIntegration } from './shell.ts';
import { launchVm } from './vm.ts';
import { auditStatus, startAuditUploader } from './audit.ts';
let auditUploader: ReturnType<typeof startAuditUploader> | undefined;
let invocation: ReturnType<typeof parseInvocation>;
const value = (key: string, fallback?: string) =>
  invocation.options.get(key) ?? fallback;
const json = (v: unknown) =>
  process.stdout.write(JSON.stringify(v, null, 2) + '\n');
function mode() {
  return selectedMode(value('--mode'));
}
async function environment(dir: string, fallback?: string) {
  const { config, bundle } = await loadBundle(dir);
  await requestRefresh(dir).catch(() => {});
  return resolveEnvironment(
    bundle,
    value(
      '--environment',
      process.env.CLEO_ENVIRONMENT ??
        config.environment ??
        fallback ??
        config.environmentIds[0],
    )!,
  );
}
async function executable(command: string) {
  const candidates = command.includes('/')
    ? [resolve(command)]
    : (process.env.PATH ?? '').split(delimiter).map((p) => join(p, command));
  for (const path of candidates) {
    try {
      await access(path, constants.X_OK);
      if ((await stat(path)).isFile()) return await realpath(path);
    } catch {}
  }
  throw new Error(`Executable not found: ${command}`);
}
function wrappedCommand() {
  if (!invocation.agent.length)
    throw new Error(
      'No agent was passed. Use cleo -- python agent.py, or enable cleo init zsh before using cleo | agent. A literal shell pipe does not contain its right-hand process; that process may already be running.',
    );
  return invocation.agent;
}
async function main() {
  invocation = parseInvocation(process.argv.slice(2));
  const { command, positionals } = invocation;
  const dir = dataDir();
  if (['run', 'authorize', 'mcp', 'sync', '__refresh'].includes(command))
    auditUploader = startAuditUploader(dir);
  if (command === 'init') {
    if (positionals.length !== 1 || positionals[0] !== 'zsh')
      throw new Error(
        'Use cleo init zsh. Only interactive zsh integration is supported.',
      );
    process.stdout.write(
      zshIntegration([
        process.execPath,
        ...process.execArgv,
        resolve(process.argv[1]),
      ]),
    );
    return;
  }
  if (command === '__rewrite-zsh') {
    let line = '';
    for await (const chunk of process.stdin) {
      line += chunk;
      if (line.length > 65536) throw new Error('Shell command exceeds 64 KiB');
    }
    process.stdout.write(rewritePipeline(line.replace(/\n$/, '')));
    return;
  }
  if (
    positionals.length &&
    !(
      command === 'audit' &&
      positionals.length === 1 &&
      positionals[0] === 'flush'
    )
  )
    throw new Error(
      'Unexpected arguments. Put the agent command and its arguments after --.',
    );
  if (command === 'help' || command === '--help') {
    if (!process.argv.slice(2).length && !process.stdout.isTTY)
      throw new Error(
        'Bare cleo does not control the right-hand process of a literal pipe. Enable the interactive zsh hook with eval "$(cleo init zsh)", or use cleo -- agent. The right-hand process may already be running. Use cleo --help for usage.',
      );
    process.stdout.write(
      `Cleopatr ${VERSION} — local Cedar authorization\n\nInteractive zsh setup (once per shell):\n  eval "$(cleo init zsh)"\n\nWith the hook enabled, enter one simple command:\n  cleo | python -m my_agent\n  cleo --audit | ./agent-service.sh\n  cleo --env=PCI | npm run dev\n\nPortable launch (scripts and other shells):\n  cleo [--audit] [--env=NAME_OR_ID] -- command [args...]\n\nCommands:\n  cleo enroll --config enrollment.json     Pin tenant, key, and client identity\n  cleo sync                                Fetch and verify the latest bundle\n  cleo import --file bundle.json           Activate a signed offline bundle\n  cleo authorize --request action.json      Evaluate an explicit action\n  cleo mcp [--audit] -- command          Mediate MCP stdio JSON-RPC\n  cleo init zsh                            Print the opt-in interactive shell hook\n  cleo status                              Inspect enrollment and policy cache\n  cleo doctor                              Report actual adapter coverage\n  cleo audit flush                         Upload redacted local decisions\n\nOptions: --env NAME_OR_ID (also --environment), --audit, --enforce, --mode audit|enforce\n  --backend auto|vm|linux|cooperative (default: auto; macOS uses the managed Linux VM)\nEnvironment policy modes apply by default. --audit logs policy denials without blocking them, including inherited Enforce policies.\n--audit keeps enclave isolation and adapter limits. --enforce remains an optional force-Enforce override.\nEnvironment names must resolve uniquely within the assigned cached bundle.\nThe environment field in .cleo/config sets the default environment. CLEO_HOME overrides the config/cache directory.\n\nThe hook rewrites the pipe before execution; it is not a Unix data pipe.\nWithout the hook, the shell starts the right-hand process independently.\nOnly simple literal commands are supported by the hook; use a script for shell logic.\nThe default requires a protected Linux boundary; macOS ARM64 requires Docker Desktop.\n--backend linux selects the experimental kernel boundary and refuses uncontained fallback.\nLegacy 'cleo run -- command' remains supported.\n`,
    );
    return;
  }
  if (command === '--version') {
    process.stdout.write(VERSION + '\n');
    return;
  }
  if (command === 'doctor') {
    json({
      version: VERSION,
      platform: platform(),
      kernel: release(),
      capabilities: {
        localCedar: 'available',
        signedBundles: 'Ed25519',
        explicitAuthorization: 'pre-authorize',
        processLauncher:
          'auto: managed Linux VM on macOS; native supervisor on Linux',
        pipeSyntax:
          'opt-in interactive zsh accept-line rewrite; not a Unix data pipe',
        mcpStdio: 'mediated requests only',
        linuxCgroup: 'experimental Linux supervisor: per-session cgroup v2',
        kernelFilesystem:
          'experimental Linux supervisor: Landlock directory/executable grants',
        kernelNetwork:
          'experimental Linux supervisor: seccomp broker and private network namespace',
        httpProxy:
          'experimental Linux supervisor: HTTP/1.1 and MCP HTTP; opaque CONNECT allowed only for entirely Audit sessions, encrypted requests not inspected',
        processSignals:
          'pidfd-mediated kill/tkill/tgkill within the session cgroup',
        privilegeAttempts:
          'UID/GID, capabilities and namespace/mount attempts assessed; privilege elevation remains prohibited',
        fileMetadata:
          'stat/statx, chmod/chown and timestamps mediated on pinned objects; xattrs remain unsupported',
        networkListen:
          'policy-mediated bind/listen within the private network namespace; no host exposure',
        dns: 'protected UDP/TCP resolver with per-question decisions; registered database host aliases',
        postgresProxy:
          'protocol 3.0 simple queries and explicit transactions; verified upstream TLS; prepared/COPY/replication unsupported',
        mysqlProxy:
          'protocol 10 COM_QUERY and explicit transactions; verified upstream TLS; prepared/compression/multi-statements unsupported',
      },
      boundary:
        'Default auto selects a managed Linux VM on macOS ARM64 (Docker required), or a separately installed Linux supervisor. Cooperative mode is explicit and bypassable. No uncontained fallback. Production coverage remains incomplete.',
      linuxSupervisor: {
        supportedPlatform: platform() === 'linux',
        probe: '/usr/lib/cleopatr/cleo-supervisor doctor',
        requiredLandlockAbi: 5,
        productionReady: false,
      },
    });
    return;
  }
  if (command === 'enroll') {
    const file = value('--config');
    if (!file) throw new Error('Use --config enrollment.json');
    const config = JSON.parse(await readFile(resolve(file), 'utf8'));
    validateConfig(config);
    await ensureDir(dir);
    const old = await readCache(dir);
    if (old)
      throw new Error(
        'Already enrolled with a policy cache. Use a separate CLEO_HOME for another enrollment.',
      );
    await atomicJson(join(dir, 'config'), config);
    json({
      enrolled: true,
      tenant: config.tenant,
      environments: config.environmentIds,
      next: 'Run cleo sync, or import a signed bundle. Keep the enrollment file private.',
    });
    return;
  }
  if (command === 'sync') {
    await ensureDir(dir);
    json(await sync(dir));
    return;
  }
  if (command === '__refresh') {
    await refreshWorker(dir);
    return;
  }
  if (command === 'import') {
    const file = value('--file');
    if (!file) throw new Error('Use --file signed-bundle.json');
    const bundle = await activate(
      JSON.parse(await readFile(resolve(file), 'utf8')),
      dir,
      0,
    );
    json({
      activated: true,
      sequence: bundle.sequence,
      environments: bundle.environmentIds,
    });
    return;
  }
  if (command === 'status') {
    const config = await readConfig(dir);
    let cache;
    try {
      const loaded = await loadBundle(dir);
      cache = {
        verified: true,
        bundle: loaded.bundle.bundleId,
        sequence: loaded.bundle.sequence,
        environment: config.environment ?? config.environmentIds[0],
        lastChecked: new Date(loaded.cache.checkedAt).toISOString(),
        stale: Date.now() - loaded.cache.checkedAt >= 300000,
      };
    } catch (e) {
      cache = { verified: false, error: (e as Error).message };
    }
    json({
      version: VERSION,
      server: config.server,
      tenant: config.tenant,
      environments: config.environmentIds,
      cache,
      refreshIntervalSeconds: 300,
      audit: await auditStatus(dir),
    });
    return;
  }
  if (command === 'audit' && positionals[0] === 'flush') {
    json({
      uploaded: await flushAudit(dir, { maxBatches: 20 }),
      ...(await auditStatus(dir)),
    });
    return;
  }
  if (command === 'authorize') {
    const file = value('--request');
    if (!file)
      throw new Error('Use --request action.json (or --request - for stdin)');
    const request = JSON.parse(
      await readFile(file === '-' ? '/dev/stdin' : resolve(file), 'utf8'),
    ) as ActionRequest;
    request.environmentId = await environment(dir, request.environmentId);
    request.sessionId ??=
      process.env.CLEO_SESSION_ID ?? 'agt_' + crypto.randomUUID();
    const result = await authorize(request, { dir, mode: mode() });
    json(result);
    process.exitCode = result.allowed ? 0 : result.errors.length ? 3 : 2;
    return;
  }
  if (command === 'run') {
    const [cmd, ...argv] = wrappedCommand();
    const selected = value('--backend', 'auto');
    if (!['auto', 'vm', 'linux', 'cooperative'].includes(selected!))
      throw new Error('Backend must be auto, vm, linux or cooperative');
    const backend =
      selected === 'auto'
        ? platform() === 'darwin'
          ? 'vm'
          : 'linux'
        : selected;
    if (backend === 'vm') {
      await launchVm({
        dir,
        argv: [cmd, ...argv],
        environment: value('--environment', process.env.CLEO_ENVIRONMENT),
        enforce: mode() === 'ENFORCE',
        audit: mode() === 'AUDIT',
      });
      return;
    }
    if (backend === 'linux') {
      if (platform() !== 'linux')
        throw new Error(
          'The Linux security supervisor requires Linux. No uncontained fallback was started.',
        );
      const args = ['launch'];
      let selector = value('--environment', process.env.CLEO_ENVIRONMENT);
      if (!selector) {
        const text = await readFile(join(dir, 'config'), 'utf8').catch(
          async (error: NodeJS.ErrnoException) => {
            if (error.code !== 'ENOENT') throw error;
            return readFile(join(dir, 'config.json'), 'utf8').catch(
              (legacy: NodeJS.ErrnoException) => {
                if (legacy.code !== 'ENOENT') throw legacy;
                return '{}';
              },
            );
          },
        );
        const local = JSON.parse(text);
        if (
          local.environment !== undefined &&
          (typeof local.environment !== 'string' || !local.environment.trim())
        )
          throw new Error(
            'Invalid environment selector in local configuration',
          );
        selector = local.environment;
      }
      if (selector) args.push('--env', selector);
      if (mode() === 'ENFORCE') args.push('--enforce');
      if (mode() === 'AUDIT') args.push('--audit');
      args.push('--', cmd, ...argv);
      const child = spawn('/usr/lib/cleopatr/cleo-supervisor', args, {
        stdio: 'inherit',
        env: { PATH: '/usr/bin:/bin', NODE_ENV: 'production' },
      });
      for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP'] as NodeJS.Signals[])
        process.on(signal, () => {
          child.kill(signal);
        });
      await new Promise<void>((resolve, reject) => {
        child.once('error', reject);
        child.once('close', (code, signal) => {
          process.exitCode = code ?? (signal === 'SIGINT' ? 130 : 143);
          resolve();
        });
      });
      return;
    }
    const path = await executable(cmd);
    const environmentId = await environment(dir);
    const sessionId = 'agt_' + crypto.randomUUID();
    const request: ActionRequest = {
      environmentId,
      sessionId,
      action: 'process.execute',
      resource: { type: 'Process', id: path },
      workspace: process.cwd(),
      context: {
        executable: path,
        argv,
        cwd: process.cwd(),
        confidence: 'configured',
      },
    };
    const result = await authorize(request, { dir, mode: mode() });
    process.stderr.write(
      `cleo: ${result.mode} · policy snapshot ${result.sequence} · launcher ${result.effectiveResult}\ncleo: descendant filesystem/network/process interception unavailable; use mediated adapters.\n`,
    );
    if (!result.allowed) {
      process.stderr.write(
        'cleo: denied by ' +
          (result.determiningPolicies.join(', ') || 'default deny') +
          '\n',
      );
      process.exitCode = 2;
      return;
    }
    const child = spawn(path, argv, {
      stdio: 'inherit',
      env: {
        ...process.env,
        CLEO_SESSION_ID: sessionId,
        CLEO_ENVIRONMENT: environmentId,
        CLEO_MODE: mode() ?? 'POLICY',
      },
    });
    for (const signal of [
      'SIGINT',
      'SIGTERM',
      'SIGHUP',
      'SIGWINCH',
    ] as NodeJS.Signals[])
      process.on(signal, () => {
        try {
          child.kill(signal);
        } catch {}
      });
    child.on('error', (error) => {
      process.stderr.write(`cleo: ${error.message}\n`);
      process.exitCode = 127;
    });
    await new Promise<void>((res) =>
      child.on('close', (code, signal) => {
        process.exitCode =
          code ?? (signal === 'SIGINT' ? 130 : signal === 'SIGTERM' ? 143 : 1);
        res();
      }),
    );
    return;
  }
  if (command === 'mcp') {
    await runMcp(dir);
    return;
  }
  throw new Error(`Unknown command: ${command}. Run cleo --help.`);
}
async function runMcp(dir: string) {
  const [cmd, ...argv] = wrappedCommand();
  const path = await executable(cmd);
  const environmentId = await environment(dir);
  const sessionId = process.env.CLEO_SESSION_ID ?? 'agt_' + crypto.randomUUID();
  const initial = await authorize(
    {
      environmentId,
      sessionId,
      action: 'process.execute',
      resource: { type: 'Process', id: path },
      context: { executable: path, argv, confidence: 'configured' },
    },
    { dir, mode: mode() },
  );
  if (!initial.allowed) throw new Error('MCP server launch denied');
  const child = spawn(path, argv, {
    stdio: ['pipe', 'pipe', 'inherit'],
    env: {
      ...process.env,
      CLEO_SESSION_ID: sessionId,
      CLEO_ENVIRONMENT: environmentId,
      CLEO_MODE: mode() ?? 'POLICY',
    },
  });
  child.stdout.pipe(process.stdout);
  const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
  let chain = Promise.resolve();
  const passthrough = new Set([
    'initialize',
    'ping',
    'tools/list',
    'resources/list',
    'resources/templates/list',
    'prompts/list',
    'notifications/initialized',
    'notifications/cancelled',
    'notifications/progress',
    'logging/setLevel',
    'completion/complete',
  ]);
  lines.on('line', (line) => {
    chain = chain
      .then(async () => {
        if (Buffer.byteLength(line) > 1024 * 1024)
          throw new Error('MCP message exceeds one MiB');
        const msg = JSON.parse(line);
        if (!msg.method) {
          child.stdin.write(line + '\n');
          return;
        }
        const mapping: Record<string, string> = {
          'tools/call': 'mcp.tool.invoke',
          'resources/read': 'mcp.resource.read',
          'prompts/get': 'mcp.prompt.get',
        };
        const action = mapping[msg.method];
        if (!action && !passthrough.has(msg.method)) {
          if (msg.id !== undefined)
            process.stdout.write(
              JSON.stringify({
                jsonrpc: '2.0',
                id: msg.id,
                error: {
                  code: -32601,
                  message:
                    'MCP operation is not supported by this Cleopatr adapter',
                },
              }) + '\n',
            );
          return;
        }
        if (action) {
          const tool = String(msg.params?.name ?? msg.params?.uri ?? 'unknown');
          const context: Record<string, unknown> = {
            tool,
            server: value('--server', basename(path))!,
            confidence: 'semantic',
          };
          if (Number.isSafeInteger(msg.params?.arguments?.amount))
            context.amount = msg.params.arguments.amount;
          const result = await authorize(
            {
              environmentId,
              sessionId,
              action,
              resource: { type: 'MCPTool', id: value('--resource', tool)! },
              context,
            },
            { dir, mode: mode() },
          );
          if (!result.allowed) {
            if (msg.id !== undefined)
              process.stdout.write(
                JSON.stringify({
                  jsonrpc: '2.0',
                  id: msg.id,
                  error: {
                    code: -32003,
                    message: 'Denied by Cleopatr',
                    data: {
                      policies: result.determiningPolicies,
                      snapshot: result.sequence,
                    },
                  },
                }) + '\n',
              );
            return;
          }
        }
        if (!child.stdin.write(line + '\n'))
          await new Promise<void>((res) => child.stdin.once('drain', res));
      })
      .catch((e) => {
        process.stderr.write(`cleo MCP: ${(e as Error).message}\n`);
        child.kill('SIGTERM');
        lines.close();
        process.exitCode = 3;
      });
  });
  lines.on('close', () => void chain.then(() => child.stdin.end()));
  for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP'] as NodeJS.Signals[])
    process.on(signal, () => child.kill(signal));
  child.on('error', (e) => {
    process.stderr.write(`cleo MCP: ${e.message}\n`);
    lines.close();
    process.exitCode = 127;
  });
  await new Promise<void>((res) =>
    child.on('close', (code) => {
      lines.close();
      process.exitCode = process.exitCode || code || 0;
      res();
    }),
  );
}
main()
  .catch((error) => {
    process.stderr.write(`cleo: ${error.message}\n`);
    process.exitCode = 3;
  })
  .finally(async () => {
    await auditUploader?.stop();
  });
