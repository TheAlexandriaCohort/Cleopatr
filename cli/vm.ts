import { createHash } from 'node:crypto';
import {
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  realpath,
  lstat,
  rm,
} from 'node:fs/promises';
import { join, relative, isAbsolute, sep } from 'node:path';
import { arch, homedir, tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { atomicJson, loadBundle, requestRefresh } from './cache.ts';
import { resolveEnvironment } from './options.ts';
import { compileProfile, requireExecutableGrant } from '../runtime/profile.ts';
import { runManagedCommand } from './child-process.ts';
import { importVmEvents } from './vm-events.ts';

const dockerEnv = () => ({
  ...process.env,
  PATH: '/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/Applications/Docker.app/Contents/Resources/bin',
});

function inside(parent: string, child: string) {
  const path = relative(parent, child);
  return (
    path === '' ||
    (!path.startsWith('..' + sep) && path !== '..' && !isAbsolute(path))
  );
}
async function docker(
  args: string[],
  stage: string,
  timeoutMs = 10000,
  inherit = false,
) {
  return runManagedCommand('docker', args, {
    stage,
    timeoutMs,
    timeoutMessage: `${stage} timed out after ${timeoutMs / 1000}s. Docker Desktop may be unresponsive; restart it and retry.`,
    stdio: inherit ? 'output' : 'capture',
    env: dockerEnv(),
  });
}
async function assetsDirectory() {
  for (const url of [
    new URL('./vm/', import.meta.url),
    new URL('../dist-runtime/vm-runtime/', import.meta.url),
  ]) {
    const directory = fileURLToPath(url);
    if (
      await lstat(join(directory, 'Dockerfile'))
        .then((s) => s.isFile())
        .catch(() => false)
    )
      return realpath(directory);
  }
  throw new Error(
    'Managed VM assets are missing. Install the updated Cleopatr CLI package. No uncontained process was started.',
  );
}
async function imageName(directory: string) {
  const hash = createHash('sha256');
  async function visit(path: string) {
    for (const entry of (await readdir(path, { withFileTypes: true })).sort(
      (a, b) => a.name.localeCompare(b.name),
    )) {
      const file = join(path, entry.name);
      if (entry.isDirectory()) await visit(file);
      else if (entry.isFile()) {
        hash.update(relative(directory, file));
        hash.update(await readFile(file));
      } else throw new Error('Unexpected link in managed VM build assets');
    }
  }
  await visit(directory);
  return `cleopatr-managed-vm:${hash.digest('hex').slice(0, 24)}`;
}
export async function launchVm(options: {
  dir: string;
  argv: string[];
  environment?: string;
  enforce: boolean;
  audit?: boolean;
}) {
  if (arch() !== 'arm64')
    throw new Error(
      'The managed VM preview currently supports Apple Silicon / ARM64 hosts only. Use a configured native Linux supervisor on other architectures.',
    );
  const workspace = await realpath(process.cwd());
  const cacheDir = await realpath(options.dir);
  await requestRefresh(cacheDir).catch(() => {});
  const { bundle, cache, config } = await loadBundle(cacheDir);
  const environment = resolveEnvironment(
    bundle,
    options.environment ?? config.environment ?? config.environmentIds[0],
  );
  const principal = bundle.client?.name ?? config.clientName;
  if (!principal)
    throw new Error('Signed client identity is required; run cleo sync');
  requireExecutableGrant(
    compileProfile(
      bundle,
      environment,
      principal,
      options.enforce,
      options.audit,
    ),
  );
  const assets = await assetsDirectory();
  if (options.audit)
    process.stderr.write(
      'cleo: audit override · policy denials are allowed and logged; enclave restrictions still apply\n',
    );
  if (
    [sep, homedir(), tmpdir()].includes(workspace) ||
    inside(workspace, assets) ||
    inside(workspace, await realpath(process.argv[1]))
  )
    throw new Error(
      'Choose a project workspace that does not contain the installed Cleopatr CLI or VM runtime. Install the CLI outside the workspace first.',
    );
  if (workspace.includes(':') || workspace.includes('\n'))
    throw new Error('Unsupported workspace path for Docker bind mounting');
  const masks: string[] = [];
  if (inside(workspace, cacheDir)) {
    const mask = relative(workspace, cacheDir);
    if (!mask)
      throw new Error('The policy store cannot also be the workload workspace');
    masks.push(mask);
  }
  if (
    !masks.includes('.cleo') &&
    (await lstat(join(workspace, '.cleo'))
      .then((s) => s.isDirectory() && !s.isSymbolicLink())
      .catch(() => false))
  )
    masks.push('.cleo');
  const enrollment = await lstat(
    join(workspace, 'cleopatr-enrollment.json'),
  ).catch(() => undefined);
  if (enrollment) {
    if (!enrollment.isFile() || enrollment.isSymbolicLink())
      throw new Error(
        'The workspace enrollment file must be a regular file to mask it safely',
      );
    masks.push('cleopatr-enrollment.json');
  }
  process.stderr.write('cleo: checking Docker Desktop (10s timeout)\n');
  const ready = await docker(
    ['info', '--format', '{{.OSType}}'],
    'Docker readiness check',
  );
  if (ready.code !== 0 || ready.output.trim() !== 'linux')
    throw new Error(
      'Start Docker Desktop with Linux containers to use the managed Linux enclave. No cooperative fallback was started.',
    );
  const image = await imageName(assets);
  process.stderr.write(
    'cleo: checking managed Linux runtime image (10s timeout)\n',
  );
  if (
    (await docker(['image', 'inspect', image], 'Docker image check')).code !== 0
  ) {
    process.stderr.write(
      'cleo: preparing the managed Linux runtime (first launch builds the image; 15m timeout)\n',
    );
    if (
      (
        await docker(
          ['build', '-t', image, assets],
          'Docker runtime build',
          900000,
          true,
        )
      ).code !== 0
    )
      throw new Error('Managed Linux runtime image build failed');
  }
  const uid = process.getuid?.() ?? 0,
    gid = process.getgid?.() ?? 0;
  if (!uid)
    throw new Error('Run the managed VM CLI as your normal user, not root');
  const shared = await mkdtemp(join(tmpdir(), 'cleo-vm-'));
  const name = 'cleo-vm-' + crypto.randomUUID();
  let timer: ReturnType<typeof setInterval> | undefined;
  let updating = false;
  let sequence = bundle.sequence;
  const transferEvents = (limit?: number) =>
    importVmEvents(shared, cacheDir, limit);
  const update = async () => {
    if (updating) return;
    updating = true;
    try {
      await transferEvents();
      await requestRefresh(cacheDir).catch(() => {});
      const current = await loadBundle(cacheDir);
      if (current.bundle.sequence > sequence) {
        await atomicJson(join(shared, 'bundle.json'), current.cache);
        sequence = current.bundle.sequence;
      }
    } finally {
      updating = false;
    }
  };
  try {
    if (inside(workspace, shared))
      throw new Error(
        'The VM control directory must be outside the workload workspace',
      );
    await mkdir(join(shared, 'events'), { mode: 0o700 });
    // Actual control-plane credentials stay on the Mac, outside the enclave.
    await atomicJson(join(shared, 'config.json'), {
      ...config,
      token: 'host-managed-offline',
      server: 'http://127.0.0.1:1',
    });
    await atomicJson(join(shared, 'bundle.json'), cache);
    const mapPath = (value: string) =>
      value === process.execPath
        ? '/usr/local/bin/node'
        : isAbsolute(value) && inside(workspace, value)
          ? '/workspace/' + relative(workspace, value).split(sep).join('/')
          : value;
    const argv = options.argv.map(mapPath);
    if (argv[0].includes('/') && !isAbsolute(argv[0]))
      argv[0] = '/workspace/' + argv[0];
    await atomicJson(join(shared, 'request.json'), {
      uid,
      gid,
      environment,
      enforce: options.enforce,
      audit: options.audit === true,
      argv,
      masks,
      sessionId: name,
    });
    process.stderr.write(
      `cleo: Linux VM enclave · policy snapshot ${sequence} · ${environment}\ncleo: booting protected supervisor (180s timeout); selected workspace will be mounted at /workspace\n`,
    );
    const completion = runManagedCommand(
      'docker',
      [
        'run',
        '--rm',
        '-i',
        '--name',
        name,
        '--user',
        `${uid}:${gid}`,
        '--cap-drop',
        'ALL',
        '--memory',
        '4g',
        '--pids-limit',
        '256',
        '--security-opt',
        'no-new-privileges',
        '-v',
        `${workspace}:/workspace-host`,
        '-v',
        `${shared}:/session`,
        image,
      ],
      {
        stage: 'Linux VM startup',
        timeoutMs: 180000,
        timeoutMessage:
          'Linux VM startup timed out after 180s before the protected supervisor became ready.',
        stdio: 'inherit',
        env: dockerEnv(),
        isReady: async () => {
          try {
            const status = JSON.parse(
              await readFile(join(shared, 'ready.json'), 'utf8'),
            );
            return status.sessionId === name;
          } catch (error) {
            if ((error as NodeJS.ErrnoException).code === 'ENOENT')
              return false;
            throw error;
          }
        },
        onReady: () =>
          process.stderr.write(
            'cleo: protected supervisor ready; launching agent\n',
          ),
      },
    );
    timer = setInterval(() => {
      void update().catch((error) =>
        process.stderr.write(`cleo VM sync: ${(error as Error).message}\n`),
      );
    }, 1000);
    const { code: exit } = await completion;
    if (timer) clearInterval(timer);
    while (updating) await new Promise((resolve) => setTimeout(resolve, 10));
    const result = await readFile(join(shared, 'exit.json'), 'utf8')
      .then(JSON.parse)
      .catch(() => undefined);
    if (
      !result ||
      !Number.isInteger(result.code) ||
      result.code < 0 ||
      result.code > 255
    )
      throw new Error(
        `Linux VM stopped without a verified completion status (${exit ?? 'signal'}); no host fallback was started`,
      );
    process.exitCode = result.code;
  } finally {
    if (timer) clearInterval(timer);
    let cleaned = true;
    await docker(['rm', '-f', name], 'Docker enclave cleanup', 5000)
      .then((result) => {
        if (result.code !== 0 && !result.output.includes('No such container'))
          throw new Error('Docker did not confirm container removal');
      })
      .catch((error) => {
        cleaned = false;
        process.stderr.write(
          `cleo: ${(error as Error).message} Check for leftover container ${name} when Docker responds.\n`,
        );
      });
    while (updating) await new Promise((resolve) => setTimeout(resolve, 10));
    try {
      // Also run on cancellation/failure, and drain all final records before
      // removing the guest's export directory. Live transfers remain bounded.
      await transferEvents(Number.MAX_SAFE_INTEGER);
    } catch (error) {
      cleaned = false;
      process.stderr.write(
        `cleo: audit recovery required: ${(error as Error).message}\n`,
      );
    }
    if (cleaned) await rm(shared, { recursive: true, force: true });
    else
      process.stderr.write(
        `cleo: retained VM session files for recovery at ${shared}\n`,
      );
  }
}
