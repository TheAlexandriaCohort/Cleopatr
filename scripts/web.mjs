import { existsSync } from 'node:fs';
import { spawn } from 'node:child_process';

if (existsSync('.env')) process.loadEnvFile('.env');
const [command, ...args] = process.argv.slice(2);
if (!['dev', 'start'].includes(command))
  throw new Error('Expected dev or start');
let host = process.env.CLEO_HOST ?? '127.0.0.1';
for (let i = 0; i < args.length; i++) {
  if (args[i] === '-H' || args[i] === '--hostname') host = args[++i];
  else if (args[i].startsWith('--hostname=')) host = args[i].slice(11);
}
if (
  !['localhost', '127.0.0.1', '::1'].includes(host) &&
  !process.env.CLEO_ADMIN_TOKEN
)
  throw new Error(
    'Set CLEO_ADMIN_TOKEN before exposing Cleopatr beyond localhost.',
  );
const child = spawn(
  process.execPath,
  [
    'node_modules/next/dist/bin/next',
    command,
    '-H',
    host,
    '-p',
    process.env.PORT ?? '3000',
    ...args,
  ],
  { stdio: 'inherit', env: process.env },
);
for (const signal of ['SIGINT', 'SIGTERM'])
  process.on(signal, () => child.kill(signal));
child.on('error', (error) => {
  console.error(error.message);
  process.exitCode = 1;
});
child.on('exit', (code) => {
  process.exitCode = code ?? 1;
});
