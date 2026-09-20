#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { setTimeout } from 'node:timers/promises';

const url = 'https://www.google.com/search?q=test+frameworks&oq=test+framework';

for (let attempt = 1; attempt <= 5; attempt++) {
  console.log(`[${attempt}/5] GET ${url}`);
  const code = await new Promise((resolve) => {
    const request = spawn(
      'curl',
      [
        '--request',
        'GET',
        '--include',
        '--show-error',
        '--fail-with-body',
        '--max-time',
        '30',
        url,
      ],
      { stdio: 'inherit' },
    );

    request.once('error', (error) => {
      console.error(`Request failed: ${error.message}`);
      resolve(1);
    });
    request.once('close', (code, signal) => {
      if (signal) console.error(`Request interrupted: ${signal}`);
      resolve(code ?? 1);
    });
  });
  if (code !== 0) process.exitCode = code;
  if (attempt < 5) await setTimeout(5000);
}
