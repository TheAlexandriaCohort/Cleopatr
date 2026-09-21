import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  // Cedar loads its WASM alongside the Node package at runtime.
  serverExternalPackages: ['@cedar-policy/cedar-wasm'],
  poweredByHeader: false,
  outputFileTracingIncludes: { '/api/v1/*': ['./migrations/*.sql'] },
  outputFileTracingExcludes: {
    '/*': [
      './.local/**',
      './.cleo/**',
      './.env*',
      './.git/**',
      './cleopatr-enrollment.json',
      './dist-cli/**',
      './dist-runtime/**',
      './runtime/**',
      './tests/**',
      './docs/**',
      './public/downloads/**',
    ],
  },
};

export default nextConfig;
