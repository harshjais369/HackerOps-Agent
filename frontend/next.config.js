// Suppress DEP0060 deprecation warning caused by internal http-proxy using util._extend on Node 22+
const util = require('util');
try {
  Object.defineProperty(util, '_extend', {
    value: Object.assign,
    writable: true,
    configurable: true,
    enumerable: true,
  });
} catch (_) {}

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: false,
  swcMinify: true,
  typescript: {
    ignoreBuildErrors: true,
  },
  eslint: {
    ignoreDuringBuilds: true,
  },
  experimental: {
    cpus: 1,
  },
  async rewrites() {
    const backendInternal = process.env.BACKEND_INTERNAL_URL || 'http://127.0.0.1:8000';
    return [
      {
        source: '/api/:path*',
        destination: `${backendInternal}/api/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;
