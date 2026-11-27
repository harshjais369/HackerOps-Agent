/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: false,
  outputFileTracing: false,
  typescript: {
    ignoreBuildErrors: true,
  },
  eslint: {
    ignoreDuringBuilds: true,
  },
  async rewrites() {
    const backendInternal = process.env.BACKEND_INTERNAL_URL || 'http://backend:8000';
    return [
      {
        source: '/api/:path*',
        destination: `${backendInternal}/api/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;
