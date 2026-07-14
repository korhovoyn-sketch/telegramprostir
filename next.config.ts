import type { NextConfig } from 'next'

const nextConfig: NextConfig = {
  output: 'export',
  trailingSlash: true,
  poweredByHeader: false,
  images: {
    unoptimized: true,
  },
  env: {
    // Build stamp shown in the Profile footer — Vercel injects the commit sha
    // at build time; local/dev builds show 'dev'. Lets support answer «який
    // білд відкрито на пристрої?» without guessing about webview caches.
    NEXT_PUBLIC_BUILD_SHA: (process.env.VERCEL_GIT_COMMIT_SHA ?? 'dev').slice(0, 7),
  },
}

export default nextConfig
