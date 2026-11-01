import type { NextConfig } from "next";

import { securityHeaders as buildSecurityHeaders } from "./lib/security-headers.mjs";

// NEXT_EXPORT=1 → static export bundled into the Python package (agent-bom api).
// Rewrites require a running Node server so they are disabled in export mode.
const isExport = process.env.NEXT_EXPORT === "1";
// NEXT_PUBLIC_STATIC_DEMO=1 → read-only sample-data export served under a
// sub-path (GitHub Pages /agent-bom/demo); it reads shipped JSON, never an API.
const basePath = process.env.NEXT_PUBLIC_BASE_PATH || undefined;

// Single source of truth for CSP + companion headers lives in
// lib/security-headers.ts. ui/scripts/sync-vercel-headers.mjs regenerates
// ui/vercel.json from the same module so the standalone server (this config)
// and the Vercel static deployment never drift. Tests in
// tests/security-headers.test.ts pin the contract.
const securityHeaders = buildSecurityHeaders();
const headersForNextServer =
  process.env.NODE_ENV === "development"
    ? securityHeaders.map((header) =>
        header.key === "Content-Security-Policy"
          ? { ...header, value: header.value.replace("script-src 'self'", "script-src 'self' 'unsafe-eval'") }
          : header,
      )
    : securityHeaders;

const nextConfig: NextConfig = {
  // Reuse application modules across routes instead of emitting
  // another copy in each page chunk. Keep Next's framework/runtime groups intact.
  webpack(config, { dev, isServer }) {
    if (!dev && !isServer && config.optimization?.splitChunks) {
      config.optimization.splitChunks.cacheGroups.appShared = {
        test: /[\\/]ui[\\/](?:components|hooks|lib)[\\/]/,
        minChunks: 2,
        minSize: 4_000,
        priority: 1,
        reuseExistingChunk: true,
      };
      // Page-lane headers are below appShared's size threshold but occur in
      // ten route chunks. Share their component and metadata once.
      config.optimization.splitChunks.cacheGroups.pageLaneShared = {
        test: /[\\/]ui[\\/](?:components[\\/]page-lane|lib[\\/]page-lanes)\.tsx?$/,
        name: "page-lane",
        minChunks: 2,
        minSize: 0,
        priority: 2,
        reuseExistingChunk: true,
      };
      // The shared pagination bar is likewise below that threshold and was
      // emitted into ten route chunks.
      config.optimization.splitChunks.cacheGroups.paginationShared = {
        test: /[\\/]ui[\\/]components[\\/]pagination-bar\.tsx$/,
        name: "pagination-bar",
        minChunks: 2,
        minSize: 0,
        priority: 2,
        reuseExistingChunk: true,
      };
      // Each icon module is far below the default split size, so routes that
      // share icons would otherwise each carry their own copy.
      config.optimization.splitChunks.cacheGroups.lucideShared = {
        test: /[\\/]node_modules[\\/]lucide-react[\\/]/,
        name: "lucide-icons",
        minChunks: 2,
        minSize: 0,
        priority: 2,
        reuseExistingChunk: true,
      };
    }
    return config;
  },
  ...(basePath && { basePath }),
  images: { unoptimized: true },
  productionBrowserSourceMaps: false,
  // The Python package uses static export, while the standalone Docker image
  // needs a Node server bundle for the separate control-plane UI container.
  output: isExport ? "export" : "standalone",
  // Server-only runtime routing is owned by server/runtime-api-proxy.ts.
  ...(!isExport && {
    async headers() {
      return [{ source: "/:path*", headers: headersForNextServer }];
    },

  }),
};

export default nextConfig;
