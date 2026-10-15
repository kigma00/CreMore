import type { NextConfig } from "next";
import path from "node:path";

const repositoryRoot = path.resolve(__dirname, "..");

const config: NextConfig = {
  output: "standalone",
  outputFileTracingRoot: repositoryRoot,
  turbopack: { root: repositoryRoot },
  poweredByHeader: false,
  // The console lived at /console while it replaced the dashboard; an address kept from then (its query too) still
  // opens the same screen. The dashboard's example page (/demo) is gone: its address opens the console.
  async redirects() {
    return [
      { source: "/console", destination: "/", permanent: false },
      { source: "/demo", destination: "/", permanent: false },
    ];
  },
  // The console serves logos as plain <img> files and never uses next/image,
  // so the optimizer and its sharp/libvips (LGPL) binaries stay out of the image.
  // A "*" key also matches Next's own next-server trace, where sharp enters.
  images: { unoptimized: true },
  outputFileTracingExcludes: {
    "*": ["**/node_modules/sharp/**/*", "**/node_modules/@img/**/*"],
  },
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "no-referrer" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
        ],
      },
    ];
  },
};

export default config;
