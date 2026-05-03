import type { NextConfig } from "next";

const apiTarget = process.env.AI_RECON_API_URL ?? "http://localhost:8000";

const config: NextConfig = {
  reactStrictMode: true,
  async rewrites() {
    return [
      { source: "/api/:path*", destination: `${apiTarget}/api/:path*` },
      { source: "/ws/:path*", destination: `${apiTarget}/ws/:path*` },
    ];
  },
};

export default config;
