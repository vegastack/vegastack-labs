import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  generateBuildId: async () => "vegastack-console-v1",
  images: {
    unoptimized: true,
  },
  output: "export",
  poweredByHeader: false,
  reactStrictMode: true,
};

export default nextConfig;
