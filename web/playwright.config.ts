import { defineConfig, devices } from "@playwright/test";

const phase3Output = process.env.VSK_PHASE3_PLAYWRIGHT_OUTPUT;

export default defineConfig({
  testDir: "./e2e",
  outputDir: phase3Output || "./test-results",
  reporter: "line",
  use: { baseURL: "http://127.0.0.1:4173", trace: phase3Output ? "off" : "retain-on-failure", screenshot: phase3Output ? "off" : "only-on-failure" },
  webServer: { command: "pnpm preview", url: "http://127.0.0.1:4173", reuseExistingServer: false, timeout: 30_000 },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
