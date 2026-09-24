import { expect, test } from "@playwright/test";
import { fixtureAudit, fixtureState, installReadFixture, phase5ProtectedEffectPaths } from "./api-fixture";
import {
  assertPrivacyEvidence,
  captureVisibleBrowserEvidence,
  phase5PrivateCanaries,
} from "./browser-privacy-proof.mjs";

test.beforeEach(async ({ page }) => installReadFixture(page));

test("Phase 5 acceptance keeps protected recovery authority out of the browser", async ({ page }) => {
  fixtureState.mode = "recovery-required";
  const statusResponse = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/v1/backups/status");
  await page.goto("/backups");
  const response = await statusResponse;
  console.log("[DEBUG-7a2c] acceptance status", await response.text());
  console.log("[DEBUG-7a2c] acceptance body", await page.locator("body").innerText());

  await expect(page.getByText("Recovery required", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Create inert restore draft" })).toBeDisabled();
  await expect(page.getByRole("button", { name: /force|run restore|delete|reveal|start run/i })).toHaveCount(0);

  const denials = await page.evaluate(async (paths) => Promise.all(paths.map(async (path) => {
    const response = await fetch(path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
      credentials: "same-origin",
    });
    const result = await response.json();
    return { path, status: response.status, code: result.errors?.[0]?.code ?? null };
  })), phase5ProtectedEffectPaths);
  expect(denials).toEqual(phase5ProtectedEffectPaths.map((path) => ({
    path,
    status: 403,
    code: "AUTHORIZATION_DENIED",
  })));
  const requested = fixtureAudit.requests.map((value) => new URL(value).pathname);
  for (const protectedPath of phase5ProtectedEffectPaths) expect(requested).toContain(protectedPath);
});

test("Phase 5 acceptance artifacts contain no private or secret material", async ({ page }) => {
  const consoleMessages: string[] = [];
  page.on("console", (message) => consoleMessages.push(message.text()));
  await page.goto("/audit");
  await expect(page.getByRole("heading", { name: "Independent verification" })).toBeVisible();

  const evidence = await captureVisibleBrowserEvidence(page, consoleMessages);
  assertPrivacyEvidence(evidence, phase5PrivateCanaries, "Phase 5 browser evidence");
  assertPrivacyEvidence(fixtureAudit.responses, phase5PrivateCanaries, "Phase 5 response evidence");
});
