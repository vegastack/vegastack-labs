import { expect, test } from "@playwright/test";
import { fixtureAudit, fixtureState, installReadFixture } from "./api-fixture";
import {
  assertPrivacyEvidence,
  captureVisibleBrowserEvidence,
  phase5PrivateCanaries,
} from "./browser-privacy-proof.mjs";

test.beforeEach(async ({ page }) => installReadFixture(page));

test("Phase 5 acceptance keeps protected recovery authority out of the browser", async ({ page }) => {
  fixtureState.mode = "recovery-required";
  await page.goto("/backups");

  await expect(page.getByText("Recovery required", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Create inert restore draft" })).toBeDisabled();
  await expect(page.getByRole("button", { name: /force|run restore|delete|reveal|start run/i })).toHaveCount(0);

  const requested = fixtureAudit.requests.map((value) => new URL(value).pathname);
  for (const protectedPath of [
    "/api/v1/backup-policies/policy-a/jobs",
    "/api/v1/recovery-points/point-a/verifications",
    "/api/v1/restore-plans/plan-a/runs",
    "/api/v1/database/exports",
    "/api/v1/scheduled-job-policies/policy-a/occurrences",
  ]) expect(requested).not.toContain(protectedPath);
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
