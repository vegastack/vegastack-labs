import { expect, test } from "@playwright/test";
import { fixtureAudit, fixtureState, installReadFixture } from "./api-fixture";
import { phase5PrivateCanaries } from "./browser-privacy-proof.mjs";

test.beforeEach(async ({ page }) => installReadFixture(page));

test("Phase 5 recovery shows sanitized reads and creates only an inert restore draft", async ({ page }) => {
  await page.goto("/backups");
  await expect(page.getByRole("heading", { name: "Backup status", exact: true })).toBeVisible();
  await expect(page.getByText("point-a", { exact: true }).first()).toBeVisible();
  await expect(page.getByRole("heading", { name: "Restore status" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Scheduled jobs" })).toBeVisible();
  await page.getByRole("button", { name: "Create inert restore draft" }).click();
  await expect(page.getByRole("status").filter({ hasText: "draft-restore-a" })).toContainText("Continue through the plan flow");
  const requests = fixtureAudit.requests.map((value) => new URL(value).pathname);
  expect(requests).toContain("/api/v1/recovery-points/point-a/restore-drafts");
  for (const protectedPath of ["/api/v1/backup-policies/policy-a/jobs", "/api/v1/restore-plans/plan-a/runs", "/api/v1/database/exports"]) expect(requests).not.toContain(protectedPath);
});

test("Phase 5 recovery-required and audit incident states disable ordinary mutations", async ({ page }) => {
  fixtureState.mode = "recovery-required";
  await page.goto("/backups");
  await expect(page.getByText("Recovery required", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Create inert restore draft" })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Start run" })).toHaveCount(0);
  await page.goto("/audit");
  await expect(page.getByText("Audit incident", { exact: true })).toBeVisible();
  await expect(page.getByText("follow the audit continuity runbook", { exact: true })).toBeVisible();
});

test("Phase 5 Audit separates checkpoints from independent verification", async ({ page }) => {
  await page.goto("/audit");
  await expect(page.getByRole("heading", { name: "Independent verification" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Audit checkpoints", exact: true })).toBeVisible();
  await expect(page.getByText("checkpoint-a", { exact: true })).toBeVisible();
  const exposed = [await page.locator("body").innerText(), JSON.stringify(fixtureAudit.responses)].join("\n");
  for (const canary of [...phase5PrivateCanaries, "humanAcknowledgementId", "formerControllerFenceDigest", "signerReferenceId"]) expect(exposed).not.toContain(canary);
});

test("Phase 5 pages retain a useful no-JavaScript fallback", async ({ browser }) => {
  const context = await browser.newContext({ javaScriptEnabled: false });
  const page = await context.newPage();
  for (const [route, command] of [["/gates", "vsk-labs gate list"], ["/backups", "vsk-labs backup status"], ["/audit", "vsk-labs audit checkpoints"]] as const) {
    const response = await page.goto(route);
    expect(response).not.toBeNull();
    const html = await response!.text();
    const fallbacks = [...html.matchAll(/<noscript(?:\s[^>]*)?>([\s\S]*?)<\/noscript>/gi)].map((match) => match[1]);
    expect(fallbacks.some((fallback) => fallback?.includes(command))).toBeTruthy();
  }
  await context.close();
});
