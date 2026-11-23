import { expect, test } from "@playwright/test";
import { fixtureAudit, installReadFixture } from "./api-fixture";

const failure = (code: string) => ({ schema: "vegastack-labs.dev/browser-run-result", schemaVersion: "1.0.0", toolVersion: "test", command: "api.v1.restores.list", runId: null, status: "failed", changed: false, recoveryEpoch: 2, stateRevision: 8, snapshotDigest: null, releaseBuildId: "test", sourceRevision: null, planId: null, errors: [{ code, target: "read", retryable: false }], data: {} });

test("a denied restore list explains access without retaining backup actions", async ({ page }, info) => {
  await installReadFixture(page);
  await page.route("**/api/v1/restore-plans?**", route => route.fulfill({ status: 403, json: failure("AUTHORIZATION_DENIED") }));
  await page.goto("/backups");
  await expect(page.getByText("Backup access is limited", { exact: true })).toBeVisible();
  await expect(page.getByText(/Ask a Labs administrator to check your backup and restore viewing permissions/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Prepare restore", exact: true })).toHaveCount(0);
  await expect(page.locator("main")).not.toContainText("point-a");
  expect(fixtureAudit.requests.every(url => !url.includes("/restore-drafts"))).toBeTruthy();
  await page.screenshot({ path: info.outputPath("backups-access-guidance.png"), fullPage: true });
});

test("invalid backup information is distinguished from missing permissions", async ({ page }) => {
  await installReadFixture(page);
  await page.route("**/api/v1/restore-plans?**", route => route.fulfill({ status: 200, contentType: "application/json", body: "{invalid" }));
  await page.goto("/backups");
  await expect(page.getByText("Backup information could not be verified", { exact: true })).toBeVisible();
  await expect(page.getByText("Backup access is limited", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Prepare restore", exact: true })).toHaveCount(0);
});

test("readiness cards have understandable names and retain exact references in details", async ({ page }, info) => {
  await installReadFixture(page);
  await page.goto("/gates");
  await expect(page.getByText("Backup storage and recovery", { exact: true })).toBeVisible();
  await expect(page.getByText("Chaabi production migration", { exact: true })).toBeVisible();
  await expect(page.getByText("Check reference: G-008", { exact: true })).toBeHidden();
  await page.locator('[data-gate-outcome="blocked"] > div').first().locator('..').locator('summary').filter({hasText: /^Technical details$/}).last().click();
  await expect(page.getByText("Check reference: G-008", { exact: true })).toBeVisible();
  await expect(page.getByText("Results last reviewed / valid for", { exact: true }).first()).toBeVisible();
  await page.screenshot({ path: info.outputPath("readiness-check-guidance.png"), fullPage: true });
});
