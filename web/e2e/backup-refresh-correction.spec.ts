import { expect, test } from "@playwright/test";
import { installReadFixture } from "./api-fixture";

const digest = `sha256:${"a".repeat(64)}`;
function envelope(command: string, data: unknown, code?: string) {
  return { schema: "vegastack-labs.dev/browser-run-result", schemaVersion: "1.0.0", toolVersion: "test", command, runId: null, status: code ? "failed" : "succeeded", changed: false, recoveryEpoch: 2, stateRevision: 8, snapshotDigest: null, releaseBuildId: "test", sourceRevision: null, planId: null, errors: code ? [{ code, target: "backup", retryable: false }] : [], data };
}
for (const code of ["AUTHORIZATION_DENIED", "SESSION_EXPIRED"] as const) {
  test(`Backups ${code} latches denial against a late parallel recovery-point success`, async ({ page }) => {
    await installReadFixture(page);
    let refreshing = false;
    let releaseLate!: () => void;
    let lateStarted!: () => void;
    let lateDelivered!: () => void;
    const lateGate = new Promise<void>(resolve => { releaseLate = resolve; });
    const started = new Promise<void>(resolve => { lateStarted = resolve; });
    const delivered = new Promise<void>(resolve => { lateDelivered = resolve; });
    await page.route("**/api/v1/recovery-points?**", async route => {
      if (!refreshing) return route.fallback();
      lateStarted();
      await lateGate;
      const point = { schema: "vegastack-labs.dev/browser-recovery-point", schemaVersion: "1.0.0", pointId: "late-private-point", sourceKind: "local", proofClass: "live", contentDigest: digest, manifestDigest: digest, createdAt: "2026-09-24T03:00:00Z", verifiedAt: "2026-09-24T03:05:00Z", verificationStatus: "verified", reasonCode: "integrity-verified", recoveryEpoch: 2 };
      try {
        await route.fulfill({ json: envelope("api.v1.recovery-points.list", { schema: "vegastack-labs.dev/browser-recovery-point-list-data", schemaVersion: "1.0.0", items: [point], nextCursor: null, stateRevision: 8, recoveryEpoch: 2 }) });
      } finally { lateDelivered(); }
    });
    await page.route("**/api/v1/backups/status", async route => {
      if (!refreshing) return route.fallback();
      await started;
      await route.fulfill({ status: code === "SESSION_EXPIRED" ? 401 : 403, json: envelope("api.v1.backups.status", {}, code) });
    });
    await page.goto("/backups");
    await expect(page.getByRole("button", { name: "Create inert restore draft", exact: true })).toBeEnabled();
    refreshing = true;
    await page.getByRole("button", { name: "Refresh Backups", exact: true }).click();
    await started;
    await expect(page.locator('[data-read-state="denied"]')).toBeVisible();
    releaseLate();
    await delivered;
    // Give the already delivered response a rendering turn before checking that
    // neither records nor actions can return without an explicit recovery read.
    await page.waitForTimeout(100);
    await expect(page.locator("main")).not.toContainText("late-private-point");
    await expect(page.getByRole("button", { name: "Create inert restore draft", exact: true })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Request Slack approval", exact: true })).toHaveCount(0);
    await expect(page.locator('[data-read-state="denied"]')).toBeVisible();
    await page.unroute("**/api/v1/backups/status");
    await page.unroute("**/api/v1/recovery-points?**");
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    await expect(page.getByRole("button", { name: "Create inert restore draft", exact: true })).toBeEnabled();
    await expect(page.getByText("point-a", { exact: true }).first()).toBeVisible();
  });
}
