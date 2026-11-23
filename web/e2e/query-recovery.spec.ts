import { expect, test } from "@playwright/test";
import { installReadFixture } from "./api-fixture";

function envelope(command: string, data: unknown, code?: string) {
  return { schema: "vegastack-labs.dev/browser-run-result", schemaVersion: "1.0.0", toolVersion: "test", command, runId: null, status: code ? "failed" : "succeeded", changed: false, recoveryEpoch: 2, stateRevision: 8, snapshotDigest: null, releaseBuildId: "test", sourceRevision: null, planId: null, errors: code ? [{ code, target: "recovery-read", retryable: false }] : [], data };
}

test("Nodes explicitly recovers a cleared registered-host query after initial session failure", async ({ page }) => {
  await installReadFixture(page);
  let authorized = false;
  let calls = 0;
  let hostStarted!: () => void;
  const started = new Promise<void>(resolve => { hostStarted = resolve; });
  let releaseLate!: () => void;
  const lateGate = new Promise<void>(resolve => { releaseLate = resolve; });
  let delivered!: () => void;
  const lateDelivered = new Promise<void>(resolve => { delivered = resolve; });
  const hostList = () => envelope("api.v1.hosts.list", { schema: "vegastack-labs.dev/managed-host-list", schemaVersion: "1.0.0", hosts: [], stateRevision: 8, recoveryEpoch: 2 });
  await page.route("**/api/v1/hosts", async route => {
    calls++;
    if (authorized) return route.fulfill({ json: hostList() });
    hostStarted();
    await lateGate;
    try { await route.fulfill({ json: hostList() }); }
    finally { delivered(); }
  });
  await page.route("**/api/v1/inventory-drafts?**", async route => {
    if (authorized) return route.fallback();
    await started;
    await route.fulfill({ status: 401, json: envelope("api.v1.inventory-drafts.list", {}, "SESSION_EXPIRED") });
  });
  await page.goto("/nodes");
  await expect(page.getByText("Host workflow unavailable", { exact: true })).toBeVisible();
  releaseLate();
  await lateDelivered;
  expect(calls).toBe(1); // Denial must not trigger automatic retries.
  authorized = true;
  await page.getByRole("button", { name: "Refresh", exact: true }).first().click();
  await expect(page.getByText("No registered hosts are visible to your account.", { exact: true })).toBeVisible();
  await expect(page.getByText("Loading registered hosts…", { exact: true })).toHaveCount(0);
  expect(calls).toBe(2);
});

test("History checks cancels late private data and lets an explicit refresh recover parallel reads", async ({ page }) => {
  await installReadFixture(page);
  let recovering = false;
  let checkpointStarted!: () => void;
  const started = new Promise<void>(resolve => { checkpointStarted = resolve; });
  let releaseLate!: () => void;
  const lateGate = new Promise<void>(resolve => { releaseLate = resolve; });
  let delivered!: () => void;
  const lateDelivered = new Promise<void>(resolve => { delivered = resolve; });
  let checkpointCalls = 0;
  let verificationCalls = 0;
  await page.route("**/api/v1/audit-checkpoints?**", async route => {
    checkpointCalls++;
    if (recovering) return route.fallback();
    checkpointStarted();
    await lateGate;
    const checkpoint = { schema: "vegastack-labs.dev/browser-audit-checkpoint", schemaVersion: "1.0.0", checkpointId: "late-private-checkpoint", firstEventId: 1, lastEventId: 4, chainDigest: `sha256:${"a".repeat(64)}`, status: "anchored", reasonCode: "independent-match", sourceKind: "independent", proofClass: "live", verifiedAt: "2026-09-24T03:05:00Z", verificationStatus: "verified", recoveryEpoch: 2 };
    try { await route.fulfill({ json: envelope("api.v1.audit-checkpoints.list", { schema: "vegastack-labs.dev/browser-audit-checkpoint-list-data", schemaVersion: "1.0.0", items: [checkpoint], nextCursor: null, stateRevision: 8, recoveryEpoch: 2 }) }); }
    finally { delivered(); }
  });
  await page.route("**/api/v1/audit-history/verification", async route => {
    verificationCalls++;
    if (recovering) return route.fallback();
    await started;
    await route.fulfill({ status: 401, json: envelope("api.v1.audit-history.verification", {}, "SESSION_EXPIRED") });
  });
  await page.goto("/audit");
  await expect(page.getByText("History verification unavailable", { exact: true })).toBeVisible();
  releaseLate();
  await lateDelivered;
  // Let the delivered response finish rendering before asserting it stays cleared.
  await page.waitForTimeout(100);
  await expect(page.locator("main")).not.toContainText("late-private-checkpoint");
  expect(verificationCalls).toBe(1);
  expect(checkpointCalls).toBe(1);
  const refresh = page.getByRole("button", { name: "Refresh History Checks", exact: true });
  await expect(refresh).toBeEnabled();
  recovering = true;
  await refresh.click();
  await expect(page.getByText("checkpoint-a", { exact: true })).toBeVisible();
  await expect(page.getByText("History verified", { exact: true })).toBeVisible();
  await expect(page.getByText("Loading audit checkpoints", { exact: true })).toHaveCount(0);
  await expect(page.locator("main")).not.toContainText("late-private-checkpoint");
  expect(verificationCalls).toBe(2);
  expect(checkpointCalls).toBe(2);
});
