import { expect, test, type Page } from "@playwright/test";
import axe from "axe-core";
import { changeFixture, installChangeFixture, privateChangeCanaries } from "./change-api-fixture";

test.describe.configure({ mode: "serial" });
test.beforeEach(async ({ page }) => installChangeFixture(page));

async function expectAccessible(page: Page) {
  await page.evaluate(axe.source);
  const violations = await page.evaluate(async () => {
    const runtime = (globalThis as unknown as { axe: { run: (root: Document) => Promise<{ violations: Array<{ impact: string | null; id: string }> }> } }).axe;
    return (await runtime.run(document)).violations.filter(({ impact }) => impact === "serious" || impact === "critical").map(({ id }) => id);
  });
  expect(violations).toEqual([]);
}

test("declaration save, plan review, approval observation, and durable run stay server-owned", async ({ page }) => {
  await page.goto("/changes");
  await page.getByLabel("Declaration ID").fill("declaration-one");
  await page.getByLabel("Revision").fill("1");
  await page.getByRole("button", { name: "Open declaration" }).click();
  await expect(page.getByText("Draft revision 1", { exact: true })).toBeVisible();

  await page.getByLabel("Reason digest").fill(changeFixture.reasonDigest);
  await page.getByLabel("Reason digest").blur();
  expect(changeFixture.requestBodies).toEqual([]);
  await page.getByRole("button", { name: "Save declaration" }).click();
  await expect(page.getByText("Draft revision 2", { exact: true })).toBeVisible();
  expect(JSON.parse(changeFixture.requestBodies.at(-1) ?? "{}").expectedRevision).toBe(2);
  await page.getByRole("button", { name: "Generate plan" }).click();
  await expect(page.getByText(changeFixture.planDigest, { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: /approve/i })).toHaveCount(0);

  await page.getByRole("button", { name: "Request Slack approval" }).click();
  await expect(page.getByText("Pending", { exact: true })).toBeVisible();
  changeFixture.approval = "approved";
  await page.getByRole("button", { name: "Refresh approval status" }).click();
  await expect(page.getByText("Approved", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Start run" }).click();
  await page.getByRole("button", { name: "Start exact run" }).click();
  await expect(page.locator('[data-run-status="running"]').getByText("Running", { exact: true }).first()).toBeVisible();

  changeFixture.run = "interrupted";
  await page.dispatchEvent("body", "online");
  await expect(page.locator('[data-run-status="interrupted"]').getByText("Interrupted", { exact: true }).first()).toBeVisible();
  expect(changeFixture.executeRequests).toBe(1);
  await page.getByRole("button", { name: "Resume run" }).click();
  await page.getByRole("button", { name: "Resume exact run" }).click();
  await expect(page.locator('[data-run-status="running"]')).toBeVisible();
  await page.getByRole("button", { name: "Cancel run" }).click();
  await page.getByRole("button", { name: "Request cancel" }).click();
  await expect(page.locator('[data-run-status="cancelled"]')).toBeVisible();
  expect(changeFixture.requestPaths.every(path => !/provider|sqlite|acknowledgements/i.test(path))).toBeTruthy();
  await expectAccessible(page);
});

test("save cancels the old revision read and mounts the exact returned revision", async ({ page }) => {
  await page.goto("/changes");
  await page.getByLabel("Declaration ID").fill("declaration-one");
  await page.getByLabel("Revision").fill("1");
  await page.getByRole("button", { name: "Open declaration" }).click();
  await expect(page.getByText("Draft revision 1", { exact: true })).toBeVisible();
  const revisionOneReads = changeFixture.requestPaths.filter(path => path === "/api/v1/declarations/declaration-one/revisions/1").length;

  await page.getByLabel("Reason digest").fill(changeFixture.reasonDigest);
  await page.getByRole("button", { name: "Save declaration" }).click();
  await expect(page.getByText("Draft revision 2", { exact: true })).toBeVisible();
  expect(changeFixture.requestPaths.filter(path => path === "/api/v1/declarations/declaration-one/revisions/1")).toHaveLength(revisionOneReads);
  await expect(page.getByText("Change details cleared", { exact: true })).toHaveCount(0);
});

test("refresh restores the exact durable plan and run without resubmitting", async ({ page }) => {
  await page.goto("/changes");
  await page.getByLabel("Declaration ID").fill("declaration-one");
  await page.getByLabel("Revision").fill("1");
  await page.getByRole("button", { name: "Open declaration" }).click();
  await page.getByRole("button", { name: "Generate plan" }).click();
  await page.getByRole("button", { name: "Request Slack approval" }).click();
  changeFixture.approval = "approved";
  await page.getByRole("button", { name: "Refresh approval status" }).click();
  await page.getByRole("button", { name: "Start run" }).click();
  await page.getByRole("button", { name: "Start exact run" }).click();
  await expect(page.locator('[data-run-status="running"]')).toBeVisible();
  const beforeReload = changeFixture.executeRequests;
  const safeHandles = await page.evaluate(() => history.state.vskChangeHandles);
  expect(safeHandles).toEqual({ declarationId: "declaration-one", revision: 1, planId: "plan-one", runId: "run-one" });

  await page.reload();
  await expect(page.getByText(changeFixture.planDigest, { exact: true })).toBeVisible();
  await expect(page.locator('[data-run-status="running"]')).toBeVisible();
  expect(changeFixture.executeRequests).toBe(beforeReload);
  expect(await page.evaluate(() => ({ local: { ...localStorage }, session: { ...sessionStorage }, search: location.search, hash: location.hash }))).toEqual({ local: {}, session: {}, search: "", hash: "" });
});

test("approval expiry and a final server recheck fail closed", async ({ page }) => {
  const now = Date.now();
  await page.clock.install({ time: now });
  await page.goto("/changes");
  await page.getByLabel("Declaration ID").fill("declaration-one");
  await page.getByLabel("Revision").fill("1");
  await page.getByRole("button", { name: "Open declaration" }).click();
  await page.getByRole("button", { name: "Generate plan" }).click();
  await expect(page.getByText(changeFixture.planDigest, { exact: true })).toBeVisible();
  changeFixture.approval = "approved";
  changeFixture.approvalExpiresAt = new Date(now + 60_000).toISOString().replace(/\.\d{3}Z$/, "Z");
  await page.getByRole("button", { name: "Request Slack approval" }).click();
  await expect(page.getByRole("button", { name: "Start run" })).toBeEnabled();
  await page.clock.fastForward(60_001);
  await expect(page.getByRole("button", { name: "Start run" })).toBeDisabled();

  changeFixture.approvalExpiresAt = new Date(now + 120_000).toISOString().replace(/\.\d{3}Z$/, "Z");
  await page.getByRole("button", { name: "Refresh approval status" }).click();
  await page.getByRole("button", { name: "Start run" }).click();
  changeFixture.approval = "expired";
  await page.getByRole("button", { name: "Start exact run" }).click();
  await expect(page.getByRole("button", { name: "Start run" })).toBeDisabled();
  expect(changeFixture.approvalStatusRequests).toBeGreaterThanOrEqual(3);
  expect(changeFixture.executeRequests).toBe(0);
});

test("SSE reconnect carries the last event and re-reads without resubmitting", async ({ page }) => {
  changeFixture.eventMode = "reconnect";
  await page.goto("/changes");
  await page.getByLabel("Declaration ID").fill("declaration-one");
  await page.getByLabel("Revision").fill("1");
  await page.getByRole("button", { name: "Open declaration" }).click();
  await page.getByRole("button", { name: "Generate plan" }).click();
  changeFixture.approval = "approved";
  await page.getByRole("button", { name: "Request Slack approval" }).click();
  await page.getByRole("button", { name: "Start run" }).click();
  await page.getByRole("button", { name: "Start exact run" }).click();
  await expect(page.locator('[data-run-status="interrupted"]')).toBeVisible({ timeout: 5_000 });
  expect(changeFixture.eventConnections).toBeGreaterThanOrEqual(2);
  expect(changeFixture.eventLastIds.slice(0, 2)).toEqual(["", "1"]);
  expect(changeFixture.executeRequests).toBe(1);
});

test("authorization loss clears every mounted change projection", async ({ page }) => {
  await page.goto("/changes");
  await page.getByLabel("Declaration ID").fill("declaration-one");
  await page.getByLabel("Revision").fill("1");
  await page.getByRole("button", { name: "Open declaration" }).click();
  await page.getByRole("button", { name: "Generate plan" }).click();
  changeFixture.approval = "approved";
  await page.getByRole("button", { name: "Request Slack approval" }).click();
  await page.getByRole("button", { name: "Start run" }).click();
  await page.getByRole("button", { name: "Start exact run" }).click();
  await expect(page.locator('[data-run-status="running"]')).toBeVisible();
  changeFixture.hardFailurePath = "/api/v1/runs/run-one";
  await page.getByRole("button", { name: "Refresh run" }).click();
  await expect(page.getByText("Change details cleared", { exact: true })).toBeVisible();
  await expect(page.locator("[data-run-status]")).toHaveCount(0);
  await expect(page.locator("[data-plan-status]")).toHaveCount(0);
  await expect(page.getByText(/Draft revision/)).toHaveCount(0);
  expect(await page.evaluate(() => history.state.vskChangeHandles)).toBeUndefined();
});

test("stale authorization is disabled and private fields never reach browser-visible state", async ({ page }) => {
  changeFixture.approval = "expired";
  await page.goto("/changes");
  await page.getByLabel("Declaration ID").fill("declaration-one");
  await page.getByLabel("Revision").fill("1");
  await page.getByRole("button", { name: "Open declaration" }).click();
  await page.getByRole("button", { name: "Generate plan" }).click();
  await page.getByRole("button", { name: "Request Slack approval" }).click();
  await expect(page.getByRole("button", { name: "Start run" })).toBeDisabled();
  const visible = [await page.locator("body").innerText(), page.url(), JSON.stringify(await page.evaluate(() => ({ local: { ...localStorage }, session: { ...sessionStorage } }))), changeFixture.requestBodies.join("\n")].join("\n");
  for (const canary of privateChangeCanaries) expect(visible).not.toContain(canary);
});

test("approval and durable run state matrix is textual, accessible, and responsive", async ({ page }) => {
  await page.goto("/changes");
  await page.getByLabel("Declaration ID").fill("declaration-one");
  await page.getByLabel("Revision").fill("1");
  await page.getByRole("button", { name: "Open declaration" }).click();
  await page.getByRole("button", { name: "Generate plan" }).click();
  await page.getByRole("button", { name: "Request Slack approval" }).click();
  for (const state of ["pending", "rejected", "expired", "approved"] as const) {
    changeFixture.approval = state;
    await page.getByRole("button", { name: "Refresh approval status" }).click();
    await expect(page.locator(`[data-approval-status="${state}"]`)).toBeVisible();
  }
  await page.getByRole("button", { name: "Start run" }).click();
  await page.getByRole("button", { name: "Start exact run" }).click();
  for (const state of ["queued", "running", "partial", "failed", "cancelled", "interrupted", "succeeded"] as const) {
    changeFixture.run = state;
    await page.getByRole("button", { name: "Refresh run" }).click();
    await expect(page.locator(`[data-run-status="${state}"]`)).toBeVisible();
  }
  await page.setViewportSize({ width: 390, height: 844 });
  await page.evaluate(() => { document.documentElement.style.zoom = "2"; });
  await expect(page.locator("main")).toBeVisible();
  await expectAccessible(page);
});
