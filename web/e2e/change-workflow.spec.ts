import { expect, test, type Page } from "@playwright/test";
import axe from "axe-core";
import { changeFixture, installChangeFixture, privateChangeCanaries, resetChangeFixture } from "./change-api-fixture";

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

async function activateWithKeyboard(page: Page, button: ReturnType<Page["getByRole"]>) {
  await button.focus();
  await expect(button).toBeFocused();
  await page.keyboard.press("Enter");
}

async function expectStateSurface(page: Page) {
  await expectAccessible(page);
  const layout = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }));
  expect(layout.scrollWidth).toBeLessThanOrEqual(layout.clientWidth + 1);
}

async function selectTheme(page: Page, theme: "light" | "dark") {
  const button = page.getByRole("button", { name: /Use (light|dark) theme/ });
  await expect(button).toBeVisible();
  const action = await button.getAttribute("aria-label");
  if ((theme === "light" && action === "Use light theme") || (theme === "dark" && action === "Use dark theme")) {
    await activateWithKeyboard(page, button);
  }
  await expect(page.locator("html")).toHaveClass(new RegExp(`(^| )${theme}( |$)`));
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

test("a lost execute response resolves one durable run without resubmitting", async ({ page }) => {
  changeFixture.dropExecuteResponseOnce = true;
  changeFixture.resolutionDelayMs = 400;
  await page.goto("/changes");
  await page.getByLabel("Declaration ID").fill("declaration-one");
  await page.getByLabel("Revision").fill("1");
  await page.getByRole("button", { name: "Open declaration" }).click();
  await page.getByRole("button", { name: "Generate plan" }).click();
  changeFixture.approval = "approved";
  await page.getByRole("button", { name: "Request Slack approval" }).click();
  await page.getByRole("button", { name: "Start run" }).click();
  await page.getByRole("button", { name: "Start exact run" }).click();

  await expect.poll(() => page.evaluate(() => history.state.vskChangeHandles?.executionKey ?? null)).toMatch(/^console-run-/);
  await expect(page.getByRole("button", { name: "Start run" })).toBeDisabled();
  await expect(page.locator('[data-run-status="running"]')).toBeVisible();
  expect(changeFixture.executeRequests).toBe(1);
  expect(changeFixture.resolutionRequests).toBe(1);
  expect(await page.evaluate(() => history.state.vskChangeHandles)).toEqual({ declarationId: "declaration-one", revision: 1, planId: "plan-one", runId: "run-one" });

  await page.reload();
  await expect(page.locator('[data-run-status="running"]')).toBeVisible();
  expect(changeFixture.executeRequests).toBe(1);
  expect(changeFixture.resolutionRequests).toBe(1);
});

test("pending approval polling survives reload while the plan is still planned", async ({ page }) => {
  await page.goto("/changes");
  await page.getByLabel("Declaration ID").fill("declaration-one");
  await page.getByLabel("Revision").fill("1");
  await page.getByRole("button", { name: "Open declaration" }).click();
  await page.getByRole("button", { name: "Generate plan" }).click();
  await page.getByRole("button", { name: "Request Slack approval" }).click();
  await expect(page.locator('[data-approval-status="pending"]')).toBeVisible();
  expect(changeFixture.approvalRequestPosts).toBe(1);
  const requestsBeforeReload = changeFixture.approvalStatusRequests;
  expect(await page.evaluate(() => history.state.vskChangeHandles.approvalPlanId)).toBe("plan-one");
  await page.reload();
  await expect(page.locator('[data-plan-status="planned"]')).toBeVisible();
  await expect(page.locator('[data-approval-status="pending"]')).toBeVisible();
  expect(changeFixture.approvalStatusRequests).toBeGreaterThan(requestsBeforeReload);
  expect(changeFixture.approvalRequestPosts).toBe(1);
});

test("a cached running response waits for the fresh terminal GET before opening SSE", async ({ page }) => {
  changeFixture.eventMode = "reconnect";
  changeFixture.run = "running";
  changeFixture.runAfterExecute = "succeeded";
  await page.goto("/changes");
  await page.getByLabel("Declaration ID").fill("declaration-one");
  await page.getByLabel("Revision").fill("1");
  await page.getByRole("button", { name: "Open declaration" }).click();
  await page.getByRole("button", { name: "Generate plan" }).click();
  changeFixture.approval = "approved";
  await page.getByRole("button", { name: "Request Slack approval" }).click();
  await page.getByRole("button", { name: "Start run" }).click();
  await page.getByRole("button", { name: "Start exact run" }).click();
  await expect(page.locator('[data-run-status="succeeded"]')).toBeVisible();
  await page.waitForTimeout(250);
  expect(changeFixture.eventConnections).toBe(0);
});

test("a fresh terminal run never opens an SSE watcher", async ({ page }) => {
  for (const state of ["cancelled", "failed", "interrupted", "partial", "succeeded"] as const) {
    resetChangeFixture();
    changeFixture.run = state;
    await page.goto("/changes");
    await page.getByLabel("Declaration ID").fill("declaration-one");
    await page.getByLabel("Revision").fill("1");
    await page.getByRole("button", { name: "Open declaration" }).click();
    await page.getByRole("button", { name: "Generate plan" }).click();
    changeFixture.approval = "approved";
    await page.getByRole("button", { name: "Request Slack approval" }).click();
    await page.getByRole("button", { name: "Start run" }).click();
    await page.getByRole("button", { name: "Start exact run" }).click();
    await expect(page.locator(`[data-run-status="${state}"]`)).toBeVisible();
    await page.waitForTimeout(100);
    expect(changeFixture.eventConnections).toBe(0);
  }
});

test("focus follows an explicit save into the new immutable revision", async ({ page }) => {
  await page.goto("/changes");
  await page.getByLabel("Declaration ID").fill("declaration-one");
  await page.getByLabel("Revision").fill("1");
  await page.getByRole("button", { name: "Open declaration" }).click();
  await page.getByLabel("Reason digest").fill(changeFixture.reasonDigest);
  await page.getByRole("button", { name: "Save declaration" }).click();
  await expect(page.getByText("Draft revision 2", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Reason digest")).toBeFocused();
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

test("every change state preserves keyboard focus, accessibility, themes, mobile layout, and 200% reflow", async ({ page }) => {
  test.setTimeout(120_000);
  const approvalStates = [
    { state: "pending", label: "Pending", authorization: "Authorization is not current" },
    { state: "rejected", label: "Rejected", authorization: "Authorization is not current" },
    { state: "expired", label: "Expired", authorization: "Authorization is not current" },
    { state: "approved", label: "Approved", authorization: "Authorization is current" },
  ] as const;
  const runStates = [
    { state: "queued", label: "Queued", next: "inspect or cancel through the server" },
    { state: "running", label: "Running", next: "inspect or cancel through the server" },
    { state: "partial", label: "Partial", next: "recovery required; inspect the durable run" },
    { state: "failed", label: "Failed", next: "inspect the durable run" },
    { state: "cancelled", label: "Cancelled", next: "inspect the durable run" },
    { state: "interrupted", label: "Interrupted", next: "inspect, then resume or cancel through the server" },
    { state: "succeeded", label: "Succeeded", next: "none; execution completed" },
  ] as const;
  const themes = ["light", "dark"] as const;
  const viewports = [
    { name: "desktop", width: 1280, height: 800, zoom: 1 },
    { name: "mobile", width: 320, height: 800, zoom: 1 },
    { name: "390px-200%-reflow", width: 390, height: 844, zoom: 2 },
  ] as const;

  for (const theme of themes) {
    for (const viewport of viewports) {
      resetChangeFixture();
      await page.setViewportSize({ width: viewport.width, height: viewport.height });
      await page.goto("/changes");
      await page.evaluate(zoom => { document.documentElement.style.zoom = String(zoom); }, viewport.zoom);
      await selectTheme(page, theme);
      if (viewport.name === "390px-200%-reflow") {
        expect(page.viewportSize()?.width).toBe(390);
        expect(await page.evaluate(() => document.documentElement.style.zoom)).toBe("2");
      }

      // empty
      const empty = page.locator('[data-read-state="empty"]');
      await expect(empty.getByRole("status")).toContainText("No declaration open");
      await expect(empty.getByText("No declaration open", { exact: true })).toBeVisible();
      await page.getByLabel("Declaration ID").focus();
      await expect(page.getByLabel("Declaration ID")).toBeFocused();
      await expectStateSurface(page);

      // loading
      changeFixture.declarationDelayMs = 150;
      await page.getByLabel("Declaration ID").fill("declaration-one");
      await page.getByLabel("Revision").fill("1");
      const open = page.getByRole("button", { name: "Open declaration" });
      await activateWithKeyboard(page, open);
      const loading = page.locator('[data-read-state="loading"]');
      await expect(loading.getByRole("status")).toContainText("Loading declaration");
      await expect(loading.getByText("Loading declaration", { exact: true })).toBeVisible();
      await expect(open).toBeFocused();
      await expectStateSurface(page);
      await expect(page.getByText("Draft revision 1", { exact: true })).toBeVisible();
      changeFixture.declarationDelayMs = 0;

      await activateWithKeyboard(page, page.getByRole("button", { name: "Generate plan" }));
      await activateWithKeyboard(page, page.getByRole("button", { name: "Request Slack approval" }));
      for (const expected of approvalStates) {
        changeFixture.approval = expected.state;
        const refresh = page.getByRole("button", { name: "Refresh approval status" });
        await activateWithKeyboard(page, refresh);
        const approval = page.locator(`[data-approval-status="${expected.state}"]`);
        await expect(approval.getByRole("status")).toContainText(expected.label);
        await expect(approval.getByRole("status")).toContainText(expected.authorization);
        await expect(approval.getByText(expected.label, { exact: true })).toBeVisible();
        await expect(refresh).toBeFocused();
        await expectStateSurface(page);
      }

      const start = page.getByRole("button", { name: "Start run" });
      await activateWithKeyboard(page, start);
      const startDialog = page.getByRole("alertdialog");
      await expect(startDialog).toBeVisible();
      await expect(startDialog.locator(":focus")).toHaveCount(1);
      await page.keyboard.press("Escape");
      await expect(start).toBeFocused();
      await activateWithKeyboard(page, start);
      await activateWithKeyboard(page, page.getByRole("button", { name: "Start exact run" }));

      for (const expected of runStates) {
        changeFixture.run = expected.state;
        const refresh = page.getByRole("button", { name: "Refresh run" });
        await activateWithKeyboard(page, refresh);
        const run = page.locator(`[data-run-status="${expected.state}"]`);
        await expect(run.getByRole("status").first()).toContainText(expected.label);
        await expect(run.getByText(expected.label, { exact: true }).first()).toBeVisible();
        await expect(run.getByText(expected.next, { exact: true })).toBeVisible();
        await expect(refresh).toBeFocused();
        if (expected.state === "partial") {
          await expect(run.getByRole("status").first()).toContainText("Recovery required");
          await expect(run.getByText("Recovery required", { exact: true })).toBeVisible();
        }
        await expectStateSurface(page);
      }

      // stale retains the last authorized run without claiming it is current.
      changeFixture.run = "running";
      await activateWithKeyboard(page, page.getByRole("button", { name: "Refresh run" }));
      changeFixture.retryableFailurePath = "/api/v1/runs/run-one";
      await activateWithKeyboard(page, page.getByRole("button", { name: "Refresh run" }));
      const stale = page.locator('[data-read-state="stale"]');
      await expect(stale.getByRole("status")).toContainText("Showing last known run state");
      await expect(stale.getByText("Showing last known run state", { exact: true })).toBeVisible();
      await expectStateSurface(page);
      changeFixture.retryableFailurePath = null;

      // denied clears all mounted projections and protected handles.
      changeFixture.hardFailurePath = "/api/v1/runs/run-one";
      await activateWithKeyboard(page, page.getByRole("button", { name: "Refresh run" }));
      const denied = page.locator('[data-read-state="denied"]');
      await expect(denied.getByRole("alert")).toContainText("Change details cleared");
      await expect(denied.getByText("Change details cleared", { exact: true })).toBeVisible();
      await expect(page.locator("[data-run-status], [data-plan-status], [data-approval-status]")).toHaveCount(0);
      await page.getByLabel("Declaration ID").focus();
      await expect(page.getByLabel("Declaration ID")).toBeFocused();
      await expectStateSurface(page);
    }
  }
});
