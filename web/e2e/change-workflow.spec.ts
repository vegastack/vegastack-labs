import { expect, test, type Page } from "@playwright/test";
import axe from "axe-core";
import { changeFixture, installChangeFixture, privateChangeCanaries } from "./change-api-fixture";

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
