import { expect, test } from "@playwright/test";
import { fixtureState, installReadFixture } from "./api-fixture";

test.beforeEach(async ({ page }) => installReadFixture(page));

test("Overview keeps retryable stale data but hides it after denial", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByText("State revision 8", { exact: false })).toBeVisible();
  fixtureState.mode = "dependency";
  await page.getByRole("button", { name: "Refresh Overview" }).click();
  await expect(page.getByRole("status")).toContainText(/showing last known/i);
  fixtureState.mode = "denied";
  await page.getByRole("button", { name: "Refresh Overview" }).click();
  await expect(page.locator('[data-read-state="denied"]')).toContainText(/access denied/i);
  await expect(page.locator("[data-overview-records]")).toHaveCount(0);
});

test("Nodes loads separate collections and restores focus after details", async ({ page }) => {
  await page.goto("/nodes");
  await expect(page.getByText("node-one")).toBeVisible();
  await expect(page.getByText("alias-one")).toBeVisible();
  const trigger = page.getByRole("button", { name: "View node" });
  await trigger.click();
  await expect(page.getByText("assetId")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(trigger).toBeFocused();
  expect(page.url()).not.toContain("draft-one");
});

test("Gates reports capability only and offers no mutation control", async ({ page }) => {
  await page.goto("/gates");
  await expect(page.getByText(/gate evaluation is not implemented/i)).toBeVisible();
  await expect(page.getByRole("button", { name: /pass|approve|apply/i })).toHaveCount(0);
});

test("empty, loading, mobile, and privacy states remain explicit", async ({ page }) => {
  fixtureState.delay = 250;
  await page.goto("/nodes");
  await expect(page.getByText("Loading Nodes")).toBeVisible();
  fixtureState.delay = 0; fixtureState.mode = "empty";
  await page.reload();
  await expect(page.getByText("No inventory draft")).toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.getByRole("heading", { name: "Nodes" })).toBeVisible();
  const body = await page.locator("body").innerText();
  expect(body).not.toContain("private-canary");
  expect(page.url()).not.toContain("cursor");
  const storage = await page.evaluate(() => ({ local: Object.keys(localStorage), session: Object.keys(sessionStorage) }));
  expect(storage.local.every(key => key === "theme")).toBeTruthy();
  expect(storage.session).toEqual([]);
});
