import { expect, test } from "@playwright/test";
import { fixtureState, installReadFixture } from "./api-fixture";

test.beforeEach(async ({ page }) => installReadFixture(page));

for (const [route, populated, button, empty] of [
  ["/gates", "G-008", "Refresh Gates", "No gates in this read scope"],
  ["/backups", "point-a", "Refresh Backups", "No recovery points"],
  ["/audit", "checkpoint-a", "Refresh Audit", "No audit checkpoints"],
] as const) {
  test(`${button} updates successful visible records`, async ({ page }) => {
    await page.goto(route);
    await expect(page.getByText(populated, { exact: true }).first()).toBeVisible();
    await expect(page.getByRole("button", { name: button, exact: true })).toBeEnabled();
    fixtureState.mode = "empty";
    await page.getByRole("button", { name: button, exact: true }).click();
    await expect(page.getByText(empty, { exact: true })).toBeVisible();
    const records = route === "/backups" ? page.locator("section[aria-labelledby=\"recovery-points-title\"]") : page.locator("main");
    await expect(records.getByText(populated, { exact: true })).toHaveCount(0);
    fixtureState.mode = "healthy";
    await page.getByRole("button", { name: button, exact: true }).click();
    await expect(page.getByText(populated, { exact: true }).first()).toBeVisible();
  });
}

test("Refresh Audit updates verification as well as checkpoints", async ({ page }) => {
  await page.goto("/audit");
  await expect(page.getByText("checkpoint-a", { exact: true })).toBeVisible();
  await expect(page.getByText("independent-match", { exact: true }).first()).toBeVisible();
  fixtureState.mode = "recovery-required";
  await page.getByRole("button", { name: "Refresh Audit", exact: true }).click();
  await expect(page.getByText("Audit incident", { exact: true })).toBeVisible();
  await expect(page.getByText("independent-mismatch", { exact: true })).toBeVisible();
});
