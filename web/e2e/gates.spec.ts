import { expect, test } from "@playwright/test";
import { installReadFixture } from "./api-fixture";

test.beforeEach(async ({ page }) => installReadFixture(page));

test("deferred not-applicable gate shows its reason without a pass or mutation control", async ({ page }) => {
  await page.goto("/gates");
  const deferred = page.locator('[data-gate-outcome="not-applicable"]');
  await expect(deferred).toContainText("G-023");
  await expect(deferred).toContainText("Reason: deferred");
  await expect(deferred).toContainText("Ready for input: no");
  await expect(deferred.getByText("passed", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /pass|approve|apply|revoke/i })).toHaveCount(0);
});
