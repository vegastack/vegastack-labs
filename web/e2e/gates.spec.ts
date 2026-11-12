import { expect, test } from "@playwright/test";
import { installReadFixture } from "./api-fixture";

test.beforeEach(async ({ page }) => installReadFixture(page));

test("deferred not-applicable gate shows its reason without a pass or mutation control", async ({ page }) => {
  await page.goto("/gates");
  const deferred = page.locator('[data-gate-outcome="not-applicable"]');
  const applicability = deferred.locator('[data-slot="property-row"]').filter({ has: page.getByText("When this check is needed", { exact: true }) });
  await expect(deferred).toContainText("G-023");
  await expect(applicability.locator('[data-slot="property-value"]')).toHaveText("Planned for later");
  await expect(deferred.getByText("Not required", { exact: true })).toBeVisible();
  const reason = deferred.locator("details").filter({ hasText: "Reason code: deferred" });
  await reason.locator("summary").click();
  await expect(reason).toContainText("Reason code: deferred");
  await expect(deferred.getByText("Passed", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /pass|approve|apply|revoke/i })).toHaveCount(0);
});
