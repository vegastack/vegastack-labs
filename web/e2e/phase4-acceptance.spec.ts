import { expect, test } from "@playwright/test";

import {
  changeFixture,
  installChangeFixture,
  phase4AcceptancePlan,
  privateChangeCanaries,
} from "./change-api-fixture";

test("Phase 4 acceptance keeps exact plan facts and protected authority out of the browser", async ({ page }) => {
  await installChangeFixture(page);
  await page.goto("/changes");
  await page.getByLabel("Declaration ID").fill("declaration-one");
  await page.getByLabel("Revision").fill("1");
  await page.getByRole("button", { name: "Open declaration" }).click();
  await page.getByLabel("Reason digest").fill(changeFixture.reasonDigest);
  await page.getByRole("button", { name: "Save declaration" }).click();
  await page.getByRole("button", { name: "Generate plan" }).click();

  await expect(page.getByText(phase4AcceptancePlan.planDigest, { exact: true })).toBeVisible();
  await expect(page.getByText(new RegExp(`Target ${phase4AcceptancePlan.operations[0].targetId}`))).toBeVisible();
  await expect(page.getByText(phase4AcceptancePlan.risk, { exact: true })).toBeVisible();
  await expect(page.getByText(`${phase4AcceptancePlan.authorizationBranch} authorization`, { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: /approve/i })).toHaveCount(0);

  const surface = [
    await page.locator("body").innerText(),
    page.url(),
    JSON.stringify(await page.evaluate(() => ({ history: history.state, local: { ...localStorage }, session: { ...sessionStorage } }))),
    changeFixture.requestBodies.join("\n"),
    changeFixture.requestPaths.join("\n"),
  ].join("\n");
  for (const canary of privateChangeCanaries) expect(surface).not.toContain(canary);
  expect(surface).not.toMatch(/humanId|authorityId|nonceDigest|proofDigest|acknowledgementId|authorizationDecisionId|executorBindingDigest/);
  expect(changeFixture.requestPaths.every(path => !/provider|sqlite|acknowledgements|executor-leases|execution-receipts/i.test(path))).toBeTruthy();
});
