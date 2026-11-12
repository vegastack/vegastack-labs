import { expect, test } from "@playwright/test";
import { installReadFixture } from "./api-fixture";

test("saved settings help explains where references come from without submitting", async ({ page }) => {
  await installReadFixture(page);
  const writes: string[] = [];
  page.on("request", request => { if (request.url().includes("/api/") && request.method() !== "GET") writes.push(request.url()); });
  await page.goto("/changes");
  const help = page.getByRole("button", { name: "Help: Settings reference", exact: true });
  await help.focus();
  await page.keyboard.press("Enter");
  await expect(help).toHaveAttribute("aria-expanded", "true");
  await expect(page.getByText("Copy the declaration ID returned when the settings were saved.", { exact: false })).toBeVisible();
  await page.getByRole("button", { name: "Help: Version", exact: true }).click();
  await expect(page.getByText("It must match the version you want to review; do not guess the latest number.", { exact: false })).toBeVisible();
  expect(writes).toEqual([]);
});

test("proof fields explain exact report values and do not treat help as approval", async ({ page }, testInfo) => {
  const browserErrors: string[] = [];
  page.on("pageerror", error => browserErrors.push(error.stack ?? error.message));
  page.on("console", message => { if (message.type() === "error") browserErrors.push(message.text()); });
  try {
    await installReadFixture(page);
    const writes: string[] = [];
    page.on("request", request => { if (request.url().includes("/api/") && request.method() !== "GET") writes.push(request.url()); });
    await page.goto("/gates");
    await expect(page.getByRole("heading", { name: "Checks", exact: true })).toBeVisible();
    const check = page.locator('[data-gate-outcome="blocked"]').first();
    await check.getByText("Check results and submit proof", { exact: true }).click();
    await check.getByRole("button", { name: "Help: Target fingerprint", exact: true }).click();
    await expect(check.getByText("Copy targetDigest from the command line check output", { exact: false })).toBeVisible();
    await check.getByRole("button", { name: "Prepare proof", exact: true }).click();
    await check.getByText("Technical details — proof report fields", { exact: true }).click();
    const artifactHelp = check.getByRole("button", { name: "Help: Artifact digest", exact: true });
    await artifactHelp.click();
    const artifactGuidance = page.locator(`[id="${await artifactHelp.getAttribute("aria-controls")}"]`);
    await expect(artifactGuidance).toBeVisible();
    await expect(artifactGuidance).toContainText("Copy artifactDigest from the report.");
    await expect(artifactGuidance).toContainText("Copy the complete value; do not invent one.");
    await expect(check.getByRole("button", { name: /approve|apply/i })).toHaveCount(0);
    expect(writes).toEqual([]);
  } finally {
    await testInfo.attach("proof-form-browser-errors", { body: JSON.stringify(browserErrors, null, 2), contentType: "application/json" });
    expect(browserErrors, "Opening and using proof help must not cause a render error").toEqual([]);
  }
});

test("connection and history terms have practical explanations", async ({ page }) => {
  await installReadFixture(page);
  await page.route("**/api/v1/providers", route => route.fulfill({ json: {
    schema: "vegastack-labs.dev/browser-run-result", schemaVersion: "1.0.0", toolVersion: "test", command: "api.v1.providers.list", runId: null, status: "succeeded", changed: false, recoveryEpoch: 2, stateRevision: 8, snapshotDigest: null, releaseBuildId: "test", sourceRevision: null, planId: null, errors: [],
    data: { schema: "vegastack-labs.dev/operator-provider-list", schemaVersion: "1.0.0", providers: [{ schema: "vegastack-labs.dev/operator-provider", schemaVersion: "1.0.0", capability: "identity", configured: true, connectivity: "unknown" }], stateRevision: 8, recoveryEpoch: 2 },
  } }));
  await page.goto("/providers");
  await expect(page.getByRole("heading", { name: "Connections", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Help: Provider setup", exact: true }).first().click();
  await expect(page.getByText("A provider is an outside service used by this Console.", { exact: false }).first()).toBeVisible();
  await page.goto("/audit");
  await expect(page.getByRole("heading", { name: "History checks", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Help: History status", exact: true }).click();
  await expect(page.getByText("A checkpoint marks a verified section of that history.", { exact: false })).toBeVisible();
});
