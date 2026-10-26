import { expect, test, type Page } from "@playwright/test";
import axe from "axe-core";
import { fixtureAudit, fixtureState, installReadFixture, privateDomainCanaries, serviceFixtureRecord, serviceFixtureState } from "./api-fixture";

test.beforeEach(async ({ page }) => installReadFixture(page));

async function inspect(page: Page) {
  await page.getByRole("button", { name: "Inspect service-a", exact: true }).click();
  await expect(page.getByText("Coolify reported status: running:healthy", { exact: true })).toBeVisible();
}

async function accessible(page: Page) {
  await page.evaluate(axe.source);
  const violations = await page.evaluate(async () => {
    const runtime = (globalThis as unknown as { axe: { run: (root: Document) => Promise<{ violations: Array<{ id: string; impact: string | null }> }> } }).axe;
    return (await runtime.run(document)).violations.filter(item => item.impact === "serious" || item.impact === "critical").map(item => item.id);
  });
  expect(violations).toEqual([]);
}

test("Services is accessible on mobile with keyboard, truthful observations and bounded pagination", async ({ page }, info) => {
  await page.setViewportSize({ width: 390, height: 844 });
  let releaseList = () => {};
  const listGate = new Promise<void>(resolve => { releaseList = resolve; });
  await page.route(/\/api\/v1\/services(?:\?|$)/, async route => { await listGate; await route.fallback(); }, { times: 1 });
  await page.goto("/services");
  await expect(page.locator('[data-read-state="loading"]')).toBeVisible();
  releaseList();
  const inspectButton = page.getByRole("button", { name: "Inspect service-a", exact: true });
  await inspectButton.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByText("Coolify reported status: running:healthy", { exact: true })).toBeVisible();
  await expect(page.getByText("Configured image: fixture/app:v1", { exact: true })).toBeVisible();
  for (const text of ["Actual running digest: unknown", "Application health: unknown", "Signature: unverified", "Provenance: unverified", "Scan: findings"]) await expect(page.getByText(text, { exact: true })).toBeVisible();
  await expect(page.getByRole("list", { name: "Registered services" })).toContainText("registered");
  await expect(page.getByRole("list", { name: "Registered services" })).toContainText("Host admission: not-verified");
  await expect(page.getByRole("link", { name: "Changes", exact: true }).last()).toHaveAttribute("href", "/changes");
  await expect(page.getByRole("button", { name: /import|deploy|apply|approve/i })).toHaveCount(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await accessible(page);
  await page.screenshot({ path: info.outputPath("services-current-narrow.png"), fullPage: true });
  await page.getByRole("button", { name: "Next services page" }).click();
  await expect(page.getByRole("button", { name: "Inspect service-b", exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "Service detail" })).toHaveCount(0);
  expect(fixtureAudit.requests.some(url => url.includes("after=service-a") && url.includes("limit=25"))).toBe(true);
  await page.getByRole("button", { name: "Previous services page" }).click();
  await expect(inspectButton).toBeVisible();
});

test("Services distinguishes every safe status: empty, denied, unavailable and malformed", async ({ page }, info) => {
  for (const [mode, state] of [["empty", "empty"], ["denied", "denied"], ["unavailable", "unavailable"], ["malformed", "error"]] as const) {
    fixtureState.mode = mode;
    await page.goto("/services");
    await expect(page.locator(`[data-read-state="${state}"]`)).toBeVisible();
    await expect(page.getByRole("list", { name: "Registered services" })).toHaveCount(0);
    await page.screenshot({ path: info.outputPath(`services-${state}.png`), fullPage: true });
  }
  fixtureState.mode = "healthy";
  await page.getByRole("button", { name: "Refresh Services", exact: true }).click();
  await expect(page.getByRole("button", { name: "Inspect service-a", exact: true })).toBeVisible();
});

test("provider unavailability stays explicit while registration remains visible", async ({ page }) => {
  serviceFixtureState.unavailableProviders = true;
  await page.goto("/services");
  await page.getByRole("button", { name: "Inspect service-a", exact: true }).click();
  await expect(page.getByText("Hosting observation: unavailable · provider-unavailable", { exact: true })).toBeVisible();
  await expect(page.getByText("Artifact observation: unavailable · provider-unavailable", { exact: true })).toBeVisible();
  await expect(page.getByText("Scan: unavailable", { exact: true })).toBeVisible();
  await expect(page.getByRole("list", { name: "Registered services" })).toContainText("registered");
});

test("retryable observation failure visibly labels retained data stale", async ({ page }) => {
  await page.goto("/services");
  await inspect(page);
  fixtureState.mode = "dependency";
  await page.getByRole("button", { name: "Refresh observations", exact: true }).click();
  await expect(page.locator('[data-read-state="stale"]')).toBeVisible();
  await expect(page.getByText("Coolify reported status: running:healthy", { exact: true })).toBeVisible();
  await expect(page.getByText(/Provider availability and current state have not been confirmed/)).toBeVisible();
});

test("observation denial removes every visible private service record", async ({ page }) => {
  await page.goto("/services");
  await inspect(page);
  serviceFixtureState.deniedObservation = true;
  await page.getByRole("button", { name: "Refresh observations", exact: true }).click();
  await expect(page.getByText("Services access denied", { exact: true })).toBeVisible();
  await expect(page.getByRole("list", { name: "Registered services" })).toHaveCount(0);
  await expect(page.getByRole("region", { name: "Service detail" })).toHaveCount(0);
  await expect(page.locator("main")).not.toContainText("fixture/app:v1");
});

for (const denial of ["scoped", "session"] as const) {
  test(`${denial} revocation clears retained list, detail and observations including a late response`, async ({ page }) => {
    await page.goto("/services");
    await inspect(page);
    // Start an older authorized observation and let denial on another read win.
    serviceFixtureState.observationDelay = 500;
    const pending = page.waitForRequest(request => request.url().endsWith("/services/service-a/observation"));
    await page.getByRole("button", { name: "Refresh observations", exact: true }).click();
    await pending;
    if (denial === "session") {
      await page.route("**/api/v1/services/service-a", route => route.fulfill({ status: 401, json: { schema: "vegastack-labs.dev/browser-run-result", schemaVersion: "1.0.0", toolVersion: "test", command: "api.v1.services.get", runId: null, status: "failed", changed: false, recoveryEpoch: 2, stateRevision: 8, snapshotDigest: null, releaseBuildId: "test", sourceRevision: null, planId: null, errors: [{ code: "SESSION_EXPIRED", target: "session", retryable: false }], data: {} } }));
    } else fixtureState.mode = "denied";
    await page.getByRole("button", { name: "Refresh registration", exact: true }).click();
    await expect(page.getByText("Services access denied", { exact: true })).toBeVisible();
    await page.waitForTimeout(650);
    await expect(page.getByRole("list", { name: "Registered services" })).toHaveCount(0);
    await expect(page.getByRole("region", { name: "Service detail" })).toHaveCount(0);
    for (const privateValue of ["service-a", "owner-a", "fixture/app:v1", "running:healthy"]) await expect(page.locator("main")).not.toContainText(privateValue);
  });
}

test("private domain backing records never reach the browser", async ({ page }) => {
  await page.goto("/services");
  await inspect(page);
  const storage = await page.evaluate(async () => ({ local: Object.entries(localStorage), session: Object.entries(sessionStorage), databases: (await indexedDB.databases()).map(database => database.name), caches: await caches.keys() }));
  const exposed = [await page.locator("body").innerText(), fixtureAudit.requests.join("\n"), fixtureAudit.responses.join("\n"), JSON.stringify(storage)].join("\n");
  for (const canary of privateDomainCanaries) expect(exposed).not.toContain(canary);
  expect(storage.session).toEqual([]);
  expect(storage.databases).toEqual([]);
  expect(storage.caches).toEqual([]);
});

// Preserve the historical evidence selector while proving the current Services
// record contract: a valid envelope for a different service is still rejected.
test("a valid but wrong source response is rejected", async ({ page }) => {
  const result = (command: string, data: unknown) => ({
    schema: "vegastack-labs.dev/browser-run-result", schemaVersion: "1.0.0", toolVersion: "test", command, runId: null, status: "succeeded", changed: false, recoveryEpoch: 2, stateRevision: 8, snapshotDigest: null, releaseBuildId: "test", sourceRevision: null, planId: null, errors: [], data,
  });
  const wrongRecord = serviceFixtureRecord("service-b");
  const wrongObservation = {
    schema: "vegastack-labs.dev/service-observation", schemaVersion: "1.0.0", serviceId: "service-b", bindingDigest: wrongRecord.definition.bindingDigest, observedAt: "2026-10-26T04:01:00Z", hostingState: "observed", hostingReason: "observed", providerStatus: "wrong-service-status-canary", configuredImage: "wrong-service-image-canary", artifactState: "not-configured", artifactReason: "not-configured", artifactKind: "unknown", scanState: "unknown", signatureState: "unverified", provenanceState: "unverified", runningDigestState: "unknown", healthState: "unknown", hostAdmission: "not-verified", stateRevision: 8, recoveryEpoch: 2,
  };
  for (const observation of [false, true]) {
    const url = `**/api/v1/services/service-a${observation ? "/observation" : ""}`;
    await page.route(url, route => route.fulfill({ json: result(observation ? "api.v1.services.observation.get" : "api.v1.services.get", observation ? wrongObservation : wrongRecord) }));
    await page.goto("/services");
    await page.getByRole("button", { name: "Inspect service-a", exact: true }).click();
    await expect(page.locator('[data-read-state="error"]').first()).toBeVisible();
    await expect(page.getByRole("region", { name: "Service detail" })).toHaveCount(0);
    await expect(page.getByRole("list", { name: "Registered services" })).toHaveCount(0);
    await expect(page.locator("main")).not.toContainText("service-b");
    await expect(page.locator("main")).not.toContainText("wrong-service-status-canary");
    await expect(page.locator("main")).not.toContainText("wrong-service-image-canary");
    await page.unroute(url);
  }
});

test("Services distinguishes desired settings and blocked placement from partial deployment and unverified recovery", async ({ page }) => {
  await page.goto("/services");
  await inspect(page);
  await expect(page.getByText("Explicit target eligibility: blocked · admission-or-capacity-unavailable", { exact: true })).toBeVisible();
  await expect(page.getByText("CPU quota: 100% · Memory: 268435456 bytes", { exact: true })).toBeVisible();
  await expect(page.getByText("Deployment: partial · deploy", { exact: true })).toBeVisible();
  await expect(page.getByText("Recovery: blocked · backup", { exact: true })).toBeVisible();
  await expect(page.getByText("Consistent restore verified: false", { exact: true })).toBeVisible();
  fixtureState.mode = "denied";
  await page.getByRole("button", { name: "Refresh Services", exact: true }).click();
  await expect(page.getByRole("region", { name: "Service detail" })).toHaveCount(0);
  for (const text of ["CPU quota: 100% · Memory: 268435456 bytes", "Deployment: partial · deploy", "Recovery: blocked · backup"]) await expect(page.getByText(text, { exact: true })).toHaveCount(0);
});
