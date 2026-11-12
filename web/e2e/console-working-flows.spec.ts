import { expect, test } from "@playwright/test";
import { installReadFixture } from "./api-fixture";
import { changeFixture, installChangeFixture } from "./change-api-fixture";
import axe from "axe-core";

test.beforeEach(async ({ page }) => {
  await installReadFixture(page);
  const contract = (name: string) => ({ schema: `vegastack-labs.dev/${name}`, schemaVersion: "1.0.0" });
  const envelope = (command: string, data: unknown) => ({ ...contract("browser-run-result"), toolVersion: "test", command, runId: null, status: "succeeded", changed: false, recoveryEpoch: 2, stateRevision: 8, snapshotDigest: null, releaseBuildId: "test", sourceRevision: null, planId: null, errors: [], data });
  await page.route("**/api/v1/people?**", route => route.fulfill({ json: envelope("api.v1.people.list", { ...contract("operator-people-page"), people: [{ ...contract("operator-person"), principalId: "fixture-person", status: "active", grantRevision: 1 }], nextAfter: "", stateRevision: 8, recoveryEpoch: 2 }) }));
  await page.route("**/api/v1/providers", route => route.fulfill({ json: envelope("api.v1.providers.list", { ...contract("operator-provider-list"), providers: [{ ...contract("operator-provider"), capability: "identity", configured: true, connectivity: "unknown" }], stateRevision: 8, recoveryEpoch: 2 }) }));
  const host = { ...contract("managed-host"), hostId: "fixture-node", targetId: "fixture-target", observationId: "fixture-observation", profileId: "fixture-profile", identityClass: "physical", status: "adopted-unadmitted", stateRevision: 8, recoveryEpoch: 2 };
  await page.route("**/api/v1/hosts", route => route.fulfill({ json: envelope("api.v1.hosts.list", { ...contract("managed-host-list"), hosts: [host], stateRevision: 8, recoveryEpoch: 2 }) }));
  await page.route("**/api/v1/hosts/fixture-node", route => route.fulfill({ json: envelope("api.v1.hosts.get", host) }));
});

test("Overview separates controller availability, recorded information and reviewed changes", async ({ page }, info) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Recorded information", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Help: Changes", exact: true })).toBeVisible();
  await expect(page.getByText("Mutations", { exact: true })).toHaveCount(0);
  await expect(page.getByText(/Each change still requires/)).toBeVisible();
  await expect(page.getByText("Last error: No collection time available", { exact: true })).toHaveCount(0);
  await page.screenshot({ path: info.outputPath("overview-recorded-state.png"), fullPage: true });
});

test("normal node inspection does not expose advanced forms before they are requested", async ({ page }) => {
  await page.goto("/nodes");
  for (const name of ["Add or prepare a node", "Repair or configure a node (administrator)", "Proposed inventory (read only)"]) {
    const summary = page.getByText(name, { exact: true });
    await expect(summary).toBeVisible();
    await expect(summary.locator("..")).toHaveJSProperty("open", false);
  }
});

test("an existing run can be inspected without executing or requesting approval", async ({ page }) => {
  await installChangeFixture(page);
  changeFixture.run = "succeeded";
  await page.goto("/changes");
  await page.getByLabel("Operation reference", { exact: true }).fill("run-one");
  await page.getByRole("button", { name: "Look up operation", exact: true }).click();
  await expect(page.locator('[data-run-status="succeeded"]')).toBeVisible();
  expect(changeFixture.executeRequests).toBe(0);
  expect(changeFixture.approvalRequestPosts).toBe(0);
  expect(changeFixture.requestPaths.some(path => path.includes("/execute"))).toBe(false);
});

test("missing audit status disables restore preparation instead of inviting a doomed action", async ({ page }) => {
  await page.route("**/api/v1/audit-history/verification", route => route.fulfill({ status: 503, json: {
    schema: "vegastack-labs.dev/browser-run-result", schemaVersion: "1.0.0", toolVersion: "test", command: "api.v1.audit-history.verification", runId: null, status: "failed", changed: false, recoveryEpoch: 2, stateRevision: 8, snapshotDigest: null, releaseBuildId: "test", sourceRevision: null, planId: null,
    errors: [{ code: "DEPENDENCY_UNAVAILABLE", target: "audit", retryable: true }], data: {},
  } }));
  await page.goto("/backups");
  await expect(page.getByText("point-a", { exact: true }).first()).toBeVisible();
  await expect(page.getByRole("button", { name: "Prepare restore", exact: true })).toBeDisabled();
  await expect(page.getByText("Restore preparation is unavailable until backup and audit status can be read.", { exact: true })).toBeVisible();
});

test("unimplemented addresses do not claim the connected controller is down", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("link", { name: "Settings", exact: true })).toHaveCount(0);
  await page.goto("/unavailable");
  await expect(page.getByText("Control plane is not connected", { exact: true })).toHaveCount(0);
  await page.getByRole("link", { name: "Return to Overview", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Overview", exact: true })).toBeVisible();
  await page.goto("/dashboard");
  await expect(page.getByRole("heading", { name: "Overview", exact: true })).toBeVisible();
  await expect(page.getByText(/Data integration is not implemented/)).toHaveCount(0);
});

const routes = [["/", "Overview"], ["/nodes", "Nodes"], ["/people", "People"], ["/services", "Services"], ["/backups", "Backups and recovery"], ["/providers", "Connections"], ["/gates", "Checks"], ["/audit", "History checks"], ["/changes", "Changes"]] as const;
for (const narrow of [false, true]) for (const [route, title] of routes) {
  test(`${narrow ? "mobile" : "desktop"} ${route} has readable layout, navigation and no serious accessibility errors`, async ({ page }, info) => {
    await page.setViewportSize(narrow ? { width: 390, height: 844 } : { width: 1440, height: 1000 });
    const errors: string[] = [];
    page.on("pageerror", error => errors.push(error.message));
    await page.goto(route, { waitUntil: "networkidle" });
    await expect(page.getByRole("heading", { name: title, exact: true }).first()).toBeVisible();
    if (route === "/nodes") await expect(page.getByRole("list", { name: "Registered host list" })).toContainText("fixture-node");
    if (route === "/people") await expect(page.getByRole("button", { name: "View access for fixture-person", exact: true })).toBeVisible();
    if (route === "/providers") await expect(page.getByRole("list", { name: "Provider capabilities" })).toContainText("Connection status: Not checked");
    if (route === "/services") await expect(page.getByRole("button", { name: "View service-a", exact: true })).toBeVisible();
    await expect(page.getByText(/could not be read|could not be loaded/i)).toHaveCount(0);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await page.evaluate(axe.source);
    const serious = await page.evaluate(async () => {
      const runtime = (globalThis as unknown as { axe: { run: (root: Document) => Promise<{ violations: { id: string; impact: string | null }[] }> } }).axe;
      return (await runtime.run(document)).violations.filter(item => item.impact === "critical" || item.impact === "serious").map(item => item.id);
    });
    expect(serious).toEqual([]);
    expect(errors).toEqual([]);
    await page.screenshot({ path: info.outputPath(`${narrow ? "mobile" : "desktop"}-${route === "/" ? "overview" : route.slice(1)}.png`), fullPage: true });
  });
}


test("sidebar navigation reaches every page without rendering or navigation errors", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  page.on("console", message => { if (message.type() === "error") errors.push(message.text()); });
  await page.goto("/");
  for (const [route, title] of routes) {
    const label = route === "/backups" ? "Backups" : title;
    await page.getByRole("navigation", { name: "Console navigation" }).getByRole("link", { name: label, exact: true }).click();
    await expect(page.getByRole("heading", { name: title, exact: true }).first()).toBeVisible();
  }
  expect(errors).toEqual([]);
});


test("expanded node tools remain usable on a narrow screen", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/nodes");
  for (const name of ["Inspect a host by ID", "Add or prepare a node", "Repair or configure a node (administrator)", "Proposed inventory (read only)"]) await page.getByText(name, { exact: true }).click();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});
