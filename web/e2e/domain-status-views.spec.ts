import { expect, test, type Page } from "@playwright/test";
import axe from "axe-core";
import { fixtureAudit, fixtureState, installReadFixture, privateDomainBackingRecords, privateDomainCanaries } from "./api-fixture";

const domains = [
  { route: "/people", title: "People", source: "people", capability: "identity.person.read" },
  { route: "/services", title: "Services", source: "services", capability: "service.read" },
  { route: "/backups", title: "Backups", source: "backups", capability: "backup.status.read" },
  { route: "/providers", title: "Providers", source: "providers", capability: "adapter.status.read" },
] as const;

test.beforeEach(async ({ page }) => installReadFixture(page));

async function expectNoSeriousAccessibilityViolations(page: Page) {
  await page.evaluate(axe.source);
  const violations = await page.evaluate(async () => {
    const runtime = (globalThis as unknown as { axe: { run: (root: Document) => Promise<{ violations: Array<{ id: string; impact: string | null; nodes: Array<{ target: unknown }> }> }> } }).axe;
    const result = await runtime.run(document);
    return result.violations.filter(item => item.impact === "serious" || item.impact === "critical").map(item => `${item.id}: ${item.nodes.map(node => JSON.stringify(node.target)).join(", ")}`);
  });
  expect(violations).toEqual([]);
}

for (const domain of domains) {
  test(`${domain.title} requests only its source and makes no record claim`, async ({ page }, testInfo) => {
    fixtureState.domainState = "healthy";
    await page.goto(domain.route);
    await expect(page.getByText(/status observation is current/i)).toBeVisible();
    await expect(page.getByText(domain.capability, { exact: false })).toBeVisible();
    expect(fixtureAudit.requests.some(url => url.includes(`/api/v1/sources?limit=1&source=${domain.source}`))).toBeTruthy();
    await expect(page.getByRole("button", { name: /create|restore|configure|suspend|apply/i })).toHaveCount(0);
    await expect(page.getByText(/records arrive in their owning later phase/i)).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath(`${domain.source}-current.png`), fullPage: true });
  });

  test(`${domain.title} distinguishes every safe status and failure`, async ({ page }) => {
    fixtureState.domainState = "healthy";
    fixtureState.delay = 200;
    await page.goto(domain.route);
    await expect(page.locator('[data-read-state="loading"]')).toBeVisible();
    fixtureState.delay = 0;
    await expect(page.getByText(/status observation is current/i)).toBeVisible();
    for (const [domainState, readState] of [["stale", "stale"], ["unknown", "unknown"], ["unavailable", "unavailable"], ["failed", "error"]] as const) {
      fixtureState.domainState = domainState;
      await page.reload();
      await expect(page.locator(`[data-read-state="${readState}"]`)).toBeVisible();
      await expect(page.locator(`[data-source-state="${domainState}"]`)).toBeVisible();
    }
    fixtureState.mode = "denied";
    await page.reload();
    await expect(page.locator('[data-read-state="denied"]')).toBeVisible();
    await expect(page.locator("[data-source-state]")).toHaveCount(0);
    fixtureState.mode = "malformed";
    await page.reload();
    await expect(page.locator('[data-read-state="error"]')).toBeVisible();
    await expect(page.locator("[data-source-state]")).toHaveCount(0);
  });

  test(`${domain.title} labels retryable old status stale and stays accessible on mobile`, async ({ page }, testInfo) => {
    fixtureState.domainState = "healthy";
    await page.setViewportSize({ width: 390, height: 844 });
    await page.addInitScript(() => localStorage.setItem("theme", "light"));
    await page.goto(domain.route);
    await expect(page.getByRole("heading", { name: domain.title, exact: true })).toBeVisible();
    await expect(page.locator("html")).toHaveClass(/light/);
    await expectNoSeriousAccessibilityViolations(page);
    const refresh = page.getByRole("button", { name: `Refresh ${domain.title}` });
    await refresh.focus();
    await expect(refresh).toBeFocused();
    fixtureState.mode = "dependency";
    await page.keyboard.press("Enter");
    await expect(page.locator('[data-read-state="stale"]')).toBeVisible();
    await expect(page.locator('[data-source-state="healthy"]')).toBeVisible();
    await expect(page.getByRole("button", { name: `Refresh ${domain.title}` })).toBeFocused();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
    await expectNoSeriousAccessibilityViolations(page);
    await page.getByRole("button", { name: "Use dark theme" }).click();
    await expect(page.locator("html")).toHaveClass(/dark/);
    if (domain.source === "backups") await page.screenshot({ path: testInfo.outputPath("backups-stale-mobile-dark.png"), fullPage: true });
  });
}

test("a valid but wrong source response is rejected", async ({ page }) => {
  fixtureState.mode = "mismatched-source";
  fixtureState.domainState = "healthy";
  await page.goto("/people");
  await expect(page.locator('[data-read-state="error"]')).toBeVisible();
  await expect(page.locator("[data-source-state]")).toHaveCount(0);
});

test("private domain backing records never reach the browser", async ({ page }) => {
  const logs: string[] = [];
  const rendered: string[] = [];
  page.on("console", message => logs.push(message.text()));
  fixtureState.domainState = "healthy";
  expect(privateDomainBackingRecords).toHaveLength(4);
  expect(privateDomainBackingRecords.every(record => record.scope === "another-project")).toBeTruthy();
  for (const domain of domains) {
    await page.goto(domain.route);
    await expect(page.getByText(/status observation is current/i)).toBeVisible();
    rendered.push(await page.locator("body").innerText());
  }
  for (const domain of domains) expect(fixtureAudit.domainProjections).toContainEqual({ source: domain.source, candidates: 2, excluded: 1 });
  const browserState = await page.evaluate(async () => ({ local: Object.entries(localStorage), session: Object.entries(sessionStorage), databases: (await indexedDB.databases()).map(database => database.name), caches: await caches.keys() }));
  const exposed = [rendered.join("\n"), page.url(), JSON.stringify(browserState), JSON.stringify(await page.context().cookies()), logs.join("\n"), fixtureAudit.requests.join("\n"), fixtureAudit.responses.join("\n")].join("\n");
  for (const canary of privateDomainCanaries) expect(exposed).not.toContain(canary);
  expect(browserState.local.every(([key]) => key === "theme")).toBeTruthy();
  expect(browserState.session).toEqual([]);
  expect(browserState.databases).toEqual([]);
  expect(browserState.caches).toEqual([]);
});
