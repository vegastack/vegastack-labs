import { expect, test, type Page } from "@playwright/test";
import axe from "axe-core";
import { fixtureAudit, fixtureState, installReadFixture, privateFixtureRecords } from "./api-fixture";

test.beforeEach(async ({ page }) => installReadFixture(page));

async function expectNoSeriousAccessibilityViolations(page: Page) {
  await page.evaluate(axe.source);
  const violations = await page.evaluate(async () => {
    const runtime = (globalThis as unknown as { axe: { run: (root: Document) => Promise<{ violations: Array<{ id: string; impact: string | null; nodes: Array<{ target: unknown }> }> }> } }).axe;
    const result = await runtime.run(document);
    return result.violations.filter(violation => violation.impact === "serious" || violation.impact === "critical").map(violation => `${violation.id}: ${violation.nodes.map(node => JSON.stringify(node.target)).join(", ")}`);
  });
  expect(violations).toEqual([]);
}

test("Overview keeps only retryable per-query stale data and hides it after denial", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByText("State revision 8", { exact: false })).toBeVisible();
  await expect(page.getByText("Collected: 11-09-2026 01:30 PM IST", { exact: true }).first()).toBeVisible();
  fixtureState.mode = "dependency";
  await page.getByRole("button", { name: "Refresh Overview" }).click();
  await expect(page.locator('[data-read-state="stale"]')).toContainText(/showing last known/i);
  fixtureState.mode = "denied";
  await page.getByRole("button", { name: "Refresh Overview" }).click();
  await expect(page.locator('[data-read-state="denied"]')).toContainText(/access denied/i);
  await expect(page.locator("[data-overview-records]")).toHaveCount(0);
});

test("Overview renders every domain and marks omitted domains unknown", async ({ page }) => {
  fixtureState.mode = "missing";
  await page.goto("/");
  await expect(page.locator('[data-read-state="partial"]')).toBeVisible();
  await expect(page.locator("[data-source-state]" )).toHaveCount(7);
  await expect(page.locator('[data-source-state="unknown"]')).toHaveCount(6);
});

test("Overview preserves source statuses when its summary is temporarily unavailable", async ({ page }) => {
  fixtureState.mode = "dependency-summary";
  await page.goto("/");
  await expect(page.locator('[data-read-state="partial"]')).toBeVisible();
  await expect(page.locator('[data-source-state]')).toHaveCount(7);
  await expect(page.getByText("database", { exact: true })).toBeVisible();
});

test("Overview treats zero drafts with missing sources as partial, not empty", async ({ page }) => {
  fixtureState.mode = "empty";
  await page.goto("/");
  await expect(page.locator('[data-read-state="partial"]')).toBeVisible();
  await expect(page.getByText(/Drafts 0 \(0 valid, 0 blocked\)/)).toBeVisible();
  await expect(page.locator('[data-source-state="unknown"]')).toHaveCount(7);
});

test("Overview distinguishes loading, unavailable, and rejected responses", async ({ page }) => {
  fixtureState.delay = 250;
  await page.goto("/");
  await expect(page.locator('[data-read-state="loading"]')).toBeVisible();
  fixtureState.delay = 0;
  for (const [mode, state] of [["unavailable", "unavailable"], ["malformed", "error"]] as const) {
    fixtureState.mode = mode;
    await page.reload();
    await expect(page.locator(`[data-read-state="${state}"]`).first()).toBeVisible();
  }
});

test("Nodes pages independently with opaque cursors and opens every detail kind", async ({ page }) => {
  await page.goto("/nodes");
  for (const collection of ["nodes", "aliases", "observations"] as const) {
    await page.getByRole("button", { name: `Next ${collection} page` }).click();
    await expect(page.getByText(collection === "nodes" ? "node-two" : collection === "aliases" ? "alias-two" : "observation-two")).toBeVisible();
    expect(fixtureAudit.requests.some(url => url.includes(`cursor=opaque%2F${collection}%2Ftwo`))).toBeTruthy();
    expect(page.url()).not.toContain("opaque");
    await page.getByRole("button", { name: `Previous ${collection} page` }).click();
  }
  for (const kind of ["node", "alias", "observation"] as const) {
    const trigger = page.getByRole("button", { name: `View ${kind}` }).first();
    await trigger.click();
    await expect(page.getByText(`${kind} details`, { exact: true })).toBeVisible();
    if (kind === "observation") await expect(page.getByText("11-09-2026 01:30 PM IST", { exact: true })).toBeVisible();
    const closeSize = await page.locator('[data-slot="sheet-close"]').evaluate(element => ({ width: element.getBoundingClientRect().width, height: element.getBoundingClientRect().height }));
    expect(closeSize.width).toBeGreaterThanOrEqual(44);
    expect(closeSize.height).toBeGreaterThanOrEqual(44);
    await page.keyboard.press("Escape");
    await expect(trigger).toBeFocused();
  }
});

test("leaving a screen cancels its superseded generated reads", async ({ page }) => {
  let aborts = 0;
  await page.exposeFunction("recordReadAbort", () => { aborts += 1; });
  await page.addInitScript(() => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (input, init) => {
      init?.signal?.addEventListener("abort", () => void (globalThis as unknown as { recordReadAbort: () => Promise<void> }).recordReadAbort(), { once: true });
      return originalFetch(input, init);
    };
  });
  await page.goto("/");
  fixtureState.delay = 1_000;
  await page.getByRole("button", { name: "Refresh Overview" }).click();
  await page.getByRole("navigation", { name: "Console navigation" }).getByRole("link", { name: "Plans" }).click();
  await expect.poll(() => aborts).toBeGreaterThan(0);
});

test("Gates reports capability only and classifies every failure family", async ({ page }) => {
  fixtureState.delay = 250;
  await page.goto("/gates");
  await expect(page.locator('[data-read-state="loading"]')).toBeVisible();
  fixtureState.delay = 0;
  await expect(page.getByText(/gate evaluation is not implemented/i)).toBeVisible();
  await expect(page.getByText("Last success: 10-09-2026 12:30 PM IST", { exact: true })).toBeVisible();
  await expect(page.getByText("Last error: 11-09-2026 01:30 PM IST", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: /pass|approve|apply/i })).toHaveCount(0);
  fixtureState.mode = "dependency";
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(page.locator('[data-read-state="stale"]')).toBeVisible();
  for (const [mode, state] of [["empty", "unknown"], ["unavailable", "unavailable"], ["denied", "denied"], ["malformed", "error"]] as const) {
    fixtureState.mode = mode;
    await page.reload();
    await expect(page.locator(`[data-read-state="${state}"]`)).toBeVisible();
  }
});

test("Nodes classifies loading, empty, unavailable, denied, and rejected responses", async ({ page }) => {
  fixtureState.delay = 250;
  await page.goto("/nodes");
  await expect(page.locator('[data-read-state="loading"]')).toBeVisible();
  fixtureState.delay = 0;
  for (const [mode, state] of [["empty", "empty"], ["unavailable", "unavailable"], ["denied", "denied"], ["malformed", "error"]] as const) {
    fixtureState.mode = mode;
    await page.reload();
    await expect(page.locator(`[data-read-state="${state}"]`).first()).toBeVisible();
  }
});

test("Nodes distinguishes stale, partial, unknown, and scope denial after successful reads", async ({ page }) => {
  await page.goto("/nodes");
  await expect(page.getByText("node-one", { exact: true })).toBeVisible();

  fixtureState.mode = "dependency";
  await page.getByRole("button", { name: "Refresh Nodes" }).click();
  await expect(page.locator('[data-read-state="stale"]')).toBeVisible();

  fixtureState.mode = "healthy";
  await page.reload();
  fixtureState.mode = "dependency-node-page";
  await page.getByRole("button", { name: "Next nodes page" }).click();
  await expect(page.locator('[data-read-state="partial"]')).toBeVisible();
  await expect(page.getByText("Nodes temporarily unavailable", { exact: true })).toBeVisible();

  fixtureState.mode = "healthy";
  await page.reload();
  fixtureState.mode = "deny-node-page";
  await page.getByRole("button", { name: "Next nodes page" }).click();
  await expect(page.locator('[data-read-state="denied"]')).toBeVisible();
  await expect(page.getByText("No inventory draft", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "View node" })).toHaveCount(0);

  fixtureState.mode = "missing";
  await page.reload();
  await expect(page.locator('[data-source-state="unknown"]')).toContainText(/no health can be inferred/i);
});

test("private fixture records remain behind the authorized response boundary", async ({ page }) => {
  const logs: string[] = [];
  page.on("console", message => logs.push(message.text()));
  expect(privateFixtureRecords).toContain("private-canary");
  await page.goto("/nodes");
  fixtureState.mode = "denied";
  await page.reload();
  fixtureState.mode = "malformed";
  await page.getByRole("button", { name: "Refresh" }).click();
  const browserState = await page.evaluate(async () => ({
    local: Object.entries(localStorage),
    session: Object.entries(sessionStorage),
    databases: (await indexedDB.databases()).map(database => database.name),
    caches: await caches.keys(),
  }));
  const exposed = [await page.locator("body").innerText(), page.url(), JSON.stringify(browserState), JSON.stringify(await page.context().cookies()), logs.join("\n"), fixtureAudit.requests.join("\n"), fixtureAudit.responses.join("\n")].join("\n");
  for (const canary of privateFixtureRecords) expect(exposed).not.toContain(canary);
  expect(browserState.local.every(([key]) => key === "theme")).toBeTruthy();
  expect(browserState.session).toEqual([]);
  expect(browserState.databases).toEqual([]);
  expect(browserState.caches).toEqual([]);
});

test("Overview, Nodes, Gates, and the details overlay have no serious accessibility violations", async ({ page }) => {
  for (const [route, ready] of [["/", "[data-overview-records]"], ["/nodes", "text=node-one"], ["/gates", "text=Gate evaluation is not implemented"]] as const) {
    await page.goto(route);
    await expect(page.locator(ready)).toBeVisible();
    await expectNoSeriousAccessibilityViolations(page);
  }
  await page.goto("/nodes");
  await page.getByRole("button", { name: "View node" }).click();
  await expectNoSeriousAccessibilityViolations(page);
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.locator("main")).toBeVisible();
  await expectNoSeriousAccessibilityViolations(page);
  await page.keyboard.press("Escape");
  for (const mode of ["denied", "malformed"] as const) {
    fixtureState.mode = mode;
    await page.goto("/");
    await expect(page.locator(`[data-read-state="${mode === "denied" ? "denied" : "error"}"]`)).toBeVisible();
    await expectNoSeriousAccessibilityViolations(page);
  }
});

test("Nodes remains readable and operable on a narrow screen", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/nodes");
  for (const heading of ["Nodes", "Aliases", "Observations"]) await expect(page.getByRole("heading", { name: heading, exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Toggle sidebar" }).click();
  await expect(page.getByRole("navigation", { name: "Console navigation" }).getByRole("link", { name: "Nodes", exact: true })).toHaveAttribute("aria-current", "page");
  await page.keyboard.press("Escape");
  const layout = await page.evaluate(() => ({ pageWidth: document.documentElement.scrollWidth, viewportWidth: window.innerWidth }));
  expect(layout.pageWidth).toBeLessThanOrEqual(layout.viewportWidth);
  const targets = await page.locator("main button:visible").evaluateAll(elements => elements.map(element => ({ width: element.getBoundingClientRect().width, height: element.getBoundingClientRect().height })));
  expect(targets.length).toBeGreaterThan(0);
  expect(targets.every(target => target.width >= 44 && target.height >= 44)).toBeTruthy();
});
