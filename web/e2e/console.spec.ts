import { expect, test, type Page } from "@playwright/test";
import { installReadFixture } from "./api-fixture";

const ORIGIN = "http://127.0.0.1:4173";
const GENERATED_READ_PATH = /^(?:\/api\/v1\/(?:summary|sources|health|database\/status|events)|\/api\/v1\/inventory-drafts(?:\/[^/]+\/revisions\/\d+(?:\/(?:assets|nodes|aliases|observations)(?:\/[^/]+)?)?)?)$/;
const SOURCE_IDS = new Set(["database", "nodes", "gates", "people", "services", "backups", "providers"]);
const SOURCE_STATES = new Set(["healthy", "stale", "unknown", "unavailable", "failed"]);

function validLimit(value: string | null) {
  return value === null || (/^[1-9]\d*$/.test(value) && Number(value) <= 200);
}

function validLength(value: string | null, maximum: number) {
  return value === null || value.length <= maximum;
}

function validPathValue(value: string | undefined) {
  if (!value) return false;
  try {
    const decoded = decodeURIComponent(value);
    return decoded.length >= 1 && decoded.length <= 128;
  } catch {
    return false;
  }
}

function validGeneratedPath(pathname: string) {
  if (!pathname.startsWith("/api/v1/inventory-drafts/")) return true;
  const segments = pathname.split("/").filter(Boolean);
  const revision = segments[5];
  if (!validPathValue(segments[3]) || !revision || !/^[1-9]\d*$/.test(revision) || !Number.isSafeInteger(Number(revision))) return false;
  return segments.length < 8 || validPathValue(segments[7]);
}

function isGeneratedReadRequest(url: URL) {
  if (!GENERATED_READ_PATH.test(url.pathname) || !validGeneratedPath(url.pathname)) return false;
  const keys = [...url.searchParams.keys()];
  if (new Set(keys).size !== keys.length) return false;
  if (url.pathname === "/api/v1/sources") return keys.every(key => ["cursor", "limit", "sort", "source", "state"].includes(key))
    && validLimit(url.searchParams.get("limit"))
    && validLength(url.searchParams.get("cursor"), 2048)
    && (url.searchParams.get("sort") === null || ["id-asc", "id-desc"].includes(url.searchParams.get("sort")!))
    && (url.searchParams.get("source") === null || SOURCE_IDS.has(url.searchParams.get("source")!))
    && (url.searchParams.get("state") === null || SOURCE_STATES.has(url.searchParams.get("state")!));
  if (url.pathname === "/api/v1/inventory-drafts" || /\/(?:assets|nodes|aliases|observations)$/.test(url.pathname)) return keys.every(key => ["cursor", "limit", "sort"].includes(key))
    && validLimit(url.searchParams.get("limit"))
    && validLength(url.searchParams.get("sort"), 64)
    && validLength(url.searchParams.get("cursor"), 2048);
  return keys.length === 0;
}

function monitorBrowser(page: Page) {
  const failures: string[] = [];
  page.on("console", message => message.type() === "error" && failures.push(`console: ${message.text()}`));
  page.on("pageerror", error => failures.push(`page: ${error.message}`));
  page.on("requestfailed", request => failures.push(`request: ${request.url()}`));
  page.on("request", request => {
    const url = new URL(request.url());
    const allowedRead = url.origin === ORIGIN && request.method() === "GET" && isGeneratedReadRequest(url) && request.resourceType() === "fetch";
    if (url.origin !== ORIGIN || (["fetch", "xhr", "websocket", "eventsource"].includes(request.resourceType()) && !allowedRead)) failures.push(`unexpected: ${request.resourceType()} ${url.href}`);
  });
  page.on("response", response => response.status() >= 400 && failures.push(`response: ${response.status()} ${response.url()}`));
  return { failures, assertClean: () => expect(failures).toEqual([]) };
}

test.beforeEach(async ({ page }) => installReadFixture(page));

test("skip link, focus order, and named landmarks work", async ({ page }) => {
  const { assertClean } = monitorBrowser(page);
  await page.goto("/");
  await page.keyboard.press("Tab");
  const skip = page.getByRole("link", { name: "Skip to main content" });
  await expect(skip).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "VegaStack Labs", exact: true }).first()).toBeFocused();
  await page.keyboard.press("Shift+Tab");
  await expect(skip).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("main", { name: "Overview" })).toBeFocused();
  await expect(page.getByRole("banner")).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Console navigation" })).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Console navigation" }).getByRole("link", { name: "Overview", exact: true })).toHaveAttribute("aria-current", "page");
  const targets = await page.getByRole("button", { name: /theme/i }).evaluateAll(elements => elements.map(element => ({ width: element.getBoundingClientRect().width, height: element.getBoundingClientRect().height })));
  expect(targets.every(target => target.width >= 44 && target.height >= 44)).toBeTruthy();
  assertClean();
});

test("each route has a unique browser title", async ({ page }) => {
  const { assertClean } = monitorBrowser(page);
  const routes = new Map([["/", "Overview"], ["/nodes", "Nodes — VegaStack Labs Console"], ["/gates", "Gates — VegaStack Labs Console"], ["/dashboard", "Console foundation — VegaStack Labs Console"], ["/states", "Foundation states — VegaStack Labs Console"], ["/unavailable", "Service unavailable — VegaStack Labs Console"]]);
  const titles = new Set<string>();
  for (const [route, title] of routes) {
    await page.goto(route);
    await expect(page).toHaveTitle(title);
    titles.add(await page.title());
  }
  expect(titles.size).toBe(routes.size);
  assertClean();
});

test("truthful empty, loading, error, and unavailable states render", async ({ page }) => {
  const { assertClean } = monitorBrowser(page);
  await page.goto("/");
  await expect(page.getByText(/State revision 8/i)).toBeVisible();
  await page.goto("/states");
  for (const kind of ["loading", "empty", "error", "unavailable"]) await expect(page.locator(`[data-console-state="${kind}"]`)).toBeVisible();
  assertClean();
});

for (const viewport of [{ name: "desktop", width: 1440, height: 900 }, { name: "mobile", width: 390, height: 844 }]) {
  test(`light and dark themes render and persist on ${viewport.name}`, async ({ page }) => {
    const { assertClean } = monitorBrowser(page);
    await page.setViewportSize(viewport);
    await page.addInitScript(() => { if (!localStorage.getItem("theme")) localStorage.setItem("theme", "light"); });
    await page.goto("/");
    await expect(page.locator("html")).toHaveClass(/light/);
    const light = await page.locator("body").evaluate(element => getComputedStyle(element).backgroundColor);
    await page.getByRole("button", { name: "Use dark theme" }).click();
    await expect(page.locator("html")).toHaveClass(/dark/);
    const dark = await page.locator("body").evaluate(element => getComputedStyle(element).backgroundColor);
    expect(dark).not.toBe(light);
    await page.reload();
    await expect(page.locator("html")).toHaveClass(/dark/);
    assertClean();
  });
}

test("desktop sidebar is visible and mobile drawer opens and closes", async ({ page }) => {
  const { assertClean } = monitorBrowser(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/");
  await expect(page.getByRole("navigation", { name: "Console navigation" })).toBeVisible();
  await expect(page.locator('[data-slot="app-shell-sidebar"]')).toHaveAttribute("data-state", "expanded");

  await page.setViewportSize({ width: 390, height: 844 });
  await page.reload();
  await expect(page.getByRole("navigation", { name: "Console navigation" })).toBeHidden();
  await page.getByRole("button", { name: "Toggle sidebar" }).click();
  await expect(page.getByRole("navigation", { name: "Console navigation" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("navigation", { name: "Console navigation" })).toBeHidden();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  assertClean();
});

test("same-origin server requests are detected", async ({ page }) => {
  const { failures } = monitorBrowser(page);
  await page.goto("/");
  await page.evaluate(() => fetch("/health").catch(() => undefined));
  await expect.poll(() => failures).toContainEqual(expect.stringMatching(/fetch .*\/health|404 .*\/health/));
  await page.evaluate(() => fetch("/api/v1/unapproved-operation").catch(() => undefined));
  await expect.poll(() => failures).toContainEqual(expect.stringMatching(/unapproved-operation/));
  await page.evaluate(() => fetch("/api/v1/summary?unapproved=1").catch(() => undefined));
  await expect.poll(() => failures).toContainEqual(expect.stringMatching(/summary\?unapproved=1/));
  await page.evaluate(() => Promise.all([
    fetch("/api/v1/sources?source=private-canary"),
    fetch("/api/v1/sources?limit=999999"),
    fetch("/api/v1/inventory-drafts/node/revisions/0/nodes"),
    fetch(`/api/v1/inventory-drafts/${"a".repeat(129)}/revisions/1/nodes`),
    new Promise<void>(resolve => { const request = new XMLHttpRequest(); request.open("GET", "/api/v1/summary"); request.onloadend = () => resolve(); request.send(); }),
    new Promise<void>(resolve => { const source = new EventSource("/api/v1/events"); const done = () => { source.close(); resolve(); }; source.onerror = done; setTimeout(done, 200); }),
  ]));
  await expect.poll(() => failures).toContainEqual(expect.stringMatching(/source=private-canary/));
  await expect.poll(() => failures).toContainEqual(expect.stringMatching(/limit=999999/));
  await expect.poll(() => failures).toContainEqual(expect.stringMatching(/revisions\/0\/nodes/));
  await expect.poll(() => failures).toContainEqual(expect.stringMatching(new RegExp(`inventory-drafts/${"a".repeat(129)}`)));
  await expect.poll(() => failures).toContainEqual(expect.stringMatching(/unexpected: xhr .*\/summary/));
  await expect.poll(() => failures).toContainEqual(expect.stringMatching(/unexpected: eventsource .*\/events/));
});
