import { expect, test, type Page } from "@playwright/test";

const ORIGIN = "http://127.0.0.1:4173";

function monitorBrowser(page: Page) {
  const failures: string[] = [];
  page.on("console", message => message.type() === "error" && failures.push(`console: ${message.text()}`));
  page.on("pageerror", error => failures.push(`page: ${error.message}`));
  page.on("requestfailed", request => failures.push(`request: ${request.url()}`));
  page.on("request", request => {
    const url = new URL(request.url());
    if (url.origin !== ORIGIN || ["fetch", "xhr", "websocket", "eventsource"].includes(request.resourceType())) failures.push(`unexpected: ${request.resourceType()} ${url.href}`);
  });
  page.on("response", response => response.status() >= 400 && failures.push(`response: ${response.status()} ${response.url()}`));
  return { failures, assertClean: () => expect(failures).toEqual([]) };
}

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
  assertClean();
});

test("each route has a unique browser title", async ({ page }) => {
  const { assertClean } = monitorBrowser(page);
  const routes = new Map([["/", "Overview"], ["/dashboard", "Console foundation — VegaStack Labs Console"], ["/states", "Foundation states — VegaStack Labs Console"], ["/unavailable", "Service unavailable — VegaStack Labs Console"]]);
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
  await expect(page.getByText(/data integration is not implemented/i)).toBeVisible();
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
});
