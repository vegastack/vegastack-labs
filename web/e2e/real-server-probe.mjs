import { chromium } from "@playwright/test";
import axe from "axe-core";

const baseURL = process.env.VSK_PHASE3_BASE_URL;
const controllerURL = process.env.VSK_PHASE3_CONTROLLER_URL;
const assertion = process.env.VSK_PHASE3_ASSERTION;

if (!baseURL || !controllerURL || !assertion) throw new Error("phase 3 fixture inputs are required");

const browser = await chromium.launch({ headless: true });
let stage = "desktop-session";
try {
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    colorScheme: "dark",
    viewport: { width: 1440, height: 900 },
    extraHTTPHeaders: { "Cf-Access-Jwt-Assertion": assertion },
  });
  const page = await context.newPage();
  const browserRequests = [];
  page.on("request", request => {
    if (["fetch", "xhr", "websocket", "eventsource"].includes(request.resourceType())) browserRequests.push(request.url());
  });

  async function controller(path, method = "POST") {
    const response = await fetch(`${controllerURL}${path}`, { method });
    if (!response.ok) throw new Error("fixture controller rejected operation");
    return response.json();
  }

  async function createSession(targetContext = context) {
    const response = await targetContext.request.post(`${baseURL}/api/v1/session`, {
      headers: { Origin: baseURL, "Content-Type": "application/json" },
      data: { requestVersion: "1.0.0" },
    });
    if (response.status() !== 200) throw new Error("session bootstrap failed");
    const cookie = (await targetContext.cookies(baseURL)).find(item => item.name === "vsk_labs_session");
    if (!cookie || !cookie.httpOnly || !cookie.secure || cookie.sameSite !== "Strict") throw new Error("session cookie policy failed");
  }

  await createSession();
  stage = "desktop-navigation";
  const navigation = await page.goto(`${baseURL}/`, { waitUntil: "networkidle" });
  if (!navigation || navigation.status() !== 200) throw new Error("embedded Console navigation failed");
  for (const header of ["content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy", "cache-control"]) {
    if (!navigation.headers()[header]) throw new Error("browser security header missing");
  }
  await page.getByRole("heading", { name: "Overview", exact: true }).waitFor();
  const summaryStatus = await page.evaluate(async () => (await fetch("/api/v1/summary")).status);
  if (summaryStatus !== 200) throw new Error("same-origin generated read failed");
  await page.evaluate(axe.source);
  const violations = await page.evaluate(async () => {
    const result = await globalThis.axe.run(document);
    return result.violations.filter(item => item.impact === "serious" || item.impact === "critical").map(item => item.id);
  });
  if (violations.length) throw new Error("serious accessibility violation");
  if (browserRequests.some(value => new URL(value).origin !== baseURL)) throw new Error("browser attempted a cross-origin data request");

  stage = "keyboard";
  await page.keyboard.press("Tab");
  if (await page.getByRole("link", { name: "Skip to main content" }).evaluate(element => element !== document.activeElement)) throw new Error("keyboard focus order failed");
  await page.keyboard.press("Enter");
  if (await page.getByRole("main", { name: "Overview" }).evaluate(element => element !== document.activeElement)) throw new Error("skip-link focus recovery failed");

  stage = "routes";
  const routes = [["/nodes", "Nodes"], ["/gates", "Gates"], ["/people", "People"], ["/services", "Services"], ["/backups", "Backups"], ["/providers", "Providers"]];
  for (const [route, heading] of routes) {
    await page.goto(`${baseURL}${route}`, { waitUntil: "networkidle" });
    await page.getByRole("heading", { name: heading, exact: true }).waitFor();
  }
  await page.goBack({ waitUntil: "networkidle" });
  if (new URL(page.url()).pathname !== "/backups") throw new Error("browser back navigation failed");
  await page.goForward({ waitUntil: "networkidle" });
  if (new URL(page.url()).pathname !== "/providers") throw new Error("browser forward navigation failed");
  await page.reload({ waitUntil: "networkidle" });

  stage = "mobile";
  const mobileContext = await browser.newContext({
    ignoreHTTPSErrors: true,
    colorScheme: "light",
    reducedMotion: "reduce",
    viewport: { width: 390, height: 844 },
    extraHTTPHeaders: { "Cf-Access-Jwt-Assertion": assertion },
  });
  try {
    stage = "mobile-session";
    await createSession(mobileContext);
    await mobileContext.addInitScript(() => localStorage.setItem("theme", "light"));
    const mobile = await mobileContext.newPage();
    stage = "mobile-navigation";
    await mobile.goto(`${baseURL}/backups`, { waitUntil: "networkidle" });
    await mobile.getByRole("heading", { name: "Backups", exact: true }).waitFor();
    stage = "mobile-reflow";
    const layout = await mobile.evaluate(() => ({ width: document.documentElement.scrollWidth, viewport: window.innerWidth }));
    if (layout.width > layout.viewport) throw new Error("mobile reflow failed");
    stage = "mobile-accessibility";
    await mobile.evaluate(axe.source);
    const mobileViolations = await mobile.evaluate(async () => {
      const result = await globalThis.axe.run(document);
      return result.violations.filter(item => item.impact === "serious" || item.impact === "critical").map(item => item.id);
    });
    if (mobileViolations.length) throw new Error("mobile accessibility violation");
    stage = "mobile-targets";
    const targets = await mobile.locator("button:visible").evaluateAll(elements => elements.map(element => {
      const bounds = element.getBoundingClientRect();
      const hitArea = getComputedStyle(element, "::before");
      const expansion = value => Math.max(0, -(Number.parseFloat(value) || 0));
      return {
        width: bounds.width + expansion(hitArea.left) + expansion(hitArea.right),
        height: bounds.height + expansion(hitArea.top) + expansion(hitArea.bottom),
      };
    }));
    if (!targets.length || targets.some(target => target.width < 44 || target.height < 44)) throw new Error("mobile control target failed");
    stage = "mobile-theme-control";
    const themeButton = mobile.getByRole("button", { name: /Use (?:light|dark) theme/ });
    await themeButton.waitFor();
    const themeLabel = await themeButton.getAttribute("aria-label");
    const expectedTheme = themeLabel === "Use dark theme" ? "dark" : themeLabel === "Use light theme" ? "light" : undefined;
    if (!expectedTheme) throw new Error("theme control label failed");
    stage = "mobile-theme-change";
    await themeButton.click();
    await mobile.waitForFunction(theme => document.documentElement.classList.contains(theme), expectedTheme);
    stage = "mobile-cookie";
    if ((await mobileContext.cookies(baseURL)).some(cookie => !cookie.httpOnly || !cookie.secure || cookie.sameSite !== "Strict")) throw new Error("mobile session cookie policy failed");
  } finally {
    await mobileContext.close();
  }

  stage = "forbidden-method";
  const forbidden = await context.request.post(`${baseURL}/api/v1/summary`, {
    headers: { Origin: baseURL, "Content-Type": "application/json" },
    data: { requestVersion: "1.0.0" },
  });
  if (forbidden.status() !== 404) throw new Error("forbidden method was not rejected");

  stage = "expiry";
  await controller("/expire");
  await page.reload({ waitUntil: "networkidle" });
  await page.locator('[data-read-state="denied"]').first().waitFor();

  stage = "revocation";
  await createSession();
  await controller("/revoke");
  await page.reload({ waitUntil: "networkidle" });
  await page.locator('[data-read-state="denied"]').first().waitFor();

  stage = "logout";
  await createSession();
  const logout = await context.request.post(`${baseURL}/api/v1/session/logout`, {
    headers: { Origin: baseURL, "Content-Type": "application/json" },
    data: { requestVersion: "1.0.0" },
  });
  if (logout.status() !== 200) throw new Error("logout failed");
  const afterLogout = await context.request.get(`${baseURL}/api/v1/summary`);
  if (afterLogout.status() !== 401) throw new Error("logged-out session remained usable");

  stage = "identity-outage";
  await createSession();
  await controller("/provider-outage");
  const outage = await page.goto(`${baseURL}/`, { waitUntil: "domcontentloaded" });
  if (!outage || outage.status() !== 401) throw new Error("expired JWKS outage was accepted");
  const local = await controller("/local-status", "GET");
  if (local.status !== "succeeded") throw new Error("local recovery failed during identity outage");

  process.stdout.write(`${JSON.stringify({ schemaVersion: 1, check: "phase-3-real-server", status: "pass" })}\n`);
} catch {
  process.stderr.write(`PROBE_FAILED:${stage}\n`);
  process.exitCode = 1;
} finally {
  await browser.close();
}
