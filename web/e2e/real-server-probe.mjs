import { chromium } from "@playwright/test";
import axe from "axe-core";

const baseURL = process.env.VSK_PHASE3_BASE_URL;
const controllerURL = process.env.VSK_PHASE3_CONTROLLER_URL;
const assertion = process.env.VSK_PHASE3_ASSERTION;

if (!baseURL || !controllerURL || !assertion) throw new Error("phase 3 fixture inputs are required");

const browser = await chromium.launch({ headless: true });
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

  async function createSession() {
    const response = await context.request.post(`${baseURL}/api/v1/session`, {
      headers: { Origin: baseURL, "Content-Type": "application/json" },
      data: { requestVersion: "1.0.0" },
    });
    if (response.status() !== 200) throw new Error("session bootstrap failed");
    const cookie = (await context.cookies(baseURL)).find(item => item.name === "vsk_labs_session");
    if (!cookie || !cookie.httpOnly || !cookie.secure || cookie.sameSite !== "Strict") throw new Error("session cookie policy failed");
  }

  await createSession();
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

  const forbidden = await context.request.post(`${baseURL}/api/v1/summary`, {
    headers: { Origin: baseURL, "Content-Type": "application/json" },
    data: { requestVersion: "1.0.0" },
  });
  if (forbidden.status() !== 405) throw new Error("forbidden method was not rejected");

  await controller("/expire");
  await page.reload({ waitUntil: "networkidle" });
  await page.locator('[data-read-state="denied"]').first().waitFor();

  await createSession();
  await controller("/revoke");
  await page.reload({ waitUntil: "networkidle" });
  await page.locator('[data-read-state="denied"]').first().waitFor();

  await createSession();
  const logout = await context.request.post(`${baseURL}/api/v1/session/logout`, {
    headers: { Origin: baseURL, "Content-Type": "application/json" },
    data: { requestVersion: "1.0.0" },
  });
  if (logout.status() !== 200) throw new Error("logout failed");
  const afterLogout = await context.request.get(`${baseURL}/api/v1/summary`);
  if (afterLogout.status() !== 401) throw new Error("logged-out session remained usable");

  await createSession();
  await controller("/provider-outage");
  const outage = await page.goto(`${baseURL}/`, { waitUntil: "domcontentloaded" });
  if (!outage || outage.status() !== 401) throw new Error("expired JWKS outage was accepted");
  const local = await controller("/local-status", "GET");
  if (local.status !== "succeeded") throw new Error("local recovery failed during identity outage");

  process.stdout.write(`${JSON.stringify({ schemaVersion: 1, check: "phase-3-real-server", status: "pass" })}\n`);
} finally {
  await browser.close();
}
