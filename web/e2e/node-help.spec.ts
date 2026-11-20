import { test, expect } from "@playwright/test";
import { installReadFixture } from "./api-fixture";

test("node field help is keyboard accessible and never submits a draft", async ({ page }) => {
  await installReadFixture(page);
  const writes: string[] = [];
  page.on("request", request => { if (request.url().includes("/api/") && request.method() !== "GET") writes.push(request.url()); });
  await page.goto("/nodes");
  await page.getByText("Add or prepare a node", { exact: true }).click();
  const help = page.getByRole("button", { name: "Help: Machine address", exact: true });
  await expect(help).toHaveAttribute("aria-expanded", "false");
  await help.focus();
  await page.keyboard.press("Enter");
  await expect(help).toHaveAttribute("aria-expanded", "true");
  const guidance = page.getByText("The approved IP address or DNS name for this machine, for example 192.0.2.10. Do not enter a URL or a group of machines.", { exact: true });
  await expect(guidance).toBeVisible();
  await page.getByRole("textbox", { name: "Machine address", exact: true }).fill("192.0.2.10");
  await expect(guidance).toBeHidden();
  await help.click();
  await expect(guidance).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(guidance).toBeHidden();
  await expect(page.getByLabel("Current server state revision", { exact: true }).first()).toHaveValue("");
  expect(writes).toEqual([]);
});

test("node repair explains administrator inputs and keeps execution unavailable without a file", async ({ page }) => {
  await installReadFixture(page);
  await page.goto("/nodes");
  await page.getByText("Repair or configure a node (administrator)", { exact: true }).click();
  await page.getByRole("button", { name: "Help: Administrator configuration file", exact: true }).click();
  await expect(page.getByText("This Console imports a prepared file; it does not generate these policies.", { exact: false })).toBeVisible();
  await expect(page.getByRole("button", { name: "Prepare security configuration draft", exact: true })).toBeDisabled();
  await page.getByRole("button", { name: "Help: Replacement request file", exact: true }).click();
  await expect(page.getByText("The file must reference existing records and contain no passwords or private keys.", { exact: false })).toBeVisible();
  await expect(page.getByRole("button", { name: "Prepare replacement draft", exact: true })).toBeDisabled();
});

test("node help icons stay beside their labels instead of occupying form columns", async ({ page }, testInfo) => {
  await installReadFixture(page);
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto("/nodes");
  await page.getByText("Add or prepare a node", { exact: true }).click();
  const fieldLabel = page.locator("label").filter({ hasText: /^Machine address$/ });
  const fieldHelp = page.getByRole("button", { name: "Help: Machine address", exact: true });
  const labelBox = (await fieldLabel.boundingBox())!;
  const helpBox = (await fieldHelp.boundingBox())!;
  expect(Math.abs(labelBox.y + labelBox.height / 2 - helpBox.y - helpBox.height / 2), "help must align with its label").toBeLessThan(4);
  const loginHelp = page.getByRole("button", { name: "Help: Discovery login method", exact: true });
  const login = page.getByLabel("Discovery login method", { exact: true });
  const loginBox = (await login.boundingBox())!;
  const loginHelpBox = (await loginHelp.boundingBox())!;
  expect(loginHelpBox.x, "login help must share the selector's column").toBeGreaterThanOrEqual(loginBox.x);
  expect(loginHelpBox.x + loginHelpBox.width).toBeLessThanOrEqual(loginBox.x + loginBox.width);
  await expect(fieldHelp.locator("svg")).toBeVisible();
  const before = (await page.getByRole("textbox", { name: "Machine address", exact: true }).boundingBox())!;
  await fieldHelp.hover();
  await expect(page.getByRole("dialog", { name: "Machine address", exact: true })).toBeVisible();
  const after = (await page.getByRole("textbox", { name: "Machine address", exact: true }).boundingBox())!;
  expect(after.y).toBe(before.y);
  await page.screenshot({ path: testInfo.outputPath("node-help-desktop.png"), animations: "disabled" });
  await page.keyboard.press("Escape");
  await expect(fieldHelp).toHaveAttribute("aria-expanded", "false");
});
