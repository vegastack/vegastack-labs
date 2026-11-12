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
  await page.getByLabel("Machine address", { exact: true }).fill("192.0.2.10");
  await expect(guidance).toBeVisible();
  await help.click();
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
