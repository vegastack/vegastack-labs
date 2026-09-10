import { expect, test } from "@playwright/test";

test("keyboard, themes, states, and responsive shell work without browser errors", async ({ page }) => {
  const errors: string[] = [];
  const external: string[] = [];
  page.on("console", message => message.type() === "error" && errors.push(message.text()));
  page.on("request", request => new URL(request.url()).hostname !== "127.0.0.1" && external.push(request.url()));

  await page.goto("/");
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "Skip to main content" })).toBeFocused();
  await expect(page.getByRole("navigation", { name: "Console navigation" })).toBeVisible();
  await expect(page.getByText(/data integration is not implemented/i)).toBeVisible();

  const theme = page.getByRole("button", { name: /theme/i });
  await theme.click();
  await expect(page.locator("html")).toHaveClass(/dark/);
  await page.reload();
  await expect(page.locator("html")).toHaveClass(/dark/);

  await page.goto("/states");
  for (const kind of ["loading", "empty", "error", "unavailable"]) {
    await expect(page.locator(`[data-console-state="${kind}"]`)).toBeVisible();
  }
  expect(errors).toEqual([]);
  expect(external).toEqual([]);
});

test("mobile layout exposes the navigation trigger", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await expect(page.getByRole("button", { name: /sidebar/i })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
});
