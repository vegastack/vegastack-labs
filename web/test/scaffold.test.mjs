import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (relativePath) => readFile(new URL(`../${relativePath}`, import.meta.url), "utf8");
const readJson = async (relativePath) => JSON.parse(await read(relativePath));

test("the web scaffold remains a static server component", async () => {
  const [config, layout, page] = await Promise.all([
    read("next.config.ts"),
    read("app/layout.tsx"),
    read("app/page.tsx"),
  ]);

  assert.match(config, /output:\s*["']export["']/);
  assert.match(config, /unoptimized:\s*true/);
  assert.doesNotMatch(`${layout}\n${page}`, /["']use client["']/);
  assert.doesNotMatch(`${layout}\n${page}`, /next\/(font|headers|server)/);
  assert.match(page, /ConsoleShell/);
  assert.match(page, /Data integration is not implemented/);
});

test("the public stylesheet has one design-system import", async () => {
  const stylesheet = await read("app/globals.css");
  const presetImports = stylesheet.match(/@vegastack\/design\/preset\.css/g) ?? [];

  assert.equal(presetImports.length, 1);
  assert.doesNotMatch(stylesheet, /@import\s+["']tailwindcss["']/);
});

test("registry configuration contains placeholders, never values", async () => {
  const components = JSON.parse(await read("components.json"));
  const headers = components.registries["@vegastack"].headers;

  assert.equal(headers["CF-Access-Client-Id"], "${CF_ACCESS_CLIENT_ID}");
  assert.equal(headers["CF-Access-Client-Secret"], "${CF_ACCESS_CLIENT_SECRET}");
});

test("the verified provider owns the one application provider boundary", async () => {
  const [layout, provider, lock] = await Promise.all([
    read("app/layout.tsx"),
    read("components/ui/provider.tsx"),
    readJson("../tooling/design-system-lock.json"),
  ]);

  assert.equal((layout.match(/<VegaStackProvider>/g) ?? []).length, 1);
  assert.match(layout, /suppressHydrationWarning/);
  assert.match(provider, /next-themes/);
  assert.equal(lock.registryVersion, "0.6.0");
});
