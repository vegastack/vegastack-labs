import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (relativePath) => readFile(new URL(`../${relativePath}`, import.meta.url), "utf8");

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
  assert.match(page, /Development scaffold/);
  assert.match(page, /does not expose/);
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
