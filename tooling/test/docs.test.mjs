import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { githubSlug, verifyDocumentation } from "../verify-docs.mjs";

test("GitHub-style heading slugs are stable", () => {
  assert.equal(githubSlug("Security, failure, and recovery"), "security-failure-and-recovery");
});

test("missing local links fail closed", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "vegastack-docs-"));
  await mkdir(path.join(root, "docs"));
  await writeFile(path.join(root, "README.md"), "[missing](docs/missing.md)\n", "utf8");

  await assert.rejects(verifyDocumentation(root), /missing target/);
});

test("valid links, fragments, and JSON pass", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "vegastack-docs-"));
  await mkdir(path.join(root, "docs"));
  await writeFile(path.join(root, "README.md"), "[section](docs/guide.md#safe-section)\n", "utf8");
  await writeFile(path.join(root, "docs/guide.md"), "# Safe section\n", "utf8");
  await writeFile(path.join(root, "fixture.json"), '{"valid":true}\n', "utf8");

  const result = await verifyDocumentation(root);
  assert.deepEqual(result, { markdownFiles: 2, jsonFiles: 1 });
});

test("future-session mandates require one selected complete pre-PR proof and affected CI", async () => {
  const files = ["AGENTS.md", "docs/development/operating-mandate.md", ".vegastack/dev.md"];
  for (const file of files) {
    const text = await readFile(new URL(`../../${file}`, import.meta.url), "utf8");
    assert.match(text, /one successful complete public check.*exact clean.*branch head/is, file);
    assert.match(text, /browser.*only.*browser-(?:facing|impacting)/is, file);
    assert.match(text, /fail(?:s|ed)? closed.*full/is, file);
    assert.match(text, /pull request.*GitHub-hosted.*Ubuntu 24\.04/is, file);
    assert.match(text, /vsk-node-01.*vsk-node-06/is, file);
    assert.match(text, /disposable/is, file);
  }
  for (const file of files.slice(0, 2)) {
    const text = await readFile(new URL(`../../${file}`, import.meta.url), "utf8");
    assert.match(text, /pinned local.*pnpm check.*or.*manual Public CI/is, file);
  }
  const profile = await readFile(new URL("../../.vegastack/dev.md", import.meta.url), "utf8");
  assert.match(profile, /^ship-check: ci-full-exact-head\b/m);
  assert.match(profile, /manual full-mode Public CI run as that proof/i);
});
