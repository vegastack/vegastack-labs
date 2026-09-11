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

test("all future-session mandates require one pre-PR full run and affected CI", async () => {
  for (const file of ["AGENTS.md", "docs/development/operating-mandate.md", ".vegastack/dev.md"]) {
    const text = await readFile(new URL(`../../${file}`, import.meta.url), "utf8");
    assert.match(text, /one successful.*pnpm check.*immediately before.*pull request/is, file);
    assert.match(text, /browser.*only.*browser-(?:facing|impacting)/is, file);
    assert.match(text, /fail(?:s|ed)? closed.*full/is, file);
    assert.match(text, /macOS 15.*primary/is, file);
    assert.match(text, /Ubuntu 24\.04.*Linux/is, file);
  }
});
