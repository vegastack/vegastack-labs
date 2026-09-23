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

test("future-session mandates require local affected proof and manual-only Phase 5 CI", async () => {
  const files = ["AGENTS.md", "docs/development/operating-mandate.md", ".vegastack/dev.md"];
  for (const file of files) {
    const text = await readFile(new URL(`../../${file}`, import.meta.url), "utf8");
    assert.match(text, /local `pnpm check:affected`/i, file);
    assert.match(text, /exact.*remote.*main.*exact.*(?:branch )?head/is, file);
    assert.match(text, /(?:no `pull_request` or `push` trigger|pull requests and `main` pushes.*(?:no CI|do not trigger Public CI)|no automatic pull-request)/is, file);
    assert.match(text, /(?:workflow_dispatch.*(?:final Phase 5|complete final Phase 5)|(?:final Phase 5|complete final Phase 5).*workflow_dispatch)/is, file);
    assert.match(text, /vsk-node-01.*vsk-node-06/is, file);
    assert.match(text, /disposable/is, file);
  }
  for (const file of files.slice(0, 2)) {
    const text = await readFile(new URL(`../../${file}`, import.meta.url), "utf8");
    assert.match(text, /complete final Phase 5 integration\/acceptance lane|complete final Phase 5 integration or acceptance lane/is, file);
  }
  const profile = await readFile(new URL("../../.vegastack/dev.md", import.meta.url), "utf8");
  assert.match(profile, /^ship-check: local-affected-exact-head\b/m);
  assert.match(profile, /configured local affected command once/i);
  assert.match(profile, /Public CI has only a manual `workflow_dispatch` trigger/i);
  assert.match(profile, /final Phase 5 integration\/acceptance candidate alone.*full_check/is);
});
