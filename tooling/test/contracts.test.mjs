import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

test("the public lane checks generated contracts without writing them", async () => {
  const packageJson = JSON.parse(await readFile(path.join(ROOT, "package.json"), "utf8"));
  assert.equal(
    packageJson.scripts["generate:contracts"],
    "go run ./tooling/generate-contracts --write",
  );
  assert.equal(
    packageJson.scripts["check:contracts"],
    "go run ./tooling/generate-contracts --check",
  );

  const check = await readFile(path.join(ROOT, "tooling/check.mjs"), "utf8");
  assert.match(
    check,
    /stage\("generated contracts", "go", \["run", "\.\/tooling\/generate-contracts", "--check"\]\)/,
  );
  assert.doesNotMatch(check, /generate-contracts", "--write"/);
});

test("development docs expose the approved Phase 1 generated-contract boundary", async () => {
  const phase = await readFile(
    path.join(ROOT, "docs/development/phases/01-portable-executable-and-generated-contracts.md"),
    "utf8",
  );
  const contributing = await readFile(path.join(ROOT, "CONTRIBUTING.md"), "utf8");
  const phaseZero = await readFile(
    path.join(ROOT, "docs/development/phases/00-development-foundation.md"),
    "utf8",
  );
  assert.match(phase, /Issue #24.*Issue #25/is);
  assert.match(phase, /available.*planned/is);
  assert.match(phase, /G-018.*remain(?:s)? open/is);
  assert.match(contributing, /pnpm generate:contracts/);
  assert.match(contributing, /never edit.*generated/is);
  assert.match(phaseZero, /Issue #22.*PR #23.*9b57392/is);
  assert.doesNotMatch(phaseZero, /correction candidate/i);
});
