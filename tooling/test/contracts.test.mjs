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
