import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import { executeScenarioProofs } from "../verify-phase-2.mjs";

const ROOT = path.resolve(import.meta.dirname, "../..");

test("child denial and privacy proofs expose only stable scenario IDs", async () => {
  const manifest = JSON.parse(await readFile(path.join(ROOT, "tooling/phase-2-evidence.json"), "utf8"));
  const selected = new Set(manifest.scenarios.filter(({ category }) =>
    (category === "denial" || category === "privacy"))
    .filter(({ ownerIssue }) => ownerIssue !== 38).map(({ id }) => id));
  assert.deepEqual(manifest.scenarios.filter(({ ownerIssue }) => ownerIssue === 38)
    .map(({ id, proof }) => [id, proof]), [
    ["phase2.no-mutation", "node-test:tooling/test/phase-2-mutation.test.mjs"],
    ["phase2.production-closure", "node-test:tooling/test/phase-2-evidence.test.mjs"],
  ]);
  const result = await executeScenarioProofs(manifest, ROOT, selected);
  assert.equal(result.status, "pass");
  assert.deepEqual(result.codes, []);
  assert.deepEqual(result.scenarios, [...selected]);
  assert.doesNotMatch(JSON.stringify(result), /password|private.key|bearer|cookie|authorization/i);
});
