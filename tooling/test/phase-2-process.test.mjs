import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import { executeScenarioProofs } from "../verify-phase-2.mjs";

const ROOT = path.resolve(import.meta.dirname, "../..");

async function json(relative) {
  return JSON.parse(await readFile(path.join(ROOT, relative), "utf8"));
}

test("the integrated happy, parity, and production-trust scenarios execute from public fixtures", async () => {
  const expected = await json("tooling/testdata/phase-2/expected-scenarios.json");
  const manifest = await json("tooling/phase-2-evidence.json");
  const requiredScenarios = manifest.scenarios.filter(({ id, category }) =>
    category === "happy" || category === "parity" ||
    id === "read.event-reconnect" || id === "export.production-trust-blocked")
    .map(({ id }) => id);
  assert.deepEqual(expected.scenarios, requiredScenarios);
  const fixtures = {
    minimal: await json("tooling/testdata/phase-2/minimal-inventory.json"),
    labs: await readFile(path.join(ROOT, "tooling/testdata/phase-2/labs-sheet1.csv"), "utf8"),
  };
  assert.equal(fixtures.minimal.schema, "vegastack-labs.dev/inventory-draft-input");
  assert.equal(fixtures.minimal.schemaVersion, "1.0.0");
  assert.deepEqual(Object.keys(fixtures.minimal).sort(), [
    "addresses", "aliases", "assets", "nodes", "observations", "provenance", "schema", "schemaVersion", "source",
  ]);
  assert.equal(fixtures.labs.trim().split("\n").length, 2);
  assert.equal(fixtures.labs.split("\n", 1)[0].split(",").length, 15);

  const result = await executeScenarioProofs(manifest, ROOT, new Set(requiredScenarios));
  assert.deepEqual(result.scenarios, expected.scenarios);
  assert.deepEqual(result.codes, []);
  assert.equal(result.status, "pass");
});
