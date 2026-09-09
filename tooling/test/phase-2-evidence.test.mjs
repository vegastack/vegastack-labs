import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import { collectIntegratedFacts, validateEvidence } from "../verify-phase-2.mjs";

const ROOT = path.resolve(import.meta.dirname, "../..");

async function loadManifest() {
  return JSON.parse(await readFile(path.join(ROOT, "tooling/phase-2-evidence.json"), "utf8"));
}

test("every Phase 2 requirement has one owner and evidence", async () => {
  const manifest = await loadManifest();
  const broken = structuredClone(manifest);
  broken.requirements[0].scenarioIds = [];
  const result = validateEvidence(broken, await collectIntegratedFacts(ROOT));
  assert.equal(result.status, "fail");
  assert.deepEqual(result.codes, ["PHASE2_TRACEABILITY_GAP"]);
});

test("contract drift, mutation availability, fixture reachability, and stale children fail closed", async () => {
  const manifest = await loadManifest();
  const facts = await collectIntegratedFacts(ROOT);

  for (const [field, mutate, expected] of [
    ["routes", (copy) => copy.endpointIds.push("api.v1.plans.create"), "PHASE2_CONTRACT_DRIFT"],
    ["commands", (copy) => copy.availableCommands.push("apply"), "PHASE2_MUTATION_AVAILABLE"],
    ["production", (copy) => { copy.productionImports.push("internal/phase2fixture"); }, "PHASE2_PRODUCTION_BYPASS"],
    ["children", (copy) => { copy.children[0].state = "OPEN"; }, "PHASE2_CHILD_INCOMPLETE"],
  ]) {
    const copy = structuredClone(facts);
    mutate(copy);
    const result = validateEvidence(manifest, copy);
    assert.ok(result.codes.includes(expected), `${field}: ${JSON.stringify(result)}`);
  }
});

test("the checked manifest matches the merged Phase 2 contract", async () => {
  const manifest = await loadManifest();
  const first = validateEvidence(manifest, await collectIntegratedFacts(ROOT));
  const second = validateEvidence(manifest, await collectIntegratedFacts(ROOT));
  assert.deepEqual(first, second);
  assert.deepEqual(first, { status: "pass", codes: [], scenarios: manifest.scenarios.map(({ id }) => id) });
});
