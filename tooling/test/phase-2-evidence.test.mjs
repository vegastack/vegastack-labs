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
    ["routes", (copy) => copy.endpointIds.shift(), "PHASE2_CONTRACT_DRIFT"],
    ["commands", (copy) => { copy.mutationAvailable = true; }, "PHASE2_MUTATION_AVAILABLE"],
    ["production", (copy) => { copy.productionImports.push("github.com/vegastack/vegastack-labs/internal/testsupport"); }, "PHASE2_PRODUCTION_BYPASS"],
    ["children", (copy) => { copy.children[0].state = "OPEN"; }, "PHASE2_CHILD_INCOMPLETE"],
  ]) {
    const copy = structuredClone(facts);
    mutate(copy);
    const result = validateEvidence(manifest, copy);
    assert.ok(result.codes.includes(expected), `${field}: ${JSON.stringify(result)}`);
  }
});

test("later additive contracts do not rewrite accepted Phase 2 evidence", async () => {
  const manifest = await loadManifest();
  const facts = await collectIntegratedFacts(ROOT);
  assert.ok(facts.endpointIds.includes("api.v1.sources.list"));
  assert.ok(facts.productionImports.includes("github.com/vegastack/vegastack-labs/internal/consoleassets"));
  facts.endpointIds.push("api.v1.future-read.get");
  facts.availableCommands.push("future read");
  facts.migrations.push({ file: "0005_future.sql", sha256: "future" });
  const result = validateEvidence(manifest, facts);
  assert.equal(result.status, "pass", JSON.stringify(result));
});

test("the checked manifest matches the merged Phase 2 contract", async () => {
  const manifest = await loadManifest();
  const first = validateEvidence(manifest, await collectIntegratedFacts(ROOT));
  const second = validateEvidence(manifest, await collectIntegratedFacts(ROOT));
  assert.deepEqual(first, second);
  assert.deepEqual(first, { status: "pass", codes: [], scenarios: manifest.scenarios.map(({ id }) => id) });
});
