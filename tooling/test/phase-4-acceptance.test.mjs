import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import { phase4ScenarioDigest, validatePhase4AcceptanceDefinition } from "../verify-phase-4.mjs";

const ROOT = path.resolve(import.meta.dirname, "../..");

async function definitions() {
  const [scenarios, evidence] = await Promise.all([
    readFile(path.join(ROOT, "tooling/testdata/phase-4/acceptance-scenarios.json"), "utf8").then(JSON.parse),
    readFile(path.join(ROOT, "tooling/phase-4-evidence.json"), "utf8").then(JSON.parse),
  ]);
  return { scenarios, evidence };
}

test("Phase 4 acceptance requires every hostile and recovery scenario", async () => {
  const { scenarios, evidence } = await definitions();
  assert.equal(await validatePhase4AcceptanceDefinition(ROOT, scenarios, evidence), true);
  assert.match(phase4ScenarioDigest(scenarios), /^sha256:[a-f0-9]{64}$/);
  assert.equal(evidence.quarantined.length, 0);
  assert.deepEqual(evidence.requiredScenarioIds, scenarios.scenarios.map(({ id }) => id));
});

test("Phase 4 acceptance rejects missing proof, hidden quarantine, and changed ordering", async () => {
  const { scenarios, evidence } = await definitions();
  const missing = structuredClone(scenarios);
  missing.scenarios.pop();
  await assert.rejects(() => validatePhase4AcceptanceDefinition(ROOT, missing, evidence), /PHASE4_FAILED:definition/);
  const quarantined = structuredClone(evidence);
  quarantined.quarantined.push(evidence.requiredScenarioIds[0]);
  await assert.rejects(() => validatePhase4AcceptanceDefinition(ROOT, scenarios, quarantined), /PHASE4_FAILED:definition/);
  const reordered = structuredClone(scenarios);
  reordered.scenarios.reverse();
  await assert.rejects(() => validatePhase4AcceptanceDefinition(ROOT, reordered, evidence), /PHASE4_FAILED:definition/);
});
