import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import {
  parseGoScenarioPass,
  parseNodeScenarioPass,
  parsePlaywrightScenarioPass,
  phase4ScenarioDigest,
  REQUIRED_PHASE4_SCENARIO_IDS,
  validatePhase4AcceptanceDefinition,
} from "../verify-phase-4.mjs";

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
  assert.deepEqual(evidence.requiredScenarioIds, REQUIRED_PHASE4_SCENARIO_IDS);
  assert.deepEqual(scenarios.scenarios.map(({ id }) => id), REQUIRED_PHASE4_SCENARIO_IDS);
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

  const colludingDefinition = structuredClone(scenarios);
  const colludingEvidence = structuredClone(evidence);
  colludingDefinition.scenarios.pop();
  colludingEvidence.requiredScenarioIds.pop();
  await assert.rejects(() => validatePhase4AcceptanceDefinition(ROOT, colludingDefinition, colludingEvidence), /PHASE4_FAILED:definition/);

  const nonTestProof = structuredClone(scenarios);
  nonTestProof.scenarios[0].path = "README.md";
  await assert.rejects(() => validatePhase4AcceptanceDefinition(ROOT, nonTestProof, evidence), /PHASE4_FAILED:definition/);
});

test("Phase 4 result parsers require an exact executed pass", () => {
  const goName = "TestExact/sub_case";
  const goPass = `${JSON.stringify({ Action: "run", Test: goName })}\n${JSON.stringify({ Action: "pass", Test: goName })}\n`;
  assert.doesNotThrow(() => parseGoScenarioPass(goPass, goName));
  assert.throws(() => parseGoScenarioPass("", goName), /PHASE4_FAILED:scenario-result/);
  assert.throws(() => parseGoScenarioPass(`${JSON.stringify({ Action: "skip", Test: goName })}\n`, goName), /PHASE4_FAILED:scenario-result/);

  const browserName = "exact browser proof";
  const browserPass = {
    errors: [], stats: { expected: 1, skipped: 0, unexpected: 0, flaky: 0 },
    suites: [{ specs: [{ title: browserName, tests: [{ status: "expected", expectedStatus: "passed", results: [{ status: "passed" }] }] }] }],
  };
  assert.doesNotThrow(() => parsePlaywrightScenarioPass(browserPass, browserName));
  assert.throws(() => parsePlaywrightScenarioPass({ suites: [] }, browserName), /PHASE4_FAILED:scenario-result/);
  const browserSkipped = structuredClone(browserPass);
  browserSkipped.suites[0].specs[0].tests[0].results[0].status = "skipped";
  assert.throws(() => parsePlaywrightScenarioPass(browserSkipped, browserName), /PHASE4_FAILED:scenario-result/);

  const nodeName = "exact node proof";
  assert.doesNotThrow(() => parseNodeScenarioPass(`ok 1 - ${nodeName}\n`, nodeName));
  assert.throws(() => parseNodeScenarioPass("TAP version 13\n", nodeName), /PHASE4_FAILED:scenario-result/);
  assert.throws(() => parseNodeScenarioPass(`ok 1 - ${nodeName} # TODO\n`, nodeName), /PHASE4_FAILED:scenario-result/);
});
