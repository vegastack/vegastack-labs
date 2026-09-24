import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  executeAcceptanceScenarios,
  parseGoScenarioPass,
  parseNodeScenarioPass,
  parsePlaywrightScenarioPass,
} from "../lib/acceptance-scenarios.mjs";
import {
  phase5Definitions,
  phase5FailureDiagnostic,
  phase5ScenarioDigest,
  REQUIRED_PHASE5_SCENARIOS,
  scanPhase5Captured,
  validatePhase5AcceptanceDefinition,
} from "../verify-phase-5.mjs";

const ROOT = new URL("../../", import.meta.url).pathname;

test("Phase 5 acceptance rejects a weakened, reordered, skipped, or falsely live scenario", async () => {
  const { definition, evidence } = await phase5Definitions(ROOT);
  assert.equal(await validatePhase5AcceptanceDefinition(ROOT, definition, evidence), true);
  const mutations = [
    copy => { copy.scenarios.pop(); },
    copy => { [copy.scenarios[0], copy.scenarios[1]] = [copy.scenarios[1], copy.scenarios[0]]; },
    copy => { copy.scenarios[0].expected.state = "weaker-state"; },
    copy => { copy.scenarios[0].expected.result = "skip"; },
    copy => { copy.scenarios[0].proofClass = "live"; },
  ];
  for (const mutate of mutations) {
    const changed = structuredClone(definition);
    mutate(changed);
    await assert.rejects(
      () => validatePhase5AcceptanceDefinition(ROOT, changed, evidence),
      /PHASE5_FAILED:definition/,
    );
  }
  const colluding = structuredClone(evidence);
  const shortened = structuredClone(definition);
  shortened.scenarios.pop();
  colluding.requiredScenarioIds.pop();
  await assert.rejects(
    () => validatePhase5AcceptanceDefinition(ROOT, shortened, colluding),
    /PHASE5_FAILED:definition/,
  );
});

test("Phase 5 catalog covers every durable boundary", async () => {
  const { definition, evidence } = await phase5Definitions(ROOT);
  assert.equal(definition.scenarios.length, 47);
  assert.deepEqual(definition.scenarios, REQUIRED_PHASE5_SCENARIOS);
  assert.deepEqual(evidence.requiredScenarioIds, REQUIRED_PHASE5_SCENARIOS.map(({ id }) => id));
  assert.deepEqual(evidence.quarantined, []);
  assert.deepEqual(new Set(definition.scenarios.map(({ seam }) => seam)), new Set([
    "gate", "credential", "backup-local", "backup-offsite", "audit", "restore", "schedule", "surface", "suite",
  ]));
  assert.match(phase5ScenarioDigest(definition), /^sha256:[a-f0-9]{64}$/);
  for (const scenario of definition.scenarios) {
    assert.equal(scenario.proofClass, "fixture");
    assert.equal(scenario.expected.result, "pass");
    assert.equal(scenario.requirementId.endsWith(`.${scenario.id}`), true);
  }
  assert.deepEqual(
    definition.scenarios.filter(({ repeat }) => repeat > 1).map(({ id, repeat, seed }) => ({ id, repeat, seed })),
    [
      { id: "audit.concurrent-chain-single", repeat: 3, seed: "phase5-concurrency-v1" },
      { id: "schedule.overlap-single", repeat: 3, seed: "phase5-concurrency-v1" },
    ],
  );
});

test("Phase 5 exact-pass parsers enforce repeat counts", () => {
  const goName = "TestRepeated";
  const goPass = `${JSON.stringify({ Action: "pass", Test: goName })}\n`.repeat(2);
  assert.doesNotThrow(() => parseGoScenarioPass(goPass, goName, 2, 5));
  assert.throws(() => parseGoScenarioPass(goPass, goName, 1, 5), /PHASE5_FAILED:scenario-result/);

  const nodeName = "repeated node proof";
  const nodePass = `ok 1 - ${nodeName}\nok 2 - ${nodeName}\n`;
  assert.doesNotThrow(() => parseNodeScenarioPass(nodePass, nodeName, 2, 5));
  assert.throws(() => parseNodeScenarioPass(nodePass, nodeName, 1, 5), /PHASE5_FAILED:scenario-result/);

  const browserName = "repeated browser proof";
  const browserPass = {
    errors: [], stats: { expected: 2, skipped: 0, unexpected: 0, flaky: 0 },
    suites: [{ specs: [0, 1].map(() => ({
      title: browserName,
      tests: [{ status: "expected", expectedStatus: "passed", results: [{ status: "passed" }] }],
    })) }],
  };
  assert.doesNotThrow(() => parsePlaywrightScenarioPass(browserPass, browserName, 2, 5));
  browserPass.stats.flaky = 1;
  assert.throws(() => parsePlaywrightScenarioPass(browserPass, browserName, 2, 5), /PHASE5_FAILED:scenario-result/);
});

test("Phase 5 diagnostics and captured output never disclose child data", () => {
  assert.equal(
    phase5FailureDiagnostic(new Error("PHASE5_FAILED:scenario-result:restore.partial-fence-denied")),
    "Phase 5 verification failed at scenario-result (scenario restore.partial-fence-denied)\n",
  );
  assert.equal(
    phase5FailureDiagnostic(new Error("PHASE5_FAILED:scenario-result:private-value")),
    "Phase 5 verification failed at verification\n",
  );
  assert.equal(scanPhase5Captured({ stdout: "ok\n", stderr: "" }), true);
  assert.throws(
    () => scanPhase5Captured({ stdout: "", stderr: "Authorization: Bearer secret" }),
    /PHASE5_FAILED:evidence-sanitizer/,
  );
});

test("Phase 5 repeated scenarios receive the fixed named seed on every execution", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "vsk-phase5-seed-test-"));
  const file = "seed.test.mjs";
  const selector = "seeded acceptance child";
  try {
    await writeFile(path.join(root, file), `
      import assert from "node:assert/strict";
      import test from "node:test";
      test(${JSON.stringify(selector)}, () => {
        assert.equal(process.env.VSK_PHASE5_SEED, "phase5-concurrency-v1");
        assert.match(process.env.VSK_PHASE5_REPEAT ?? "", /^(?:0|1)$/);
      });
    `);
    const outcomes = await executeAcceptanceScenarios({
      root,
      phase: 5,
      definition: { scenarios: [{
        id: "suite.seed-test", kind: "node-test", path: file, selector,
        environment: "fixture", repeat: 2, seed: "phase5-concurrency-v1",
      }] },
      scanCaptured: scanPhase5Captured,
    });
    assert.deepEqual(outcomes, [{ id: "suite.seed-test", environment: "fixture", status: "pass" }]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
