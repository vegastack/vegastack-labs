import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  executeAcceptanceScenarios,
  parseGoScenarioPass,
  parseNodeScenarioPass,
  parsePlaywrightScenarioPass,
} from "../lib/acceptance-scenarios.mjs";
import { runCommand } from "../lib/process.mjs";
import {
  cleanPhase5SourceState,
  executePhase5Scenarios,
  phase5Definitions,
  phase5FailureDiagnostic,
  phase5ScenarioDigest,
  REQUIRED_PHASE5_SCENARIOS,
  resolveLinuxOnlyAcceptancePaths,
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
      { id: "suite.deterministic-repeat", repeat: 3, seed: "phase5-concurrency-v1" },
    ],
  );

  const scenarios = Object.fromEntries(definition.scenarios.map(scenario => [scenario.id, scenario]));
  assert.equal(scenarios["suite.durable-boundary-complete"].selector, "TestPhase5AcceptanceDurableFaultMatrix");
  assert.equal(scenarios["suite.deterministic-repeat"].selector, "TestPhase5AcceptanceSeededConcurrency");
  assert.equal(scenarios["surface.cli-api-console-parity"].selector, "TestPhase5AcceptanceBuiltProcessRecoveryAndIsolation");
});

test("Phase 5 catalog resolves Linux build constraints instead of trusting environment labels", async () => {
  const { definition } = await phase5Definitions(ROOT);
  const linuxOnly = await resolveLinuxOnlyAcceptancePaths(ROOT, definition.scenarios);
  const classified = definition.scenarios.filter(({ path: file }) => linuxOnly.has(file));
  assert.ok(classified.length > 0);
  assert.ok(classified.every(({ environment }) => environment === "built-linux"));
  for (const id of [
    "gate.replaced-evidence-denied",
    "backup.corruption-denied",
    "audit.private-payload-redacted",
    "schedule.provider-outage-isolated",
  ]) {
    assert.equal(classified.find(scenario => scenario.id === id)?.environment, "built-linux");
  }
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

test("Phase 5 source binding rejects an untracked executable source", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "vsk-phase5-source-test-"));
  try {
    const runGit = (...args) => runCommand("git", args, { cwd: root, capture: true, timeoutMs: 30_000 });
    await runGit("init", "--quiet");
    await writeFile(path.join(root, "tracked.txt"), "tracked\n");
    await runGit("add", "tracked.txt");
    await runGit("-c", "user.name=Phase Five Test", "-c", "user.email=phase5@example.invalid", "commit", "--quiet", "-m", "fixture");
    assert.match(await cleanPhase5SourceState(root), /^[0-9a-f]{40}$/);

    await writeFile(path.join(root, "untracked-probe.mjs"), "process.exit(0);\n", { mode: 0o755 });
    await assert.rejects(() => cleanPhase5SourceState(root), /PHASE5_FAILED:source-dirty/);
    await rm(path.join(root, "untracked-probe.mjs"));

    const externalArtifact = path.join(await mkdtemp(path.join(tmpdir(), "vsk-phase5-external-artifact-")), "result.json");
    try {
      await writeFile(externalArtifact, "{}\n");
      assert.match(await cleanPhase5SourceState(root), /^[0-9a-f]{40}$/);
    } finally {
      await rm(path.dirname(externalArtifact), { recursive: true, force: true });
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Phase 5 scans failed child output before replacing it with a closed diagnostic", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "vsk-phase5-failure-output-"));
  const selector = "private failed child";
  try {
    await writeFile(path.join(root, "failure.test.mjs"), `
      import test from "node:test";
      test(${JSON.stringify(selector)}, () => {
        process.stderr.write("Authorization: Bearer private-child-value\\n");
        throw new Error("opaque child failure");
      });
    `);
    await assert.rejects(
      () => executeAcceptanceScenarios({
        root,
        phase: 5,
        definition: { scenarios: [{
          id: "suite.failed-child", kind: "node-test", path: "failure.test.mjs", selector,
          environment: "fixture", repeat: 1, seed: null,
        }] },
        scanCaptured: scanPhase5Captured,
      }),
      error => error.message === "PHASE5_FAILED:evidence-sanitizer" && !error.message.includes("private-child-value"),
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Phase 5 scans browser artifacts after scenario failure and before caller cleanup", async () => {
  const artifacts = await mkdtemp(path.join(tmpdir(), "vsk-phase5-failed-artifacts-"));
  try {
    const canaries = JSON.parse(await readFile(path.join(ROOT, "tooling/testdata/phase-3/private-canaries.json"), "utf8"));
    await writeFile(path.join(artifacts, "failed-browser.txt"), `${canaries.canaries[0]}\n`);
    await assert.rejects(
      () => executePhase5Scenarios(ROOT, { scenarios: [] }, {
        artifactRoot: artifacts,
        executeScenarios: async () => { throw new Error("PHASE5_FAILED:scenario-execution:browser.artifact-private-free"); },
      }),
      error => error.message === "PHASE5_FAILED:evidence-sanitizer" && !error.message.includes(canaries.canaries[0]),
    );
  } finally {
    await rm(artifacts, { recursive: true, force: true });
  }
});
