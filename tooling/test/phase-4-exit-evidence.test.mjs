import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

const ROOT = path.resolve(import.meta.dirname, "../..");

async function loadEvidence() {
  return JSON.parse(await readFile(path.join(ROOT, "tooling/phase-4-exit-evidence.json"), "utf8"));
}

test("Phase 4 exit maps every requirement to current exact-commit proof", async () => {
  const evidence = await loadEvidence();
  const acceptance = JSON.parse(await readFile(path.join(ROOT, evidence.proofCatalog.evidence), "utf8"));
  assert.equal(evidence.schema, "vegastack-labs.dev/phase-evidence-definition");
  assert.equal(evidence.version, "1.0.0");
  assert.equal(evidence.phase, 4);
  assert.equal(evidence.status, "accepted");
  assert.deepEqual(evidence.acceptance, {
    operator: "omkarmohanta09",
    acceptedOn: "14-09-2026",
    sourceCommit: "6bbb81231644c84ef34c8633e9de5671a4186180",
    evidenceDigest: "sha256:fc4803ea63fd18f8685648e2d3dba00fbc8d3484ac1691b936d8232c076bb82a",
    runs: [
      "https://github.com/vegastack/vegastack-labs/actions/runs/34787342900",
      "https://github.com/vegastack/vegastack-labs/actions/runs/34787841878",
    ],
  });
  assert.ok(evidence.requirements.length >= 8);
  assert.ok(evidence.requirements.every((item) => item.expectedStatus === "pass" && item.proofIds.length > 0));
  assert.equal(evidence.proofCatalog.expectedScenarioCount, 34);
  assert.equal(evidence.proofCatalog.expectedStatus, "pass");
  assert.equal(evidence.proofCatalog.quarantined, false);
  assert.deepEqual(acceptance.quarantined, []);
  assert.ok(evidence.limitations.some((item) => /No live Slack, provider, host, deployment, release, or fleet proof/i.test(item.statement)));
});

test("development records bind accepted Phase 4 to its exact main proof", async () => {
  const [evidence, phase, overview, roadmap, chronicle] = await Promise.all([
    loadEvidence(),
    readFile(path.join(ROOT, "docs/development/phases/04-declarations-plans-authorization-execution.md"), "utf8"),
    readFile(path.join(ROOT, "docs/development/README.md"), "utf8"),
    readFile(path.join(ROOT, "docs/development/roadmap.md"), "utf8"),
    readFile(path.join(ROOT, ".vegastack/chronicle.md"), "utf8"),
  ]);
  assert.equal(evidence.status, "accepted");
  for (const document of [phase, overview, roadmap, chronicle]) {
    assert.match(document, /Phase 4.*accepted/is);
    assert.match(document, /6bbb81231644c84ef34c8633e9de5671a4186180/);
  }
  assert.match(phase, /34787342900/);
  assert.match(phase, /34787841878/);
  assert.match(phase, /sha256:fc4803ea63fd18f8685648e2d3dba00fbc8d3484ac1691b936d8232c076bb82a/);
});
