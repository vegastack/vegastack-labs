import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { REQUIRED_PHASE5_SCENARIOS } from "../verify-phase-5.mjs";

const ROOT = path.resolve(import.meta.dirname, "../..");
const CHILDREN = [102, 104, 123, 124, 125, 132, 133, 134, 135, 140, 141, 143, 144, 146, 153, 159, 106, 114, 115, 117, 118, 154, 107, 108, 109, 110, 111];
const CREDENTIAL_CHILDREN = [123, 124, 125, 132, 133, 134, 135, 140, 141, 143, 144, 146, 153, 159];

async function loadEvidence() {
  return JSON.parse(await readFile(path.join(ROOT, "tooling/phase-5-exit-evidence.json"), "utf8"));
}

test("accepted Phase 5 binds the operator words and unchanged-main proof", async () => {
  const evidence = await loadEvidence();
  assert.equal(evidence.schema, "vegastack-labs.dev/phase-evidence-definition");
  assert.equal(evidence.version, "1.0.0");
  assert.equal(evidence.phase, 5);
  assert.equal(evidence.status, "accepted");
  assert.deepEqual(evidence.acceptance, {
    operator: "omkarmohanta09",
    acceptedOn: "28-09-2026",
    sourceCommit: "9a433b43b59030285607435a8326814a311f3687",
    evidenceDigest: "sha256:a8f1bfa3ed33be295b690021eff83c88c612ce62c2c9bbffc0a140d5611bd6af",
    runs: ["https://github.com/vegastack/vegastack-labs/actions/runs/36416709341"],
    words: "accept phase 5",
  });
  assert.deepEqual(evidence.children.map(({ issue }) => issue), CHILDREN);
  assert.deepEqual(evidence.research.map(({ issue }) => issue), [103, 139, 145]);
  assert.deepEqual(evidence.maps, [{
    issue: 105,
    childIssues: CREDENTIAL_CHILDREN,
    status: "closed",
    evidence: "https://github.com/vegastack/vegastack-labs/issues/105#issuecomment-5809902263",
  }]);
  const proofIds = evidence.requirements.flatMap((item) => item.proofIds);
  assert.ok(REQUIRED_PHASE5_SCENARIOS.every(({ id }) => proofIds.includes(id)));
  assert.equal(evidence.proofCatalog.expectedScenarioCount, REQUIRED_PHASE5_SCENARIOS.length);
  assert.deepEqual(JSON.parse(await readFile(path.join(ROOT, evidence.proofCatalog.evidence), "utf8")).quarantined, []);
  for (const issue of [106, 117]) {
    assert.equal(evidence.children.find((child) => child.issue === issue).postMergeProof, "epic-phase-5-exit");
  }
});

test("Phase 5 records state acceptance and every live limitation", async () => {
  const [evidence, phase, overview, roadmap] = await Promise.all([
    loadEvidence(),
    readFile(path.join(ROOT, "docs/development/phases/05-evidence-secrets-backups-recovery.md"), "utf8"),
    readFile(path.join(ROOT, "docs/development/README.md"), "utf8"),
    readFile(path.join(ROOT, "docs/development/roadmap.md"), "utf8"),
  ]);
  for (const document of [phase, overview, roadmap]) assert.match(document, /Phase 5.*accepted/is);
  assert.match(phase, /9a433b43b59030285607435a8326814a311f3687/);
  assert.ok(evidence.limitations.some(({ id }) => id.startsWith("g-007.")));
  assert.ok(evidence.limitations.some(({ id }) => id.startsWith("g-008.")));
  assert.ok(evidence.limitations.every(({ status }) => status === "not-exercised"));
});
