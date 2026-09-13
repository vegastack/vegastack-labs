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
  assert.equal(evidence.status, "implemented-awaiting-operator-acceptance");
  assert.ok(evidence.requirements.length >= 8);
  assert.ok(evidence.requirements.every((item) => item.expectedStatus === "pass" && item.proofIds.length > 0));
  assert.equal(evidence.proofCatalog.expectedScenarioCount, 34);
  assert.equal(evidence.proofCatalog.expectedStatus, "pass");
  assert.equal(evidence.proofCatalog.quarantined, false);
  assert.deepEqual(acceptance.quarantined, []);
  assert.ok(evidence.limitations.some((item) => /No live Slack, provider, host, deployment, release, or fleet proof/i.test(item.statement)));
});

test("Phase 4 remains awaiting explicit operator acceptance", async () => {
  const [evidence, phase, chronicle] = await Promise.all([
    loadEvidence(),
    readFile(path.join(ROOT, "docs/development/phases/04-declarations-plans-authorization-execution.md"), "utf8"),
    readFile(path.join(ROOT, ".vegastack/chronicle.md"), "utf8"),
  ]);
  assert.equal(Object.hasOwn(evidence, "acceptance"), false);
  assert.match(phase, /^Status: implemented; awaiting exact-commit operator acceptance\./m);
  assert.doesNotMatch(phase, /^Status: accepted/m);
  assert.match(chronicle, /Phase 4 is implemented and awaits exact-commit acceptance/);
});
