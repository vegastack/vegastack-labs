import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

// Preserve the accepted Phase 3 proof selector while #104 upgrades the view
// from a capability placeholder to generated, server-derived gate records.
test("Gates renders capability status without invented gate records or controls", async () => {
  const source = await readFile(new URL("../components/gates-view.tsx", import.meta.url), "utf8");
  assert.match(source, /readQueries\.gates/);
  assert.doesNotMatch(source, /const gateRecords|mockGates|approveGate|passGate|applyGate/);
});

test("Gates consumes generated derived blockers without approval controls", async () => {
  const source = await readFile(new URL("../components/gates-view.tsx", import.meta.url), "utf8");
  assert.match(source, /readQueries\.gates/);
  assert.match(source, /reasonCode/);
  assert.match(source, /not-applicable/);
  assert.match(source, /evidenceSource/);
  assert.doesNotMatch(source, /source: "gates"|Gate evaluation is not implemented/);
  assert.doesNotMatch(source, /approveGate|passGate|applyGate|force continue/i);
  assert.match(source, /GateEvidenceForm/);
  assert.match(source, /useCheckGate/);
});
