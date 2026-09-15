import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("Gates consumes generated derived blockers without approval controls", async () => {
  const source = await readFile(new URL("../components/gates-view.tsx", import.meta.url), "utf8");
  assert.match(source, /readQueries\.gates/);
  assert.match(source, /reasonCode/);
  assert.match(source, /not-applicable/);
  assert.match(source, /evidenceSource/);
  assert.doesNotMatch(source, /source: "gates"|Gate evaluation is not implemented/);
  assert.doesNotMatch(source, /<Button|approveGate|passGate|applyGate/);
});
