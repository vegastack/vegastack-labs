import assert from "node:assert/strict";
import test from "node:test";
import { fullCheckPlan } from "../check-groups.mjs";

const expectedCurrentStageNames = [
  "repository safety and tool pins",
  "public CI policy",
  "documentation and JSON",
  "Phase 0.3 contract fixtures",
  "Phase 0.4 contract fixtures",
  "Phase 0.5 exit evidence",
  "Phase 2 integrated evidence",
  "historical artifacts",
  "pinned Design System source",
  "dependency provenance",
  "Go dependency provenance",
  "Go version",
  "Go formatting",
  "generated contracts",
  "web static build",
  "static export and embedded asset contract",
  "authorized read API boundary",
  "portable CLI boundary and target builds",
  "local control service boundary",
  "Go vet",
  "Go unit tests",
  "Go package build",
  "tooling tests",
  "web lint",
  "web typecheck",
  "web unit tests",
  "Console browser evidence",
  "Git whitespace",
];

test("the full group plan contains every current check exactly once in order", () => {
  const plan = fullCheckPlan();
  const names = plan.flatMap((group) => group.steps.map((step) => step.name));
  assert.deepEqual(names, expectedCurrentStageNames);
  assert.equal(new Set(names).size, expectedCurrentStageNames.length);
  assert.equal(names.at(-1), "Git whitespace");
});

test("group names and step arrays are immutable", () => {
  const plan = fullCheckPlan();
  assert.deepEqual([...new Set(plan.map((group) => group.name))].sort(), ["always", "browser", "go", "phase", "tooling", "web"]);
  assert.throws(() => plan.push({ name: "extra", steps: [] }), TypeError);
  assert.throws(() => plan[0].steps.push({ name: "extra" }), TypeError);
});
