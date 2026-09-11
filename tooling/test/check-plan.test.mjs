import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  checkStepsForPlan,
  classifyChangedPaths,
  fullCheckPlan,
} from "../lib/check-plan.mjs";
import { parseNameStatus, planForCommits } from "../check-affected.mjs";

const scenarios = JSON.parse(
  await readFile(new URL("../testdata/check-plan/scenarios.json", import.meta.url), "utf8"),
);

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

test("the complete plan preserves every existing check exactly once and in order", () => {
  const names = checkStepsForPlan(fullCheckPlan()).map((step) => step.name);
  assert.deepEqual(names, expectedCurrentStageNames);
  assert.equal(new Set(names).size, names.length);
});

test("browser runs only for browser impact and unknown input fails closed", () => {
  const docs = classifyChangedPaths([{ status: "M", path: "docs/README.md" }]);
  const server = classifyChangedPaths([{ status: "M", path: "internal/server/browser_auth.go" }]);
  const console = classifyChangedPaths([{ status: "M", path: "web/components/console-shell.tsx" }]);
  const fallback = fullCheckPlan("invalid-base");
  assert.equal(docs.browser, false);
  assert.equal(server.browser, true);
  assert.equal(console.browser, true);
  assert.equal(fallback.browser, true);
  assert.equal(fallback.failClosed, true);
  assert.equal(Object.hasOwn(docs, "linux"), false);
  assert.equal(Object.hasOwn(fallback, "linux"), false);
});

for (const scenario of scenarios) {
  test(`selector: ${scenario.name}`, () => {
    const plan = classifyChangedPaths(scenario.changes);
    assert.equal(plan.mode, scenario.mode);
    assert.equal(plan.browser, scenario.browser);
    assert.equal(plan.failClosed, scenario.failClosed);
    assert.deepEqual(plan.groups, scenario.groups);
    assert.deepEqual(plan.changedPaths, scenario.changedPaths);
  });
}

test("selection is deterministic and never duplicates a check", () => {
  const changes = [
    { status: "M", path: "web/components/console-shell.tsx" },
    { status: "M", path: "internal/api/router.go" },
    { status: "M", path: "web/components/console-shell.tsx" },
  ];
  const first = classifyChangedPaths(changes);
  const second = classifyChangedPaths([...changes].reverse());
  assert.deepEqual(first, second);
  const names = checkStepsForPlan(first).map((step) => step.name);
  assert.equal(new Set(names).size, names.length);
});

test("NUL-delimited rename and deletion records retain every affected path", () => {
  assert.deepEqual(parseNameStatus("R100\0internal/api/session.go\0docs/session.md\0D\0web/e2e/old.spec.ts\0"), [
    { status: "R100", path: "docs/session.md", previousPath: "internal/api/session.go" },
    { status: "D", path: "web/e2e/old.spec.ts" },
  ]);
});

test("missing and invalid commit inputs select the complete lane", async () => {
  assert.equal((await planForCommits(undefined, undefined)).failClosed, true);
  assert.equal((await planForCommits("bad", "also-bad")).browser, true);
});
