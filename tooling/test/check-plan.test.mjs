import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  checkStepsForPlan,
  classifyChangedPaths,
  fullCheckPlan,
  goPackageExecutionTargets,
  goPackageTargets,
  goUnitTestArgs,
} from "../lib/check-plan.mjs";
import {
  decodeExecutionPlan,
  encodeExecutionPlan,
  parseNameStatus,
  planForCommits,
} from "../check-affected.mjs";

const scenarios = JSON.parse(
  await readFile(new URL("../testdata/check-plan/scenarios.json", import.meta.url), "utf8"),
);
const ROOT = fileURLToPath(new URL("../..", import.meta.url));

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
  "Phase 3 browser evidence",
  "Phase 4 adversarial acceptance",
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

test("Go-only changes omit only the four Chromium-backed Go acceptance tests", () => {
  const goOnly = classifyChangedPaths([{ status: "M", path: "internal/store/backup.go" }]);
  assert.equal(goOnly.browser, false);
  assert.ok(checkStepsForPlan(goOnly).some((step) => step.name === "Go unit tests"));
  assert.deepEqual(goUnitTestArgs(false), [
    "test", "./...", "-skip",
    "^(TestPhase3AcceptanceChromiumUsesRealTLSAndSessionBoundary|TestPhase4AcceptanceBuiltExecutableKeepsIntentInertAndPrivate|TestPhase4ConsoleChangesUseRealTLSAndServerOwnedApprovalBoundary|TestPhase4ConsoleChangesCompleteApprovedResumeAndCancelLoopsOverRealTLS)$",
  ]);
  assert.deepEqual(goUnitTestArgs(true), ["test", "./..."]);
  assert.deepEqual(goPackageTargets(goOnly), ["./internal/store"]);
  assert.deepEqual(goUnitTestArgs(false, goPackageTargets(goOnly)), [
    "test", "./internal/store", "-skip",
    "^(TestPhase3AcceptanceChromiumUsesRealTLSAndSessionBoundary|TestPhase4AcceptanceBuiltExecutableKeepsIntentInertAndPrivate|TestPhase4ConsoleChangesUseRealTLSAndServerOwnedApprovalBoundary|TestPhase4ConsoleChangesCompleteApprovedResumeAndCancelLoopsOverRealTLS)$",
  ]);
  const twoPackages = classifyChangedPaths([
    { status: "M", path: "internal/server/server.go" },
    { status: "A", path: "internal/store/new_test.go" },
  ]);
  assert.deepEqual(goPackageTargets(twoPackages), ["./internal/server", "./internal/store"]);
  const schema = classifyChangedPaths([{ status: "M", path: "schemas/v1/server-profile.schema.json" }]);
  assert.deepEqual(goPackageTargets(schema), ["./..."], "non-Go inputs selecting Go must retain the full package set");
  assert.equal(fullCheckPlan().browser, true);
  for (const file of [
    "internal/server/phase3_acceptance_linux_test.go",
    "internal/server/phase4_acceptance_linux_test.go",
    "internal/server/phase4_console_acceptance_linux_test.go",
    "internal/server/phase4_fixture_test.go",
  ]) {
    assert.equal(classifyChangedPaths([{ status: "M", path: file }]).browser, true, file);
  }
});

test("deleted or renamed Go packages fail closed", () => {
  for (const change of [
    { status: "D", path: "internal/store/old.go" },
    { status: "R100", previousPath: "internal/store/old.go", path: "internal/store/new.go" },
  ]) {
    const plan = classifyChangedPaths([change]);
    assert.equal(plan.mode, "full");
    assert.equal(plan.failClosed, true);
    assert.deepEqual(goPackageTargets(plan), ["./..."]);
  }
});

test("Linux-only changed packages use their supported target", () => {
  const plan = classifyChangedPaths([
    { status: "M", path: "internal/adapter/nativecredential/authority_linux.go" },
  ]);
  assert.deepEqual(goPackageExecutionTargets(plan), [{
    package: "./internal/adapter/nativecredential",
    env: { GOOS: "linux", GOARCH: "amd64" },
  }]);
});

test("Linux-only affected vet and tests are host-runnable", async () => {
  const plan = classifyChangedPaths([
    { status: "M", path: "internal/adapter/nativecredential/authority_linux.go" },
  ]);
  const goSteps = checkStepsForPlan(plan).filter((step) =>
    step.name === "Go vet" || step.name === "Go unit tests");
  assert.equal(goSteps.length, 2);
  for (const step of goSteps) await step.run(ROOT, { capture: true });
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

test("execution consumes the exact safely framed plan without reclassifying it", () => {
  const base = "1".repeat(40);
  const head = "2".repeat(40);
  const planned = fullCheckPlan("unreadable-diff");
  const encoded = encodeExecutionPlan(planned, base, head);
  const decoded = decodeExecutionPlan(encoded);

  assert.deepEqual(decoded, { schemaVersion: 1, baseSha: base, headSha: head, plan: planned });
  assert.equal(decoded.plan.mode, "full");
  assert.equal(decoded.plan.failClosed, true);
  assert.throws(() => decodeExecutionPlan(`${encoded}x`), /encoded check plan/);
});

test("embedded and public Console assets always select browser checks", () => {
  for (const status of ["A", "M", "D"]) {
    const plan = classifyChangedPaths([
      { status, path: "internal/consoleassets/dist/index.html" },
    ]);
    assert.equal(plan.browser, true);
    assert.deepEqual(plan.groups, ["always", "go", "tooling", "web", "browser"]);
  }
  const publicAsset = classifyChangedPaths([{ status: "A", path: "web/public/icon.svg" }]);
  assert.equal(publicAsset.browser, true);
  assert.deepEqual(publicAsset.groups, ["always", "tooling", "web", "browser"]);

  const renamed = classifyChangedPaths([{
    status: "R100",
    previousPath: "internal/consoleassets/dist/old.html",
    path: "docs/old-console.md",
  }]);
  assert.equal(renamed.browser, true);
});
