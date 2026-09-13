import assert from "node:assert/strict";
import test from "node:test";

import {
  assertExactCleanCommit,
  assertLinuxPlatform,
  parsePhase4ExitArgs,
  runPhase4Exit,
  validatePhase4ExitDefinition,
} from "../verify-phase-4-exit.mjs";

const SHA_A = "a".repeat(40);
const SHA_B = "b".repeat(40);

test("Phase 4 exit rejects another commit or dirty checkout", () => {
  assert.throws(
    () => assertExactCleanCommit({ expected: SHA_A, before: { head: SHA_B, defaultHead: SHA_A, clean: true }, after: { head: SHA_B, defaultHead: SHA_A, clean: true } }),
    /PHASE4_EXIT_COMMIT/,
  );
  assert.throws(
    () => assertExactCleanCommit({ expected: SHA_A, before: { head: SHA_A, defaultHead: SHA_A, clean: false }, after: { head: SHA_A, defaultHead: SHA_A, clean: true } }),
    /PHASE4_EXIT_CLEAN_TREE/,
  );
  assert.throws(
    () => assertExactCleanCommit({ expected: SHA_A, before: { head: SHA_A, defaultHead: SHA_B, clean: true }, after: { head: SHA_A, defaultHead: SHA_B, clean: true } }),
    /PHASE4_EXIT_COMMIT/,
  );
});

test("Phase 4 exit requires Linux proof", () => {
  assert.equal(assertLinuxPlatform("linux"), true);
  assert.throws(() => assertLinuxPlatform("darwin"), /PHASE4_EXIT_LINUX_REQUIRED/);
});

test("Phase 4 exit accepts only one exact commit argument", () => {
  assert.deepEqual(parsePhase4ExitArgs(["--commit", SHA_A]), { expectedCommit: SHA_A });
  for (const args of [[], ["--commit", "abc"], ["--commit", SHA_A, "extra"], ["--other", SHA_A]]) {
    assert.throws(() => parsePhase4ExitArgs(args), /PHASE4_EXIT_ARGUMENTS/);
  }
});

test("Phase 4 exit rejects missing, stale, or quarantined proof", async () => {
  const definition = await import("../phase-4-exit-evidence.json", { with: { type: "json" } }).then((module) => structuredClone(module.default));
  assert.equal(await validatePhase4ExitDefinition(definition), true);
  definition.requirements[0].proofIds = [];
  assert.throws(() => validatePhase4ExitDefinition(definition), /PHASE4_EXIT_DEFINITION/);
});

test("Phase 4 exit rejects review or post-merge proof from an earlier correction", async () => {
  const source = await import("../phase-4-exit-evidence.json", { with: { type: "json" } }).then((module) => module.default);

  const staleReview = structuredClone(source);
  const issue79 = staleReview.children.find(({ issue }) => issue === 79);
  issue79.reviewedHead = "db23c640cc982f7ac6bd1bd0a5c35019cc2a0e11";
  issue79.review = "https://github.com/vegastack/vegastack-labs/issues/79#issuecomment-5655518082";
  assert.throws(() => validatePhase4ExitDefinition(staleReview), /PHASE4_EXIT_DEFINITION/);

  const premergeEvidence = structuredClone(source);
  premergeEvidence.children.find(({ issue }) => issue === 80).evidence =
    "https://github.com/vegastack/vegastack-labs/issues/80#issuecomment-5655881078";
  assert.throws(() => validatePhase4ExitDefinition(premergeEvidence), /PHASE4_EXIT_DEFINITION/);
});

test("Phase 4 exit emits stable exact-commit evidence", async () => {
  const definition = await import("../phase-4-exit-evidence.json", { with: { type: "json" } }).then((module) => structuredClone(module.default));
  const state = async () => ({ head: SHA_A, defaultHead: SHA_A, clean: true });
  const result = await runPhase4Exit(".", {
    expectedCommit: SHA_A,
    platform: "linux",
    definition,
    acceptanceDefinition: await import("../testdata/phase-4/acceptance-scenarios.json", { with: { type: "json" } }).then((module) => module.default),
    acceptanceEvidence: await import("../phase-4-evidence.json", { with: { type: "json" } }).then((module) => module.default),
    readGitState: state,
    verifyChildren: async () => {},
    runChecks: async () => [
      { id: "public-check-catalog", status: "pass", quarantined: false },
      { id: "go-race-full", status: "pass", quarantined: false },
    ],
    digestInputs: Object.fromEntries(definition.artifacts.map(({ path }) => [path, path])),
  });
  assert.equal(result.sourceCommit, SHA_A);
  assert.equal(result.defaultBranchRef, "refs/remotes/origin/main");
  assert.equal(result.cleanTree, true);
  assert.equal(result.status, "pass");
  assert.match(result.evidenceDigest, /^sha256:[a-f0-9]{64}$/);
  assert.ok(result.requirements.every((item) => item.sourceCommit === SHA_A && item.status === "pass" && item.quarantined === false));
});
