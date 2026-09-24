import assert from "node:assert/strict";
import test from "node:test";

import {
  assertExactCleanCommit,
  assertLinuxPlatform,
  parsePhase5ExitArgs,
  runPhase5Exit,
  validatePhase5ExitDefinition,
  verifyPhase5Ancestry,
} from "../verify-phase-5-exit.mjs";

const SHA_A = "a".repeat(40);
const SHA_B = "b".repeat(40);

test("Phase 5 exit rejects another commit or dirty checkout", () => {
  assert.throws(
    () => assertExactCleanCommit({ expected: SHA_A, before: { head: SHA_B, defaultHead: SHA_A, clean: true }, after: { head: SHA_B, defaultHead: SHA_A, clean: true } }),
    /PHASE5_EXIT_COMMIT/,
  );
  assert.throws(
    () => assertExactCleanCommit({ expected: SHA_A, before: { head: SHA_A, defaultHead: SHA_A, clean: false }, after: { head: SHA_A, defaultHead: SHA_A, clean: true } }),
    /PHASE5_EXIT_CLEAN_TREE/,
  );
  assert.throws(
    () => assertExactCleanCommit({ expected: SHA_A, before: { head: SHA_A, defaultHead: SHA_B, clean: true }, after: { head: SHA_A, defaultHead: SHA_B, clean: true } }),
    /PHASE5_EXIT_COMMIT/,
  );
});

test("Phase 5 exit requires Linux proof", () => {
  assert.equal(assertLinuxPlatform("linux"), true);
  assert.throws(() => assertLinuxPlatform("darwin"), /PHASE5_EXIT_LINUX_REQUIRED/);
});

test("Phase 5 exit accepts only one exact commit argument", () => {
  assert.deepEqual(parsePhase5ExitArgs(["--commit", SHA_A]), { expectedCommit: SHA_A });
  for (const args of [[], ["--commit", "abc"], ["--commit", SHA_A, "extra"], ["--other", SHA_A]]) {
    assert.throws(() => parsePhase5ExitArgs(args), /PHASE5_EXIT_ARGUMENTS/);
  }
});

test("Phase 5 exit rejects missing, stale, or quarantined proof", async () => {
  const definition = await import("../phase-5-exit-evidence.json", { with: { type: "json" } }).then((module) => structuredClone(module.default));
  assert.equal(await validatePhase5ExitDefinition(definition), true);
  definition.requirements[0].proofIds = [];
  assert.throws(() => validatePhase5ExitDefinition(definition), /PHASE5_EXIT_DEFINITION/);
});

test("Phase 5 exit rejects review or post-merge proof from an earlier correction", async () => {
  const source = await import("../phase-5-exit-evidence.json", { with: { type: "json" } }).then((module) => module.default);

  const staleReview = structuredClone(source);
  const issue134 = staleReview.children.find(({ issue }) => issue === 134);
  issue134.reviewedHead = "1558da3".padEnd(40, "0");
  assert.throws(() => validatePhase5ExitDefinition(staleReview), /PHASE5_EXIT_DEFINITION/);

  const missingResearchReview = structuredClone(source);
  missingResearchReview.research.find(({ issue }) => issue === 145).review = null;
  assert.throws(() => validatePhase5ExitDefinition(missingResearchReview), /PHASE5_EXIT_DEFINITION/);
});

test("Phase 5 exit requires the accepted commit in current main history", async () => {
  const definition = await import("../phase-5-exit-evidence.json", { with: { type: "json" } }).then((module) => module.default);
  await assert.rejects(
    () => verifyPhase5Ancestry(".", definition, SHA_A, {
      run: async (_command, args) => {
        if (args[2] === "6bbb81231644c84ef34c8633e9de5671a4186180") throw new Error("not an ancestor");
      },
    }),
    /PHASE5_EXIT_ACCEPTANCE_HISTORY/,
  );
});

test("Phase 5 exit emits stable exact-commit evidence", async () => {
  const definition = await import("../phase-5-exit-evidence.json", { with: { type: "json" } }).then((module) => structuredClone(module.default));
  const state = async () => ({ head: SHA_A, defaultHead: SHA_A, clean: true });
  const result = await runPhase5Exit(".", {
    expectedCommit: SHA_A,
    platform: "linux",
    definition,
    acceptanceDefinition: await import("../testdata/phase-5/acceptance-scenarios.json", { with: { type: "json" } }).then((module) => module.default),
    acceptanceEvidence: await import("../phase-5-evidence.json", { with: { type: "json" } }).then((module) => module.default),
    readGitState: state,
    verifyChildren: async () => {},
    runChecks: async () => [
      { id: "public-check-catalog", status: "pass", quarantined: false },
      { id: "go-race-phase-5", status: "pass", quarantined: false },
    ],
    digestInputs: Object.fromEntries(definition.artifacts.map(({ path }) => [path, path])),
  });
  assert.equal(result.sourceCommit, SHA_A);
  assert.equal(result.defaultBranchRef, "refs/remotes/origin/main");
  assert.equal(result.cleanTree, true);
  assert.equal(result.status, "pass");
  assert.match(result.evidenceDigest, /^sha256:[a-f0-9]{64}$/);
  assert.ok(result.requirements.every((item) => item.sourceCommit === SHA_A && item.status === "pass" && item.quarantined === false));

  const repeat = await runPhase5Exit(".", {
    expectedCommit: SHA_A,
    platform: "linux",
    definition,
    acceptanceDefinition: await import("../testdata/phase-5/acceptance-scenarios.json", { with: { type: "json" } }).then((module) => module.default),
    acceptanceEvidence: await import("../phase-5-evidence.json", { with: { type: "json" } }).then((module) => module.default),
    readGitState: state,
    verifyChildren: async () => {},
    runChecks: async () => [
      { id: "public-check-catalog", status: "pass", quarantined: false },
      { id: "go-race-phase-5", status: "pass", quarantined: false },
    ],
    digestInputs: Object.fromEntries(definition.artifacts.map(({ path }) => [path, path])),
  });
  assert.equal(repeat.evidenceDigest, result.evidenceDigest);
});
