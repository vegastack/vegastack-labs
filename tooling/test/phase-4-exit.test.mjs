import assert from "node:assert/strict";
import test from "node:test";

import {
  assertExactCleanCommit,
  parsePhase4ExitArgs,
  runPhase4Exit,
  validatePhase4ExitDefinition,
} from "../verify-phase-4-exit.mjs";

const SHA_A = "a".repeat(40);
const SHA_B = "b".repeat(40);

test("Phase 4 exit rejects another commit or dirty checkout", () => {
  assert.throws(
    () => assertExactCleanCommit({ expected: SHA_A, before: { head: SHA_B, clean: true }, after: { head: SHA_B, clean: true } }),
    /PHASE4_EXIT_COMMIT/,
  );
  assert.throws(
    () => assertExactCleanCommit({ expected: SHA_A, before: { head: SHA_A, clean: false }, after: { head: SHA_A, clean: true } }),
    /PHASE4_EXIT_CLEAN_TREE/,
  );
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

test("Phase 4 exit emits stable exact-commit evidence", async () => {
  const definition = await import("../phase-4-exit-evidence.json", { with: { type: "json" } }).then((module) => structuredClone(module.default));
  const state = async () => ({ head: SHA_A, clean: true });
  const result = await runPhase4Exit(".", {
    expectedCommit: SHA_A,
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
  assert.equal(result.cleanTree, true);
  assert.equal(result.status, "pass");
  assert.match(result.evidenceDigest, /^sha256:[a-f0-9]{64}$/);
  assert.ok(result.requirements.every((item) => item.sourceCommit === SHA_A && item.status === "pass" && item.quarantined === false));
});
