import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  assertExactCleanCommit,
  parsePhase3ExitArgs,
  runPhase3Exit,
  validatePhase3EvidenceDefinition,
} from "../verify-phase-3-exit.mjs";

const SHA_A = "a".repeat(40);
const SHA_B = "b".repeat(40);

test("Phase 3 exit accepts exactly one full lowercase commit", () => {
  assert.deepEqual(parsePhase3ExitArgs(["--commit", SHA_A]), { expectedCommit: SHA_A });
  for (const args of [
    [], ["--commit"], ["--commit", "abc1234"], ["--commit", SHA_A.toUpperCase()],
    ["--commit", SHA_A, "extra"], ["--commit", SHA_A, "--commit", SHA_A],
  ]) {
    assert.throws(() => parsePhase3ExitArgs(args), /PHASE3_EXIT_ARGUMENTS/);
  }
});

test("Phase 3 exit rejects another commit or a dirty tree", () => {
  assert.throws(() => assertExactCleanCommit({
    expected: SHA_A,
    before: { head: SHA_B, clean: true },
    after: { head: SHA_B, clean: true },
  }), /COMMIT/);
  assert.throws(() => assertExactCleanCommit({
    expected: SHA_A,
    before: { head: SHA_A, clean: false },
    after: { head: SHA_A, clean: true },
  }), /CLEAN/);
});

test("Phase 3 exit rejects head and tree changes after checks", () => {
  assert.throws(() => assertExactCleanCommit({
    expected: SHA_A,
    before: { head: SHA_A, clean: true },
    after: { head: SHA_B, clean: true },
  }), /COMMIT/);
  assert.throws(() => assertExactCleanCommit({
    expected: SHA_A,
    before: { head: SHA_A, clean: true },
    after: { head: SHA_A, clean: false },
  }), /CLEAN/);
});

test("the runner re-reads commit and cleanliness after checks", async () => {
  const root = await fixtureRoot();
  for (const after of [{ head: SHA_B, clean: true }, { head: SHA_A, clean: false }]) {
    const states = [{ head: SHA_A, clean: true }, after];
    await assert.rejects(
      () => runPhase3Exit(root, {
        expectedCommit: SHA_A,
        definition: validDefinition(),
        readGitState: async () => states.shift(),
        runChecks: passingChecks,
        digestInputs: Object.fromEntries(requiredArtifacts().map((item) => [item.path, item.id])),
      }),
      after.head === SHA_B ? /PHASE3_EXIT_COMMIT/ : /PHASE3_EXIT_CLEAN_TREE/,
    );
  }
});

test("Phase 3 definition rejects runtime fields and incomplete proof", async () => {
  const root = await fixtureRoot();
  const definition = validDefinition();
  assert.equal(validatePhase3EvidenceDefinition(definition, { root }), true);

  for (const mutate of [
    (copy) => { copy.sourceCommit = SHA_A; },
    (copy) => { copy.requirements[0].proofIds = []; },
    (copy) => { copy.proofs[0].expectedStatus = "skipped"; },
    (copy) => { copy.proofs[0].quarantined = true; },
  ]) {
    const copy = structuredClone(definition);
    mutate(copy);
    assert.throws(() => validatePhase3EvidenceDefinition(copy, { root }), /PHASE3_EXIT_DEFINITION/);
  }
});

test("identical facts produce an identical envelope and artifact changes alter its digest", async () => {
  const root = await fixtureRoot();
  const states = () => async () => ({ head: SHA_A, clean: true });
  const options = {
    expectedCommit: SHA_A,
    definition: validDefinition(),
    readGitState: states(),
    runChecks: passingChecks,
    digestInputs: Object.fromEntries(requiredArtifacts().map((item) => [item.path, `${item.id}\n`])),
  };
  const first = await runPhase3Exit(root, options);
  const second = await runPhase3Exit(root, { ...options, readGitState: states() });
  assert.deepEqual(first, second);
  assert.match(first.evidenceDigest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(first.sourceCommit, SHA_A);
  assert.equal(first.status, "pass");

  const changedInputs = { ...options.digestInputs, [requiredArtifacts()[0].path]: "changed\n" };
  const changed = await runPhase3Exit(root, {
    ...options, readGitState: states(), digestInputs: changedInputs,
  });
  assert.notEqual(changed.evidenceDigest, first.evidenceDigest);
});

test("missing, skipped, failed, or quarantined check proof fails closed", async () => {
  const root = await fixtureRoot();
  const base = {
    expectedCommit: SHA_A,
    definition: validDefinition(),
    readGitState: async () => ({ head: SHA_A, clean: true }),
    digestInputs: Object.fromEntries(requiredArtifacts().map((item) => [item.path, item.id])),
  };
  for (const result of [
    [],
    [{ id: "public-check-catalog", status: "skipped", quarantined: false }],
    [{ id: "public-check-catalog", status: "failed", quarantined: false }],
    [{ id: "public-check-catalog", status: "pass", quarantined: true }],
  ]) {
    await assert.rejects(
      () => runPhase3Exit(root, { ...base, runChecks: async () => result }),
      /PHASE3_EXIT_CHECKS/,
    );
  }
});

test("failure stages never expose paths, tokens, or cookies", async () => {
  const root = await fixtureRoot();
  const tokenCanary = ["ghp", "_abcdefghijklmnopqrstuvwxyz"].join("");
  const canary = `/private/worktree ${tokenCanary} cookie=session-secret`;
  await assert.rejects(
    () => runPhase3Exit(root, {
      expectedCommit: SHA_A,
      definition: validDefinition(),
      readGitState: async () => ({ head: SHA_A, clean: true }),
      runChecks: async () => { throw new Error(canary); },
    }),
    (error) => error.message === "PHASE3_EXIT_CHECKS" && !error.message.includes(canary),
  );
  await assert.rejects(
    () => runPhase3Exit(root, {
      expectedCommit: SHA_A,
      readGitState: async () => { throw new Error(canary); },
    }),
    (error) => error.message === "PHASE3_EXIT_GIT_STATE" && !error.message.includes(canary),
  );
});

function passingChecks() {
  return [
    { id: "public-check-catalog", status: "pass", quarantined: false },
    { id: "go-race-full", status: "pass", quarantined: false },
  ];
}

function requiredArtifacts() {
  return [
    ["static-definition", "tooling/phase-3-evidence.json"],
    ["command-registry", "schemas/v1/command-registry.json"],
    ["endpoint-registry", "schemas/v1/endpoint-registry.json"],
    ["generated-read-client", "web/generated/read-api.ts"],
    ["console-asset-manifest", "internal/consoleassets/manifest.json"],
  ].map(([id, artifactPath]) => ({ id, path: artifactPath, digestAtRuntime: true }));
}

function validDefinition() {
  const issueNumbers = [50, 51, 52, 53, 54, 55, 56, 57];
  const requirementIds = [
    "roadmap.phase-3",
    "module-1.embedded-read-service",
    "module-3.protected-browser-transport",
    "module-8.health-source-freshness",
    "module-9.console-read-experience",
    "shared.generated-browser-client",
    "shared.privacy-local-recovery",
  ];
  return {
    schema: "vegastack-labs.dev/phase-evidence-definition",
    version: "1.0.0",
    phase: 3,
    status: "implemented-awaiting-operator-acceptance",
    children: issueNumbers.map((issue, index) => ({
      issue,
      phaseIssue: `3.${index + 1}`,
      pr: issue + 27,
      mergeCommit: String(index + 1).repeat(40),
      evidence: `https://github.com/vegastack/vegastack-labs/issues/${issue}#issuecomment-${1000 + issue}`,
      review: `https://github.com/vegastack/vegastack-labs/pull/${issue + 27}#issuecomment-${2000 + issue}`,
    })),
    requirements: requirementIds.map((id, index) => ({
      id,
      ownerIssue: issueNumbers[index] ?? 57,
      module: id.split(".")[0],
      environment: "fixture",
      proofIds: [`proof-${index + 1}`],
      expectedStatus: "pass",
    })),
    proofs: requirementIds.map((_, index) => ({
      id: `proof-${index + 1}`,
      kind: "node-test",
      path: `proofs/proof-${index + 1}.test.mjs`,
      selector: null,
      environment: "fixture",
      expectedStatus: "pass",
      quarantined: false,
    })),
    commands: [
      { id: "public-check-catalog", argv: ["pnpm", "check"], environment: "fixture", expectedStatus: "pass" },
      { id: "go-race-full", argv: ["go", "test", "-race", "-count=1", "./..."], environment: "fixture", expectedStatus: "pass" },
    ],
    artifacts: requiredArtifacts(),
    limitations: [
      { id: "live-access", environment: "live", status: "not-exercised", statement: "Live provider access is separately gated." },
      { id: "browser-breadth", environment: "phase-11", status: "not-exercised", statement: "Wider browser coverage remains Phase 11 work." },
      { id: "subjective-focus", environment: "operator", status: "not-exercised", statement: "Subjective focus comfort awaits operator review." },
    ],
  };
}

async function fixtureRoot() {
  const root = await mkdtemp(path.join(tmpdir(), "vsk-phase3-exit-test-"));
  for (let index = 1; index <= 7; index += 1) {
    const filename = path.join(root, `proofs/proof-${index}.test.mjs`);
    await mkdir(path.dirname(filename), { recursive: true });
    await writeFile(filename, `// proof ${index}\n`);
  }
  return root;
}
