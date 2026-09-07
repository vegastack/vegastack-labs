import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  loadPhaseZeroFiveEvidence,
  validateModuleOwnership,
  validatePhaseZeroFiveEvidence,
} from "../verify-phase-0-5.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

test("Phase 0.5 evidence rejects missing review proof and false CI success", async () => {
  const evidence = await loadPhaseZeroFiveEvidence(ROOT);
  const missingReview = structuredClone(evidence);
  missingReview.dependencies.find(({ issueNumber }) => issueNumber === 16).review.marker = null;
  assert.throws(
    () => validatePhaseZeroFiveEvidence(missingReview),
    /#16 requires clean review evidence/,
  );

  const falseSuccess = structuredClone(evidence);
  const billing = falseSuccess.limitations.find(
    ({ id }) => id === "github-actions-billing-lock",
  );
  billing.classification = "passed";
  assert.throws(
    () => validatePhaseZeroFiveEvidence(falseSuccess),
    /hosted CI must remain unavailable/,
  );
});

test("Phase 0.5 evidence binds every issue to its audited pull request and commit", async () => {
  const evidence = await loadPhaseZeroFiveEvidence(ROOT);

  for (const mutate of [
    (changed) => { changed.dependencies[0].issueState = "open"; },
    (changed) => { changed.dependencies[1].pullRequest.state = "closed"; },
    (changed) => { changed.dependencies[2].pullRequest.base = "release"; },
    (changed) => { changed.dependencies[3].pullRequest.head = "chore/widened"; },
    (changed) => { changed.dependencies[3].pullRequest.mergeCommit = "f".repeat(40); },
  ]) {
    const changed = structuredClone(evidence);
    mutate(changed);
    assert.throws(
      () => validatePhaseZeroFiveEvidence(changed),
      /must remain recorded as closed|pull-request binding/,
    );
  }
});

test("Phase 0.5 evidence distinguishes legacy summaries from marker-based evidence", async () => {
  const evidence = await loadPhaseZeroFiveEvidence(ROOT);
  const inventedLegacyMarker = structuredClone(evidence);
  inventedLegacyMarker.dependencies[0].evidence.marker = "type=evidence";
  assert.throws(
    () => validatePhaseZeroFiveEvidence(inventedLegacyMarker),
    /legacy evidence must not invent/,
  );

  const missingCurrentMarker = structuredClone(evidence);
  missingCurrentMarker.dependencies[3].evidence.marker = null;
  assert.throws(
    () => validatePhaseZeroFiveEvidence(missingCurrentMarker),
    /#17 requires marker-based implementation evidence/,
  );
});

test("Phase 0.5 evidence rejects duplicate IDs and non-GitHub references", async () => {
  const evidence = await loadPhaseZeroFiveEvidence(ROOT);
  const duplicate = structuredClone(evidence);
  duplicate.dependencies[1].issueNumber = duplicate.dependencies[0].issueNumber;
  assert.throws(
    () => validatePhaseZeroFiveEvidence(duplicate),
    /unknown or duplicate issue/,
  );

  const foreignUrl = structuredClone(evidence);
  foreignUrl.dependencies[0].evidence.url =
    "https://example.invalid/vegastack/vegastack-labs/issues/3#issuecomment-1";
  assert.throws(
    () => validatePhaseZeroFiveEvidence(foreignUrl),
    /public GitHub URL/,
  );
});

test("Phase 0.5 sanitization runs before schema errors and never echoes the value", async () => {
  const evidence = await loadPhaseZeroFiveEvidence(ROOT);
  const changed = structuredClone(evidence);
  const canary = `credential ${["ghp", "must", "not", "echo", "12345678901234567890"].join("_")}`;
  changed.dependencies[0].unexpectedSecretValue = canary;

  let message = "";
  try {
    validatePhaseZeroFiveEvidence(changed);
    assert.fail("expected sanitization to reject the secret-shaped field and value");
  } catch (error) {
    message = error.message;
  }
  assert.match(message, /prohibited/);
  assert.doesNotMatch(message, /must_not_echo/);
});

test("Phase 0.5 keeps the PR #20 merge-route divergence explicit", async () => {
  const evidence = await loadPhaseZeroFiveEvidence(ROOT);
  const changed = structuredClone(evidence);
  const merge = changed.limitations.find(({ id }) => id === "pr-20-non-squash-merge");
  merge.claim = "squash-route-conformant";
  assert.throws(
    () => validatePhaseZeroFiveEvidence(changed),
    /PR #20 must remain recorded as nonconformant/,
  );
});

test("Phase 0.5 pins the successful PR #21 post-merge result", async () => {
  const evidence = await loadPhaseZeroFiveEvidence(ROOT);
  assert.ok(evidence.postMerge, "postMerge evidence must exist");

  for (const [mutate, expected] of [
    [(changed) => { changed.postMerge.issue.state = "OPEN"; }, /Issue #18 must be closed/],
    [(changed) => { changed.postMerge.pullRequest.headCommit = "f".repeat(40); }, /PR #21 binding/],
    [(changed) => { changed.postMerge.pullRequest.mergeCommit = "e".repeat(40); }, /PR #21 binding/],
    [(changed) => { changed.postMerge.pullRequest.parentCount = 1; }, /PR #21 must remain a two-parent merge/],
    [(changed) => { changed.postMerge.hostedCheck.name = "Different check"; }, /PR #21 hosted check/],
    [(changed) => { changed.postMerge.hostedCheck.conclusion = "UNAVAILABLE"; }, /PR #21 hosted check must be successful/],
    [(changed) => { changed.postMerge.hostedCheck.runUrl = "https://github.com/vegastack/vegastack-labs/actions/runs/1"; }, /PR #21 hosted check/],
  ]) {
    const changed = structuredClone(evidence);
    mutate(changed);
    assert.throws(() => validatePhaseZeroFiveEvidence(changed), expected);
  }
});

test("Phase 0.5 distinguishes historical Issue #17 limitations from PR #21", async () => {
  const evidence = await loadPhaseZeroFiveEvidence(ROOT);
  const billing = evidence.limitations.find(({ id }) => id === "github-actions-billing-lock");
  const pr20 = evidence.limitations.find(({ id }) => id === "pr-20-non-squash-merge");
  const pr21 = evidence.limitations.find(({ id }) => id === "pr-21-non-squash-merge");

  assert.equal(billing?.scope, "issue-17-pr-20");
  assert.equal(pr20?.scope, "issue-17-pr-20");
  assert.equal(pr21?.scope, "issue-18-pr-21");
  assert.equal(evidence.postMerge.hostedCheck.conclusion, "SUCCESS");
});

test("module ownership rejects duplicate spines and a widened Phase 1 handoff", async () => {
  const evidence = await loadPhaseZeroFiveEvidence(ROOT);
  const duplicateOwner = structuredClone(evidence);
  duplicateOwner.moduleParents.find(({ issueNumber }) => issueNumber === 8).sharedSpine =
    duplicateOwner.moduleParents.find(({ issueNumber }) => issueNumber === 7).sharedSpine;
  assert.throws(
    () => validatePhaseZeroFiveEvidence(duplicateOwner),
    /shared spine owner must be unique/,
  );

  const widened = structuredClone(evidence);
  widened.phaseOneHandoff.authority = "implementation";
  assert.throws(
    () => validatePhaseZeroFiveEvidence(widened),
    /handoff authority must be planning-only/,
  );
});

test("module ownership requires every audited parent and exact delivery ownership", async () => {
  const evidence = await loadPhaseZeroFiveEvidence(ROOT);
  assert.deepEqual(validateModuleOwnership(evidence.moduleParents), {
    moduleParents: 9,
    sharedSpines: 9,
    phaseOneOwners: 4,
  });

  const missing = structuredClone(evidence.moduleParents);
  missing.pop();
  assert.throws(() => validateModuleOwnership(missing), /all nine module parents/);

  const wrongRole = structuredClone(evidence.moduleParents);
  wrongRole.find(({ issueNumber }) => issueNumber === 10).phaseOneRole = "managed-ci";
  assert.throws(() => validateModuleOwnership(wrongRole), /does not match its audited ownership/);
});

test("Phase 1 ordering rejects cycles and unknown prerequisites", async () => {
  const evidence = await loadPhaseZeroFiveEvidence(ROOT);
  const cycle = structuredClone(evidence);
  cycle.phaseOneHandoff.sequence.find(({ capability }) => capability === "metadata-graph").after =
    ["generated-cli-help-presentation"];
  assert.throws(
    () => validatePhaseZeroFiveEvidence(cycle),
    /order cycle/,
  );

  const unknown = structuredClone(evidence);
  unknown.phaseOneHandoff.sequence.find(({ capability }) => capability === "portable-contracts").after =
    ["unknown-capability"];
  assert.throws(
    () => validatePhaseZeroFiveEvidence(unknown),
    /unknown prerequisite/,
  );
});

test("current development documents name Phase 0.5 and preserve a planning-only handoff", async () => {
  const phase = await readFile(
    path.join(ROOT, "docs/development/phases/00-development-foundation.md"),
    "utf8",
  );
  const overview = await readFile(path.join(ROOT, "docs/development/README.md"), "utf8");
  assert.match(phase, /Phase 0 exit evidence/);
  assert.match(phase, /GitHub Actions.*billing.*unavailable/i);
  assert.match(phase, /two-parent.*PR #20/i);
  assert.match(phase, /metadata graph.*planning/i);
  assert.doesNotMatch(overview, /Issue 0\.2.*current approved development issue/);
});
