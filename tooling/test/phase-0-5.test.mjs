import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  loadPhaseZeroFiveEvidence,
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
