import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (path) => readFile(new URL(`../${path}`, import.meta.url), "utf8");

test("stale or rejected plans cannot apply and browser has no acknowledgement authority", async () => {
  const review = await read("components/plan-review.tsx");
  assert.match(review, /authorizationCurrent|canApply/);
  assert.match(review, /rejected|expired|stale/i);
  assert.doesNotMatch(review, /approveAcknowledgement|acknowledgePlan|Slack token|fetch\(/i);
});

test("generated approval projection excludes protected proof and identity fields", async () => {
  const generated = await read("generated/read-api.ts");
  assert.match(generated, /ApprovalStatus/);
  assert.match(generated, /requestApproval/);
  assert.doesNotMatch(generated, /interface Acknowledgement\b/);
  for (const forbidden of ["humanId", "authorityId", "nonceDigest", "proofDigest", "acknowledgementId"]) {
    assert.doesNotMatch(generated, new RegExp(`readonly \\"${forbidden}\\"`));
  }
});

test("run workflow re-reads durable state and never resubmits after disconnect", async () => {
  const progress = await read("components/run-progress.tsx");
  assert.match(progress, /getRun|refetch/);
  assert.doesNotMatch(progress, /setInterval|fetch\(/);
});
