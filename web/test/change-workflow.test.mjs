import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (path) => readFile(new URL(`../${path}`, import.meta.url), "utf8");

test("stale or rejected plans cannot apply and browser has no acknowledgement authority", async () => {
  const review = await read("components/plan-review.tsx");
  assert.match(review, /authorizationCurrent|canApply/);
  assert.match(review, /rejected|expired|stale/i);
  assert.doesNotMatch(review, /approveAcknowledgement|acknowledgePlan|Slack token|(?:^|[^A-Za-z])fetch\(/i);
});

test("generated approval projection excludes protected proof and identity fields", async () => {
  const generated = await read("generated/read-api.ts");
  assert.match(generated, /ApprovalStatus/);
  assert.match(generated, /requestApproval/);
  const projection = generated.match(/export interface ApprovalStatus \{[\s\S]*?\n\}/)?.[0] ?? "";
  assert.notEqual(projection, "");
  assert.doesNotMatch(generated, /interface Acknowledgement\b/);
  for (const forbidden of ["humanId", "authorityId", "nonceDigest", "proofDigest", "acknowledgementId"]) {
    assert.doesNotMatch(projection, new RegExp(`readonly \\"${forbidden}\\"`));
  }
});

test("run workflow re-reads durable state and never resubmits after disconnect", async () => {
  const progress = await read("components/run-progress.tsx");
  assert.match(progress, /getRun|refetch/);
  assert.doesNotMatch(progress, /setInterval|(?:^|[^A-Za-z])fetch\(/);
});

test("approval and run views name every truthful state without color-only status", async () => {
  const [approval, progress, dialog] = await Promise.all([
    read("components/approval-status.tsx"),
    read("components/run-progress.tsx"),
    read("components/run-recovery-dialog.tsx"),
  ]);
  for (const state of ["pending", "approved", "rejected", "expired"]) assert.match(approval, new RegExp(state));
  for (const state of ["queued", "running", "partial", "failed", "cancelled", "interrupted", "succeeded"]) assert.match(progress, new RegExp(state));
  assert.match(progress, /aria-live/);
  assert.match(dialog, /AlertDialog/);
  assert.doesNotMatch([approval, progress, dialog].join("\n"), /Slack token|nonceDigest|proofDigest|acknowledgementId|(?:^|[^A-Za-z])fetch\(/i);
});
