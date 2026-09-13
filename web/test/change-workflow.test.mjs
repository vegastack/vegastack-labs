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
  const [progress, queries, changeQueries, workspace, review] = await Promise.all([
    read("components/run-progress.tsx"),
    read("lib/run-queries.ts"),
    read("lib/change-queries.ts"),
    read("components/changes-workspace.tsx"),
    read("components/plan-review.tsx"),
  ]);
  assert.match(progress, /getRun|refetch/);
  assert.match(queries, /while \(!controller\.signal\.aborted\)/);
  assert.match(queries, /lastEventId:\s*lastEventId\.current/);
  assert.match(queries, /await refetch\(\)[\s\S]*streamEvents/);
  assert.doesNotMatch(progress, /setInterval|(?:^|[^A-Za-z])fetch\(/);
  assert.match(changeQueries, /changeClient\.resolveRun/);
  assert.match(workspace, /executionKey/);
  assert.match(review, /kind === "network"/);
  assert.match(review, /resolveRunAsync/);
  assert.doesNotMatch(review, /execute\.mutateAsync[\s\S]*execute\.mutateAsync/);
});

test("immutable save creates the next revision", async () => {
  const editor = await read("components/declaration-editor.tsx");
  assert.match(editor, /expectedRevision:\s*declaration\.revision \+ 1/);
});

test("refresh restores only safe change handles from navigation history", async () => {
  const workspace = await read("components/changes-workspace.tsx");
  assert.match(workspace, /history\.state/);
  assert.match(workspace, /replaceState/);
  assert.match(workspace, /planId/);
  assert.match(workspace, /runId/);
  assert.match(workspace, /approvalPlanId/);
  assert.match(workspace, /approvalPlanId === handles\.planId|handles\.approvalPlanId === handles\.planId/);
  assert.doesNotMatch(workspace, /localStorage|sessionStorage|location\.(?:search|hash)/);
});

test("terminal durable state never opens an SSE watcher", async () => {
  const queries = await read("lib/run-queries.ts");
  assert.match(queries, /terminalRunStatuses/);
  assert.match(queries, /if \(!runId \|\| !query\.data \|\| terminal\) return/);
  assert.match(queries, /const fresh = await refetch\(\)/);
  assert.match(queries, /fresh\.isSuccess[\s\S]*terminalRunStatuses\.has\(fresh\.data\.data\.run\.status\)/);
});

test("the newly mounted saved revision restores action focus", async () => {
  const [workspace, editor] = await Promise.all([
    read("components/changes-workspace.tsx"),
    read("components/declaration-editor.tsx"),
  ]);
  assert.match(workspace, /focusSavedRevision/);
  assert.match(editor, /focusAfterSave/);
  assert.match(editor, /reasonInput\.current\?\.focus\(\)/);
});

test("the workflow matrix covers every named state in both themes and reflow sizes", async () => {
  const suite = await read("e2e/change-workflow.spec.ts");
  for (const state of ["loading", "empty", "denied", "stale", "pending", "approved", "rejected", "expired", "queued", "running", "partial", "failed", "cancelled", "interrupted", "succeeded"]) {
    assert.match(suite, new RegExp(`\\b${state}\\b`));
  }
  assert.match(suite, /getByRole\("status"\)\.first\(\)\)\.toContainText\("Recovery required"\)/);
  assert.match(suite, /\["light", "dark"\]/);
  assert.match(suite, /width:\s*320/);
  assert.match(suite, /expectAccessible/);
  assert.match(suite, /scrollWidth/);
});

test("approval is refreshed through apply and expires locally closed", async () => {
  const [review, queries] = await Promise.all([
    read("components/plan-review.tsx"),
    read("lib/change-queries.ts"),
  ]);
  assert.match(review, /approval\.refetch\(\)/);
  assert.match(review, /expiresAt/);
  assert.match(review, /Date\.parse/);
  assert.match(queries, /refetchInterval:\s*20_000/);
  assert.doesNotMatch(queries, /status === "pending" \? 20_000 : false/);
});

test("hard change failures clear mounted state as well as cached data", async () => {
  const [workspace, provider] = await Promise.all([
    read("components/changes-workspace.tsx"),
    read("components/query-provider.tsx"),
  ]);
  assert.match(workspace, /useReadFailure\("changes"\)/);
  assert.match(workspace, /setReference\(null\)[\s\S]*setPlanId\(null\)[\s\S]*setRunId\(null\)/);
  assert.match(provider, /MutationCache/);
  assert.match(provider, /INTEGRITY_FAILURE|SCHEMA_UNSUPPORTED|VERSION_INCOMPATIBLE/);
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
