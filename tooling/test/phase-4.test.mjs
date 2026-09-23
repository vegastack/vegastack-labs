import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";

import { phase4FailureDiagnostic, summarizeBrowserFailure, verifyPhase4Sources } from "../verify-phase-4.mjs";
import { phase4BrowserFailureLine } from "../verify-phase-4-exit.mjs";

const ROOT = path.resolve(import.meta.dirname, "../..");

test("Phase 4 change evidence keeps the real server, safe approval, and run controls together", async () => {
  assert.equal(await verifyPhase4Sources(ROOT), true);
});

test("Phase 4 browser failure summary identifies the line and fixed failure class without private output", () => {
  const canary = "private-proof-canary";
  const selector = "SSE reconnect carries the last event and re-reads without resubmitting";
  const report = {
    suites: [{ specs: [{ title: selector, line: 238, tests: [{ status: "unexpected", results: [{ status: "failed", errors: [{ message: `\x1b[2mexpect(\x1b[22mreceived).toEqual(${canary})`, location: { file: path.join(ROOT, "web/e2e/change-workflow.spec.ts"), line: 250 } }], stdout: [{ text: canary }] }] }] }] }],
    errors: [{ message: canary }],
  };
  const summary = summarizeBrowserFailure(report, selector);
  assert.equal(summary, `browser title ${selector}; assertion web/e2e/change-workflow.spec.ts:250; status failed; class assertion; message expect.toEqual failed`);
  const error = new Error("PHASE4_FAILED:scenario-execution:browser.reconnect-no-resubmit");
  error.browserSummary = summary;
  const diagnostic = phase4FailureDiagnostic(error);
  assert.match(diagnostic, /assertion web\/e2e\/change-workflow\.spec\.ts:250; status failed; class assertion; message expect\.toEqual failed/);
  assert.doesNotMatch(diagnostic, /private-proof-canary/);
  error.browserSummary = canary;
  assert.doesNotMatch(phase4FailureDiagnostic(error), /private-proof-canary/);
  assert.equal(phase4BrowserFailureLine(`${diagnostic}${canary}\n`), diagnostic);
  assert.equal(phase4BrowserFailureLine(`${diagnostic.trimEnd()} ${canary}\n`), "");
  report.suites[0].specs[0].tests[0].results[0].errors[0].location.file = `/tmp/${canary}.spec.ts`;
  const unsafeLocation = summarizeBrowserFailure(report, selector);
  assert.match(unsafeLocation, /assertion unknown/);
  assert.doesNotMatch(unsafeLocation, /private-proof-canary/);
});
