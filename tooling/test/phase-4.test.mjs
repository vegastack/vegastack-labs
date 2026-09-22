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
    suites: [{ specs: [{ title: selector, line: 238, tests: [{ status: "unexpected", results: [{ status: "failed", errors: [{ message: `expect(received).toEqual(${canary})` }], stdout: [{ text: canary }] }] }] }] }],
    errors: [{ message: canary }],
  };
  const summary = summarizeBrowserFailure(report, selector);
  assert.equal(summary, "browser line 238; status failed; class assertion");
  const error = new Error("PHASE4_FAILED:scenario-execution:browser.reconnect-no-resubmit");
  error.browserSummary = summary;
  const diagnostic = phase4FailureDiagnostic(error);
  assert.match(diagnostic, /browser line 238; status failed; class assertion/);
  assert.doesNotMatch(diagnostic, /private-proof-canary/);
  error.browserSummary = canary;
  assert.doesNotMatch(phase4FailureDiagnostic(error), /private-proof-canary/);
  assert.equal(phase4BrowserFailureLine(`${diagnostic}${canary}\n`), diagnostic);
  assert.equal(phase4BrowserFailureLine(`${diagnostic.trimEnd()} ${canary}\n`), "");
});
