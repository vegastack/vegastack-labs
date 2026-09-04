import assert from "node:assert/strict";
import test from "node:test";
import { validatePhaseZeroThreeFixture } from "../verify-phase-0-3.mjs";

test("Phase 0.3 fixtures reject duplicate case IDs and unknown error codes", () => {
  const base = {
    schema: "vegastack-labs.dev/phase-0.3-contract-fixture",
    schemaVersion: "1.0.0",
    contract: "installation-manifest",
    cases: [
      {
        id: "duplicate",
        input: {},
        expected: { status: "blocked", errorCode: "PLAN_STALE", reason: "expired" },
      },
      {
        id: "duplicate",
        input: {},
        expected: { status: "blocked", errorCode: "INVENTED_ERROR", reason: "invalid" },
      },
    ],
  };

  assert.throws(
    () => validatePhaseZeroThreeFixture(base, "memory"),
    /duplicate case id|unknown error code/,
  );
});
