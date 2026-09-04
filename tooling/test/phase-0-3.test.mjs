import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  loadPhaseZeroThreeFixtures,
  validatePhaseZeroThreeFixture,
} from "../verify-phase-0-3.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

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

test("installation and setup fixtures cover atomic first use and interruption", async () => {
  const fixtures = await loadPhaseZeroThreeFixtures(ROOT);
  const manifestIds = fixtures.get("installation-manifest").cases.map(({ id }) => id);
  const setupIds = fixtures.get("setup-state").cases.map(({ id }) => id);

  assert.deepEqual(manifestIds, [
    "first-use-accepted",
    "consumed-replay-denied",
    "expired-denied",
    "release-substitution-denied",
    "target-substitution-denied",
    "interrupted-consumption-denied",
  ]);
  assert.ok(setupIds.includes("single-writer-handoff"));
  assert.ok(setupIds.includes("interruption-enters-recovery"));
});

test("Slack cases bind exact identity and prevent self-authorization", async () => {
  const fixtures = await loadPhaseZeroThreeFixtures(ROOT);
  const cases = fixtures.get("slack-acknowledgement").cases;

  assert.equal(
    cases.find(({ id }) => id === "wrong-workspace-denied").expected.errorCode,
    "AUTHORIZATION_DENIED",
  );
  assert.equal(
    cases.find(({ id }) => id === "recovery-epoch-mismatch").expected.errorCode,
    "RECOVERY_EPOCH_MISMATCH",
  );
  assert.equal(
    fixtures
      .get("approver-import")
      .cases.find(({ id }) => id === "proposed-user-self-add-denied").expected.errorCode,
    "AUTHORIZATION_DENIED",
  );
});
