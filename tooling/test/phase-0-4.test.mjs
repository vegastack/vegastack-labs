import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  loadPhaseZeroFourFixtures,
  validatePhaseZeroFourFixture,
} from "../verify-phase-0-4.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

test("Phase 0.4 loads an indexed host-control matrix with complete rows", async () => {
  const fixtures = await loadPhaseZeroFourFixtures(ROOT);
  assert.deepEqual(
    [...fixtures.keys()],
    ["host-control-matrix", "privileged-execution", "native-credentials"],
  );
  const accepted = fixtures
    .get("host-control-matrix")
    .cases.find(({ id }) => id === "supported-profiles-complete");
  assert.equal(accepted.expected.status, "accepted");
  for (const control of accepted.input.controls) {
    assert.deepEqual(
      Object.keys(control).sort(),
      [
        "applicability",
        "controlId",
        "desiredState",
        "evidenceMaxAgeSeconds",
        "mandatory",
        "mechanism",
        "negativeProbe",
        "ownerPhase",
        "positiveProbe",
        "profileIds",
        "recovery",
        "roleIds",
      ].sort(),
    );
  }
});

test("host controls reject unsupported profiles and incomplete or unsafe evidence", async () => {
  const fixtures = await loadPhaseZeroFourFixtures(ROOT);
  const cases = fixtures.get("host-control-matrix").cases;
  const expected = new Map([
    ["unsupported-release-denied", "SCHEMA_UNSUPPORTED"],
    ["missing-probe-denied", "INPUT_INVALID"],
    ["package-only-evidence-denied", "PREREQUISITE_BLOCKED"],
    ["unbounded-fail2ban-denied", "INPUT_INVALID"],
    ["missing-aide-baseline-denied", "PREREQUISITE_BLOCKED"],
    ["unsafe-audit-capture-denied", "INPUT_INVALID"],
    ["missing-recovery-denied", "PREREQUISITE_BLOCKED"],
  ]);
  for (const [id, errorCode] of expected) {
    assert.equal(cases.find((entry) => entry.id === id).expected.errorCode, errorCode);
  }

  const repaired = structuredClone(fixtures.get("host-control-matrix"));
  repaired.cases.find(({ id }) => id === "unsupported-release-denied").input.profiles[0] = {
    profileId: "debian-13-amd64",
    osFamily: "debian",
    release: "13.6",
    architecture: "amd64",
    supportState: "supported",
  };
  assert.throws(
    () => validatePhaseZeroFourFixture(repaired, "memory"),
    /must retain an unsupported release/,
  );
});

test("privilege and native credentials reject widening and cross-consumer use", async () => {
  const fixtures = await loadPhaseZeroFourFixtures(ROOT);
  const privilege = structuredClone(fixtures.get("privileged-execution"));
  privilege.cases.find(({ id }) => id === "undeclared-action-denied").input.requestedActions =
    privilege.cases.find(({ id }) => id === "approved-bundle-accepted").input.approvedActions;
  assert.throws(
    () => validatePhaseZeroFourFixture(privilege, "memory"),
    /must widen the approved action set/,
  );

  const credentials = structuredClone(fixtures.get("native-credentials"));
  credentials.cases.find(({ id }) => id === "cross-consumer-denied").input.requestedConsumerId =
    credentials.cases.find(({ id }) => id === "cross-consumer-denied").input.consumerId;
  assert.throws(
    () => validatePhaseZeroFourFixture(credentials, "memory"),
    /must request a different consumer/,
  );
});
