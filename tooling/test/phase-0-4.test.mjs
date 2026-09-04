import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  loadPhaseZeroFourFixtures,
  validateProtectedFiles,
  validatePhaseZeroFourContracts,
  validatePhaseZeroFourFixture,
} from "../verify-phase-0-4.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

test("Phase 0.4 loads an indexed host-control matrix with complete rows", async () => {
  const fixtures = await loadPhaseZeroFourFixtures(ROOT);
  assert.deepEqual(
    [...fixtures.keys()],
    [
      "host-control-matrix",
      "privileged-execution",
      "native-credentials",
      "macos-admission",
      "admission-evidence",
    ],
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

test("macOS and evidence contracts fail closed without source, consent, or freshness", async () => {
  const fixtures = await loadPhaseZeroFourFixtures(ROOT);
  const macos = fixtures.get("macos-admission").cases;
  assert.equal(
    macos.find(({ id }) => id === "direct-lan-fallback-denied").expected.errorCode,
    "AUTHORIZATION_DENIED",
  );
  assert.equal(
    macos.find(({ id }) => id === "consent-revoked-blocked").expected.errorCode,
    "PREREQUISITE_BLOCKED",
  );

  const evidence = fixtures.get("admission-evidence").cases;
  assert.equal(
    evidence.find(({ id }) => id === "stale-new-admission-blocked").expected.errorCode,
    "PLAN_STALE",
  );
  assert.equal(
    evidence.find(({ id }) => id === "stale-existing-workload-preserved").expected.status,
    "accepted",
  );
  assert.equal(
    evidence.find(({ id }) => id === "stale-recovery-accepted").expected.status,
    "accepted",
  );
});

test("the oracle, sanitizer, linked contracts, and Phase 0.3 hashes fail closed", async () => {
  const fixtures = await loadPhaseZeroFourFixtures(ROOT);
  const changed = new Map(fixtures);
  const evidence = structuredClone(changed.get("admission-evidence"));
  evidence.cases.find(({ id }) => id === "wrong-evidence-recovery-epoch-denied").input.recoveryEpoch =
    evidence.cases.find(({ id }) => id === "current-daily-evidence-accepted").input.recoveryEpoch;
  changed.set("admission-evidence", evidence);
  assert.throws(
    () => validatePhaseZeroFourContracts(changed),
    /recovery epoch must differ/,
  );

  const observed = new Map([
    ["tooling/verify-phase-0-3.mjs", `sha256:${"0".repeat(64)}`],
  ]);
  assert.throws(
    () =>
      validateProtectedFiles(
        {
          protectedFiles: [
            {
              path: "tooling/verify-phase-0-3.mjs",
              sha256: `sha256:${"1".repeat(64)}`,
            },
          ],
        },
        observed,
      ),
    /protected Phase 0.3 digest mismatch/,
  );
});

test("Phase 0.4 rejects repaired denials, outcome drift, duplicate IDs, and private canaries", async () => {
  const fixtures = await loadPhaseZeroFourFixtures(ROOT);

  const repaired = structuredClone(fixtures.get("macos-admission"));
  repaired.cases.find(({ id }) => id === "wrong-user-denied").input.remoteLogin.requestedUser =
    "user-synthetic-automation";
  assert.throws(() => validatePhaseZeroFourFixture(repaired, "memory"), /undeclared Remote Login user/);

  const invented = structuredClone(fixtures.get("admission-evidence"));
  invented.cases.find(({ id }) => id === "stale-new-admission-blocked").expected.errorCode =
    "EVIDENCE_EXPIRED";
  assert.throws(() => validatePhaseZeroFourFixture(invented, "memory"), /independent outcome oracle/);

  const duplicate = structuredClone(fixtures.get("native-credentials"));
  duplicate.cases[1].id = duplicate.cases[0].id;
  assert.throws(() => validatePhaseZeroFourFixture(duplicate, "memory"), /duplicate case id/);

  const privateCanary = structuredClone(fixtures.get("native-credentials"));
  privateCanary.cases[0].expected.reason =
    "private_key=material-must-not-echo";
  let message = "";
  try {
    validatePhaseZeroFourFixture(privateCanary, "memory");
    assert.fail("expected private fixture material to be rejected");
  } catch (error) {
    message = error.message;
  }
  assert.match(message, /prohibited private material/);
  assert.doesNotMatch(message, /must-not-echo/);
});

test("Phase 0.4 contracts are composed into checks and reconciled into owning specifications", async () => {
  const checks = await readFile(path.join(ROOT, "tooling", "check.mjs"), "utf8");
  assert.match(checks, /Phase 0\.4 contract fixtures/);
  assert.match(
    checks,
    /verify-phase-0-3\.mjs"\]\);\n\s+await stage\("Phase 0\.4 contract fixtures"[^\n]+verify-phase-0-4\.mjs"\]\);/,
    "Phase 0.4 must run immediately after Phase 0.3",
  );

  const expected = new Map([
    ["docs/host-onboarding-and-hardening.md", ["host.identity-accounts", "linux.fail2ban-sshd", "host-security-v1"]],
    ["docs/security-and-operations.md", ["host-action-once", "native account-free credential resolver"]],
    ["docs/platform-lifecycle.md", ["host-security-v1", "continue-existing-workload"]],
    ["docs/automation-and-agents.md", ["privileged-execution", "native-credentials"]],
    ["docs/implementation-gates.md", ["evidenceMaxAgeSeconds", "after-change"]],
    ["docs/development/phases/00-development-foundation.md", ["0.4 (#17)", "69 cases"]],
    ["docs/development/roadmap.md", ["0.4 (#17)", "host-security-v1"]],
    ["docs/architecture-and-networking.md", ["Mesh-only automated macOS SSH", "physical local console"]],
    ["docs/decisions-and-sources.md", ["D-123", "D-124", "SRC-ANS-02", "SRC-CF-12", "SRC-MAC-07"]],
  ]);
  for (const [relative, needles] of expected) {
    const contents = await readFile(path.join(ROOT, relative), "utf8");
    for (const needle of needles) assert.ok(contents.includes(needle), `${relative} must contain ${needle}`);
  }
});
