import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  loadPhaseZeroThreeFixtures,
  validatePhaseZeroThreeContracts,
  validatePhaseZeroThreeFixture,
} from "../verify-phase-0-3.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

test("Phase 0.3 fixtures reject duplicate case IDs and unknown error codes", async () => {
  const fixtures = await loadPhaseZeroThreeFixtures(ROOT);
  const base = structuredClone(fixtures.get("installation-manifest"));
  base.cases = [structuredClone(base.cases[0]), structuredClone(base.cases[1])];
  base.cases[0].id = "first-use-accepted";
  base.cases[1].id = "first-use-accepted";

  assert.throws(
    () => validatePhaseZeroThreeFixture(base, "memory"),
    /duplicate case id/,
  );

  base.cases[1].id = "consumed-replay-denied";
  base.cases[1].expected.errorCode = "INVENTED_ERROR";
  assert.throws(() => validatePhaseZeroThreeFixture(base, "memory"), /unknown error code/);
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
    "verified-ssh-bootstrap-accepted",
    "invalid-signature-denied",
    "untrusted-signer-denied",
    "post-approval-manifest-mutation-denied",
    "forged-ssh-binding-denied",
    "cross-user-binding-denied",
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
    cases.find(({ id }) => id === "automatic-break-glass-fallback-denied").expected
      .errorCode,
    "AUTHORIZATION_DENIED",
  );
  assert.equal(
    cases.find(({ id }) => id === "break-glass-handoff-recorded").input
      .breakGlassHandoff.normalAcknowledgementCreated,
    false,
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

test("SSH and profile fixtures deny shell text and account-free mutation", async () => {
  const fixtures = await loadPhaseZeroThreeFixtures(ROOT);
  const ssh = fixtures.get("constrained-ssh").cases;
  const profiles = fixtures.get("profile-gates").cases;

  assert.equal(
    ssh.find(({ id }) => id === "shell-text-denied").expected.errorCode,
    "INPUT_INVALID",
  );
  assert.equal(
    profiles.find(({ id }) => id === "minimal-read-accepted").expected.status,
    "accepted",
  );
  assert.equal(
    profiles.find(({ id }) => id === "minimal-bootstrap-without-slack-blocked").expected
      .errorCode,
    "PREREQUISITE_BLOCKED",
  );
  assert.ok(ssh.some(({ id }) => id === "response-length-denied"));
  assert.ok(ssh.some(({ id }) => id === "response-version-denied"));
  assert.ok(ssh.some(({ id }) => id === "response-correlation-denied"));
});

test("contract-specific validators reject empty or incomplete inputs", () => {
  for (const contract of [
    "installation-manifest",
    "setup-state",
    "slack-acknowledgement",
    "approver-import",
    "constrained-ssh",
    "profile-gates",
  ]) {
    assert.throws(
      () =>
        validatePhaseZeroThreeFixture(
          {
            schema: "vegastack-labs.dev/phase-0.3-contract-fixture",
            schemaVersion: "1.0.0",
            contract,
            cases: [
              {
                id: "invalid-empty-input",
                input: {},
                expected: { status: "blocked", errorCode: "INPUT_INVALID", reason: "invalid" },
              },
            ],
          },
          "memory",
        ),
      /invalid fields|fields must be/,
      contract,
    );
  }
});

test("manifest validation enforces signed exact fields without exposing Slack credentials", async () => {
  const fixtures = await loadPhaseZeroThreeFixtures(ROOT);
  const document = structuredClone(fixtures.get("installation-manifest"));
  const accepted = document.cases.find(({ id }) => id === "first-use-accepted");

  delete accepted.input.stateRevision;
  assert.throws(() => validatePhaseZeroThreeFixture(document, "memory"), /stateRevision/);

  accepted.input.stateRevision = 0;
  accepted.input.recoveryPreconditions.find(({ kind }) => kind === "manifest-integrity").verificationStatus = "invalid";
  assert.throws(() => validatePhaseZeroThreeFixture(document, "memory"), /verified signature/);

  accepted.input.recoveryPreconditions.find(({ kind }) => kind === "manifest-integrity").verificationStatus = "verified";
  accepted.input.profileProvenance.acknowledgementAdapter.extension.secretRefs.appTokenRef =
    ["xapp", "example", "credential", "must", "not", "echo"].join("-");
  let message = "";
  try {
    validatePhaseZeroThreeFixture(document, "memory");
    assert.fail("expected Slack credential validation to fail");
  } catch (error) {
    message = error.message;
  }
  assert.match(message, /Slack credential value/);
  assert.doesNotMatch(message, /must-not-echo/);
});

test("the independent oracle rejects fixture-authored outcome drift", async () => {
  const fixtures = await loadPhaseZeroThreeFixtures(ROOT);
  const document = structuredClone(fixtures.get("slack-acknowledgement"));
  document.cases.find(({ id }) => id === "wrong-workspace-denied").expected.errorCode =
    "APPROVAL_REQUIRED";
  assert.throws(() => validatePhaseZeroThreeFixture(document, "memory"), /independent outcome oracle/);
});

test("negative manifest scenarios cannot be repaired while retaining blocked outcomes", async () => {
  const fixtures = await loadPhaseZeroThreeFixtures(ROOT);
  const document = structuredClone(fixtures.get("installation-manifest"));
  const invalid = document.cases.find(({ id }) => id === "invalid-signature-denied").input;
  invalid.recoveryPreconditions.find(({ kind }) => kind === "manifest-integrity").verificationStatus =
    "verified";
  assert.throws(() => validatePhaseZeroThreeFixture(document, "memory"), /must carry invalid verification/);
});

test("whole-case sanitization rejects credentials in IDs and reasons without echoing them", async () => {
  const fixtures = await loadPhaseZeroThreeFixtures(ROOT);
  const document = structuredClone(fixtures.get("slack-acknowledgement"));
  document.cases.find(({ id }) => id === "wrong-workspace-denied").expected.reason =
    `credential ${["xapp", "example", "credential", "must", "not", "echo"].join("-")}`;
  let message = "";
  try {
    validatePhaseZeroThreeFixture(document, "memory");
    assert.fail("expected whole-case sanitization to fail");
  } catch (error) {
    message = error.message;
  }
  assert.match(message, /Slack credential value/);
  assert.doesNotMatch(message, /must-not-echo/);
});

test("Slack and SSH validators enforce subject exclusivity and response correlation", async () => {
  const fixtures = await loadPhaseZeroThreeFixtures(ROOT);
  const slack = structuredClone(fixtures.get("slack-acknowledgement"));
  slack.cases.find(({ id }) => id === "ordinary-plan-approved").input.installationManifestId =
    "manifest-synthetic-conflict";
  assert.throws(() => validatePhaseZeroThreeFixture(slack, "memory"), /name only a plan/);

  const ssh = structuredClone(fixtures.get("constrained-ssh"));
  ssh.cases.find(({ id }) => id === "read-request-accepted").input.responseFrame.requestId =
    "request-synthetic-other";
  assert.throws(() => validatePhaseZeroThreeFixture(ssh, "memory"), /request IDs must match/);
});

test("linked bootstrap fixtures bind manifest, Slack proof, and inert approver mapping", async () => {
  const fixtures = await loadPhaseZeroThreeFixtures(ROOT);
  const changed = new Map(fixtures);
  const slack = structuredClone(changed.get("slack-acknowledgement"));
  slack.cases.find(({ id }) => id === "bootstrap-approved").input.subjectDigest =
    `sha256:${"f".repeat(64)}`;
  changed.set("slack-acknowledgement", slack);
  assert.throws(() => validatePhaseZeroThreeContracts(changed), /manifest subject digest/);
});

test("cross-contract semantics reject repaired negative scenarios", async () => {
  const fixtures = await loadPhaseZeroThreeFixtures(ROOT);

  const correctWorkspace = new Map(fixtures);
  const workspaceSlack = structuredClone(correctWorkspace.get("slack-acknowledgement"));
  const ordinaryWorkspace = workspaceSlack.cases.find(({ id }) => id === "ordinary-plan-approved").input.workspaceId;
  workspaceSlack.cases.find(({ id }) => id === "wrong-workspace-denied").input.workspaceId =
    ordinaryWorkspace;
  correctWorkspace.set("slack-acknowledgement", workspaceSlack);
  assert.throws(() => validatePhaseZeroThreeContracts(correctWorkspace), /differ from the approved workspace/);

  const unexpired = new Map(fixtures);
  const slack = structuredClone(unexpired.get("slack-acknowledgement"));
  slack.cases.find(({ id }) => id === "expired-request-denied").input.receivedAt =
    "2026-09-04T13:29:00Z";
  unexpired.set("slack-acknowledgement", slack);
  assert.throws(() => validatePhaseZeroThreeContracts(unexpired), /arrive after expiry/);

  const nonSelf = new Map(fixtures);
  const approvers = structuredClone(nonSelf.get("approver-import"));
  approvers.cases.find(({ id }) => id === "proposed-user-self-add-denied").input.authorizingApproverId =
    "person-synthetic-admin";
  nonSelf.set("approver-import", approvers);
  assert.throws(() => validatePhaseZeroThreeContracts(nonSelf), /must model self-authorization/);

  const noConflict = new Map(fixtures);
  const profiles = structuredClone(noConflict.get("profile-gates"));
  profiles.cases.find(({ id }) => id === "conflicting-provenance-blocked").input.resolvedValues.pop();
  noConflict.set("profile-gates", profiles);
  assert.throws(() => validatePhaseZeroThreeContracts(noConflict), /competing owners/);

  const repairedResponse = new Map(fixtures);
  const ssh = structuredClone(repairedResponse.get("constrained-ssh"));
  const response = ssh.cases.find(({ id }) => id === "response-length-denied").input.responseFrame;
  response.actualPayloadBytes = response.declaredPayloadBytes;
  repairedResponse.set("constrained-ssh", ssh);
  assert.throws(() => validatePhaseZeroThreeContracts(repairedResponse), /framing mismatch/);
});

test("recovery handoff cannot be classified as routine approval", async () => {
  const fixtures = await loadPhaseZeroThreeFixtures(ROOT);
  const document = structuredClone(fixtures.get("slack-acknowledgement"));
  document.cases.find(({ id }) => id === "break-glass-handoff-recorded").input.riskClass =
    "assigned-project-routine";
  assert.throws(() => validatePhaseZeroThreeFixture(document, "memory"), /recovery-specific risk class/);
});
