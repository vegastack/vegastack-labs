import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURE_DIRECTORY = path.join("tooling", "testdata", "phase-0-3");
const FIXTURE_SCHEMA = "vegastack-labs.dev/phase-0.3-contract-fixture";
const INDEX_SCHEMA = "vegastack-labs.dev/phase-0.3-contract-index";
const SCHEMA_VERSION = "1.0.0";
const FIXTURE_EVALUATION_TIME = Date.parse("2026-09-04T13:15:00Z");
const FIXTURE_FACTS = Object.freeze({
  approvedReleaseBuildId: "release-synthetic-001",
  approvedReleaseDigest: `sha256:${"a".repeat(64)}`,
  approvedWorkspaceId: "workspace-synthetic-approved",
  approvedOrdinarySlackUserId: "slack-user-synthetic-maintainer",
  bootstrapApprovalRequestId: "approval-synthetic-bootstrap-001",
  bootstrapManifestId: "manifest-synthetic-001",
  bootstrapResponsibleHumanId: "person-synthetic-admin",
  bootstrapSlackUserId: "slack-user-synthetic-approved",
  consumedApprovalRequestId: "approval-synthetic-plan-consumed",
  consumedApprovalNonce: "nonce-slack-synthetic-consumed",
  currentPlanDigest: `sha256:${"a".repeat(64)}`,
  currentTargetSetDigest: `sha256:${"b".repeat(64)}`,
  currentStateRevision: 42,
  currentRecoveryEpoch: 3,
  readerPrincipalId: "ssh-principal-synthetic-reader",
  readerDeviceId: "device-synthetic-reader",
});

const DECLARED_SSH_OPERATIONS = new Set([
  "GET /api/v1/summary",
  "POST /api/v1/plans",
  "POST /api/v1/plans/plan-synthetic-001/execute",
  "GET /api/v1/runs/run-synthetic-001",
]);

const CONTRACT_NAMES = new Set([
  "installation-manifest",
  "setup-state",
  "slack-acknowledgement",
  "approver-import",
  "constrained-ssh",
  "profile-gates",
]);

const ERROR_CODES = new Set([
  "INPUT_INVALID",
  "SCHEMA_UNSUPPORTED",
  "AUTHENTICATION_REQUIRED",
  "AUTHORIZATION_DENIED",
  "APPROVAL_REQUIRED",
  "STATE_CONFLICT",
  "PLAN_STALE",
  "RECOVERY_EPOCH_MISMATCH",
  "PREREQUISITE_BLOCKED",
  "DEPENDENCY_UNAVAILABLE",
  "INTERRUPTED",
]);

const EXPECTED_CASE_OUTCOMES = {
  "installation-manifest": {
    accepted: ["first-use-accepted", "verified-ssh-bootstrap-accepted"],
    AUTHENTICATION_REQUIRED: ["forged-ssh-binding-denied"],
    AUTHORIZATION_DENIED: ["release-substitution-denied", "target-substitution-denied", "invalid-signature-denied", "untrusted-signer-denied", "post-approval-manifest-mutation-denied", "cross-user-binding-denied"],
    STATE_CONFLICT: ["consumed-replay-denied"],
    PLAN_STALE: ["expired-denied"],
    INTERRUPTED: ["interrupted-consumption-denied"],
  },
  "setup-state": {
    accepted: ["single-writer-handoff", "foundation-preparation-bounded"],
    AUTHENTICATION_REQUIRED: ["first-browser-authority-denied", "client-asserted-identity-denied"],
    AUTHORIZATION_DENIED: ["hostname-authority-denied"],
    STATE_CONFLICT: ["manifest-reuse-denied", "second-writer-denied"],
    INTERRUPTED: ["interruption-enters-recovery"],
  },
  "slack-acknowledgement": {
    accepted: ["bootstrap-approved", "ordinary-plan-approved", "ordinary-plan-rejected", "duplicate-click-idempotent", "break-glass-handoff-recorded"],
    AUTHENTICATION_REQUIRED: ["missing-authenticated-envelope"],
    AUTHORIZATION_DENIED: ["wrong-workspace-denied", "wrong-user-denied", "changed-digest-denied", "changed-target-denied", "bootstrap-approval-request-substitution-denied", "bootstrap-mapping-substitution-denied", "automatic-break-glass-fallback-denied"],
    APPROVAL_REQUIRED: ["agent-controlled-session-insufficient", "missing-proof"],
    STATE_CONFLICT: ["replay-denied"],
    PLAN_STALE: ["stale-plan-denied", "expired-request-denied"],
    RECOVERY_EPOCH_MISMATCH: ["recovery-epoch-mismatch"],
    PREREQUISITE_BLOCKED: ["lost-approver-access"],
    DEPENDENCY_UNAVAILABLE: ["socket-mode-outage", "adapter-token-failure"],
  },
  "approver-import": {
    accepted: ["bootstrap-seed-remains-inert", "existing-admin-add-accepted", "existing-admin-widen-accepted", "removal-invalidates-outstanding"],
    AUTHORIZATION_DENIED: ["proposed-user-self-add-denied", "proposed-user-self-widen-denied", "file-replacement-cannot-authorize"],
  },
  "constrained-ssh": {
    accepted: ["read-request-accepted", "plan-request-accepted", "approved-apply-request-accepted", "disconnect-queries-durable-run"],
    INPUT_INVALID: ["shell-text-denied", "path-denied", "malformed-length-denied", "unknown-operation-denied", "response-length-denied"],
    SCHEMA_UNSUPPORTED: ["unsupported-version-denied", "response-version-denied"],
    AUTHENTICATION_REQUIRED: ["client-asserted-identity-denied"],
    AUTHORIZATION_DENIED: ["direct-sqlite-denied", "principal-device-mismatch"],
    STATE_CONFLICT: ["response-correlation-denied"],
    RECOVERY_EPOCH_MISMATCH: ["recovery-epoch-mismatch"],
  },
  "profile-gates": {
    accepted: ["minimal-read-accepted", "minimal-plan-accepted", "non-labs-slack-configured", "labs-slack-configured", "inapplicable-gate-is-not-passed"],
    AUTHORIZATION_DENIED: ["wrong-workspace-blocked"],
    STATE_CONFLICT: ["conflicting-provenance-blocked"],
    PLAN_STALE: ["stale-slack-binding-blocked"],
    PREREQUISITE_BLOCKED: ["minimal-bootstrap-without-slack-blocked", "minimal-apply-without-slack-blocked", "missing-mandatory-evidence-blocked"],
    DEPENDENCY_UNAVAILABLE: ["slack-unavailable-blocked"],
  },
};

const EXPECTED_OUTCOMES = new Map();
for (const [contract, outcomes] of Object.entries(EXPECTED_CASE_OUTCOMES)) {
  for (const [outcome, caseIds] of Object.entries(outcomes)) {
    for (const caseId of caseIds) {
      const key = `${contract}/${caseId}`;
      if (EXPECTED_OUTCOMES.has(key)) throw new Error(`duplicate expected fixture outcome for ${key}`);
      EXPECTED_OUTCOMES.set(key, outcome === "accepted" ? ["accepted", null] : ["blocked", outcome]);
    }
  }
}

function assertPlainObject(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
}

function assertExactKeys(value, expected, label) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    throw new Error(`${label} fields must be ${wanted.join(", ")}; found ${actual.join(", ")}`);
  }
}

function assertNonemptyString(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${label} must be a nonempty string`);
  }
}

function assertNullableString(value, label) {
  if (value !== null) assertNonemptyString(value, label);
}

function assertNonnegativeInteger(value, label) {
  if (!Number.isInteger(value) || value < 0) {
    throw new Error(`${label} must be a nonnegative integer`);
  }
}

function assertBoolean(value, label) {
  if (typeof value !== "boolean") throw new Error(`${label} must be a boolean`);
}

function assertEnum(value, allowed, label) {
  if (!allowed.includes(value)) {
    throw new Error(`${label} must be one of ${allowed.join(", ")}`);
  }
}

function assertStringArray(value, label, { nonempty = false } = {}) {
  if (!Array.isArray(value) || (nonempty && value.length === 0)) {
    throw new Error(`${label} must be ${nonempty ? "a nonempty" : "an"} array`);
  }
  value.forEach((entry, index) => assertNonemptyString(entry, `${label}[${index}]`));
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !/^sha256:[0-9a-f]{64}$/.test(value)) {
    throw new Error(`${label} must be a lowercase sha256 digest`);
  }
}

function assertTimestamp(value, label) {
  assertNonemptyString(value, label);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value) || Number.isNaN(Date.parse(value))) {
    throw new Error(`${label} must be a valid UTC timestamp`);
  }
}

function assertNullableTimestamp(value, label) {
  if (value !== null) assertTimestamp(value, label);
}

function assertSyntheticIdentifier(value, label, prefix) {
  assertNonemptyString(value, label);
  if (!value.startsWith(prefix) || !value.includes("synthetic")) {
    throw new Error(`${label} must use the ${prefix} synthetic identifier namespace`);
  }
}

function assertKeys(value, required, optional, label) {
  const actual = Object.keys(value).sort();
  const allowed = new Set([...required, ...optional]);
  const missing = required.filter((key) => !Object.hasOwn(value, key));
  const extra = actual.filter((key) => !allowed.has(key));
  if (missing.length > 0 || extra.length > 0) {
    throw new Error(`${label} has invalid fields; missing ${missing.join(", ") || "none"}; extra ${extra.join(", ") || "none"}`);
  }
}

function assertSanitized(value, label = "fixture") {
  const forbiddenKey = /(?:password|private.?key|signing.?secret|secret.?value|credential.?value|raw.?payload|host.?fact|operational.?evidence)/i;
  const slackToken = /\bx(?:app|ox[abprs])-[A-Za-z0-9-]+/;
  const privateValues = [
    [/\b(?:slack[ _-]?)?signing[ _-]?secret\s*(?:=|:)\s*["']?[A-Za-z0-9][A-Za-z0-9_-]{7,}/i, "signing-secret value"],
    [/\bT[A-Z0-9]{8,}\s*(?:->|:|\/)\s*U[A-Z0-9]{8,}\b/, "private Slack user mapping"],
    [/\bprivate[ _-]?user[ _-]?mapping\s*(?:=|:)\s*["']?[^\s,"'}]{4,}/i, "private user mapping"],
    [/\bhost[ _-]?fact\s*(?:=|:)\s*["']?[^\s,"'}]{4,}/i, "private host fact"],
    [/\boperational[ _-]?evidence\s*(?:=|:)\s*["']?[^\s,"'}]{4,}/i, "private operational evidence"],
  ];
  function inspectString(current) {
    if (slackToken.test(current)) throw new Error(`${label} contains a Slack credential value`);
    for (const [pattern, category] of privateValues) {
      if (pattern.test(current)) throw new Error(`${label} contains prohibited ${category}`);
    }
  }
  function visit(current) {
    if (typeof current === "string") {
      inspectString(current);
      return;
    }
    if (Array.isArray(current)) {
      current.forEach((entry) => visit(entry));
      return;
    }
    if (current === null || typeof current !== "object") return;
    for (const [key, child] of Object.entries(current)) {
      inspectString(key);
      if (forbiddenKey.test(key)) throw new Error(`${label} contains a forbidden private-value field`);
      if (/token/i.test(key) && !/(?:Ref|Refs)$/.test(key)) {
        throw new Error(`${label} contains a token field that is not a logical reference`);
      }
      visit(child);
    }
  }
  visit(value);
}

const MANIFEST_KEYS = [
  "manifestId", "releaseBuildId", "releaseDigest", "intendedOperation",
  "hostIdentity", "databasePathRef", "initialAdministrator", "profileId", "profileVersion", "profileDefaultsDigest",
  "profileProvenance", "stateRevision", "recoveryEpoch", "recoveryPreconditions",
  "approvalRequestId", "expiresAt", "nonce", "state",
];

function manifestIntegrity(input, label) {
  const matches = input.recoveryPreconditions.filter((entry) => entry.kind === "manifest-integrity");
  if (matches.length !== 1) throw new Error(`${label}.recoveryPreconditions must contain exactly one manifest-integrity prerequisite`);
  return matches[0];
}

function manifestAcknowledgementExtension(input, label) {
  const adapter = input.profileProvenance.acknowledgementAdapter;
  assertPlainObject(adapter, `${label}.profileProvenance.acknowledgementAdapter`);
  assertExactKeys(adapter, ["kind", "extension"], `${label}.profileProvenance.acknowledgementAdapter`);
  assertEnum(adapter.kind, ["slack-socket-mode"], `${label}.profileProvenance.acknowledgementAdapter.kind`);
  assertPlainObject(adapter.extension, `${label}.profileProvenance.acknowledgementAdapter.extension`);
  assertExactKeys(adapter.extension, ["initialMapping", "secretRefs"], `${label}.profileProvenance.acknowledgementAdapter.extension`);
  return adapter.extension;
}

function validateInstallationManifest(input, contractCase, label) {
  assertExactKeys(input, MANIFEST_KEYS, label);
  assertSyntheticIdentifier(input.manifestId, `${label}.manifestId`, "manifest-");
  assertSyntheticIdentifier(input.releaseBuildId, `${label}.releaseBuildId`, "release-");
  assertDigest(input.releaseDigest, `${label}.releaseDigest`);
  assertEnum(input.intendedOperation, ["create-control-plane"], `${label}.intendedOperation`);
  assertPlainObject(input.hostIdentity, `${label}.hostIdentity`);
  assertExactKeys(input.hostIdentity, ["kind", "subject"], `${label}.hostIdentity`);
  assertEnum(input.hostIdentity.kind, ["local-os-peer", "verified-ssh"], `${label}.hostIdentity.kind`);
  assertSyntheticIdentifier(input.hostIdentity.subject, `${label}.hostIdentity.subject`, input.hostIdentity.kind === "verified-ssh" ? "ssh-principal-" : "person-");
  assertNonemptyString(input.databasePathRef, `${label}.databasePathRef`);
  assertPlainObject(input.initialAdministrator, `${label}.initialAdministrator`);
  assertExactKeys(input.initialAdministrator, ["localPrincipalId", "sshPrincipalId", "slackBindingId"], `${label}.initialAdministrator`);
  assertSyntheticIdentifier(input.initialAdministrator.localPrincipalId, `${label}.initialAdministrator.localPrincipalId`, "person-");
  assertNullableString(input.initialAdministrator.sshPrincipalId, `${label}.initialAdministrator.sshPrincipalId`);
  if (input.initialAdministrator.sshPrincipalId !== null) assertSyntheticIdentifier(input.initialAdministrator.sshPrincipalId, `${label}.initialAdministrator.sshPrincipalId`, "ssh-principal-");
  assertSyntheticIdentifier(input.initialAdministrator.slackBindingId, `${label}.initialAdministrator.slackBindingId`, "binding-");
  assertNonemptyString(input.profileId, `${label}.profileId`);
  assertNonemptyString(input.profileVersion, `${label}.profileVersion`);
  assertDigest(input.profileDefaultsDigest, `${label}.profileDefaultsDigest`);
  assertPlainObject(input.profileProvenance, `${label}.profileProvenance`);
  assertExactKeys(input.profileProvenance, ["source", "acknowledgementAdapter"], `${label}.profileProvenance`);
  assertNonemptyString(input.profileProvenance.source, `${label}.profileProvenance.source`);
  const extension = manifestAcknowledgementExtension(input, label);
  assertPlainObject(extension.initialMapping, `${label}.profileProvenance.acknowledgementAdapter.extension.initialMapping`);
  assertExactKeys(extension.initialMapping, ["workspaceId", "slackUserId", "localHumanPrincipalId", "approvalClasses"], `${label}.profileProvenance.acknowledgementAdapter.extension.initialMapping`);
  assertSyntheticIdentifier(extension.initialMapping.workspaceId, `${label}.profileProvenance.acknowledgementAdapter.extension.initialMapping.workspaceId`, "workspace-");
  assertSyntheticIdentifier(extension.initialMapping.slackUserId, `${label}.profileProvenance.acknowledgementAdapter.extension.initialMapping.slackUserId`, "slack-user-");
  assertSyntheticIdentifier(extension.initialMapping.localHumanPrincipalId, `${label}.profileProvenance.acknowledgementAdapter.extension.initialMapping.localHumanPrincipalId`, "person-");
  assertStringArray(extension.initialMapping.approvalClasses, `${label}.profileProvenance.acknowledgementAdapter.extension.initialMapping.approvalClasses`, { nonempty: true });
  assertPlainObject(extension.secretRefs, `${label}.profileProvenance.acknowledgementAdapter.extension.secretRefs`);
  assertExactKeys(extension.secretRefs, ["appTokenRef", "botTokenRef"], `${label}.profileProvenance.acknowledgementAdapter.extension.secretRefs`);
  for (const key of ["appTokenRef", "botTokenRef"]) assertSyntheticIdentifier(extension.secretRefs[key], `${label}.profileProvenance.acknowledgementAdapter.extension.secretRefs.${key}`, "secret-ref-");
  assertNonnegativeInteger(input.stateRevision, `${label}.stateRevision`);
  assertNonnegativeInteger(input.recoveryEpoch, `${label}.recoveryEpoch`);
  if (!Array.isArray(input.recoveryPreconditions) || input.recoveryPreconditions.length === 0) throw new Error(`${label}.recoveryPreconditions must be a nonempty array`);
  input.recoveryPreconditions.forEach((entry, index) => {
    const entryLabel = `${label}.recoveryPreconditions[${index}]`;
    assertPlainObject(entry, entryLabel);
    assertNonemptyString(entry.kind, `${entryLabel}.kind`);
    if (entry.kind === "manifest-integrity") {
      assertExactKeys(entry, ["kind", "manifestDigest", "signatureFormat", "signerKeyId", "verificationBundleRef", "verificationStatus"], entryLabel);
      assertDigest(entry.manifestDigest, `${entryLabel}.manifestDigest`);
      assertEnum(entry.signatureFormat, ["detached-verification-bundle"], `${entryLabel}.signatureFormat`);
      assertSyntheticIdentifier(entry.signerKeyId, `${entryLabel}.signerKeyId`, "signer-key-");
      assertSyntheticIdentifier(entry.verificationBundleRef, `${entryLabel}.verificationBundleRef`, "verification-bundle-");
      assertEnum(entry.verificationStatus, ["verified", "invalid", "untrusted"], `${entryLabel}.verificationStatus`);
    } else {
      assertExactKeys(entry, ["kind", "status"], entryLabel);
      assertEnum(entry.status, ["verified", "missing"], `${entryLabel}.status`);
    }
  });
  const integrity = manifestIntegrity(input, label);
  assertSyntheticIdentifier(input.approvalRequestId, `${label}.approvalRequestId`, "approval-");
  assertTimestamp(input.expiresAt, `${label}.expiresAt`);
  assertSyntheticIdentifier(input.nonce, `${label}.nonce`, "nonce-");
  assertEnum(input.state, ["pending", "consuming", "consumed", "failed"], `${label}.state`);

  if (contractCase.id === "consumed-replay-denied" && input.state !== "consumed") throw new Error(`${label} consumed replay case must use a consumed manifest`);
  if (contractCase.id === "expired-denied" && Date.parse(input.expiresAt) >= FIXTURE_EVALUATION_TIME) throw new Error(`${label} expired manifest case must precede the fixture evaluation time`);
  if (contractCase.id === "invalid-signature-denied" && integrity.verificationStatus !== "invalid") throw new Error(`${label} invalid-signature case must carry invalid verification`);
  if (contractCase.id === "untrusted-signer-denied" && integrity.verificationStatus !== "untrusted") throw new Error(`${label} untrusted-signer case must carry untrusted verification`);
  if (contractCase.id === "post-approval-manifest-mutation-denied" && integrity.verificationStatus !== "invalid") throw new Error(`${label} post-approval mutation must invalidate manifest verification`);

  if (contractCase.expected.status === "accepted") {
    if (integrity.verificationStatus !== "verified") throw new Error(`${label} accepted manifest must have a verified signature`);
    if (extension.initialMapping.localHumanPrincipalId !== input.initialAdministrator.localPrincipalId) throw new Error(`${label} accepted manifest must bind acknowledgement and local human identities`);
    const expectedSubject = input.hostIdentity.kind === "verified-ssh" ? input.initialAdministrator.sshPrincipalId : input.initialAdministrator.localPrincipalId;
    if (expectedSubject === null || input.hostIdentity.subject !== expectedSubject) throw new Error(`${label} accepted manifest must bind the observed host principal`);
  }
}

function validateSetupState(input, _contractCase, label) {
  assertExactKeys(input, ["from", "operation", "to", "manifestState", "writerState", "stateRevision", "recoveryEpoch", "postconditions"], label);
  const states = ["uninitialized", "local-setup-service", "foundation-preparation", "qualified-capability", "site-accepted", "recovery-required"];
  assertEnum(input.from, states, `${label}.from`);
  assertEnum(input.to, states, `${label}.to`);
  assertNonemptyString(input.operation, `${label}.operation`);
  assertEnum(input.manifestState, ["pending", "consuming", "consumed", "failed"], `${label}.manifestState`);
  assertEnum(input.writerState, ["server-exclusive", "unknown", "conflicting-writer", "none"], `${label}.writerState`);
  assertNonnegativeInteger(input.stateRevision, `${label}.stateRevision`);
  assertNonnegativeInteger(input.recoveryEpoch, `${label}.recoveryEpoch`);
  assertStringArray(input.postconditions, `${label}.postconditions`);
}

function validateSlackAcknowledgement(input, contractCase, label) {
  const required = ["requestId", "requestKind", "planId", "installationManifestId", "subjectDigest", "targetSetDigest", "reasonDigest", "riskClass", "responsibleHumanId", "workspaceId", "slackUserId", "action", "envelopeId", "sessionControl", "receivedAt", "expiresAt", "nonce", "stateRevision", "recoveryEpoch"];
  assertKeys(input, required, ["breakGlassHandoff"], label);
  assertSyntheticIdentifier(input.requestId, `${label}.requestId`, input.requestKind === "recovery-handoff" ? "recovery-handoff-" : "approval-");
  assertEnum(input.requestKind, ["bootstrap", "plan", "recovery-handoff"], `${label}.requestKind`);
  assertNullableString(input.planId, `${label}.planId`);
  assertNullableString(input.installationManifestId, `${label}.installationManifestId`);
  ["subjectDigest", "targetSetDigest", "reasonDigest"].forEach((key) => assertDigest(input[key], `${label}.${key}`));
  assertNonemptyString(input.riskClass, `${label}.riskClass`);
  assertSyntheticIdentifier(input.responsibleHumanId, `${label}.responsibleHumanId`, "person-");
  assertSyntheticIdentifier(input.workspaceId, `${label}.workspaceId`, "workspace-");
  assertSyntheticIdentifier(input.slackUserId, `${label}.slackUserId`, "slack-user-");
  if (input.action !== null) assertEnum(input.action, ["approve", "reject", "handoff-break-glass", "automatic-break-glass-fallback"], `${label}.action`);
  assertNullableString(input.envelopeId, `${label}.envelopeId`);
  assertEnum(input.sessionControl, ["independent-human", "agent-accessible", "unknown", "unavailable", "adapter-credential-invalid", "revoked"], `${label}.sessionControl`);
  assertNullableTimestamp(input.receivedAt, `${label}.receivedAt`);
  assertTimestamp(input.expiresAt, `${label}.expiresAt`);
  assertSyntheticIdentifier(input.nonce, `${label}.nonce`, "nonce-");
  assertNonnegativeInteger(input.stateRevision, `${label}.stateRevision`);
  assertNonnegativeInteger(input.recoveryEpoch, `${label}.recoveryEpoch`);

  if (input.requestKind === "bootstrap" && (input.planId !== null || input.installationManifestId === null)) throw new Error(`${label} bootstrap request must name only an installation manifest`);
  if (input.requestKind === "plan" && (input.planId === null || input.installationManifestId !== null)) throw new Error(`${label} plan request must name only a plan`);
  if (input.requestKind === "recovery-handoff" && (input.planId !== null || input.installationManifestId !== null)) throw new Error(`${label} recovery handoff cannot masquerade as plan or manifest approval`);
  if (input.requestKind === "recovery-handoff" && input.riskClass !== "control-plane-recovery-break-glass") throw new Error(`${label} recovery handoff must use the recovery-specific risk class`);
  if (input.requestKind !== "recovery-handoff" && input.riskClass === "control-plane-recovery-break-glass") throw new Error(`${label} normal acknowledgement cannot use the recovery-specific risk class`);
  if (input.breakGlassHandoff !== undefined) {
    assertPlainObject(input.breakGlassHandoff, `${label}.breakGlassHandoff`);
    assertExactKeys(input.breakGlassHandoff, ["authorizationState", "separateAuthorizationRequired", "normalAcknowledgementCreated", "targetSetDigest", "reasonDigest", "fromRecoveryEpoch", "toRecoveryEpoch"], `${label}.breakGlassHandoff`);
    assertEnum(input.breakGlassHandoff.authorizationState, ["separately-authorized", "absent"], `${label}.breakGlassHandoff.authorizationState`);
    assertBoolean(input.breakGlassHandoff.separateAuthorizationRequired, `${label}.breakGlassHandoff.separateAuthorizationRequired`);
    assertBoolean(input.breakGlassHandoff.normalAcknowledgementCreated, `${label}.breakGlassHandoff.normalAcknowledgementCreated`);
    assertDigest(input.breakGlassHandoff.targetSetDigest, `${label}.breakGlassHandoff.targetSetDigest`);
    assertDigest(input.breakGlassHandoff.reasonDigest, `${label}.breakGlassHandoff.reasonDigest`);
    assertNonnegativeInteger(input.breakGlassHandoff.fromRecoveryEpoch, `${label}.breakGlassHandoff.fromRecoveryEpoch`);
    assertNonnegativeInteger(input.breakGlassHandoff.toRecoveryEpoch, `${label}.breakGlassHandoff.toRecoveryEpoch`);
    if (input.breakGlassHandoff.normalAcknowledgementCreated) throw new Error(`${label} break-glass handoff cannot create a normal acknowledgement`);
    if (contractCase.expected.status === "accepted" && input.breakGlassHandoff.toRecoveryEpoch <= input.breakGlassHandoff.fromRecoveryEpoch) throw new Error(`${label} accepted recovery handoff must advance the recovery epoch`);
  }
}

function validateApproverImport(input, _contractCase, label) {
  assertExactKeys(input, ["workspaceId", "mappings", "priorEffectivePolicyRevision", "proposedRevision", "authorizingApproverId", "operation"], label);
  assertSyntheticIdentifier(input.workspaceId, `${label}.workspaceId`, "workspace-");
  if (!Array.isArray(input.mappings)) throw new Error(`${label}.mappings must be an array`);
  input.mappings.forEach((mapping, index) => {
    const mappingLabel = `${label}.mappings[${index}]`;
    assertPlainObject(mapping, mappingLabel);
    assertExactKeys(mapping, ["slackUserId", "localHumanPrincipalId", "approvalClasses"], mappingLabel);
    assertSyntheticIdentifier(mapping.slackUserId, `${mappingLabel}.slackUserId`, "slack-user-");
    assertSyntheticIdentifier(mapping.localHumanPrincipalId, `${mappingLabel}.localHumanPrincipalId`, "person-");
    assertStringArray(mapping.approvalClasses, `${mappingLabel}.approvalClasses`, { nonempty: true });
  });
  if (input.priorEffectivePolicyRevision !== null) assertNonnegativeInteger(input.priorEffectivePolicyRevision, `${label}.priorEffectivePolicyRevision`);
  assertNonnegativeInteger(input.proposedRevision, `${label}.proposedRevision`);
  assertNullableString(input.authorizingApproverId, `${label}.authorizingApproverId`);
  if (input.authorizingApproverId !== null) assertSyntheticIdentifier(input.authorizingApproverId, `${label}.authorizingApproverId`, "person-");
  assertEnum(input.operation, ["seed-bootstrap-desired-state", "add-approver", "widen-approver", "remove-approver-and-invalidate-requests", "replace-private-file"], `${label}.operation`);
}

function validateResponseEnvelope(envelope, contractCase, label) {
  assertExactKeys(envelope, ["schemaVersion", "toolVersion", "command", "requestId", "runId", "status", "changed", "recoveryEpoch", "stateRevision", "snapshotDigest", "releaseBuildId", "sourceRevision", "planId", "errors", "data"], label);
  if (envelope.schemaVersion !== 1) throw new Error(`${label}.schemaVersion must be 1`);
  assertNonemptyString(envelope.toolVersion, `${label}.toolVersion`);
  assertEnum(envelope.command, ["api-ssh"], `${label}.command`);
  assertNonemptyString(envelope.requestId, `${label}.requestId`);
  assertNullableString(envelope.runId, `${label}.runId`);
  assertEnum(envelope.status, ["succeeded", "blocked"], `${label}.status`);
  assertBoolean(envelope.changed, `${label}.changed`);
  assertNonnegativeInteger(envelope.recoveryEpoch, `${label}.recoveryEpoch`);
  assertNonnegativeInteger(envelope.stateRevision, `${label}.stateRevision`);
  assertNullableString(envelope.snapshotDigest, `${label}.snapshotDigest`);
  assertNonemptyString(envelope.releaseBuildId, `${label}.releaseBuildId`);
  assertNullableString(envelope.sourceRevision, `${label}.sourceRevision`);
  assertNullableString(envelope.planId, `${label}.planId`);
  if (!Array.isArray(envelope.errors)) throw new Error(`${label}.errors must be an array`);
  envelope.errors.forEach((error, index) => {
    const errorLabel = `${label}.errors[${index}]`;
    assertPlainObject(error, errorLabel);
    assertExactKeys(error, ["code", "target", "retryable"], errorLabel);
    if (!ERROR_CODES.has(error.code)) throw new Error(`${errorLabel}.code is not in the Phase 0.3 error registry`);
    assertNonemptyString(error.target, `${errorLabel}.target`);
    assertBoolean(error.retryable, `${errorLabel}.retryable`);
  });
  assertPlainObject(envelope.data, `${label}.data`);
  if (contractCase.expected.status === "accepted" && (envelope.status !== "succeeded" || envelope.errors.length !== 0)) throw new Error(`${label} accepted result must carry a successful response envelope`);
  if (contractCase.expected.status !== "accepted" && envelope.errors[0]?.code !== contractCase.expected.errorCode) throw new Error(`${label} blocked result must carry its expected response error`);
}

function validateConstrainedSsh(input, contractCase, label) {
  assertExactKeys(input, ["protocol", "version", "requestId", "sshPrincipalId", "deviceId", "operation", "arguments", "payloadDigest", "declaredPayloadBytes", "actualPayloadBytes", "recoveryEpoch", "responseFrame"], label);
  assertNonemptyString(input.protocol, `${label}.protocol`);
  assertNonemptyString(input.version, `${label}.version`);
  assertSyntheticIdentifier(input.requestId, `${label}.requestId`, "request-");
  assertSyntheticIdentifier(input.sshPrincipalId, `${label}.sshPrincipalId`, input.sshPrincipalId.startsWith("client-") ? "client-" : "ssh-principal-");
  assertSyntheticIdentifier(input.deviceId, `${label}.deviceId`, "device-");
  assertNonemptyString(input.operation, `${label}.operation`);
  assertStringArray(input.arguments, `${label}.arguments`);
  assertDigest(input.payloadDigest, `${label}.payloadDigest`);
  assertNonnegativeInteger(input.declaredPayloadBytes, `${label}.declaredPayloadBytes`);
  assertNonnegativeInteger(input.actualPayloadBytes, `${label}.actualPayloadBytes`);
  assertNonnegativeInteger(input.recoveryEpoch, `${label}.recoveryEpoch`);
  assertPlainObject(input.responseFrame, `${label}.responseFrame`);
  assertExactKeys(input.responseFrame, ["protocol", "version", "requestId", "declaredPayloadBytes", "actualPayloadBytes", "envelope"], `${label}.responseFrame`);
  assertNonemptyString(input.responseFrame.protocol, `${label}.responseFrame.protocol`);
  assertNonemptyString(input.responseFrame.version, `${label}.responseFrame.version`);
  assertNonemptyString(input.responseFrame.requestId, `${label}.responseFrame.requestId`);
  assertNonnegativeInteger(input.responseFrame.declaredPayloadBytes, `${label}.responseFrame.declaredPayloadBytes`);
  assertNonnegativeInteger(input.responseFrame.actualPayloadBytes, `${label}.responseFrame.actualPayloadBytes`);
  assertPlainObject(input.responseFrame.envelope, `${label}.responseFrame.envelope`);
  validateResponseEnvelope(input.responseFrame.envelope, contractCase, `${label}.responseFrame.envelope`);
  if (input.responseFrame.requestId !== input.responseFrame.envelope.requestId) throw new Error(`${label} response frame and envelope request IDs must match`);
  if (contractCase.expected.status === "accepted") {
    if (input.protocol !== "vegastack-labs.api-ssh" || input.version !== "1.0.0") throw new Error(`${label} accepted request must use the supported protocol`);
    if (input.declaredPayloadBytes !== input.actualPayloadBytes) throw new Error(`${label} accepted request lengths must match`);
    if (input.responseFrame.protocol !== "vegastack-labs.api-ssh" || input.responseFrame.version !== "1.0.0") throw new Error(`${label} accepted response must use the supported protocol`);
    if (input.responseFrame.declaredPayloadBytes !== input.responseFrame.actualPayloadBytes) throw new Error(`${label} accepted response lengths must match`);
    if (input.responseFrame.requestId !== input.requestId) throw new Error(`${label} accepted response must correlate to the request`);
  }
}

function validateProfileGates(input, contractCase, label) {
  assertExactKeys(input, ["fixtureProfile", "owningLayer", "profileId", "profileVersion", "defaultsDigest", "resolvedValues", "gates", "requestedOperation", "slackCapabilityState", "recoveryEpoch"], label);
  assertEnum(input.fixtureProfile, ["minimal-no-account", "synthetic-non-labs", "vegastack-labs-synthetic"], `${label}.fixtureProfile`);
  assertEnum(input.owningLayer, ["portable-core", "typed-approval-adapter", "deployment-profile"], `${label}.owningLayer`);
  assertNonemptyString(input.profileId, `${label}.profileId`);
  assertNonemptyString(input.profileVersion, `${label}.profileVersion`);
  assertDigest(input.defaultsDigest, `${label}.defaultsDigest`);
  if (!Array.isArray(input.resolvedValues)) throw new Error(`${label}.resolvedValues must be an array`);
  input.resolvedValues.forEach((entry, index) => {
    const entryLabel = `${label}.resolvedValues[${index}]`;
    assertPlainObject(entry, entryLabel);
    assertExactKeys(entry, ["key", "value", "provenance"], entryLabel);
    ["key", "value", "provenance"].forEach((key) => assertNonemptyString(entry[key], `${entryLabel}.${key}`));
  });
  if (!Array.isArray(input.gates)) throw new Error(`${label}.gates must be an array`);
  input.gates.forEach((gate, index) => {
    const gateLabel = `${label}.gates[${index}]`;
    assertPlainObject(gate, gateLabel);
    assertExactKeys(gate, ["gateId", "gateVersion", "subjects", "applicability", "prerequisites", "evidenceState", "recoveryEpoch"], gateLabel);
    assertSyntheticIdentifier(gate.gateId, `${gateLabel}.gateId`, gate.gateId.startsWith("labs-") ? "labs-" : "synthetic-");
    assertNonemptyString(gate.gateVersion, `${gateLabel}.gateVersion`);
    assertStringArray(gate.subjects, `${gateLabel}.subjects`);
    assertEnum(gate.applicability, ["applicable", "not-applicable"], `${gateLabel}.applicability`);
    assertStringArray(gate.prerequisites, `${gateLabel}.prerequisites`);
    assertEnum(gate.evidenceState, ["current", "missing", "not-evaluated"], `${gateLabel}.evidenceState`);
    assertNonnegativeInteger(gate.recoveryEpoch, `${gateLabel}.recoveryEpoch`);
  });
  assertNonemptyString(input.requestedOperation, `${label}.requestedOperation`);
  assertEnum(input.slackCapabilityState, ["not-configured", "qualified", "unavailable", "stale", "wrong-workspace"], `${label}.slackCapabilityState`);
  assertNonnegativeInteger(input.recoveryEpoch, `${label}.recoveryEpoch`);
  if (contractCase.id === "stale-slack-binding-blocked" && input.slackCapabilityState !== "stale") throw new Error(`${label} stale binding case must carry stale Slack capability state`);
  if (contractCase.id === "wrong-workspace-blocked" && input.slackCapabilityState !== "wrong-workspace") throw new Error(`${label} wrong-workspace case must carry wrong-workspace capability state`);
  if (contractCase.id === "missing-mandatory-evidence-blocked" && !input.gates.some(({ evidenceState }) => evidenceState === "missing")) throw new Error(`${label} missing-evidence case must carry a missing evidence state`);
  if (contractCase.expected.status === "accepted" && ["bootstrap-control-plane", "apply-plan"].includes(input.requestedOperation) && input.slackCapabilityState !== "qualified") throw new Error(`${label} accepted mutation requires qualified Slack capability`);
}

const INPUT_VALIDATORS = new Map([
  ["installation-manifest", validateInstallationManifest],
  ["setup-state", validateSetupState],
  ["slack-acknowledgement", validateSlackAcknowledgement],
  ["approver-import", validateApproverImport],
  ["constrained-ssh", validateConstrainedSsh],
  ["profile-gates", validateProfileGates],
]);

function requireNegativeFact(condition, label, description) {
  if (!condition) throw new Error(`${label} must preserve its denial fact: ${description}`);
}

function validateInstallationNegativeFacts(contractCase, inputs, label) {
  const input = contractCase.input;
  const accepted = inputs.get("first-use-accepted");
  requireNegativeFact(accepted.releaseBuildId === FIXTURE_FACTS.approvedReleaseBuildId && accepted.releaseDigest === FIXTURE_FACTS.approvedReleaseDigest, label, "the accepted reference carries the pinned approved release");
  const integrity = manifestIntegrity(input, label);
  switch (contractCase.id) {
    case "consumed-replay-denied":
      requireNegativeFact(input.state === "consumed", label, "the manifest is already consumed");
      break;
    case "expired-denied":
      requireNegativeFact(Date.parse(input.expiresAt) < FIXTURE_EVALUATION_TIME, label, "the manifest is expired");
      break;
    case "release-substitution-denied":
      requireNegativeFact(input.releaseBuildId !== FIXTURE_FACTS.approvedReleaseBuildId && input.releaseDigest !== FIXTURE_FACTS.approvedReleaseDigest, label, "release build and digest differ from the approved release");
      break;
    case "target-substitution-denied":
    case "forged-ssh-binding-denied":
      requireNegativeFact(input.hostIdentity.kind === "verified-ssh" && input.hostIdentity.subject !== input.initialAdministrator.sshPrincipalId, label, "the observed SSH subject differs from the administrator binding");
      break;
    case "interrupted-consumption-denied":
      requireNegativeFact(input.state === "consuming", label, "manifest consumption is interrupted in progress");
      break;
    case "invalid-signature-denied":
      requireNegativeFact(integrity.verificationStatus === "invalid", label, "signature verification is invalid");
      break;
    case "untrusted-signer-denied":
      requireNegativeFact(integrity.verificationStatus === "untrusted", label, "the signer is untrusted");
      break;
    case "post-approval-manifest-mutation-denied":
      requireNegativeFact(integrity.verificationStatus === "invalid" && input.releaseDigest !== FIXTURE_FACTS.approvedReleaseDigest, label, "post-approval content changed and invalidated verification");
      break;
    case "cross-user-binding-denied": {
      const mapping = manifestAcknowledgementExtension(input, label).initialMapping;
      requireNegativeFact(mapping.localHumanPrincipalId !== input.initialAdministrator.localPrincipalId, label, "the Slack mapping resolves to another local human");
      break;
    }
    default:
      throw new Error(`${label} has no independent installation-manifest denial-fact validator`);
  }
}

function validateSetupNegativeFacts(contractCase, _inputs, label) {
  const input = contractCase.input;
  const expected = {
    "interruption-enters-recovery": ["resume-interrupted-manifest", "consuming", "unknown", "recovery-required"],
    "manifest-reuse-denied": ["reuse-consumed-manifest", "consumed", "server-exclusive", "local-setup-service"],
    "second-writer-denied": ["open-second-writable-database", "consumed", "conflicting-writer", "recovery-required"],
    "hostname-authority-denied": ["bind-administrator-from-hostname", "pending", "none", "uninitialized"],
    "first-browser-authority-denied": ["bind-first-browser-visitor", "pending", "none", "uninitialized"],
    "client-asserted-identity-denied": ["bind-client-asserted-principal", "pending", "none", "uninitialized"],
  }[contractCase.id];
  requireNegativeFact(expected !== undefined && [input.operation, input.manifestState, input.writerState, input.to].every((value, index) => value === expected[index]), label, "the named setup authority or writer hazard remains present");
}

function validateSlackNegativeFacts(contractCase, inputs, label) {
  const input = contractCase.input;
  const bootstrap = inputs.get("bootstrap-approved");
  const duplicate = inputs.get("duplicate-click-idempotent");
  requireNegativeFact(bootstrap.requestId === FIXTURE_FACTS.bootstrapApprovalRequestId && bootstrap.installationManifestId === FIXTURE_FACTS.bootstrapManifestId && bootstrap.responsibleHumanId === FIXTURE_FACTS.bootstrapResponsibleHumanId && bootstrap.slackUserId === FIXTURE_FACTS.bootstrapSlackUserId, label, "the accepted bootstrap reference carries the pinned request and mapping");
  requireNegativeFact(duplicate.requestId === FIXTURE_FACTS.consumedApprovalRequestId && duplicate.nonce === FIXTURE_FACTS.consumedApprovalNonce, label, "the idempotent duplicate reference carries the consumed request and nonce");
  switch (contractCase.id) {
    case "missing-authenticated-envelope":
      requireNegativeFact(input.envelopeId === null, label, "the authenticated interaction envelope is absent");
      break;
    case "wrong-workspace-denied":
      requireNegativeFact(input.workspaceId !== FIXTURE_FACTS.approvedWorkspaceId, label, "the workspace differs from the configured workspace");
      break;
    case "wrong-user-denied":
      requireNegativeFact(input.slackUserId !== FIXTURE_FACTS.approvedOrdinarySlackUserId, label, "the Slack user differs from the configured user");
      break;
    case "agent-controlled-session-insufficient":
      requireNegativeFact(input.sessionControl === "agent-accessible", label, "the session is accessible to the assisting agent");
      break;
    case "changed-digest-denied":
      requireNegativeFact(input.subjectDigest !== FIXTURE_FACTS.currentPlanDigest && input.targetSetDigest === FIXTURE_FACTS.currentTargetSetDigest, label, "only the protected subject digest changed");
      break;
    case "changed-target-denied":
      requireNegativeFact(input.targetSetDigest !== FIXTURE_FACTS.currentTargetSetDigest && input.subjectDigest === FIXTURE_FACTS.currentPlanDigest, label, "only the protected target set changed");
      break;
    case "stale-plan-denied":
      requireNegativeFact(input.stateRevision < FIXTURE_FACTS.currentStateRevision, label, "the request state revision is stale");
      break;
    case "expired-request-denied":
      requireNegativeFact(Date.parse(input.receivedAt) > Date.parse(input.expiresAt), label, "the action arrived after expiry");
      break;
    case "replay-denied":
      requireNegativeFact(input.requestId === FIXTURE_FACTS.consumedApprovalRequestId && input.nonce === FIXTURE_FACTS.consumedApprovalNonce && (input.planId !== duplicate.planId || input.subjectDigest !== duplicate.subjectDigest), label, "a consumed request and nonce are reused for a different subject");
      break;
    case "recovery-epoch-mismatch":
      requireNegativeFact(input.recoveryEpoch < FIXTURE_FACTS.currentRecoveryEpoch, label, "the request belongs to an earlier recovery epoch");
      break;
    case "socket-mode-outage":
      requireNegativeFact(input.sessionControl === "unavailable" && input.envelopeId === null, label, "Socket Mode and its authenticated envelope are unavailable");
      break;
    case "adapter-token-failure":
      requireNegativeFact(input.sessionControl === "adapter-credential-invalid" && input.envelopeId === null, label, "the adapter credential is invalid");
      break;
    case "lost-approver-access":
      requireNegativeFact(input.sessionControl === "revoked" && input.envelopeId === null, label, "approver access is revoked");
      break;
    case "missing-proof":
      requireNegativeFact(input.action === null && input.envelopeId === null && input.receivedAt === null, label, "no human action proof exists");
      break;
    case "bootstrap-approval-request-substitution-denied":
      requireNegativeFact(input.requestId !== FIXTURE_FACTS.bootstrapApprovalRequestId && input.installationManifestId === FIXTURE_FACTS.bootstrapManifestId, label, "the bootstrap approval request was substituted");
      break;
    case "bootstrap-mapping-substitution-denied":
      requireNegativeFact(input.requestId === FIXTURE_FACTS.bootstrapApprovalRequestId && (input.responsibleHumanId !== FIXTURE_FACTS.bootstrapResponsibleHumanId || input.slackUserId !== FIXTURE_FACTS.bootstrapSlackUserId), label, "the bootstrap human mapping was substituted");
      break;
    case "automatic-break-glass-fallback-denied":
      requireNegativeFact(input.action === "automatic-break-glass-fallback" && input.breakGlassHandoff?.authorizationState === "absent" && input.breakGlassHandoff?.toRecoveryEpoch === input.breakGlassHandoff?.fromRecoveryEpoch, label, "break-glass has no separate authorization and does not advance the epoch");
      break;
    default:
      throw new Error(`${label} has no independent Slack denial-fact validator`);
  }
}

function validateApproverNegativeFacts(contractCase, _inputs, label) {
  const input = contractCase.input;
  if (["proposed-user-self-add-denied", "proposed-user-self-widen-denied"].includes(contractCase.id)) {
    requireNegativeFact(input.authorizingApproverId === input.mappings[0]?.localHumanPrincipalId, label, "the proposed user attempts to authorize themself");
  } else if (contractCase.id === "file-replacement-cannot-authorize") {
    requireNegativeFact(input.operation === "replace-private-file" && input.authorizingApproverId === null, label, "file replacement has no effective authorizer");
  } else {
    throw new Error(`${label} has no independent approver-import denial-fact validator`);
  }
}

function validateSshNegativeFacts(contractCase, inputs, label) {
  const input = contractCase.input;
  const reader = inputs.get("read-request-accepted");
  const apply = inputs.get("approved-apply-request-accepted");
  requireNegativeFact(reader.sshPrincipalId === FIXTURE_FACTS.readerPrincipalId && reader.deviceId === FIXTURE_FACTS.readerDeviceId && apply.recoveryEpoch === FIXTURE_FACTS.currentRecoveryEpoch, label, "accepted SSH references carry the pinned principal/device and recovery epoch");
  switch (contractCase.id) {
    case "shell-text-denied":
      requireNegativeFact(input.operation === "shell" && input.arguments.some((argument) => /[;&|`$]/.test(argument)), label, "arbitrary shell text is present");
      break;
    case "path-denied":
      requireNegativeFact(input.operation === "read-file" && input.arguments.some((argument) => argument.includes("/") || argument.includes("control-database")), label, "a direct filesystem path is requested");
      break;
    case "direct-sqlite-denied":
      requireNegativeFact(input.operation === "sqlite-query" && input.arguments.some((argument) => /\b(?:select|insert|update|delete|sqlite)\b/i.test(argument)), label, "direct SQLite access is requested");
      break;
    case "malformed-length-denied":
      requireNegativeFact(input.declaredPayloadBytes !== input.actualPayloadBytes, label, "request frame lengths disagree");
      break;
    case "unsupported-version-denied":
      requireNegativeFact(input.version !== "1.0.0", label, "the request protocol version is unsupported");
      break;
    case "unknown-operation-denied":
      requireNegativeFact(!DECLARED_SSH_OPERATIONS.has(input.operation), label, "the operation is not in the declared API allowlist");
      break;
    case "client-asserted-identity-denied":
      requireNegativeFact(input.sshPrincipalId.startsWith("client-asserted-"), label, "identity is client asserted rather than transport verified");
      break;
    case "principal-device-mismatch":
      requireNegativeFact(input.sshPrincipalId === FIXTURE_FACTS.readerPrincipalId && input.deviceId !== FIXTURE_FACTS.readerDeviceId, label, "the verified principal is paired with an unbound device");
      break;
    case "recovery-epoch-mismatch":
      requireNegativeFact(input.recoveryEpoch < FIXTURE_FACTS.currentRecoveryEpoch, label, "the request belongs to an earlier recovery epoch");
      break;
    case "response-length-denied":
      requireNegativeFact(input.responseFrame.declaredPayloadBytes !== input.responseFrame.actualPayloadBytes, label, "response frame lengths disagree");
      break;
    case "response-version-denied":
      requireNegativeFact(input.responseFrame.version !== "1.0.0", label, "the response protocol version is unsupported");
      break;
    case "response-correlation-denied":
      requireNegativeFact(input.responseFrame.requestId !== input.requestId, label, "the response does not correlate to the request");
      break;
    default:
      throw new Error(`${label} has no independent constrained-SSH denial-fact validator`);
  }
}

function validateProfileNegativeFacts(contractCase, _inputs, label) {
  const input = contractCase.input;
  switch (contractCase.id) {
    case "minimal-bootstrap-without-slack-blocked":
      requireNegativeFact(input.requestedOperation === "bootstrap-control-plane" && input.slackCapabilityState === "not-configured", label, "bootstrap lacks Slack acknowledgement capability");
      break;
    case "minimal-apply-without-slack-blocked":
      requireNegativeFact(input.requestedOperation === "apply-plan" && input.slackCapabilityState === "not-configured", label, "apply lacks Slack acknowledgement capability");
      break;
    case "slack-unavailable-blocked":
      requireNegativeFact(input.slackCapabilityState === "unavailable", label, "Slack acknowledgement is unavailable");
      break;
    case "stale-slack-binding-blocked":
      requireNegativeFact(input.slackCapabilityState === "stale", label, "the Slack binding is stale");
      break;
    case "wrong-workspace-blocked":
      requireNegativeFact(input.slackCapabilityState === "wrong-workspace", label, "the workspace does not match the profile");
      break;
    case "missing-mandatory-evidence-blocked":
      requireNegativeFact(input.gates.some((gate) => gate.applicability === "applicable" && gate.evidenceState === "missing"), label, "an applicable gate lacks mandatory evidence");
      break;
    case "conflicting-provenance-blocked": {
      const byKey = new Map();
      let conflict = false;
      for (const entry of input.resolvedValues) {
        const prior = byKey.get(entry.key);
        if (prior !== undefined && (prior.value !== entry.value || prior.provenance !== entry.provenance)) conflict = true;
        byKey.set(entry.key, entry);
      }
      requireNegativeFact(conflict, label, "one resolved value has competing owners");
      break;
    }
    default:
      throw new Error(`${label} has no independent profile-gates denial-fact validator`);
  }
}

const NEGATIVE_FACT_VALIDATORS = new Map([
  ["installation-manifest", validateInstallationNegativeFacts],
  ["setup-state", validateSetupNegativeFacts],
  ["slack-acknowledgement", validateSlackNegativeFacts],
  ["approver-import", validateApproverNegativeFacts],
  ["constrained-ssh", validateSshNegativeFacts],
  ["profile-gates", validateProfileNegativeFacts],
]);

export function validatePhaseZeroThreeFixture(document, source) {
  assertPlainObject(document, source);
  assertSanitized(document, source);
  assertExactKeys(document, ["schema", "schemaVersion", "contract", "cases"], source);

  if (document.schema !== FIXTURE_SCHEMA) {
    throw new Error(`${source} has unsupported fixture schema ${JSON.stringify(document.schema)}`);
  }
  if (document.schemaVersion !== SCHEMA_VERSION) {
    throw new Error(`${source} has unsupported schema version ${JSON.stringify(document.schemaVersion)}`);
  }
  if (!CONTRACT_NAMES.has(document.contract)) {
    throw new Error(`${source} has unknown contract ${JSON.stringify(document.contract)}`);
  }
  if (!Array.isArray(document.cases) || document.cases.length === 0) {
    throw new Error(`${source} cases must be a nonempty array`);
  }

  const caseIds = new Set();
  for (const [index, contractCase] of document.cases.entries()) {
    const label = `${source} cases[${index}]`;
    assertPlainObject(contractCase, label);
    assertSanitized(contractCase, label);
    assertExactKeys(contractCase, ["id", "input", "expected"], label);
    assertNonemptyString(contractCase.id, `${label}.id`);
    if (caseIds.has(contractCase.id)) {
      throw new Error(`${source} has duplicate case id ${JSON.stringify(contractCase.id)}`);
    }
    caseIds.add(contractCase.id);
    assertPlainObject(contractCase.input, `${label}.input`);
    INPUT_VALIDATORS.get(document.contract)(contractCase.input, contractCase, `${label}.input`);
    assertPlainObject(contractCase.expected, `${label}.expected`);
    assertExactKeys(
      contractCase.expected,
      ["status", "errorCode", "reason"],
      `${label}.expected`,
    );

    if (!["accepted", "blocked", "failed"].includes(contractCase.expected.status)) {
      throw new Error(`${label} has unknown expected status ${JSON.stringify(contractCase.expected.status)}`);
    }
    if (contractCase.expected.status === "accepted") {
      if (contractCase.expected.errorCode !== null) {
        throw new Error(`${label} accepted result must have a null error code`);
      }
    } else if (!ERROR_CODES.has(contractCase.expected.errorCode)) {
      throw new Error(`${label} has unknown error code ${JSON.stringify(contractCase.expected.errorCode)}`);
    }
    assertNonemptyString(contractCase.expected.reason, `${label}.expected.reason`);
    const pinnedOutcome = EXPECTED_OUTCOMES.get(`${document.contract}/${contractCase.id}`);
    if (pinnedOutcome === undefined) throw new Error(`${label} is not registered in the independent outcome oracle`);
    if (contractCase.expected.status !== pinnedOutcome[0] || contractCase.expected.errorCode !== pinnedOutcome[1]) {
      throw new Error(`${label} disagrees with the independent outcome oracle`);
    }
  }

  const inputs = new Map(document.cases.map((contractCase) => [contractCase.id, contractCase.input]));
  for (const [index, contractCase] of document.cases.entries()) {
    if (contractCase.expected.status === "accepted") continue;
    const label = `${source} cases[${index}].input`;
    NEGATIVE_FACT_VALIDATORS.get(document.contract)(contractCase, inputs, label);
  }

  return { contract: document.contract, cases: document.cases.length };
}

function validateIndex(document, source) {
  assertPlainObject(document, source);
  assertExactKeys(document, ["schema", "schemaVersion", "contracts"], source);
  if (document.schema !== INDEX_SCHEMA || document.schemaVersion !== SCHEMA_VERSION) {
    throw new Error(`${source} has an unsupported index schema or version`);
  }
  if (!Array.isArray(document.contracts)) {
    throw new Error(`${source}.contracts must be an array`);
  }

  const contracts = new Set();
  const files = new Set();
  for (const [index, entry] of document.contracts.entries()) {
    const label = `${source} contracts[${index}]`;
    assertPlainObject(entry, label);
    assertExactKeys(entry, ["contract", "file", "requiredCaseIds"], label);
    if (!CONTRACT_NAMES.has(entry.contract)) {
      throw new Error(`${label} has unknown contract ${JSON.stringify(entry.contract)}`);
    }
    if (contracts.has(entry.contract)) {
      throw new Error(`${source} has duplicate contract ${JSON.stringify(entry.contract)}`);
    }
    contracts.add(entry.contract);
    assertNonemptyString(entry.file, `${label}.file`);
    if (entry.file !== path.basename(entry.file) || !entry.file.endsWith(".json")) {
      throw new Error(`${label}.file must be a JSON basename`);
    }
    if (entry.file === "contract-index.json" || files.has(entry.file)) {
      throw new Error(`${source} has duplicate or reserved fixture file ${JSON.stringify(entry.file)}`);
    }
    files.add(entry.file);
    if (!Array.isArray(entry.requiredCaseIds) || entry.requiredCaseIds.length === 0) {
      throw new Error(`${label}.requiredCaseIds must be a nonempty array`);
    }
    const required = new Set();
    for (const caseId of entry.requiredCaseIds) {
      assertNonemptyString(caseId, `${label}.requiredCaseIds entry`);
      if (required.has(caseId)) {
        throw new Error(`${label} has duplicate required case id ${JSON.stringify(caseId)}`);
      }
      required.add(caseId);
    }
  }
  if (contracts.size !== CONTRACT_NAMES.size) {
    const missing = [...CONTRACT_NAMES].filter((contract) => !contracts.has(contract));
    throw new Error(`${source} must index every Phase 0.3 contract; missing ${missing.join(", ")}`);
  }
  return document.contracts;
}

async function loadJson(file) {
  return JSON.parse(await readFile(file, "utf8"));
}

async function validateDocumentedErrorRegistry(root) {
  const source = await readFile(path.join(root, "docs", "automation-and-agents.md"), "utf8");
  const section = source.split("### Exit and error registry")[1]?.split("\n## ")[0];
  if (section === undefined) throw new Error("docs/automation-and-agents.md is missing the exit and error registry");
  const missing = [...ERROR_CODES].filter((code) => !section.includes(`\`${code}\``));
  if (missing.length > 0) throw new Error(`Phase 0.3 error codes missing from the documented registry: ${missing.join(", ")}`);
}

export function validatePhaseZeroThreeContracts(fixtures) {
  const manifest = fixtures.get("installation-manifest")?.cases.find(({ id }) => id === "first-use-accepted")?.input;
  const slack = fixtures.get("slack-acknowledgement")?.cases.find(({ id }) => id === "bootstrap-approved")?.input;
  const approver = fixtures.get("approver-import")?.cases.find(({ id }) => id === "bootstrap-seed-remains-inert")?.input;
  if (manifest === undefined || slack === undefined || approver === undefined) {
    throw new Error("Phase 0.3 bootstrap contracts are missing their linked positive cases");
  }
  const mapping = approver.mappings[0];
  const integrity = manifestIntegrity(manifest, "installation-manifest/first-use-accepted");
  const extension = manifestAcknowledgementExtension(manifest, "installation-manifest/first-use-accepted");
  const initialMapping = extension.initialMapping;
  const comparisons = [
    [manifest.manifestId, slack.installationManifestId, "manifest ID"],
    [manifest.approvalRequestId, slack.requestId, "approval request ID"],
    [integrity.manifestDigest, slack.subjectDigest, "manifest subject digest"],
    [manifest.stateRevision, slack.stateRevision, "state revision"],
    [manifest.recoveryEpoch, slack.recoveryEpoch, "recovery epoch"],
    [manifest.initialAdministrator.localPrincipalId, slack.responsibleHumanId, "responsible local human"],
    [initialMapping.workspaceId, slack.workspaceId, "Slack workspace"],
    [initialMapping.slackUserId, slack.slackUserId, "Slack user"],
    [initialMapping.localHumanPrincipalId, slack.responsibleHumanId, "Slack-to-local-human mapping"],
    [initialMapping.workspaceId, approver.workspaceId, "approver workspace"],
    [initialMapping.slackUserId, mapping?.slackUserId, "approver Slack user"],
    [initialMapping.localHumanPrincipalId, mapping?.localHumanPrincipalId, "approver local human"],
    [JSON.stringify(initialMapping.approvalClasses), JSON.stringify(mapping?.approvalClasses), "approval classes"],
    [initialMapping.approvalClasses[0], slack.riskClass, "bootstrap risk class"],
  ];
  for (const [left, right, label] of comparisons) {
    if (left !== right) throw new Error(`linked bootstrap contracts disagree on ${label}`);
  }
  for (const ref of Object.values(extension.secretRefs)) {
    if (!ref.startsWith("secret-ref-synthetic-")) throw new Error("bootstrap Slack credentials must be logical synthetic references");
  }

  const cases = (contract) => new Map(fixtures.get(contract).cases.map((entry) => [entry.id, entry.input]));
  const slackCases = cases("slack-acknowledgement");
  const ordinaryApproval = slackCases.get("ordinary-plan-approved");
  const wrongWorkspace = slackCases.get("wrong-workspace-denied");
  const wrongUser = slackCases.get("wrong-user-denied");
  if (wrongWorkspace.workspaceId === ordinaryApproval.workspaceId) throw new Error("wrong-workspace case must differ from the approved workspace");
  if (wrongUser.slackUserId === ordinaryApproval.slackUserId) throw new Error("wrong-user case must differ from the approved Slack user");
  const expired = slackCases.get("expired-request-denied");
  if (Date.parse(expired.receivedAt) <= Date.parse(expired.expiresAt)) throw new Error("expired Slack case must arrive after expiry");
  const duplicate = slackCases.get("duplicate-click-idempotent");
  const replay = slackCases.get("replay-denied");
  if (duplicate.requestId !== replay.requestId || duplicate.nonce !== replay.nonce) throw new Error("duplicate and replay cases must share the consumed request and nonce");
  if (duplicate.planId === replay.planId && duplicate.subjectDigest === replay.subjectDigest) throw new Error("replay case must attempt a different consumed subject");

  const approverCases = cases("approver-import");
  for (const id of ["proposed-user-self-add-denied", "proposed-user-self-widen-denied"]) {
    const input = approverCases.get(id);
    if (input.authorizingApproverId !== input.mappings[0]?.localHumanPrincipalId) throw new Error(`${id} must model self-authorization`);
  }
  for (const id of ["existing-admin-add-accepted", "existing-admin-widen-accepted"]) {
    const input = approverCases.get(id);
    if (input.authorizingApproverId === null || input.authorizingApproverId === input.mappings[0]?.localHumanPrincipalId) throw new Error(`${id} must be authorized by a different existing approver`);
  }

  const profileCases = cases("profile-gates");
  const conflicting = profileCases.get("conflicting-provenance-blocked").resolvedValues;
  const conflictingKeys = new Map();
  for (const value of conflicting) {
    const prior = conflictingKeys.get(value.key);
    if (prior !== undefined && (prior.value !== value.value || prior.provenance !== value.provenance)) conflictingKeys.set(value.key, "conflict");
    else if (prior === undefined) conflictingKeys.set(value.key, value);
  }
  if (![...conflictingKeys.values()].includes("conflict")) throw new Error("conflicting-provenance case must contain competing owners for one value");

  const sshCases = cases("constrained-ssh");
  const responseLength = sshCases.get("response-length-denied");
  if (responseLength.responseFrame.declaredPayloadBytes === responseLength.responseFrame.actualPayloadBytes) throw new Error("response-length case must contain a framing mismatch");
  const responseVersion = sshCases.get("response-version-denied");
  if (responseVersion.responseFrame.version === "1.0.0") throw new Error("response-version case must use an unsupported response version");
  const responseCorrelation = sshCases.get("response-correlation-denied");
  if (responseCorrelation.responseFrame.requestId === responseCorrelation.requestId) throw new Error("response-correlation case must mismatch the originating request ID");
}

export async function loadPhaseZeroThreeFixtures(root = ROOT) {
  await validateDocumentedErrorRegistry(root);
  const directory = path.join(root, FIXTURE_DIRECTORY);
  const indexPath = path.join(directory, "contract-index.json");
  const entries = validateIndex(await loadJson(indexPath), "contract-index.json");
  const expectedFiles = new Set(["contract-index.json", ...entries.map(({ file }) => file)]);
  const actualFiles = (await readdir(directory)).filter((file) => file.endsWith(".json"));
  for (const file of actualFiles) {
    if (!expectedFiles.has(file)) {
      throw new Error(`unindexed Phase 0.3 fixture file ${JSON.stringify(file)}`);
    }
  }
  for (const file of expectedFiles) {
    if (!actualFiles.includes(file)) {
      throw new Error(`indexed Phase 0.3 fixture file is missing: ${file}`);
    }
  }

  const fixtures = new Map();
  for (const entry of entries) {
    const document = await loadJson(path.join(directory, entry.file));
    validatePhaseZeroThreeFixture(document, entry.file);
    if (document.contract !== entry.contract) {
      throw new Error(`${entry.file} contract does not match its index entry`);
    }
    const caseIds = new Set(document.cases.map(({ id }) => id));
    for (const requiredCaseId of entry.requiredCaseIds) {
      if (!caseIds.has(requiredCaseId)) {
        throw new Error(`${entry.file} is missing required case ${JSON.stringify(requiredCaseId)}`);
      }
    }
    fixtures.set(entry.contract, document);
  }
  validatePhaseZeroThreeContracts(fixtures);
  return fixtures;
}

export async function verifyPhaseZeroThree(root = ROOT) {
  const fixtures = await loadPhaseZeroThreeFixtures(root);
  const contracts = [...fixtures.keys()].sort();
  const cases = [...fixtures.values()].reduce((total, fixture) => total + fixture.cases.length, 0);
  return { fixtureFiles: fixtures.size, cases, contracts };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const result = await verifyPhaseZeroThree();
    process.stdout.write(
      `${JSON.stringify({ schemaVersion: 1, check: "phase-0-3-contracts", status: "pass", ...result })}\n`,
    );
  } catch (error) {
    process.stderr.write(`Phase 0.3 contract verification failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
