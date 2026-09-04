import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURE_DIRECTORY = path.join("tooling", "testdata", "phase-0-3");
const FIXTURE_SCHEMA = "vegastack-labs.dev/phase-0.3-contract-fixture";
const INDEX_SCHEMA = "vegastack-labs.dev/phase-0.3-contract-index";
const SCHEMA_VERSION = "1.0.0";

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
  function visit(current, currentLabel) {
    if (typeof current === "string") {
      if (slackToken.test(current)) throw new Error(`${currentLabel} contains a Slack credential value`);
      return;
    }
    if (Array.isArray(current)) {
      current.forEach((entry, index) => visit(entry, `${currentLabel}[${index}]`));
      return;
    }
    if (current === null || typeof current !== "object") return;
    for (const [key, child] of Object.entries(current)) {
      if (forbiddenKey.test(key)) throw new Error(`${currentLabel}.${key} is a forbidden private-value field`);
      if (/token/i.test(key) && !/(?:Ref|Refs)$/.test(key)) {
        throw new Error(`${currentLabel}.${key} must be represented as a logical reference`);
      }
      visit(child, `${currentLabel}.${key}`);
    }
  }
  visit(value, label);
}

const MANIFEST_KEYS = [
  "manifestId", "releaseBuildId", "releaseDigest", "manifestIntegrity", "intendedOperation",
  "hostIdentity", "databasePathRef", "initialAdministrator", "initialSlackMapping",
  "slackSecretRefs", "profileId", "profileVersion", "profileDefaultsDigest",
  "profileProvenance", "stateRevision", "recoveryEpoch", "recoveryPreconditions",
  "approvalRequestId", "expiresAt", "nonce", "state",
];

function validateInstallationManifest(input, contractCase, label) {
  assertExactKeys(input, MANIFEST_KEYS, label);
  assertSyntheticIdentifier(input.manifestId, `${label}.manifestId`, "manifest-");
  assertSyntheticIdentifier(input.releaseBuildId, `${label}.releaseBuildId`, "release-");
  assertDigest(input.releaseDigest, `${label}.releaseDigest`);
  assertPlainObject(input.manifestIntegrity, `${label}.manifestIntegrity`);
  assertExactKeys(input.manifestIntegrity, ["manifestDigest", "signatureFormat", "signerKeyId", "verificationBundleRef", "verificationStatus"], `${label}.manifestIntegrity`);
  assertDigest(input.manifestIntegrity.manifestDigest, `${label}.manifestIntegrity.manifestDigest`);
  assertEnum(input.manifestIntegrity.signatureFormat, ["detached-verification-bundle"], `${label}.manifestIntegrity.signatureFormat`);
  assertSyntheticIdentifier(input.manifestIntegrity.signerKeyId, `${label}.manifestIntegrity.signerKeyId`, "signer-key-");
  assertSyntheticIdentifier(input.manifestIntegrity.verificationBundleRef, `${label}.manifestIntegrity.verificationBundleRef`, "verification-bundle-");
  assertEnum(input.manifestIntegrity.verificationStatus, ["verified", "invalid", "untrusted"], `${label}.manifestIntegrity.verificationStatus`);
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
  assertPlainObject(input.initialSlackMapping, `${label}.initialSlackMapping`);
  assertExactKeys(input.initialSlackMapping, ["workspaceId", "slackUserId", "localHumanPrincipalId", "approvalClasses"], `${label}.initialSlackMapping`);
  assertSyntheticIdentifier(input.initialSlackMapping.workspaceId, `${label}.initialSlackMapping.workspaceId`, "workspace-");
  assertSyntheticIdentifier(input.initialSlackMapping.slackUserId, `${label}.initialSlackMapping.slackUserId`, "slack-user-");
  assertSyntheticIdentifier(input.initialSlackMapping.localHumanPrincipalId, `${label}.initialSlackMapping.localHumanPrincipalId`, "person-");
  assertStringArray(input.initialSlackMapping.approvalClasses, `${label}.initialSlackMapping.approvalClasses`, { nonempty: true });
  assertPlainObject(input.slackSecretRefs, `${label}.slackSecretRefs`);
  assertExactKeys(input.slackSecretRefs, ["appTokenRef", "botTokenRef"], `${label}.slackSecretRefs`);
  for (const key of ["appTokenRef", "botTokenRef"]) assertSyntheticIdentifier(input.slackSecretRefs[key], `${label}.slackSecretRefs.${key}`, "secret-ref-");
  assertNonemptyString(input.profileId, `${label}.profileId`);
  assertNonemptyString(input.profileVersion, `${label}.profileVersion`);
  assertDigest(input.profileDefaultsDigest, `${label}.profileDefaultsDigest`);
  assertNonemptyString(input.profileProvenance, `${label}.profileProvenance`);
  assertNonnegativeInteger(input.stateRevision, `${label}.stateRevision`);
  assertNonnegativeInteger(input.recoveryEpoch, `${label}.recoveryEpoch`);
  assertStringArray(input.recoveryPreconditions, `${label}.recoveryPreconditions`, { nonempty: true });
  assertSyntheticIdentifier(input.approvalRequestId, `${label}.approvalRequestId`, "approval-");
  assertTimestamp(input.expiresAt, `${label}.expiresAt`);
  assertSyntheticIdentifier(input.nonce, `${label}.nonce`, "nonce-");
  assertEnum(input.state, ["pending", "consuming", "consumed", "failed"], `${label}.state`);

  if (contractCase.expected.status === "accepted") {
    if (input.manifestIntegrity.verificationStatus !== "verified") throw new Error(`${label} accepted manifest must have a verified signature`);
    if (input.initialSlackMapping.localHumanPrincipalId !== input.initialAdministrator.localPrincipalId) throw new Error(`${label} accepted manifest must bind Slack and local human identities`);
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

export function validatePhaseZeroThreeFixture(document, source) {
  assertPlainObject(document, source);
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
    assertExactKeys(contractCase, ["id", "input", "expected"], label);
    assertNonemptyString(contractCase.id, `${label}.id`);
    if (caseIds.has(contractCase.id)) {
      throw new Error(`${source} has duplicate case id ${JSON.stringify(contractCase.id)}`);
    }
    caseIds.add(contractCase.id);
    assertPlainObject(contractCase.input, `${label}.input`);
    assertSanitized(contractCase.input, `${label}.input`);
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
  const comparisons = [
    [manifest.manifestId, slack.installationManifestId, "manifest ID"],
    [manifest.approvalRequestId, slack.requestId, "approval request ID"],
    [manifest.manifestIntegrity.manifestDigest, slack.subjectDigest, "manifest subject digest"],
    [manifest.stateRevision, slack.stateRevision, "state revision"],
    [manifest.recoveryEpoch, slack.recoveryEpoch, "recovery epoch"],
    [manifest.initialAdministrator.localPrincipalId, slack.responsibleHumanId, "responsible local human"],
    [manifest.initialSlackMapping.workspaceId, slack.workspaceId, "Slack workspace"],
    [manifest.initialSlackMapping.slackUserId, slack.slackUserId, "Slack user"],
    [manifest.initialSlackMapping.localHumanPrincipalId, slack.responsibleHumanId, "Slack-to-local-human mapping"],
    [manifest.initialSlackMapping.workspaceId, approver.workspaceId, "approver workspace"],
    [manifest.initialSlackMapping.slackUserId, mapping?.slackUserId, "approver Slack user"],
    [manifest.initialSlackMapping.localHumanPrincipalId, mapping?.localHumanPrincipalId, "approver local human"],
    [JSON.stringify(manifest.initialSlackMapping.approvalClasses), JSON.stringify(mapping?.approvalClasses), "approval classes"],
    [manifest.initialSlackMapping.approvalClasses[0], slack.riskClass, "bootstrap risk class"],
  ];
  for (const [left, right, label] of comparisons) {
    if (left !== right) throw new Error(`linked bootstrap contracts disagree on ${label}`);
  }
  for (const ref of Object.values(manifest.slackSecretRefs)) {
    if (!ref.startsWith("secret-ref-synthetic-")) throw new Error("bootstrap Slack credentials must be logical synthetic references");
  }
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
