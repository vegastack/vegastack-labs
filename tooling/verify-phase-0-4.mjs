import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURE_DIRECTORY = path.join("tooling", "testdata", "phase-0-4");
const FIXTURE_SCHEMA = "vegastack-labs.dev/phase-0.4-contract-fixture";
const INDEX_SCHEMA = "vegastack-labs.dev/phase-0.4-contract-index";
const SCHEMA_VERSION = "1.0.0";

const CONTRACT_NAMES = new Set([
  "host-control-matrix",
  "privileged-execution",
  "native-credentials",
]);
const ERROR_CODES = new Set([
  "INPUT_INVALID",
  "SCHEMA_UNSUPPORTED",
  "AUTHENTICATION_REQUIRED",
  "AUTHORIZATION_DENIED",
  "PLAN_STALE",
  "RECOVERY_EPOCH_MISMATCH",
  "PREREQUISITE_BLOCKED",
  "EVIDENCE_EXPIRED",
]);

const SUPPORTED_PROFILES = new Map([
  ["debian-13-amd64", { osFamily: "debian", release: "13.6", architecture: "amd64" }],
  ["ubuntu-26-04-amd64", { osFamily: "ubuntu", release: "26.04", architecture: "amd64" }],
  ["macos-current-arm64", { osFamily: "macos", release: "current", architecture: "arm64" }],
  ["macos-previous-arm64", { osFamily: "macos", release: "previous", architecture: "arm64" }],
]);

const SUPPORTED_ROLES = new Set([
  "common",
  "control",
  "linux-ci",
  "application",
  "recovery-spare",
  "mac-developer-ci",
  "hermes",
]);

const EXPECTED_CASE_OUTCOMES = {
  "host-control-matrix": {
    accepted: [
      "supported-profiles-complete",
      "debian-13-6-common-accepted",
      "ubuntu-26-04-common-accepted",
    ],
    SCHEMA_UNSUPPORTED: ["unsupported-release-denied"],
    INPUT_INVALID: ["missing-probe-denied", "unbounded-fail2ban-denied", "unsafe-audit-capture-denied"],
    PREREQUISITE_BLOCKED: [
      "package-only-evidence-denied",
      "missing-aide-baseline-denied",
      "missing-recovery-denied",
    ],
  },
  "privileged-execution": {
    accepted: ["approved-bundle-accepted"],
    AUTHORIZATION_DENIED: [
      "wrong-plan-denied",
      "wrong-plan-digest-denied",
      "wrong-bundle-digest-denied",
      "wrong-host-denied",
      "undeclared-action-denied",
      "arbitrary-module-denied",
      "arbitrary-command-denied",
      "target-widening-denied",
      "resident-helper-denied",
      "desired-state-copy-denied",
      "wrong-executable-denied",
    ],
    RECOVERY_EPOCH_MISMATCH: ["wrong-recovery-epoch-denied"],
    PLAN_STALE: ["expired-bundle-denied"],
    PREREQUISITE_BLOCKED: ["lost-recovery-denied"],
  },
  "native-credentials": {
    accepted: [
      "cold-start-accepted",
      "correct-consumer-accepted",
      "no-cloud-account-accepted",
      "no-hardware-protection-accepted",
      "rotation-complete-accepted",
      "revocation-complete-accepted",
    ],
    AUTHORIZATION_DENIED: [
      "cross-consumer-denied",
      "cloud-required-denied",
      "plaintext-fallback-denied",
    ],
    PLAN_STALE: ["stale-material-denied"],
    PREREQUISITE_BLOCKED: [
      "revoked-material-denied",
      "incomplete-rotation-denied",
      "recovery-unavailable-denied",
    ],
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
  if (typeof value !== "string" || value.length === 0) throw new Error(`${label} must be a nonempty string`);
}

function assertNonnegativeInteger(value, label) {
  if (!Number.isInteger(value) || value < 0) throw new Error(`${label} must be a nonnegative integer`);
}

function assertBoolean(value, label) {
  if (typeof value !== "boolean") throw new Error(`${label} must be a boolean`);
}

function assertEnum(value, allowed, label) {
  if (!allowed.includes(value)) throw new Error(`${label} must be one of ${allowed.join(", ")}`);
}

function assertStringArray(value, label, { nonempty = false } = {}) {
  if (!Array.isArray(value) || (nonempty && value.length === 0)) {
    throw new Error(`${label} must be ${nonempty ? "a nonempty" : "an"} array`);
  }
  value.forEach((entry, index) => assertNonemptyString(entry, `${label}[${index}]`));
  if (new Set(value).size !== value.length) throw new Error(`${label} must not contain duplicates`);
}

function assertTimestamp(value, label) {
  assertNonemptyString(value, label);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value) || Number.isNaN(Date.parse(value))) {
    throw new Error(`${label} must be a valid UTC timestamp`);
  }
}

function assertSyntheticIdentifier(value, label, prefix) {
  assertNonemptyString(value, label);
  if (!value.startsWith(prefix) || !value.includes("synthetic")) {
    throw new Error(`${label} must use the ${prefix} synthetic identifier namespace`);
  }
}

function assertSanitized(value, label = "fixture") {
  const forbiddenKey = /(?:password|private.?key|secret.?value|credential.?value|raw.?payload|host.?fact|operational.?evidence)/i;
  const secretValue = /\b(?:x(?:app|ox[abprs])-[A-Za-z0-9-]+|AKIA[A-Z0-9]{16})\b/;
  function visit(current) {
    if (typeof current === "string") {
      if (secretValue.test(current)) throw new Error(`${label} contains a credential value`);
      return;
    }
    if (Array.isArray(current)) {
      current.forEach(visit);
      return;
    }
    if (current === null || typeof current !== "object") return;
    for (const [key, child] of Object.entries(current)) {
      if (forbiddenKey.test(key)) throw new Error(`${label} contains a forbidden private-value field`);
      visit(child);
    }
  }
  visit(value);
}

function validateControl(control, contractCase, label) {
  assertPlainObject(control, label);
  assertExactKeys(
    control,
    [
      "controlId", "profileIds", "roleIds", "applicability", "mechanism", "desiredState",
      "positiveProbe", "negativeProbe", "evidenceMaxAgeSeconds", "recovery", "mandatory", "ownerPhase",
    ],
    label,
  );
  assertNonemptyString(control.controlId, `${label}.controlId`);
  assertStringArray(control.profileIds, `${label}.profileIds`, { nonempty: true });
  assertStringArray(control.roleIds, `${label}.roleIds`, { nonempty: true });
  control.profileIds.forEach((id) => {
    if (!SUPPORTED_PROFILES.has(id)) throw new Error(`${label}.profileIds contains unsupported profile ${JSON.stringify(id)}`);
  });
  control.roleIds.forEach((id) => {
    if (!SUPPORTED_ROLES.has(id)) throw new Error(`${label}.roleIds contains unsupported role ${JSON.stringify(id)}`);
  });
  assertEnum(control.applicability, ["baseline", "role-specific", "not-applicable"], `${label}.applicability`);
  assertNonemptyString(control.mechanism, `${label}.mechanism`);
  assertNonemptyString(control.desiredState, `${label}.desiredState`);
  if (control.positiveProbe !== null) assertNonemptyString(control.positiveProbe, `${label}.positiveProbe`);
  if (control.negativeProbe !== null) assertNonemptyString(control.negativeProbe, `${label}.negativeProbe`);
  if (contractCase.id !== "missing-probe-denied" && (control.positiveProbe === null || control.negativeProbe === null)) {
    throw new Error(`${label} requires positive and negative probes`);
  }
  assertNonnegativeInteger(control.evidenceMaxAgeSeconds, `${label}.evidenceMaxAgeSeconds`);
  if (control.evidenceMaxAgeSeconds === 0) throw new Error(`${label}.evidenceMaxAgeSeconds must be positive`);
  if (control.recovery !== null) assertNonemptyString(control.recovery, `${label}.recovery`);
  if (contractCase.id !== "missing-recovery-denied" && control.recovery === null) {
    throw new Error(`${label}.recovery must be present`);
  }
  assertBoolean(control.mandatory, `${label}.mandatory`);
  assertEnum(control.ownerPhase, ["5", "6", "7", "10", "11"], `${label}.ownerPhase`);
}

function validateHostControlMatrix(input, contractCase, label) {
  assertExactKeys(input, ["profileVersion", "profiles", "roles", "controls", "observed"], label);
  assertNonemptyString(input.profileVersion, `${label}.profileVersion`);
  if (!Array.isArray(input.profiles) || input.profiles.length === 0) throw new Error(`${label}.profiles must be a nonempty array`);
  const profileIds = new Set();
  for (const [index, profile] of input.profiles.entries()) {
    const profileLabel = `${label}.profiles[${index}]`;
    assertPlainObject(profile, profileLabel);
    assertExactKeys(profile, ["profileId", "osFamily", "release", "architecture", "supportState"], profileLabel);
    assertNonemptyString(profile.profileId, `${profileLabel}.profileId`);
    if (profileIds.has(profile.profileId)) throw new Error(`${label}.profiles has duplicate profile ID`);
    profileIds.add(profile.profileId);
    assertEnum(profile.supportState, ["supported", "unsupported"], `${profileLabel}.supportState`);
    if (profile.supportState === "supported") {
      const expected = SUPPORTED_PROFILES.get(profile.profileId);
      if (expected === undefined || Object.entries(expected).some(([key, value]) => profile[key] !== value)) {
        throw new Error(`${profileLabel} does not match the supported profile registry`);
      }
    }
  }
  assertStringArray(input.roles, `${label}.roles`, { nonempty: true });
  input.roles.forEach((role) => {
    if (!SUPPORTED_ROLES.has(role)) throw new Error(`${label}.roles contains unsupported role ${JSON.stringify(role)}`);
  });
  if (!Array.isArray(input.controls) || input.controls.length === 0) throw new Error(`${label}.controls must be a nonempty array`);
  const controlIds = new Set();
  input.controls.forEach((control, index) => {
    validateControl(control, contractCase, `${label}.controls[${index}]`);
    if (controlIds.has(control.controlId)) throw new Error(`${label}.controls has duplicate control ID`);
    controlIds.add(control.controlId);
  });
  assertPlainObject(input.observed, `${label}.observed`);
  assertExactKeys(input.observed, ["profileId", "release", "roleId", "evidenceState", "collectedAt"], `${label}.observed`);
  assertNonemptyString(input.observed.profileId, `${label}.observed.profileId`);
  assertNonemptyString(input.observed.release, `${label}.observed.release`);
  assertNonemptyString(input.observed.roleId, `${label}.observed.roleId`);
  assertEnum(input.observed.evidenceState, ["configured-and-probed", "package-only", "missing-baseline"], `${label}.observed.evidenceState`);
  assertTimestamp(input.observed.collectedAt, `${label}.observed.collectedAt`);

  if (contractCase.id === "supported-profiles-complete") {
    const declaredProfiles = new Set(input.profiles.filter(({ supportState }) => supportState === "supported").map(({ profileId }) => profileId));
    const missingProfiles = [...SUPPORTED_PROFILES.keys()].filter((id) => !declaredProfiles.has(id));
    const missingRoles = [...SUPPORTED_ROLES].filter((id) => !input.roles.includes(id));
    const controlledProfiles = new Set(input.controls.flatMap(({ profileIds: ids }) => ids));
    const controlledRoles = new Set(input.controls.flatMap(({ roleIds: ids }) => ids));
    if (missingProfiles.length || missingRoles.length || [...SUPPORTED_PROFILES.keys()].some((id) => !controlledProfiles.has(id)) || [...SUPPORTED_ROLES].some((id) => !controlledRoles.has(id))) {
      throw new Error(`${label} must cover every supported profile and role`);
    }
  }
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !/^sha256:[0-9a-f]{64}$/.test(value)) {
    throw new Error(`${label} must be a lowercase sha256 digest`);
  }
}

function validateRecoveryPrecheck(value, label) {
  assertPlainObject(value, label);
  assertExactKeys(value, ["independentAccess", "rollbackArmed", "verifiedAt"], label);
  assertBoolean(value.independentAccess, `${label}.independentAccess`);
  assertBoolean(value.rollbackArmed, `${label}.rollbackArmed`);
  if (value.verifiedAt !== null) assertTimestamp(value.verifiedAt, `${label}.verifiedAt`);
}

function validatePrivilegedExecution(input, contractCase, label) {
  assertExactKeys(
    input,
    [
      "planId", "planDigest", "bundleDigest", "targetHostId", "declarationRevision",
      "recoveryEpoch", "issuedAt", "expiresAt", "observedAt", "automationPrincipalId",
      "executable", "mode", "resident", "storesDesiredState", "approvedActions",
      "requestedActions", "recoveryPrecheck",
    ],
    label,
  );
  assertSyntheticIdentifier(input.planId, `${label}.planId`, "plan-");
  assertDigest(input.planDigest, `${label}.planDigest`);
  assertDigest(input.bundleDigest, `${label}.bundleDigest`);
  assertSyntheticIdentifier(input.targetHostId, `${label}.targetHostId`, "host-");
  assertNonnegativeInteger(input.declarationRevision, `${label}.declarationRevision`);
  assertNonnegativeInteger(input.recoveryEpoch, `${label}.recoveryEpoch`);
  assertTimestamp(input.issuedAt, `${label}.issuedAt`);
  assertTimestamp(input.expiresAt, `${label}.expiresAt`);
  assertTimestamp(input.observedAt, `${label}.observedAt`);
  if (Date.parse(input.expiresAt) <= Date.parse(input.issuedAt)) throw new Error(`${label}.expiresAt must follow issuedAt`);
  assertSyntheticIdentifier(input.automationPrincipalId, `${label}.automationPrincipalId`, "automation-principal-");
  assertNonemptyString(input.executable, `${label}.executable`);
  assertNonemptyString(input.mode, `${label}.mode`);
  assertBoolean(input.resident, `${label}.resident`);
  assertBoolean(input.storesDesiredState, `${label}.storesDesiredState`);
  assertStringArray(input.approvedActions, `${label}.approvedActions`, { nonempty: true });
  assertStringArray(input.requestedActions, `${label}.requestedActions`, { nonempty: true });
  validateRecoveryPrecheck(input.recoveryPrecheck, `${label}.recoveryPrecheck`);
  if (contractCase.expected.status === "accepted") {
    if (input.executable !== "vsk-labs" || input.mode !== "host-action-once" || input.resident || input.storesDesiredState) {
      throw new Error(`${label} accepted privileged execution must use non-resident vsk-labs host-action-once without desired state`);
    }
    if (input.requestedActions.some((action) => !input.approvedActions.includes(action))) {
      throw new Error(`${label} accepted privileged execution cannot widen actions`);
    }
    if (!input.recoveryPrecheck.independentAccess || !input.recoveryPrecheck.rollbackArmed || input.recoveryPrecheck.verifiedAt === null) {
      throw new Error(`${label} accepted privileged execution requires independent recovery and armed rollback`);
    }
    if (Date.parse(input.observedAt) > Date.parse(input.expiresAt)) throw new Error(`${label} accepted privileged execution cannot be expired`);
  }
}

function validateNativeCredentials(input, contractCase, label) {
  assertExactKeys(
    input,
    [
      "credentialRef", "resolver", "consumerId", "requestedConsumerId", "materialVersion",
      "requiredMaterialVersion", "status", "cloudAccountRequired", "hardwareProtection",
      "rotation", "revocation", "recovery",
    ],
    label,
  );
  assertSyntheticIdentifier(input.credentialRef, `${label}.credentialRef`, "credential-ref-");
  assertPlainObject(input.resolver, `${label}.resolver`);
  assertExactKeys(input.resolver, ["kind", "accountFree", "pathAbstraction", "plaintextFallback"], `${label}.resolver`);
  assertEnum(input.resolver.kind, ["os-native"], `${label}.resolver.kind`);
  assertBoolean(input.resolver.accountFree, `${label}.resolver.accountFree`);
  assertEnum(input.resolver.pathAbstraction, ["platform-credential-store"], `${label}.resolver.pathAbstraction`);
  assertBoolean(input.resolver.plaintextFallback, `${label}.resolver.plaintextFallback`);
  assertSyntheticIdentifier(input.consumerId, `${label}.consumerId`, "consumer-");
  assertSyntheticIdentifier(input.requestedConsumerId, `${label}.requestedConsumerId`, "consumer-");
  assertNonnegativeInteger(input.materialVersion, `${label}.materialVersion`);
  assertNonnegativeInteger(input.requiredMaterialVersion, `${label}.requiredMaterialVersion`);
  assertEnum(input.status, ["current", "stale", "revoked"], `${label}.status`);
  assertBoolean(input.cloudAccountRequired, `${label}.cloudAccountRequired`);
  assertEnum(input.hardwareProtection, ["available", "unavailable-not-required"], `${label}.hardwareProtection`);
  assertPlainObject(input.rotation, `${label}.rotation`);
  assertExactKeys(input.rotation, ["state", "fromVersion", "toVersion", "consumersVerified"], `${label}.rotation`);
  assertEnum(input.rotation.state, ["not-required", "pending", "complete"], `${label}.rotation.state`);
  for (const key of ["fromVersion", "toVersion"]) assertNonnegativeInteger(input.rotation[key], `${label}.rotation.${key}`);
  assertBoolean(input.rotation.consumersVerified, `${label}.rotation.consumersVerified`);
  assertPlainObject(input.revocation, `${label}.revocation`);
  assertExactKeys(input.revocation, ["state", "revokedVersions"], `${label}.revocation`);
  assertEnum(input.revocation.state, ["not-required", "complete"], `${label}.revocation.state`);
  if (!Array.isArray(input.revocation.revokedVersions)) throw new Error(`${label}.revocation.revokedVersions must be an array`);
  input.revocation.revokedVersions.forEach((version, index) => assertNonnegativeInteger(version, `${label}.revocation.revokedVersions[${index}]`));
  assertPlainObject(input.recovery, `${label}.recovery`);
  assertExactKeys(input.recovery, ["independent", "available", "method"], `${label}.recovery`);
  assertBoolean(input.recovery.independent, `${label}.recovery.independent`);
  assertBoolean(input.recovery.available, `${label}.recovery.available`);
  assertNonemptyString(input.recovery.method, `${label}.recovery.method`);
  if (contractCase.expected.status === "accepted") {
    if (!input.resolver.accountFree || input.cloudAccountRequired || input.resolver.plaintextFallback) {
      throw new Error(`${label} accepted native resolution must be account-free with no plaintext fallback`);
    }
    if (input.consumerId !== input.requestedConsumerId) throw new Error(`${label} accepted native resolution must bind one consumer`);
    if (input.status !== "current" || input.materialVersion !== input.requiredMaterialVersion || input.revocation.revokedVersions.includes(input.materialVersion)) {
      throw new Error(`${label} accepted native resolution requires current non-revoked material`);
    }
    if (input.rotation.state === "pending" || !input.rotation.consumersVerified) throw new Error(`${label} accepted native resolution requires completed consumer verification`);
    if (!input.recovery.independent || !input.recovery.available) throw new Error(`${label} accepted native resolution requires independent recovery`);
  }
}

const INPUT_VALIDATORS = new Map([
  ["host-control-matrix", validateHostControlMatrix],
  ["privileged-execution", validatePrivilegedExecution],
  ["native-credentials", validateNativeCredentials],
]);

function requireNegativeFact(condition, label, description) {
  if (!condition) throw new Error(`${label} must retain ${description}`);
}

function validateHostControlNegativeFacts(contractCase, label) {
  const input = contractCase.input;
  const control = input.controls[0];
  switch (contractCase.id) {
    case "unsupported-release-denied":
      requireNegativeFact(input.profiles.some(({ supportState }) => supportState === "unsupported"), label, "an unsupported release");
      break;
    case "missing-probe-denied":
      requireNegativeFact(control.positiveProbe === null || control.negativeProbe === null, label, "a missing probe");
      break;
    case "package-only-evidence-denied":
      requireNegativeFact(input.observed.evidenceState === "package-only", label, "package-only evidence");
      break;
    case "unbounded-fail2ban-denied":
      requireNegativeFact(control.controlId === "linux.fail2ban-sshd" && /unbounded/i.test(control.desiredState), label, "an unbounded Fail2ban policy");
      break;
    case "missing-aide-baseline-denied":
      requireNegativeFact(control.controlId === "linux.aide-control" && input.observed.evidenceState === "missing-baseline", label, "a missing AIDE baseline");
      break;
    case "unsafe-audit-capture-denied":
      requireNegativeFact(control.controlId === "linux.auditd-bounded" && /all-syscall|argument capture/i.test(control.desiredState), label, "unsafe audit capture");
      break;
    case "missing-recovery-denied":
      requireNegativeFact(control.recovery === null, label, "a missing recovery path");
      break;
    default:
      throw new Error(`${label} has no independent host-control denial-fact validator`);
  }
}

function validatePrivilegedNegativeFacts(contractCase, inputs, label) {
  const input = contractCase.input;
  const accepted = inputs.get("approved-bundle-accepted");
  requireNegativeFact(accepted !== undefined, label, "the approved bundle reference");
  switch (contractCase.id) {
    case "wrong-plan-denied":
      requireNegativeFact(input.planId !== accepted.planId, label, "a different plan ID");
      break;
    case "wrong-plan-digest-denied":
      requireNegativeFact(input.planDigest !== accepted.planDigest, label, "a different plan digest");
      break;
    case "wrong-bundle-digest-denied":
      requireNegativeFact(input.bundleDigest !== accepted.bundleDigest, label, "a different action-bundle digest");
      break;
    case "wrong-host-denied":
      requireNegativeFact(input.targetHostId !== accepted.targetHostId, label, "a different target host");
      break;
    case "wrong-recovery-epoch-denied":
      requireNegativeFact(input.recoveryEpoch !== accepted.recoveryEpoch, label, "a different recovery epoch");
      break;
    case "expired-bundle-denied":
      requireNegativeFact(Date.parse(input.observedAt) > Date.parse(input.expiresAt), label, "an expired action bundle");
      break;
    case "undeclared-action-denied":
      if (!input.requestedActions.some((action) => !input.approvedActions.includes(action))) {
        throw new Error(`${label} undeclared-action case must widen the approved action set`);
      }
      break;
    case "arbitrary-module-denied":
      requireNegativeFact(input.requestedActions.some((action) => action.startsWith("module:")), label, "an arbitrary Ansible module request");
      break;
    case "arbitrary-command-denied":
      requireNegativeFact(input.requestedActions.some((action) => action.startsWith("command:")), label, "an arbitrary command request");
      break;
    case "target-widening-denied":
      requireNegativeFact(input.requestedActions.some((action) => action.includes("host-synthetic-all")), label, "target widening");
      break;
    case "lost-recovery-denied":
      requireNegativeFact(!input.recoveryPrecheck.independentAccess || !input.recoveryPrecheck.rollbackArmed, label, "a failed independent recovery precheck");
      break;
    case "resident-helper-denied":
      requireNegativeFact(input.resident, label, "a resident privileged helper");
      break;
    case "desired-state-copy-denied":
      requireNegativeFact(input.storesDesiredState, label, "an independent desired-state copy");
      break;
    case "wrong-executable-denied":
      requireNegativeFact(input.executable !== "vsk-labs" || input.mode !== "host-action-once", label, "an alternate executable or privileged mode");
      break;
    default:
      throw new Error(`${label} has no independent privileged-execution denial-fact validator`);
  }
}

function validateCredentialNegativeFacts(contractCase, _inputs, label) {
  const input = contractCase.input;
  switch (contractCase.id) {
    case "cross-consumer-denied":
      if (input.requestedConsumerId === input.consumerId) {
        throw new Error(`${label} cross-consumer case must request a different consumer`);
      }
      break;
    case "stale-material-denied":
      requireNegativeFact(input.status === "stale" || input.materialVersion < input.requiredMaterialVersion, label, "stale material");
      break;
    case "revoked-material-denied":
      requireNegativeFact(input.status === "revoked" || input.revocation.revokedVersions.includes(input.materialVersion), label, "revoked material");
      break;
    case "incomplete-rotation-denied":
      requireNegativeFact(input.rotation.state === "pending" || !input.rotation.consumersVerified, label, "an incomplete rotation");
      break;
    case "recovery-unavailable-denied":
      requireNegativeFact(!input.recovery.independent || !input.recovery.available, label, "unavailable independent recovery");
      break;
    case "cloud-required-denied":
      requireNegativeFact(input.cloudAccountRequired || !input.resolver.accountFree, label, "a cloud-account dependency");
      break;
    case "plaintext-fallback-denied":
      requireNegativeFact(input.resolver.plaintextFallback, label, "a plaintext fallback");
      break;
    default:
      throw new Error(`${label} has no independent native-credential denial-fact validator`);
  }
}

const NEGATIVE_FACT_VALIDATORS = new Map([
  ["host-control-matrix", validateHostControlNegativeFacts],
  ["privileged-execution", validatePrivilegedNegativeFacts],
  ["native-credentials", validateCredentialNegativeFacts],
]);

export function validatePhaseZeroFourFixture(document, source) {
  assertPlainObject(document, source);
  assertSanitized(document, source);
  assertExactKeys(document, ["schema", "schemaVersion", "contract", "cases"], source);
  if (document.schema !== FIXTURE_SCHEMA) throw new Error(`${source} has unsupported fixture schema`);
  if (document.schemaVersion !== SCHEMA_VERSION) throw new Error(`${source} has unsupported schema version`);
  if (!CONTRACT_NAMES.has(document.contract)) throw new Error(`${source} has unknown contract`);
  if (!Array.isArray(document.cases) || document.cases.length === 0) throw new Error(`${source}.cases must be a nonempty array`);

  const caseIds = new Set();
  for (const [index, contractCase] of document.cases.entries()) {
    const label = `${source} cases[${index}]`;
    assertPlainObject(contractCase, label);
    assertExactKeys(contractCase, ["id", "input", "expected"], label);
    assertNonemptyString(contractCase.id, `${label}.id`);
    if (caseIds.has(contractCase.id)) throw new Error(`${source} has duplicate case id`);
    caseIds.add(contractCase.id);
    assertPlainObject(contractCase.input, `${label}.input`);
    INPUT_VALIDATORS.get(document.contract)(contractCase.input, contractCase, `${label}.input`);
    assertPlainObject(contractCase.expected, `${label}.expected`);
    assertExactKeys(contractCase.expected, ["status", "errorCode", "reason"], `${label}.expected`);
    assertEnum(contractCase.expected.status, ["accepted", "blocked"], `${label}.expected.status`);
    if (contractCase.expected.status === "accepted") {
      if (contractCase.expected.errorCode !== null) throw new Error(`${label} accepted result must have a null error code`);
    } else if (!ERROR_CODES.has(contractCase.expected.errorCode)) {
      throw new Error(`${label} has unknown error code`);
    }
    assertNonemptyString(contractCase.expected.reason, `${label}.expected.reason`);
    const pinned = EXPECTED_OUTCOMES.get(`${document.contract}/${contractCase.id}`);
    if (pinned === undefined) throw new Error(`${label} is not registered in the independent outcome oracle`);
    if (contractCase.expected.status !== pinned[0] || contractCase.expected.errorCode !== pinned[1]) {
      throw new Error(`${label} disagrees with the independent outcome oracle`);
    }
  }
  const inputs = new Map(document.cases.map((contractCase) => [contractCase.id, contractCase.input]));
  for (const [index, contractCase] of document.cases.entries()) {
    if (contractCase.expected.status !== "accepted") {
      NEGATIVE_FACT_VALIDATORS.get(document.contract)(contractCase, inputs, `${source} cases[${index}].input`);
    }
  }
  return { contract: document.contract, cases: document.cases.length };
}

function validateIndex(document, source) {
  assertPlainObject(document, source);
  assertExactKeys(document, ["schema", "schemaVersion", "contracts"], source);
  if (document.schema !== INDEX_SCHEMA || document.schemaVersion !== SCHEMA_VERSION) throw new Error(`${source} has unsupported schema or version`);
  if (!Array.isArray(document.contracts)) throw new Error(`${source}.contracts must be an array`);
  const contracts = new Set();
  const files = new Set();
  for (const [index, entry] of document.contracts.entries()) {
    const label = `${source}.contracts[${index}]`;
    assertPlainObject(entry, label);
    assertExactKeys(entry, ["contract", "file", "requiredCaseIds"], label);
    if (!CONTRACT_NAMES.has(entry.contract)) throw new Error(`${label} has unknown contract`);
    if (contracts.has(entry.contract)) throw new Error(`${source} has duplicate contract`);
    contracts.add(entry.contract);
    assertNonemptyString(entry.file, `${label}.file`);
    if (entry.file !== path.basename(entry.file) || !entry.file.endsWith(".json") || entry.file === "contract-index.json" || files.has(entry.file)) {
      throw new Error(`${label}.file must be a unique JSON basename`);
    }
    files.add(entry.file);
    assertStringArray(entry.requiredCaseIds, `${label}.requiredCaseIds`, { nonempty: true });
  }
  if (contracts.size !== CONTRACT_NAMES.size) throw new Error(`${source} must index every Phase 0.4 contract`);
  return document.contracts;
}

async function loadJson(file) {
  return JSON.parse(await readFile(file, "utf8"));
}

export function validatePhaseZeroFourContracts(fixtures) {
  const matrix = fixtures.get("host-control-matrix");
  if (matrix === undefined) throw new Error("Phase 0.4 host-control matrix is missing");
}

export async function loadPhaseZeroFourFixtures(root = ROOT) {
  const directory = path.join(root, FIXTURE_DIRECTORY);
  const index = validateIndex(await loadJson(path.join(directory, "contract-index.json")), "contract-index.json");
  const expectedFiles = new Set(["contract-index.json", ...index.map(({ file }) => file)]);
  const actualFiles = (await readdir(directory)).filter((file) => file.endsWith(".json"));
  for (const file of actualFiles) if (!expectedFiles.has(file)) throw new Error(`unindexed Phase 0.4 fixture file ${JSON.stringify(file)}`);
  for (const file of expectedFiles) if (!actualFiles.includes(file)) throw new Error(`indexed Phase 0.4 fixture file is missing: ${file}`);
  const fixtures = new Map();
  for (const entry of index) {
    const document = await loadJson(path.join(directory, entry.file));
    validatePhaseZeroFourFixture(document, entry.file);
    if (document.contract !== entry.contract) throw new Error(`${entry.file} contract does not match its index entry`);
    const caseIds = new Set(document.cases.map(({ id }) => id));
    for (const required of entry.requiredCaseIds) if (!caseIds.has(required)) throw new Error(`${entry.file} is missing required case ${JSON.stringify(required)}`);
    fixtures.set(entry.contract, document);
  }
  validatePhaseZeroFourContracts(fixtures);
  return fixtures;
}

export async function verifyPhaseZeroFour(root = ROOT) {
  const fixtures = await loadPhaseZeroFourFixtures(root);
  const cases = [...fixtures.values()].reduce((total, fixture) => total + fixture.cases.length, 0);
  return { fixtureFiles: fixtures.size, cases, contracts: [...fixtures.keys()], protectedFiles: 0 };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const result = await verifyPhaseZeroFour();
    process.stdout.write(`${JSON.stringify({ schemaVersion: 1, check: "phase-0.4-contracts", status: "pass", ...result })}\n`);
  } catch (error) {
    process.stderr.write(`Phase 0.4 contract verification failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
