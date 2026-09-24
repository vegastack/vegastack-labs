import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { phase3LinkerFlags, verifyPhase3 } from "./verify-phase-3.mjs";
import {
  acceptanceScenarioDigest,
  executeAcceptanceScenarios,
  validateAcceptanceDefinition,
} from "./lib/acceptance-scenarios.mjs";
import { packageManagerInvocation, runCommand } from "./lib/process.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const PRIVATE_OUTPUT = /(?:VSK_PRIVATE_CANARY|phase5-private-canary|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|authorization\s*:\s*bearer)/i;
const FAILURE_STAGES = new Set([
  "arguments", "cli-contract", "definition", "evidence-sanitizer", "generated-contracts", "real-server",
  "scenario-execution", "scenario-result", "source-commit", "source-dirty", "source-drift", "static-contract", "web-build",
]);

async function runPhase5Command(command, args, options) {
  try {
    const result = await runCommand(command, args, options);
    scanPhase5Captured(result);
    return result;
  } catch (error) {
    if (error?.message === "PHASE5_FAILED:evidence-sanitizer") throw error;
    scanPhase5Captured(error);
    throw error;
  }
}

function requiredScenario(id, requirementPrefix, ownerIssue, seam, kind, path, selector, environment, state, repeat = 1, seed = null) {
  return Object.freeze({
    id,
    requirementId: `${requirementPrefix}.${id}`,
    ownerIssue,
    seam,
    kind,
    path,
    selector,
    environment,
    proofClass: "fixture",
    expected: Object.freeze({ result: "pass", errorCode: null, state }),
    repeat,
    seed,
    cleanup: "runner-owned-temporary-root",
    sanitizer: "phase3-private-artifact-scan",
  });
}

// The full code-owned definitions prevent coordinated catalog/evidence edits
// from weakening a Phase 5 proof while preserving its identifier.
export const REQUIRED_PHASE5_SCENARIOS = Object.freeze([
  requiredScenario("gate.invalid-evidence-denied", "5.3", 104, "gate", "go-test",
    "internal/generated/phase5_contracts_test.go", "TestPhase5GateEvidenceRejectsFixturePromotionAndInvalidFreshness", "fixture", "denied"),
  requiredScenario("gate.expired-evidence-denied", "5.3", 104, "gate", "go-test",
    "internal/run/admission_test.go", "TestAdmissionGateBindsCurrentHumanProofAndDeniesExpiredOrMissingProof", "fixture", "denied"),
  requiredScenario("gate.replaced-evidence-denied", "5.3", 104, "gate", "go-test",
    "internal/server/schedule_composition_test.go", "TestScheduledGateCheckRejectsChangedDurableEvidenceAndProfile", "built-linux", "denied"),
  requiredScenario("gate.fixture-not-live", "5.3", 104, "gate", "go-test",
    "internal/api/gates_integration_linux_test.go", "TestGateEvidenceAPIOnlyAuthorsFixtureDraftAndRejectsPrivateAttachments", "built-linux", "fixture-only"),
  requiredScenario("gate.not-applicable-not-pass", "5.3", 104, "gate", "browser-test",
    "web/e2e/gates.spec.ts", "deferred not-applicable gate shows its reason without a pass or mutation control", "chromium", "not-applicable"),
  requiredScenario("credential.resolve-after-admission", "5.4.1", 123, "credential", "go-test",
    "internal/run/credential_step_test.go", "TestCredentialStepRechecksAppliedReferenceAndExactLease", "fixture", "resolved-after-admission"),
  requiredScenario("credential.wrong-consumer-denied", "5.4.1", 123, "credential", "go-test",
    "internal/generated/phase5_contracts_test.go", "TestCredentialReferenceV11RequiresExactBinding", "fixture", "denied"),
  requiredScenario("credential.rotation-overlap-revoke", "5.4.3", 125, "credential", "go-test",
    "internal/server/credential_lifecycle_acceptance_linux_test.go", "TestFullCredentialLifecycleAcceptance", "built-linux", "revoked"),
  requiredScenario("credential.clean-host-old-key-denied", "5.4.3", 125, "credential", "go-test",
    "internal/server/credential_recovery_acceptance_linux_test.go", "TestCredentialRecoveryAcceptanceNativeWitnessAndDraft", "built-linux", "denied"),
  requiredScenario("credential.private-canary-redacted", "5.4.3", 125, "credential", "go-test",
    "internal/run/credential_lifecycle_sqlite_linux_test.go", "TestSQLiteCredentialVerifierPanicRecordsPartialWithoutSecretLeak", "built-linux", "redacted"),
  requiredScenario("backup.pending-not-verified", "5.5", 106, "backup-local", "go-test",
    "internal/backup/service_test.go", "TestPrepareFailsClosedForEveryIncompleteStage", "fixture", "pending"),
  requiredScenario("backup.capacity-never-prunes", "5.5.2", 115, "backup-local", "go-test",
    "internal/backup/retirement_capacity_test.go", "TestLocalCapacityBlocksNewStandardAtEightyPercent", "fixture", "capacity-blocked"),
  requiredScenario("backup.writer-lock-exclusive", "5.5.2", 115, "backup-local", "go-test",
    "internal/store/retirement_repository_linux_test.go", "TestUnreconciledRetentionLeaseExcludesBackupWriterAndReader", "built-linux", "exclusive"),
  requiredScenario("backup.corruption-denied", "5.5.3", 117, "backup-local", "go-test",
    "internal/backup/process_test.go", "TestPublishedCorruptionRemainsPresentButIsRejected", "built-linux", "denied"),
  requiredScenario("backup.missing-key-denied", "5.5.3", 117, "backup-local", "go-test",
    "internal/backup/custody_systemd_linux_test.go", "TestBrokeredResticRejectsCallerSelectedAuthority", "built-linux", "denied"),
  requiredScenario("backup.local-restore-isolated", "5.5.3", 117, "backup-local", "go-test",
    "internal/backup/restore_test.go", "TestVerifyRestorableUsesIsolatedTargetAndLeavesAuthorityUntouched", "fixture", "verified"),
  requiredScenario("backup.local-retirement-survivors", "5.5.2", 115, "backup-local", "go-test",
    "internal/backup/retirement_selection_test.go", "TestLocalRetirementRejectsUnqualifiedOrAmbiguousCatalog", "fixture", "survivors-retained"),
  requiredScenario("offsite.session-expiry-seal", "5.5.1", 114, "backup-offsite", "go-test",
    "internal/backup/offsite_verify_test.go", "TestSealWriterRequiresExpiryAndBothQualifiedDenials", "fixture", "sealed"),
  requiredScenario("offsite.rule-drift-denied", "5.5.1", 114, "backup-offsite", "go-test",
    "internal/backup/offsite_run_spec_test.go", "TestExactOffsiteRepositoryBindingRejectsEndpointAndPrefixLookalikes", "fixture", "denied"),
  requiredScenario("offsite.rule-capacity-denied", "5.5.1", 114, "backup-offsite", "go-test",
    "internal/backup/offsite_verify_test.go", "TestOffsiteVerifierRejectsMismatchedManifestDependenciesAndFullRead", "fixture", "denied"),
  requiredScenario("offsite.partial-delete-uncertain", "5.5.4", 118, "backup-offsite", "go-test",
    "internal/backup/offsite_retirement_verify_test.go", "TestOffsiteRetirementCannotSettleAfterPartialDeleteOrFailedSurvivor", "fixture", "uncertain"),
  requiredScenario("offsite.provider-outage-local-survives", "5.5.1", 114, "backup-offsite", "go-test",
    "internal/backup/offsite_admission_test.go", "TestAdmitOffsitePointRequiresVerifiedCurrentCriticalSource", "fixture", "local-survives"),
  requiredScenario("audit.concurrent-chain-single", "5.6", 107, "audit", "go-test",
    "internal/store/audit_chain_linux_test.go", "TestConcurrentAuditIntentsCannotForkChain", "built-linux", "single-chain"),
  requiredScenario("audit.fork-incident", "5.6", 107, "audit", "go-test",
    "internal/audit/verify_test.go", "TestVerifyLocalDetectsPayloadEditAndFork", "fixture", "incident"),
  requiredScenario("audit.rollback-incident", "5.6", 107, "audit", "go-test",
    "internal/store/audit_chain_linux_test.go", "TestAuditIntentRollbackCannotLeaveOrphanLink", "built-linux", "incident"),
  requiredScenario("audit.bad-signature-incident", "5.6", 107, "audit", "go-test",
    "internal/stateexport/signature_test.go", "TestVerifySignedExportRejectsEveryBindingTamper", "fixture", "incident"),
  requiredScenario("audit.export-failure-pending", "5.6", 107, "audit", "go-test",
    "internal/stateexport/service_test.go", "TestTerminalAuditUncertaintyLeavesPendingForFailClosedReconciliation", "fixture", "pending"),
  requiredScenario("audit.private-payload-redacted", "5.6", 107, "audit", "go-test",
    "internal/store/audit_process_test.go", "TestAuditArtifactsExcludeEveryPublicCanary", "built-linux", "redacted"),
  requiredScenario("restore.pending-source-denied", "5.7", 108, "restore", "go-test",
    "internal/recovery/source_test.go", "TestSourceVerifierAcceptsOnlyExactCurrentQualifiedOffsiteGeneration", "fixture", "denied"),
  requiredScenario("restore.old-plan-denied", "5.7", 108, "restore", "go-test",
    "internal/recovery/fence_execution_test.go", "TestExactFenceWitnessBindsImmutablePlanAndExecution", "fixture", "denied"),
  requiredScenario("restore.old-writer-denied", "5.7", 108, "restore", "go-test",
    "internal/server/recovery_process_linux_test.go", "TestReturningFormerControllerCannotMutatePromotedAuthority", "built-linux", "denied"),
  requiredScenario("restore.partial-fence-denied", "5.7", 108, "restore", "go-test",
    "internal/recovery/source_handoff_test.go", "TestInstalledSourceRejectsPartialFenceAndBurnsFailedCustody", "fixture", "denied"),
  requiredScenario("restore.lost-suffix-explicit", "5.7", 108, "restore", "go-test",
    "internal/recovery/audit_continuity_test.go", "TestRecoveredAuditSuffixNeverReplaysEffects", "fixture", "explicit-loss"),
  requiredScenario("restore.failed-canary-recovery-required", "5.7", 108, "restore", "go-test",
    "internal/recovery/canary_test.go", "TestAuthorityEnablesOnlyAfterCompleteCanary", "fixture", "recovery-required"),
  requiredScenario("restore.single-authority", "5.7", 108, "restore", "go-test",
    "internal/recovery/candidate_test.go", "TestCandidatePromotionPreservesAuthorityAndNeverCreatesTwoLocalWriters", "fixture", "single-authority"),
  requiredScenario("schedule.overlap-single", "5.8", 109, "schedule", "go-test",
    "internal/schedule/service_test.go", "TestDispatchUsesServerClockAndOneDurableSlot", "fixture", "single-occurrence"),
  requiredScenario("schedule.catch-up-latest", "5.8", 109, "schedule", "go-test",
    "internal/schedule/service_test.go", "TestCatchUpWindowIsFixedWhenOccurrenceIsClaimed", "fixture", "latest-only"),
  requiredScenario("schedule.clock-rollback-no-reopen", "5.8", 109, "schedule", "go-test",
    "internal/schedule/clock_test.go", "TestDueUsesAnchoredUTCSlotsAcrossClockJumps", "fixture", "closed"),
  requiredScenario("schedule.uncertain-no-retry", "5.8", 109, "schedule", "go-test",
    "internal/run/scheduled_engine_test.go", "TestScheduledEngineFailsClosedWithoutAdmissionOrAdapter", "fixture", "uncertain"),
  requiredScenario("schedule.human-only-denied", "5.8", 109, "schedule", "go-test",
    "internal/schedule/policy_test.go", "TestScheduledRequestCannotCarryPlanOrHumanAcknowledgement", "fixture", "denied"),
  requiredScenario("schedule.provider-outage-isolated", "5.8", 109, "schedule", "go-test",
    "internal/server/schedule_composition_test.go", "TestScheduledAuditPrerequisiteUnavailableFailsClosedWithDurableDependencies", "built-linux", "isolated"),
  requiredScenario("surface.cli-api-console-parity", "5.9", 110, "surface", "go-test",
    "internal/server/phase5_acceptance_linux_test.go", "TestPhase5AcceptanceBuiltProcessRecoveryAndIsolation", "built-linux", "parity-and-recovered"),
  requiredScenario("browser.no-direct-effect", "5.9", 110, "surface", "browser-test",
    "web/e2e/phase5-acceptance.spec.ts", "Phase 5 acceptance keeps protected recovery authority out of the browser", "chromium", "inert"),
  requiredScenario("browser.artifact-private-free", "5.9", 110, "surface", "browser-test",
    "web/e2e/phase5-acceptance.spec.ts", "Phase 5 acceptance artifacts contain no private or secret material", "chromium", "redacted"),
  requiredScenario("suite.durable-boundary-complete", "5.10", 111, "suite", "go-test",
    "internal/run/phase5_acceptance_linux_test.go", "TestPhase5AcceptanceDurableFaultMatrix", "built-linux", "complete"),
  requiredScenario("suite.no-hidden-quarantine", "5.10", 111, "suite", "node-test",
    "tooling/test/phase-5-acceptance.test.mjs", "Phase 5 acceptance rejects a weakened, reordered, skipped, or falsely live scenario", "fixture", "closed"),
  requiredScenario("suite.deterministic-repeat", "5.10", 111, "suite", "go-test",
    "internal/store/phase5_acceptance_linux_test.go", "TestPhase5AcceptanceSeededConcurrency", "built-linux", "deterministic", 3, "phase5-concurrency-v1"),
]);
const REQUIRED_PHASE5_SCENARIO_ID_SET = new Set(REQUIRED_PHASE5_SCENARIOS.map(({ id }) => id));

export function phase5FailureDiagnostic(error) {
  const match = /^PHASE5_FAILED:([a-z]+(?:-[a-z]+)*)(?::([a-z0-9]+(?:[.-][a-z0-9]+)*))?$/.exec(error?.message ?? "");
  if (!match) return "Phase 5 verification failed at verification\n";
  const [, stage, scenarioID] = match;
  if (!FAILURE_STAGES.has(stage)) return "Phase 5 verification failed at verification\n";
  if (scenarioID !== undefined && (!stage.startsWith("scenario-") || !REQUIRED_PHASE5_SCENARIO_ID_SET.has(scenarioID))) {
    return "Phase 5 verification failed at verification\n";
  }
  return scenarioID === undefined ? `Phase 5 verification failed at ${stage}\n` :
    `Phase 5 verification failed at ${stage} (scenario ${scenarioID})\n`;
}

export function phase5ScenarioDigest(definition) {
  return acceptanceScenarioDigest(definition);
}

async function goTestPathsForOS(root, packages, goos) {
  const template = "{{.Dir}}|{{join .TestGoFiles \",\"}}|{{join .XTestGoFiles \",\"}}";
  let result;
  try {
    result = await runPhase5Command("go", ["list", "-e", "-f", template, ...packages], {
      cwd: root,
      capture: true,
      env: { ...process.env, CGO_ENABLED: "0", GOOS: goos },
      timeoutMs: 60_000,
    });
  } catch (error) {
    if (error?.message === "PHASE5_FAILED:evidence-sanitizer") throw error;
    throw new Error("PHASE5_FAILED:definition");
  }
  const found = new Set();
  for (const line of result.stdout.trim().split("\n")) {
    if (!line) continue;
    const [directory, internal, external] = line.split("|");
    if (!directory || internal === undefined || external === undefined) throw new Error("PHASE5_FAILED:definition");
    const files = [internal, external].flatMap(value => value === "" ? [] : value.split(","));
    for (const file of files) found.add(path.relative(root, path.join(directory, file)).split(path.sep).join("/"));
  }
  return found;
}

export async function resolveLinuxOnlyAcceptancePaths(root, scenarios) {
  const packages = [...new Set(scenarios.filter(({ kind }) => kind === "go-test").map(({ path: file }) => `./${path.dirname(file)}`))].sort();
  const [linux, portable] = await Promise.all([
    goTestPathsForOS(root, packages, "linux"),
    goTestPathsForOS(root, packages, "darwin"),
  ]);
  return new Set([...linux].filter(file => !portable.has(file)));
}

export async function validatePhase5AcceptanceDefinition(root, definition, evidence) {
  await validateAcceptanceDefinition({ root, phase: 5, definition, evidence, requiredScenarios: REQUIRED_PHASE5_SCENARIOS });
  const linuxOnly = await resolveLinuxOnlyAcceptancePaths(root, definition.scenarios);
  if (definition.scenarios.some(scenario => linuxOnly.has(scenario.path) && scenario.environment !== "built-linux")) {
    throw new Error("PHASE5_FAILED:definition");
  }
  return true;
}

export async function phase5Definitions(root = ROOT) {
  const [definition, evidence] = await Promise.all([
    readFile(path.join(root, "tooling/testdata/phase-5/acceptance-scenarios.json"), "utf8").then(JSON.parse),
    readFile(path.join(root, "tooling/phase-5-evidence.json"), "utf8").then(JSON.parse),
  ]);
  await validatePhase5AcceptanceDefinition(root, definition, evidence);
  return { definition, evidence };
}

export function scanPhase5Captured(result) {
  for (const value of [result?.stdout, result?.stderr]) {
    if (typeof value !== "string" || Buffer.byteLength(value) > 1_048_576 || PRIVATE_OUTPUT.test(value)) {
      throw new Error("PHASE5_FAILED:evidence-sanitizer");
    }
  }
  return true;
}

export async function cleanPhase5SourceState(root) {
  const [revision, status] = await Promise.all([
    runPhase5Command("git", ["rev-parse", "HEAD"], { cwd: root, capture: true, timeoutMs: 30_000 }),
    runPhase5Command("git", ["status", "--porcelain=v1", "--untracked-files=all"], { cwd: root, capture: true, timeoutMs: 30_000 }),
  ]);
  const commit = revision.stdout.trim();
  if (!SHA_PATTERN.test(commit)) throw new Error("PHASE5_FAILED:source-commit");
  if (status.stdout.trim() !== "") throw new Error("PHASE5_FAILED:source-dirty");
  return commit;
}

async function createLinuxRuntime(root) {
  const runtimeRoot = await mkdtemp(path.join(tmpdir(), "vsk-phase5-runtime-"));
  const binary = path.join(runtimeRoot, "vsk-labs");
  const database = path.join(runtimeRoot, "control.db");
  const osRelease = path.join(runtimeRoot, "os-release");
  try {
    await writeFile(osRelease, "ID=debian\nVERSION_ID=13\n", { mode: 0o600 });
    await runPhase5Command("go", ["build", "-race", "-ldflags", phase3LinkerFlags({ database, osRelease }), "-o", binary, "./cmd/vsk-labs"], {
      cwd: root, capture: true, timeoutMs: 180_000,
    });
  } catch (error) {
    await rm(runtimeRoot, { recursive: true, force: true });
    if (error?.message === "PHASE5_FAILED:evidence-sanitizer") throw error;
    throw new Error("PHASE5_FAILED:real-server");
  }
  return { root: runtimeRoot, binary };
}

export async function executePhase5Scenarios(root, definition, {
  runtime,
  artifactRoot,
  executeScenarios = executeAcceptanceScenarios,
  verifyArtifacts = verifyPhase3,
} = {}) {
  let outcomes;
  let failure;
  try {
    outcomes = await executeScenarios({
      root, phase: 5, definition, runtime, artifactRoot,
      scanCaptured: scanPhase5Captured,
    });
  } catch (error) {
    failure = error;
  }
  try {
    const sanitized = await verifyArtifacts({ artifacts: artifactRoot, root });
    if (sanitized?.status !== "pass") failure = new Error("PHASE5_FAILED:evidence-sanitizer");
  } catch {
    failure = new Error("PHASE5_FAILED:evidence-sanitizer");
  }
  if (failure) throw failure;
  return outcomes;
}

async function runPrerequisite(command, args, root, stage) {
  try {
    await runPhase5Command(command, args, { cwd: root, capture: true, timeoutMs: 180_000 });
  } catch (error) {
    if (error?.message === "PHASE5_FAILED:evidence-sanitizer") throw error;
    throw new Error(`PHASE5_FAILED:${stage}`);
  }
}

export async function runPhase5(root = ROOT, { prepared = false } = {}) {
  const sourceCommit = await cleanPhase5SourceState(root);
  const { definition } = await phase5Definitions(root);
  if (!prepared) {
    const build = packageManagerInvocation(["--filter", "@vegastack/labs-web", "build"]);
    await runPrerequisite(build.command, build.args, root, "web-build");
    await runPrerequisite("go", ["run", "./tooling/generate-contracts", "--check"], root, "generated-contracts");
    await runPrerequisite(process.execPath, ["tooling/verify-cli.mjs"], root, "cli-contract");
    await runPrerequisite(process.execPath, ["tooling/verify-static.mjs"], root, "static-contract");
  }
  const artifacts = await mkdtemp(path.join(tmpdir(), "vsk-phase5-browser-"));
  let runtime;
  try {
    runtime = process.platform === "linux" ? await createLinuxRuntime(root) : undefined;
    const orderedOutcomes = await executePhase5Scenarios(root, definition, { runtime, artifactRoot: artifacts });
    const scenarioOutcomes = Object.fromEntries(orderedOutcomes.map(({ id, ...outcome }) => [id, outcome]));
    if (await cleanPhase5SourceState(root) !== sourceCommit) throw new Error("PHASE5_FAILED:source-drift");
    return {
      schemaVersion: 1,
      check: "phase-5",
      status: "pass",
      executionEnvironment: process.platform === "linux" ? "linux" : "portable",
      sourceCommit,
      scenarioDigest: phase5ScenarioDigest(definition),
      scenarioOutcomes,
    };
  } finally {
    await rm(artifacts, { recursive: true, force: true });
    if (runtime) await rm(runtime.root, { recursive: true, force: true });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    if (args.some(value => value !== "--prepared") || args.filter(value => value === "--prepared").length > 1) {
      throw new Error("PHASE5_FAILED:arguments");
    }
    process.stdout.write(`${JSON.stringify(await runPhase5(ROOT, { prepared: args.includes("--prepared") }))}\n`);
  } catch (error) {
    process.stderr.write(phase5FailureDiagnostic(error));
    process.exitCode = 1;
  }
}
