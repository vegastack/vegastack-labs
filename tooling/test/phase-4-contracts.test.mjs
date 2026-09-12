import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  decodePhase4Contract,
  validateExecutorLeaseBinding,
  validateExecutionReceiptBinding,
  validateLeaseTiming,
  validatePlanTiming,
  validateRunTransition,
} from "../../web/generated/read-api.ts";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const fixtures = path.join(ROOT, "tooling/testdata/phase-4/contracts");
const load = async (name) => JSON.parse(await readFile(path.join(fixtures, name), "utf8"));
const rejectsAt = (fragment) => (error) => error?.code === "INTEGRITY_FAILURE" && error?.target?.includes(fragment);
const makeRun = (plan, step, schemaVersion = "1.0.0") => ({
  schema: "vegastack-labs.dev/run", schemaVersion, runId: "run-synthetic-001",
  planId: plan.planId, planDigest: plan.planDigest, authorizationDecisionId: "decision-synthetic-001",
  acknowledgementId: "acknowledgement-synthetic-001", policyVersion: plan.binding.policyVersion,
  executorMode: plan.executorMode, executorId: plan.executorId,
  executorBindingDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  status: "running", steps: [step], cancellationRequested: false, rollbackStatus: "not-requested",
  verificationStatus: "pending", verificationDigest: null, changed: false,
  stateRevision: plan.binding.stateRevision, recoveryEpoch: plan.binding.recoveryEpoch,
  createdAt: "2026-09-12T17:00:00Z", updatedAt: "2026-09-12T17:01:00Z", extensions: [],
});

test("generated exact and compatible decoders preserve the major-version boundary", async () => {
  const plan = await load("valid-plan.json");
  assert.equal(decodePhase4Contract("vegastack-labs.dev/plan", plan).planId, plan.planId);
  for (const toolVersion of ["0.0.0-dev", "1.2.3-rc.1+build.5", "10.20.30"]) {
    assert.equal(decodePhase4Contract("vegastack-labs.dev/plan", { ...plan, binding: { ...plan.binding, toolVersion } }).binding.toolVersion, toolVersion);
  }
  for (const toolVersion of ["development", "1.2.3-..", "1.2.3-01", "01.2.3", "1.2.3+"]) {
    assert.throws(() => decodePhase4Contract("vegastack-labs.dev/plan", { ...plan, binding: { ...plan.binding, toolVersion } }), rejectsAt("plan.binding.toolVersion: pattern mismatch"));
  }
  assert.throws(() => decodePhase4Contract("vegastack-labs.dev/plan", { ...plan, schemaVersion: "1.7.0" }), rejectsAt("plan.schemaVersion: value is not in enum"));
  assert.throws(() => decodePhase4Contract("vegastack-labs.dev/plan", { ...plan, xFuture: "display-only" }), rejectsAt("plan.xFuture: additional property"));
  assert.equal(decodePhase4Contract("vegastack-labs.dev/plan", { ...plan, schemaVersion: "1.7.0", xFuture: "display-only" }, true).planId, plan.planId);
  assert.throws(() => decodePhase4Contract("vegastack-labs.dev/plan", { ...plan, schemaVersion: "2.0.0" }, true), /SCHEMA_UNSUPPORTED/);
  assert.throws(() => decodePhase4Contract("vegastack-labs.dev/plan", { ...plan, apiToken: "not-allowed" }, true), rejectsAt("plan.apiToken: unsafe additive field"));
  assert.throws(() => decodePhase4Contract("vegastack-labs.dev/plan", { ...plan, binding: { ...plan.binding, xFuture: true } }, true), rejectsAt("plan.binding.xFuture: additional property"));
  assert.throws(() => decodePhase4Contract("vegastack-labs.dev/plan", { ...plan, xFuture: { nested: [{ password: "private-canary" }] } }, true), rejectsAt("plan.xFuture.nested[0].password: unsafe additive field"));
  assert.throws(() => decodePhase4Contract("vegastack-labs.dev/plan", { ...plan, binding: { ...plan.binding, credentialHint: "private-canary" } }, true), rejectsAt("plan.binding.credentialHint: additional property"));
});

test("receipt cannot widen its exact lease binding", async () => {
  const plan = await load("valid-plan.json");
  const fixture = await load("invalid-widened-receipt.json");
  const operation = plan.operations[0];
  const step = { ...operation, stepId: fixture.lease.stepId, status: "running", effectState: "intent-recorded" };
  const run = makeRun(plan, step);
  validateExecutorLeaseBinding(plan, run, fixture.lease);
  for (const [name, candidatePlan, candidateRun] of [
    ["run ID", plan, { ...run, runId: "run-other-999" }],
    ["executor mode", plan, { ...run, executorMode: "central" }],
    ["state revision", plan, { ...run, stateRevision: run.stateRevision + 1 }],
    ["run executor", plan, { ...run, executorId: "executor-other-999" }],
    ["executor binding", plan, { ...run, executorBindingDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }],
    ["plan executor", { ...plan, executorId: "executor-other-999" }, run],
  ]) {
    assert.throws(() => validateExecutorLeaseBinding(candidatePlan, candidateRun, fixture.lease), rejectsAt("executor-lease"), name);
  }
  const mutuallyWidened = { ...fixture.lease, targetId: fixture.receipt.targetId };
  assert.throws(() => validateExecutorLeaseBinding(plan, run, mutuallyWidened), rejectsAt("executor-lease.targetId: run step widened or changed"));
  validateExecutionReceiptBinding(mutuallyWidened, fixture.receipt);
  assert.throws(() => validateExecutionReceiptBinding(fixture.lease, fixture.receipt), rejectsAt("targetId: binding widened or changed"));
});

test("generated lifecycle checks reject invalid transitions and timing", async () => {
  const plan = await load("valid-plan.json");
  validatePlanTiming(plan);
  validateRunTransition("queued", "running");
  assert.throws(() => validateRunTransition("succeeded", "running"), rejectsAt("run.status: invalid run transition"));
  const fixture = await load("invalid-widened-receipt.json");
  validateLeaseTiming(fixture.lease);
  assert.throws(() => validateLeaseTiming({ ...fixture.lease, leaseExpiresAt: "2026-09-12T17:02:00Z" }), rejectsAt("invalid lease timing"));
  assert.throws(() => validateLeaseTiming({ ...fixture.lease, maximumExpiresAt: "2026-09-12T17:02:00Z" }), rejectsAt("maximum expiry"));
});

test("closed Phase 4 schemas reject unknown states and secret-shaped fields", async () => {
  const plan = await load("valid-plan.json");
  assert.throws(() => decodePhase4Contract("vegastack-labs.dev/plan", { ...plan, risk: "unknown" }), rejectsAt("plan.risk: value is not in enum"));
  const schema = JSON.parse(await readFile(path.join(ROOT, "schemas/v1/plan.schema.json"), "utf8"));
  assert.equal(schema.additionalProperties, false);
  assert.doesNotMatch(JSON.stringify(schema.properties), /password|plaintextSecret|apiToken/i);
});

test("generated decoders reject missing plan and acknowledgement bindings", async () => {
  const plan = await load("valid-plan.json");
  const { binding: _binding, ...missingPlanBinding } = plan;
  assert.throws(() => decodePhase4Contract("vegastack-labs.dev/plan", missingPlanBinding), rejectsAt("plan.binding: required property is missing"));
  const acknowledgement = {
    schema: "vegastack-labs.dev/acknowledgement", schemaVersion: "1.0.0",
    planId: plan.planId, planDigest: plan.planDigest, targetDigest: plan.binding.targetDigest,
    reasonDigest: plan.binding.reasonDigest, humanId: "human-synthetic-001", authorityId: "authority-synthetic-001",
    nonceDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    stateRevision: plan.binding.stateRevision, recoveryEpoch: plan.binding.recoveryEpoch, expiresAt: plan.expiresAt,
    acknowledgementId: "acknowledgement-synthetic-001",
    proofDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    status: "approved", receivedAt: "2026-09-12T17:01:00Z", extensions: [],
  };
  const { authorityId: _authorityId, ...missingAuthority } = acknowledgement;
  assert.throws(() => decodePhase4Contract("vegastack-labs.dev/acknowledgement", missingAuthority), rejectsAt("acknowledgement.authorityId: required property is missing"));
});

test("compatible reads keep known authorization IDs and reject secrets in open carriers", async () => {
  const plan = await load("valid-plan.json");
  const operation = plan.operations[0];
  const run = { ...makeRun(plan, { ...operation, stepId: "step-synthetic-001", status: "running", effectState: "intent-recorded" }, "1.4.0"), xFuture: "display-only" };
  assert.equal(decodePhase4Contract("vegastack-labs.dev/run", run, true).authorizationDecisionId, run.authorizationDecisionId);

  const envelope = {
    schema: "vegastack-labs.dev/run-result", schemaVersion: "1.2.0", toolVersion: "1.0.0",
    command: "plan", requestId: "request-synthetic-001", runId: null, status: "succeeded",
    changed: false, recoveryEpoch: 4, stateRevision: 11, snapshotDigest: null,
    releaseBuildId: "build-synthetic-001", sourceRevision: null, planId: null, errors: [], data: {},
  };
  for (const key of ["password", "privateKey", "token", "credential"]) {
    assert.throws(
      () => decodePhase4Contract("vegastack-labs.dev/run-result", { ...envelope, data: { nested: { [key]: "private-canary" } } }, true),
      rejectsAt(`run-result.data.${key === "nested" ? key : `nested.${key}`}`),
    );
  }
});

test("generated schemas contain every approved lifecycle binding and state", async () => {
  const schema = async (name) => JSON.parse(await readFile(path.join(ROOT, `schemas/v1/${name}.schema.json`), "utf8"));
  const plan = await schema("plan");
  const acknowledgement = await schema("acknowledgement");
  const run = await schema("run");
  const lease = await schema("executor-lease");
  const receipt = await schema("execution-receipt");

  for (const name of ["status", "executorMode", "executorId", "binding", "operations", "createdAt", "expiresAt"]) assert.ok(plan.required.includes(name), `plan.${name}`);
  for (const name of ["acknowledgementId", "proofDigest", "receivedAt", "planDigest", "targetDigest", "reasonDigest", "humanId", "authorityId", "nonceDigest", "recoveryEpoch"]) assert.ok(acknowledgement.required.includes(name), `acknowledgement.${name}`);
  for (const name of ["authorizationDecisionId", "acknowledgementId", "policyVersion", "executorMode", "executorId", "executorBindingDigest", "verificationStatus", "verificationDigest", "changed"]) assert.ok(run.required.includes(name), `run.${name}`);
  assert.deepEqual(lease.properties.status.enum, ["active", "expired", "released", "revoked"]);
  assert.ok(lease.required.includes("maximumExpiresAt"));
  assert.deepEqual(receipt.properties.status.enum, ["failed", "partial", "running", "succeeded"]);
  assert.equal(plan.properties.binding.additionalProperties, undefined);
  assert.equal(plan.$defs["plan-binding"].additionalProperties, false);
});
