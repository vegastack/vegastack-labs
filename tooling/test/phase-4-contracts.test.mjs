import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  decodePhase4Contract,
  validatePlanTiming,
  validateRunTransition,
} from "../../web/generated/read-api.ts";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const fixtures = path.join(ROOT, "tooling/testdata/phase-4/contracts");
const load = async (name) => JSON.parse(await readFile(path.join(fixtures, name), "utf8"));
const rejectsAt = (fragment) => (error) => error?.code === "INTEGRITY_FAILURE" && error?.target?.includes(fragment);

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

test("browser decoder graph excludes protected execution and acknowledgement contracts", async () => {
  const generated = await readFile(path.join(ROOT, "web/generated/read-api.ts"), "utf8");
  for (const schema of ["acknowledgement", "authorization-decision", "execution-receipt", "executor-lease", "run"]) {
    assert.throws(() => decodePhase4Contract(`vegastack-labs.dev/${schema}`, {}), rejectsAt("schema is unavailable"));
  }
  for (const protectedName of ["Acknowledgement", "AuthorizationDecision", "ExecutionReceipt", "ExecutorLease", "Run"]) {
    assert.doesNotMatch(generated, new RegExp(`export interface ${protectedName}\\b`));
  }
  assert.doesNotMatch(generated, /validate(?:ExecutorLease|ExecutionReceipt)Binding|validateLeaseTiming/);
});

test("generated lifecycle checks reject invalid transitions and timing", async () => {
  const plan = await load("valid-plan.json");
  validatePlanTiming(plan);
  validateRunTransition("queued", "running");
  assert.throws(() => validateRunTransition("succeeded", "running"), rejectsAt("run.status: invalid run transition"));
});

test("closed Phase 4 schemas reject unknown states and secret-shaped fields", async () => {
  const plan = await load("valid-plan.json");
  assert.throws(() => decodePhase4Contract("vegastack-labs.dev/plan", { ...plan, risk: "unknown" }), rejectsAt("plan.risk: value is not in enum"));
  const schema = JSON.parse(await readFile(path.join(ROOT, "schemas/v1/plan.schema.json"), "utf8"));
  assert.equal(schema.additionalProperties, false);
  assert.doesNotMatch(JSON.stringify(schema.properties), /password|plaintextSecret|apiToken/i);
});

test("generated browser decoder rejects missing plan bindings and protected schemas", async () => {
  const plan = await load("valid-plan.json");
  const { binding: _binding, ...missingPlanBinding } = plan;
  assert.throws(() => decodePhase4Contract("vegastack-labs.dev/plan", missingPlanBinding), rejectsAt("plan.binding: required property is missing"));
  assert.throws(() => decodePhase4Contract("vegastack-labs.dev/acknowledgement", {}), rejectsAt("schema is unavailable"));
});

test("compatible reads reject secrets in open carriers", async () => {
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
