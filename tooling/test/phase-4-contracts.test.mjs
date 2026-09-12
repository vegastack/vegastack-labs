import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  decodePhase4Contract,
  validateExecutionReceiptBinding,
  validateLeaseTiming,
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
  assert.throws(() => decodePhase4Contract("vegastack-labs.dev/plan", { ...plan, xFuture: "display-only" }), rejectsAt("plan.xFuture: additional property"));
  assert.equal(decodePhase4Contract("vegastack-labs.dev/plan", { ...plan, schemaVersion: "1.7.0", xFuture: "display-only" }, true).planId, plan.planId);
  assert.throws(() => decodePhase4Contract("vegastack-labs.dev/plan", { ...plan, schemaVersion: "2.0.0" }, true), /SCHEMA_UNSUPPORTED/);
  assert.throws(() => decodePhase4Contract("vegastack-labs.dev/plan", { ...plan, apiToken: "not-allowed" }, true), rejectsAt("plan.apiToken: unsafe additive field"));
  assert.throws(() => decodePhase4Contract("vegastack-labs.dev/plan", { ...plan, binding: { ...plan.binding, xFuture: true } }, true), rejectsAt("plan.binding.xFuture: additional property"));
});

test("receipt cannot widen its exact lease binding", async () => {
  const fixture = await load("invalid-widened-receipt.json");
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
