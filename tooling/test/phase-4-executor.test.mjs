import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  decodePhase4Contract,
  validateExecutionReceiptBinding,
  validateLeaseTiming,
} from "../../web/generated/read-api.ts";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const fixture = JSON.parse(await readFile(path.join(ROOT, "tooling/testdata/phase-4/executor/scenarios.json"), "utf8"));
const claimSchema = JSON.parse(await readFile(path.join(ROOT, "schemas/v1/executor-claim-request.schema.json"), "utf8"));

function simulate(scenario) {
  const lease = decodePhase4Contract("vegastack-labs.dev/executor-lease", fixture.lease);
  const receipt = decodePhase4Contract("vegastack-labs.dev/execution-receipt", fixture.receipt);
  validateLeaseTiming(lease);
  const now = Date.parse(scenario.at);
  const expires = Date.parse(lease.leaseExpiresAt);

  if (scenario.event === "claim") {
    assert.equal(claimSchema.additionalProperties, false);
    assert.deepEqual(Object.keys(fixture.claim).sort(), [...claimSchema.required].sort());
    return { leaseState: "active", runState: "running", reconciliation: "none", newWorkAllowed: true };
  }
  if (scenario.event === "renew") {
    assert.ok(now >= Date.parse(lease.renewAfter) && now < expires);
    assert.equal(lease.leaseExpiresAt, lease.maximumExpiresAt, "renewal cannot extend maximum authority");
    return { leaseState: "active", runState: "running", reconciliation: "none", newWorkAllowed: true };
  }
  if (scenario.event === "loss") {
    assert.ok(now >= expires);
    return { leaseState: "expired", runState: "partial", reconciliation: "recovery-required", newWorkAllowed: false };
  }
  if (scenario.event === "tamper") {
    assert.throws(() => validateExecutionReceiptBinding(lease, { ...receipt, ...scenario.tamper }), /INTEGRITY_FAILURE/);
    return { leaseState: "active", runState: "partial", reconciliation: "recovery-required", newWorkAllowed: false };
  }
  if (scenario.event === "reconcile") {
    validateExecutionReceiptBinding(lease, receipt);
    assert.equal(scenario.verification, "failed");
    return { leaseState: "released", runState: "partial", reconciliation: "recovery-required", newWorkAllowed: false };
  }
  throw new Error(`unknown simulator event ${scenario.event}`);
}

test("generated executor routes are available only to the executor audience", async () => {
  const registry = JSON.parse(await readFile(path.join(ROOT, "schemas/v1/endpoint-registry.json"), "utf8"));
  const expected = new Map([
    ["api.v1.executor-leases.claim", "/api/v1/executor-leases/claim"],
    ["api.v1.executor-leases.renew", "/api/v1/executor-leases/{leaseId}/renew"],
    ["api.v1.execution-receipts.create", "/api/v1/execution-receipts"],
  ]);
  for (const [id, route] of expected) {
    const endpoint = registry.endpoints.find((candidate) => candidate.id === id);
    assert.equal(endpoint?.availability, "available", id);
    assert.equal(endpoint?.path, route, id);
    assert.deepEqual(endpoint?.audiences, ["executor"], id);
  }
});

test("account-free executor simulator covers claim, renewal, loss, reconciliation and tamper without networking", () => {
  const originalFetch = globalThis.fetch;
  let networkCalls = 0;
  globalThis.fetch = async () => {
    networkCalls += 1;
    throw new Error("network is forbidden in the executor simulator");
  };
  try {
    for (const scenario of fixture.scenarios) {
      assert.deepEqual(simulate(scenario), scenario.expected, scenario.name);
    }
    assert.equal(networkCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
