import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";

import { proveUnavailableMutations } from "../verify-phase-2.mjs";

const ROOT = path.resolve(import.meta.dirname, "../..");
const EXPECTED_PLANNED_MUTATIONS = [
  "audit",
  "connect",
  "control-plane plan",
  "control-plane recover",
  "control-plane verify",
  "device approve",
  "device request",
  "device revoke",
  "doctor",
  "maintenance plan",
  "maintenance run",
  "node add",
  "node discover",
  "node inspect",
  "node nominate",
  "node quarantine",
  "node replace",
  "service deploy",
  "service plan",
  "service rollback",
  "user offboard",
  "user onboard",
  "user resume",
  "user suspend",
];
const PROHIBITED_GATE_SETTERS = ["gate close", "gate pass", "gate profile bind", "gate profile apply"];

test("every planned mutation command is unavailable and preserves the verified state fingerprint", async () => {
  const result = await proveUnavailableMutations(ROOT);
  assert.equal(result.status, "pass");
  assert.deepEqual(result.codes, []);
  assert.deepEqual(result.commands, [...EXPECTED_PLANNED_MUTATIONS, ...PROHIBITED_GATE_SETTERS]);
  for (const directSetter of PROHIBITED_GATE_SETTERS) {
    assert.ok(result.commands.includes(directSetter), directSetter);
  }
  assert.match(result.fingerprint, /^sha256:[0-9a-f]{64}$/);
  assert.doesNotMatch(JSON.stringify(result), /private-canary|temporary|\/Users\//i);
});
