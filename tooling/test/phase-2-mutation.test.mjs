import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";

import { proveUnavailableMutations } from "../verify-phase-2.mjs";

const ROOT = path.resolve(import.meta.dirname, "../..");

test("every planned mutation command is unavailable and preserves the verified state fingerprint", async () => {
  const result = await proveUnavailableMutations(ROOT);
  assert.equal(result.status, "pass");
  assert.deepEqual(result.codes, []);
  assert.ok(result.commands.length >= 30);
  assert.match(result.fingerprint, /^sha256:[0-9a-f]{64}$/);
  assert.doesNotMatch(JSON.stringify(result), /private-canary|temporary|\/Users\//i);
});
