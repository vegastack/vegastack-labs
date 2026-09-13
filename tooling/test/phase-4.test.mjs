import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";

import { verifyPhase4Sources } from "../verify-phase-4.mjs";

const ROOT = path.resolve(import.meta.dirname, "../..");

test("Phase 4 change evidence keeps the real server, safe approval, and run controls together", async () => {
  assert.equal(await verifyPhase4Sources(ROOT), true);
});
