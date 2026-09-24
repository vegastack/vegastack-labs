import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("exact plan launcher reuses the Phase 4 plan and run boundary", async () => {
  const source = await readFile(new URL("../components/exact-plan-launcher.tsx", import.meta.url), "utf8");
  assert.match(source, /usePlan/);
  assert.match(source, /PlanReview/);
  assert.match(source, /RunProgress/);
  assert.match(source, /backup-verify/);
  assert.doesNotMatch(source, /phase5Client|humanAcknowledgementId|RunRestore|StartBackup/);
});
