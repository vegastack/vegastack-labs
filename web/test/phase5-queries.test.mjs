import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (name) => readFile(new URL(`../${name}`, import.meta.url), "utf8");

test("Phase 5 browser client exposes inert drafts but no direct effect", async () => {
  const source = await read("lib/phase5-queries.ts");
  assert.match(source, /useDraftGateEvidence/);
  assert.match(source, /useDraftRestore/);
  assert.match(source, /useCheckGate/);
  assert.doesNotMatch(source, /StartBackup|RunRestore|VerifyRestore|DatabaseExport|RunSchedule/);
  assert.doesNotMatch(source, /localStorage|sessionStorage|indexedDB/);
});

test("Phase 5 reads are bounded, abortable, and never refresh themselves", async () => {
  const source = await read("lib/phase5-queries.ts");
  for (const key of ["backupStatus", "recoveryPoints", "auditCheckpoints", "auditVerification", "restoreStatuses", "scheduledPolicies", "scheduledJobs"]) {
    assert.match(source, new RegExp(`${key}\\s*:`));
  }
  assert.match(source, /signal/);
  assert.match(source, /retry:\s*false/);
  assert.match(source, /refetchOnWindowFocus:\s*false/);
  assert.doesNotMatch(source, /refetchInterval|setInterval/);
});
