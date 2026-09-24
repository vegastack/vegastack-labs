import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("recovery-required UI has no direct restore authority", async () => {
  const source = await readFile(new URL("../components/backup-recovery-view.tsx", import.meta.url), "utf8");
  assert.match(source, /recovery-required/);
  assert.match(source, /ExactPlanLauncher/);
  assert.doesNotMatch(source, /humanAcknowledgementId|formerControllerFenceDigest|force continue/i);
  assert.match(source, /disabled/);
});

test("backup workflow keeps status, recovery, restore, and schedule regions separate", async () => {
  const source = await readFile(new URL("../components/backup-recovery-view.tsx", import.meta.url), "utf8");
  for (const label of ["Backup status", "Recovery points", "Restore status", "Scheduled jobs"]) assert.match(source, new RegExp(label, "i"));
  assert.match(source, /useDraftRestore/);
});
