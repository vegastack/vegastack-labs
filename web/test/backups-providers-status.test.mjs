import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("Backups and Providers use typed read views", async () => {
  const backups = await readFile(new URL("../app/backups/page.tsx", import.meta.url), "utf8");
  const providers = await readFile(new URL("../app/providers/page.tsx", import.meta.url), "utf8");
  assert.match(backups, /BackupRecoveryView/);
  assert.match(providers, /ProvidersView/);
  assert.doesNotMatch(`${backups}\n${providers}`, /restore now|configure provider|token|private endpoint/i);
});
