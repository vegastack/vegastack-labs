import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("Backups and Providers make no recovery or provider-operation claim", async () => {
  const backups = await readFile(new URL("../app/backups/page.tsx", import.meta.url), "utf8");
  const providers = await readFile(new URL("../app/providers/page.tsx", import.meta.url), "utf8");
  assert.match(backups, /source: "backups"/);
  assert.match(backups, /capability: "backup\.status\.read"/);
  assert.match(providers, /source: "providers"/);
  assert.match(providers, /capability: "adapter\.status\.read"/);
  assert.doesNotMatch(`${backups}\n${providers}`, /restore now|configure provider|token|private endpoint/i);
});
