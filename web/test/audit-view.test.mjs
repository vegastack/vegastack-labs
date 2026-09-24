import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("Audit view separates checkpoints from independent verification", async () => {
  const source = await readFile(new URL("../components/audit-view.tsx", import.meta.url), "utf8");
  assert.match(source, /Audit checkpoints/);
  assert.match(source, /Independent verification/);
  assert.match(source, /incident/);
  assert.doesNotMatch(source, /createCheckpoint|signingKey|privateKey/);
});
