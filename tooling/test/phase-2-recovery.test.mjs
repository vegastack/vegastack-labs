import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import { executeScenarioProofs } from "../verify-phase-2.mjs";

const ROOT = path.resolve(import.meta.dirname, "../..");

test("recovery proofs preserve prior authority or enter an explicit safe state", async () => {
  const manifest = JSON.parse(await readFile(path.join(ROOT, "tooling/phase-2-evidence.json"), "utf8"));
  const selected = new Set(manifest.scenarios.filter(({ category }) => category === "recovery").map(({ id }) => id));
  assert.deepEqual([...selected], [
    "service.socket-replacement",
    "store.concurrent-revision",
    "store.safe-mode",
    "audit.crash-restart",
    "backup.publication-interruption",
    "backup.isolated-restore",
    "read.event-reconnect",
    "export.interrupted-publication",
  ]);
  const result = await executeScenarioProofs(manifest, ROOT, selected);
  assert.deepEqual(result, { status: "pass", codes: [], scenarios: [...selected] });
});
