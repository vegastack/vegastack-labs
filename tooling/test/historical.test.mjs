import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { currentManifest, verifyHistorical } from "../historical.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

test("an altered historical artifact fails against its recorded manifest", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "vegastack-history-"));
  const artifact = "record.md";
  const manifestPath = path.join(root, "manifest.json");
  await writeFile(path.join(root, artifact), "original\n", "utf8");
  await writeFile(
    manifestPath,
    `${JSON.stringify(await currentManifest(root, [artifact]), null, 2)}\n`,
    "utf8",
  );

  await writeFile(path.join(root, artifact), "altered\n", "utf8");
  await assert.rejects(verifyHistorical(root, manifestPath, [artifact]), /does not match/);
});

test("the Phase 0 readiness report is protected as historical evidence", async () => {
  const manifest = await currentManifest(ROOT);
  assert.ok(
    manifest.artifacts.some(
      ({ path: artifact }) => artifact === "audit-reports/requirements-readiness-2026-08-27.md",
    ),
  );
});
