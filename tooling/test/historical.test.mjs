import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { currentManifest, verifyHistorical } from "../historical.mjs";

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
