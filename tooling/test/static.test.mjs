import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { verifyStaticExport } from "../verify-static.mjs";

test("server runtime artifacts fail the static export check", async () => {
  const output = await mkdtemp(path.join(tmpdir(), "vegastack-static-"));
  await writeFile(
    path.join(output, "index.html"),
    "<p>Development scaffold that does not expose operator behavior.</p>",
    "utf8",
  );
  await writeFile(path.join(output, "server.js"), "// forbidden\n", "utf8");

  await assert.rejects(verifyStaticExport(output), /server runtime artifact/);
});

test("development-only MPL package markers fail the static export check", async () => {
  const output = await mkdtemp(path.join(tmpdir(), "vegastack-static-"));
  await writeFile(
    path.join(output, "index.html"),
    "<p>Development scaffold that does not expose operator behavior.</p><script>MPL-2.0</script>",
    "utf8",
  );

  await assert.rejects(verifyStaticExport(output), /development-only dependency marker/);
});
