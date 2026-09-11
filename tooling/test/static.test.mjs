import assert from "node:assert/strict";
import { copyFile, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { verifyStaticExport } from "../verify-static.mjs";

test("server runtime artifacts fail the static export check", async () => {
  const output = await mkdtemp(path.join(tmpdir(), "vegastack-static-"));
  await writeFile(
    path.join(output, "index.html"),
    "<p>No control-plane data yet. Data integration is not implemented.</p>",
    "utf8",
  );
  await writeFile(path.join(output, "server.js"), "// forbidden\n", "utf8");

  await assert.rejects(verifyStaticExport(output), /server runtime artifact/);
});

test("development-only MPL package markers fail the static export check", async () => {
  const output = await mkdtemp(path.join(tmpdir(), "vegastack-static-"));
  await writeFile(
    path.join(output, "index.html"),
    "<p>No control-plane data yet. Data integration is not implemented.</p><script>MPL-2.0</script>",
    "utf8",
  );

  await assert.rejects(verifyStaticExport(output), /development-only dependency marker/);
});

test("credential markers and disguised server artifacts fail the static export check", async () => {
  const credentialOutput = await mkdtemp(path.join(tmpdir(), "vegastack-static-"));
  await copyFile(new URL("../testdata/static/credential-marker.html", import.meta.url), path.join(credentialOutput, "index.html"));
  await assert.rejects(verifyStaticExport(credentialOutput), /credential/i);

  const serverOutput = await mkdtemp(path.join(tmpdir(), "vegastack-static-"));
  await writeFile(path.join(serverOutput, "index.html"), "<p>No control-plane data yet. Data integration is not implemented.</p>");
  await copyFile(new URL("../testdata/static/server-artifact.json", import.meta.url), path.join(serverOutput, "server-artifact.json"));
  await assert.rejects(verifyStaticExport(serverOutput), /server runtime/i);
});
