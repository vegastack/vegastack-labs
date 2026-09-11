import assert from "node:assert/strict";
import { copyFile, mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { writeConsoleAssets } from "../console-assets.mjs";
import { verifyStaticExport } from "../verify-static.mjs";

test("server runtime artifacts fail the static export check", async () => {
  const output = await mkdtemp(path.join(tmpdir(), "vegastack-static-"));
  await writeFile(
    path.join(output, "index.html"),
    "<p>Loading Overview</p>",
    "utf8",
  );
  await writeFile(path.join(output, "server.js"), "// forbidden\n", "utf8");

  await assert.rejects(verifyStaticExport(output), /server runtime artifact/);
});

test("development-only MPL package markers fail the static export check", async () => {
  const output = await mkdtemp(path.join(tmpdir(), "vegastack-static-"));
  await writeFile(
    path.join(output, "index.html"),
    "<p>Loading Overview</p><script>MPL-2.0</script>",
    "utf8",
  );

  await assert.rejects(verifyStaticExport(output), /development-only dependency marker/);
});

test("credential markers and disguised server artifacts fail the static export check", async () => {
  const credentialOutput = await mkdtemp(path.join(tmpdir(), "vegastack-static-"));
  await copyFile(new URL("../testdata/static/credential-marker.html", import.meta.url), path.join(credentialOutput, "index.html"));
  await assert.rejects(verifyStaticExport(credentialOutput), /credential/i);

  const serverOutput = await mkdtemp(path.join(tmpdir(), "vegastack-static-"));
  await writeFile(path.join(serverOutput, "index.html"), "<p>Loading Overview</p>");
  await copyFile(new URL("../testdata/static/server-artifact.json", import.meta.url), path.join(serverOutput, "server-artifact.json"));
  await assert.rejects(verifyStaticExport(serverOutput), /server runtime/i);
});

test("embedded Console byte drift fails the static export check", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "vegastack-static-embedded-"));
  const output = path.join(root, "out");
  const destination = path.join(root, "embedded", "dist");
  const manifestPath = path.join(root, "embedded", "manifest.json");
  await mkdir(output, { recursive: true });
  await writeFile(path.join(output, "index.html"), "<p>Loading Overview</p>");
  await writeConsoleAssets({ source: output, destination, manifestPath });
  await writeFile(path.join(destination, "index.html"), "changed");
  await assert.rejects(verifyStaticExport(output, { destination, manifestPath }), /asset manifest/i);
});

test("a random or missing Console build ID fails the production static check", async () => {
  const output = await mkdtemp(path.join(tmpdir(), "vegastack-static-build-id-"));
  await writeFile(path.join(output, "index.html"), "<p>Loading Overview</p>");
  await assert.rejects(verifyStaticExport(output, false, true), /deterministic Console build ID/i);
});
