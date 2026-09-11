import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { verifyConsoleAssets, writeConsoleAssets } from "../console-assets.mjs";

async function fixture() {
  const root = await mkdtemp(path.join(os.tmpdir(), "vsk-console-assets-"));
  const source = path.join(root, "out");
  const destination = path.join(root, "embedded", "dist");
  const manifestPath = path.join(root, "embedded", "manifest.json");
  await mkdir(path.join(source, "_next", "static"), { recursive: true });
  await writeFile(path.join(source, "index.html"), "<!doctype html><title>Console</title>\n");
  await writeFile(path.join(source, "nodes.html"), "<!doctype html><title>Nodes</title>\n");
  await writeFile(path.join(source, "_next", "static", "app-0123456789abcdef.js"), "export{};\n");
  return { root, source, destination, manifestPath };
}

test("write and verify produce a deterministic regular-file manifest", async () => {
  const target = await fixture();
  const first = await writeConsoleAssets(target);
  const second = await verifyConsoleAssets(target);
  assert.deepEqual(second, first);
  const manifest = JSON.parse(await readFile(target.manifestPath, "utf8"));
  assert.deepEqual(Object.keys(manifest.files), ["_next/static/app-0123456789abcdef.js", "index.html", "nodes.html"]);
  assert.equal(manifest.files["index.html"].contentType, "text/html; charset=utf-8");
  assert.equal(manifest.files["_next/static/app-0123456789abcdef.js"].immutable, true);
});

test("verification rejects missing index and byte drift", async () => {
  const target = await fixture();
  await writeConsoleAssets(target);
  await writeFile(path.join(target.destination, "index.html"), "changed\n");
  await assert.rejects(() => verifyConsoleAssets(target), /asset manifest/i);

  const missing = await fixture();
  await writeFile(path.join(missing.source, "index.html"), "");
  await assert.rejects(() => writeConsoleAssets(missing), /index\.html/i);
});

test("generation rejects symlinks and unsupported file types", async () => {
  const linked = await fixture();
  await symlink(path.join(linked.source, "index.html"), path.join(linked.source, "linked.html"));
  await assert.rejects(() => writeConsoleAssets(linked), /regular files/i);

  const unsupported = await fixture();
  await writeFile(path.join(unsupported.source, "payload.exe"), "nope");
  await assert.rejects(() => writeConsoleAssets(unsupported), /unsupported Console asset/i);
});
