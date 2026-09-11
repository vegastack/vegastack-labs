import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rename, rm, stat, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { verifyConsoleAssets, writeConsoleAssets } from "../console-assets.mjs";

async function fixture() {
  const root = await mkdtemp(path.join(os.tmpdir(), "vsk-console-assets-"));
  const source = path.join(root, "out");
  const destination = path.join(root, "embedded", "dist");
  const manifestPath = path.join(root, "embedded", "manifest.json");
  await mkdir(path.join(source, "_next", "static", "chunks"), { recursive: true });
  await writeFile(path.join(source, "index.html"), "<!doctype html><title>Console</title>\n");
  await writeFile(path.join(source, "nodes.html"), "<!doctype html><title>Nodes</title>\n");
  await writeFile(path.join(source, "_next", "static", "chunks", "app-0123456789abcdef.js"), "export{};\n");
  return { root, source, destination, manifestPath };
}

test("write and verify produce a deterministic regular-file manifest", async () => {
  const target = await fixture();
  const first = await writeConsoleAssets(target);
  const second = await verifyConsoleAssets(target);
  assert.deepEqual(second, first);
  const manifest = JSON.parse(await readFile(target.manifestPath, "utf8"));
  assert.deepEqual(Object.keys(manifest.files), ["_next/static/chunks/app-0123456789abcdef.js", "index.html", "nodes.html"]);
  assert.equal(manifest.files["index.html"].contentType, "text/html; charset=utf-8");
  assert.equal(manifest.files["_next/static/chunks/app-0123456789abcdef.js"].immutable, true);
});

test("fixed build manifests are never cached as immutable", async () => {
  const target = await fixture();
  const buildDirectory = path.join(target.source, "_next", "static", "vegastack-console-v1");
  await mkdir(buildDirectory, { recursive: true });
  await writeFile(path.join(buildDirectory, "_buildManifest.js"), "self.__BUILD_MANIFEST={};\n");
  await writeConsoleAssets(target);
  const manifest = JSON.parse(await readFile(target.manifestPath, "utf8"));
  assert.equal(manifest.files["_next/static/chunks/app-0123456789abcdef.js"].immutable, true);
  assert.equal(manifest.files["_next/static/vegastack-console-v1/_buildManifest.js"].immutable, false);
});

test("a failed replacement restores the complete previously accepted set", async () => {
  for (const failAt of [1, 2, 3, 4]) {
    const target = await fixture();
    await writeConsoleAssets(target);
    const acceptedIndex = await readFile(path.join(target.destination, "index.html"));
    const acceptedManifest = await readFile(target.manifestPath);
    await writeFile(path.join(target.source, "index.html"), `<!doctype html><title>Changed ${failAt}</title>\n`);
    let calls = 0;
    const renamePath = async (from, to) => {
      calls++;
      if (calls === failAt) throw new Error(`injected replacement failure ${failAt}`);
      return rename(from, to);
    };
    await assert.rejects(() => writeConsoleAssets({ ...target, renamePath, removePath: rm, statPath: stat }), /injected replacement failure/);
    assert.deepEqual(await readFile(path.join(target.destination, "index.html")), acceptedIndex);
    assert.deepEqual(await readFile(target.manifestPath), acceptedManifest);
  }
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
