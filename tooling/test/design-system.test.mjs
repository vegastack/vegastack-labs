import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, writeFile, appendFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { installedPath, sourceClosureDigest, verifyPinnedDesignSystem, ROOTS, VERSION } from "../design-system.mjs";

// A synthetic lock built from the module's approved ROOTS/VERSION, so the verifier's
// logic is tested independently of whichever pin is current. Each root gets one
// placeholder file whose digest the lock records; item integrity is the approved root
// value. "provider" is always a root, so drift/owned-block cases below can target it.
async function fixture() {
  const root = await mkdtemp(path.join(tmpdir(), "vsk-design-lock-"));
  await mkdir(path.join(root, "web/components/ui"), { recursive: true });
  await mkdir(path.join(root, "tooling"), { recursive: true });
  const items = [];
  const roots = [];
  for (const [name, integrity] of ROOTS) {
    const rel = `web/components/ui/${name}.tsx`;
    const content = `export const c_${name.replace(/-/g, "_")} = ${JSON.stringify(name)};\n`;
    await writeFile(path.join(root, rel), content);
    const sha256 = `sha256-${createHash("sha256").update(content).digest("base64")}`;
    items.push({ name, type: "registry:ui", version: VERSION, integrity, files: [{ path: rel, sha256 }] });
    roots.push({ name, integrity });
  }
  items.sort((a, b) => a.name.localeCompare(b.name));
  const lock = {
    schemaVersion: 1,
    registryOrigin: "https://design.vegastack.com",
    registryVersion: VERSION,
    acceptedAt: "16-09-2026",
    roots,
    items,
  };
  lock.sourceClosureSha256 = sourceClosureDigest(lock);
  await writeFile(path.join(root, "tooling/design-system-lock.json"), `${JSON.stringify(lock, null, 2)}\n`);
  return { root, expectedClosureSha256: lock.sourceClosureSha256, count: ROOTS.size };
}

test("public verification needs no registry credentials", async () => {
  const { root, expectedClosureSha256, count } = await fixture();
  const previous = [process.env.CF_ACCESS_CLIENT_ID, process.env.CF_ACCESS_CLIENT_SECRET];
  delete process.env.CF_ACCESS_CLIENT_ID;
  delete process.env.CF_ACCESS_CLIENT_SECRET;
  try {
    assert.deepEqual(await verifyPinnedDesignSystem({ root, expectedClosureSha256 }), { itemCount: count, fileCount: count });
  } finally {
    for (const [name, value] of [["CF_ACCESS_CLIENT_ID", previous[0]], ["CF_ACCESS_CLIENT_SECRET", previous[1]]]) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
});

test("public verification fails closed on copied-source drift", async () => {
  const { root, expectedClosureSha256 } = await fixture();
  await appendFile(path.join(root, "web/components/ui/provider.tsx"), "// drift\n");
  await assert.rejects(verifyPinnedDesignSystem({ root, expectedClosureSha256 }), /provider\.tsx.*digest/i);
});

test("non-owned components cannot use the owned-block digest escape", async () => {
  const { root, expectedClosureSha256 } = await fixture();
  const lockPath = path.join(root, "tooling/design-system-lock.json");
  const lock = JSON.parse(await readFile(lockPath, "utf8"));
  const providerFile = lock.items.find(item => item.name === "provider").files[0];
  // Keep the closure hash stable (upstream = original) so the owned-block guard is what fires.
  providerFile.upstreamSha256 = providerFile.sha256;
  const changed = "export const c_provider = 'changed';\n";
  providerFile.sha256 = `sha256-${createHash("sha256").update(changed).digest("base64")}`;
  await writeFile(path.join(root, providerFile.path), changed);
  await writeFile(lockPath, `${JSON.stringify(lock, null, 2)}\n`);
  await assert.rejects(verifyPinnedDesignSystem({ root, expectedClosureSha256 }), /cannot declare an owned-block upstream digest/);
});

test("registry aliases cannot escape their installation roots", () => {
  assert.equal(installedPath("@ui/button.tsx"), "web/components/ui/button.tsx");
  assert.throws(() => installedPath("@ui/../../outside.tsx"), /escapes the repository/);
  assert.throws(() => installedPath("../outside.tsx"), /escapes the repository/);
});

test("lock rejects unsafe paths, duplicates, versions, and secret material", async () => {
  for (const mutate of [
    lock => { lock.registryVersion = "0.7.0"; },
    lock => { lock.items[0].files[0].path = "../escape.tsx"; },
    lock => { lock.items.push(structuredClone(lock.items[0])); },
    lock => { lock.items[0].name = "unknown-item"; },
    lock => { lock.items[0].integrity = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; },
    lock => { lock.items = []; },
    lock => { lock.token = [["CF", "Access", "Client", "Secret"].join("-"), "not-allowed"].join(": "); },
  ]) {
    const { root, expectedClosureSha256 } = await fixture();
    const lockPath = path.join(root, "tooling/design-system-lock.json");
    const lock = JSON.parse(await readFile(lockPath, "utf8"));
    mutate(lock);
    await writeFile(lockPath, `${JSON.stringify(lock, null, 2)}\n`);
    await assert.rejects(verifyPinnedDesignSystem({ root, expectedClosureSha256 }));
  }
});
