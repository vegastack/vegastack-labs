import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, writeFile, appendFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { verifyPinnedDesignSystem } from "../design-system.mjs";

async function fixture() {
  const root = await mkdtemp(path.join(tmpdir(), "vsk-design-lock-"));
  await mkdir(path.join(root, "web/components/ui"), { recursive: true });
  await mkdir(path.join(root, "tooling"), { recursive: true });
  await writeFile(path.join(root, "web/components/ui/provider.tsx"), "export const Provider = 1;\n");
  const digest = "sha256-" + (await import("node:crypto")).createHash("sha256").update("export const Provider = 1;\n").digest("base64");
  const lock = {
    schemaVersion: 1,
    registryOrigin: "https://design.vegastack.com",
    registryVersion: "0.6.0",
    acceptedAt: "10-09-2026",
    roots: [
      { name: "provider", integrity: "sha256-j7RJm9M0bbnthF2SXN8AfSKfoZqUnnPm169og/MPM8E=" },
      { name: "dashboard-01", integrity: "sha256-H3abUSAP+yCnOjs0Qy0Y1R9PhqJQJ3wR7w7/ZX2dI58=" },
    ],
    items: [{ name: "provider", type: "registry:ui", version: "0.6.0", integrity: "sha256-j7RJm9M0bbnthF2SXN8AfSKfoZqUnnPm169og/MPM8E=", files: [{ path: "web/components/ui/provider.tsx", sha256: digest }] }],
  };
  await writeFile(path.join(root, "tooling/design-system-lock.json"), `${JSON.stringify(lock, null, 2)}\n`);
  return root;
}

test("public verification needs no registry credentials", async () => {
  const root = await fixture();
  const previous = [process.env.CF_ACCESS_CLIENT_ID, process.env.CF_ACCESS_CLIENT_SECRET];
  delete process.env.CF_ACCESS_CLIENT_ID;
  delete process.env.CF_ACCESS_CLIENT_SECRET;
  try {
    assert.deepEqual(await verifyPinnedDesignSystem({ root }), { itemCount: 1, fileCount: 1 });
  } finally {
    for (const [name, value] of [["CF_ACCESS_CLIENT_ID", previous[0]], ["CF_ACCESS_CLIENT_SECRET", previous[1]]]) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
});

test("public verification fails closed on copied-source drift", async () => {
  const root = await fixture();
  await appendFile(path.join(root, "web/components/ui/provider.tsx"), "// drift\n");
  await assert.rejects(verifyPinnedDesignSystem({ root }), /provider\.tsx.*digest/i);
});

test("lock rejects unsafe paths, duplicates, versions, and secret material", async () => {
  for (const mutate of [
    lock => { lock.registryVersion = "0.7.0"; },
    lock => { lock.items[0].files[0].path = "../escape.tsx"; },
    lock => { lock.items.push(structuredClone(lock.items[0])); },
    lock => { lock.token = "CF-Access-Client-Secret: not-allowed"; },
  ]) {
    const root = await fixture();
    const lockPath = path.join(root, "tooling/design-system-lock.json");
    const lock = JSON.parse(await readFile(lockPath, "utf8"));
    mutate(lock);
    await writeFile(lockPath, `${JSON.stringify(lock, null, 2)}\n`);
    await assert.rejects(verifyPinnedDesignSystem({ root }));
  }
});
