import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { phase3LinkerFlags, verifyPhase3 } from "../verify-phase-3.mjs";

const ROOT = path.resolve(import.meta.dirname, "../..");

async function evidenceFixture(t, files) {
  const directory = await mkdtemp(path.join(tmpdir(), "vsk-p3-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  for (const [name, content] of Object.entries(files)) {
    const target = path.join(directory, name);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, content);
  }
  return directory;
}

test("Phase 3 test executable pins its database and supported platform fixture", () => {
  assert.equal(
    phase3LinkerFlags({ database: "/tmp/vsk-phase3/control.db", osRelease: "/tmp/vsk-phase3/os-release" }),
    "-X github.com/vegastack/vegastack-labs/internal/server.productionDatabasePath=/tmp/vsk-phase3/control.db " +
      "-X github.com/vegastack/vegastack-labs/internal/server.runtimeOSReleasePath=/tmp/vsk-phase3/os-release",
  );
});

test("Phase 3 evidence accepts only sanitized stable results", async (t) => {
  const artifacts = await evidenceFixture(t, {
    "result.json": '{"schemaVersion":1,"check":"phase-3","status":"failed","scenario":"session-expiry"}\n',
    "diagnostic.txt": "PHASE3_BROWSER_ASSERTION_FAILED\n",
  });
  assert.deepEqual(await verifyPhase3({ artifacts, root: ROOT }), { status: "pass", errors: [] });
});

test("Phase 3 evidence rejects private and credential material", async (t) => {
  for (const [name, content, code] of [
    ["canary.json", '{"value":"private-provider-canary"}\n', "PHASE3_PRIVATE_CANARY"],
    ["cookie.txt", "Cookie: vsk_labs_session=value\n", "PHASE3_PRIVATE_MATERIAL"],
    ["path.txt", "failure at /home/operator/private.db\n", "PHASE3_PRIVATE_MATERIAL"],
  ]) {
    const artifacts = await evidenceFixture(t, { [name]: content });
    const result = await verifyPhase3({ artifacts, root: ROOT });
    assert.equal(result.status, "failed");
    assert.ok(result.errors.includes(code), JSON.stringify(result));
  }
});

test("Phase 3 evidence rejects unknown files and links", async (t) => {
  const binary = await evidenceFixture(t, { "trace.zip": "not retained before sanitation" });
  assert.ok((await verifyPhase3({ artifacts: binary, root: ROOT })).errors.includes("PHASE3_ARTIFACT_TYPE"));

  const linked = await evidenceFixture(t, { "target.txt": "safe\n" });
  await symlink(path.join(linked, "target.txt"), path.join(linked, "linked.txt"));
  assert.ok((await verifyPhase3({ artifacts: linked, root: ROOT })).errors.includes("PHASE3_ARTIFACT_UNSAFE_TYPE"));
});
