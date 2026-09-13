import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { assertPrivacyEvidence, inspectTraceArchive } from "../e2e/browser-privacy-proof.mjs";

function storedArchive(entries) {
  const localParts = [];
  const centralParts = [];
  let localOffset = 0;
  for (const [name, value] of entries) {
    const nameBuffer = Buffer.from(name);
    const body = Buffer.from(value);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt32LE(body.length, 18);
    local.writeUInt32LE(body.length, 22);
    local.writeUInt16LE(nameBuffer.length, 26);
    localParts.push(local, nameBuffer, body);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt32LE(body.length, 20);
    central.writeUInt32LE(body.length, 24);
    central.writeUInt16LE(nameBuffer.length, 28);
    central.writeUInt32LE(localOffset, 42);
    centralParts.push(central, nameBuffer);
    localOffset += local.length + nameBuffer.length + body.length;
  }
  const central = Buffer.concat(centralParts);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(central.length, 12);
  end.writeUInt32LE(localOffset, 16);
  return Buffer.concat([...localParts, central, end]);
}

test("runtime privacy proof propagates a canary hidden in a captured surface", () => {
  assert.throws(
    () => assertPrivacyEvidence({
      accessibility: "button Save",
      pseudoContent: ["safe", "private-proof-canary"],
      console: [],
    }, ["private-proof-canary"], "captured browser surfaces"),
    /private-proof-canary reached captured browser surfaces/,
  );
});

test("trace resource inspection cannot swallow a private canary", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "vsk-browser-privacy-test-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const tracePath = path.join(directory, "trace.zip");
  await writeFile(tracePath, storedArchive([
    ["trace.trace", '{"type":"frame-snapshot"}'],
    ["trace.network", '{"type":"resource-snapshot"}'],
    ["resources/source.js", 'globalThis.value = "private-proof-canary";'],
  ]));
  await assert.rejects(
    inspectTraceArchive(tracePath, ["private-proof-canary"]),
    /private-proof-canary reached trace entry resources\/source\.js/,
  );
});
