import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  assertPrivacyEvidence,
  assertSettledPrivacyChecks,
  finalizeProbeResources,
  inspectTraceArchive,
  settlePrivacyCheck,
} from "../e2e/browser-privacy-proof.mjs";

test("the real browser probe reports a startup failure without leaking diagnostics", () => {
  const missingCertificate = path.join(tmpdir(), "vsk-missing-probe-certificate.pem");
  const result = spawnSync(process.execPath, [fileURLToPath(new URL("../e2e/real-change-server-probe.mjs", import.meta.url))], {
    encoding: "utf8",
    env: {
      ...process.env,
      NODE_NO_WARNINGS: "1",
      VSK_PHASE3_ASSERTION: "test-assertion",
      VSK_PHASE3_BASE_URL: "https://127.0.0.1:1",
      VSK_PHASE3_CONTROLLER_URL: "http://127.0.0.1:1",
      VSK_PHASE4_PROXY_CERTIFICATE: missingCertificate,
      VSK_PHASE4_PROXY_PRIVATE_KEY: missingCertificate,
    },
  });
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.equal(result.stderr, "PROBE_FAILED:credential-proxy\n");
  assert.doesNotMatch(result.stderr, /vsk-missing-probe-certificate|ENOENT|\/tmp\//);
});

test("traced browser traffic receives no authentication credentials", async () => {
  const probe = await readFile(new URL("../e2e/real-change-server-probe.mjs", import.meta.url), "utf8");
  assert.match(probe, /startCredentialProxy/);
  assert.match(probe, /withoutCredentialHeaders\(incoming\.headers\)/);
  assert.match(probe, /withoutCredentialHeaders\(response\.headers\)/);
  assert.match(probe, /forbiddenBrowserEvidence\.push\(sessionCookie/);
  assert.match(probe, /rm\(tracePath, \{ force: true \}\)/);
  assert.doesNotMatch(probe, /route\.(?:continue|fetch)\(\{ headers: \{ \.\.\.route\.request\(\)\.headers, "Cf-Access-Jwt-Assertion"/);
  assert.doesNotMatch(probe, /const headers = \{[^\n]+Cf-Access-Jwt-Assertion/);
});

test("a response privacy failure is handled immediately and propagated at the final boundary", async () => {
  const failure = new Error("privacy-response-failure");
  const settled = settlePrivacyCheck(Promise.reject(failure));
  await new Promise(resolve => setImmediate(resolve));
  await assert.rejects(() => assertSettledPrivacyChecks([settled]), error => error === failure);
});

test("probe finalization returns one stable stage and attempts every cleanup", async () => {
  const calls = [];
  const stage = await finalizeProbeResources({
    browser: { close: async () => { calls.push("browser"); } },
    context: { tracing: { stop: async () => { calls.push("trace"); throw new Error("private trace path"); } } },
    credentialProxy: { close: async () => { calls.push("proxy"); } },
    remove: async target => { calls.push(`remove:${target}`); throw new Error("private artifact path"); },
    screenshotPath: "screenshot",
    tracePath: "trace",
    traceStarted: true,
  });
  assert.equal(stage, "trace-finalization");
  assert.deepEqual(calls, ["trace", "remove:trace", "remove:screenshot", "browser", "proxy"]);
});

test("artifact cleanup failure is not swallowed after a successful trace stop", async () => {
  const stage = await finalizeProbeResources({
    context: { tracing: { stop: async () => undefined } },
    remove: async () => { throw new Error("private artifact path"); },
    tracePath: "trace",
    traceStarted: true,
  });
  assert.equal(stage, "artifact-cleanup");
});

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

test("trace inspection excludes only the probe source that defines its canaries", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "vsk-browser-privacy-test-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const tracePath = path.join(directory, "trace.zip");
  await writeFile(tracePath, storedArchive([
    ["trace.trace", '{"type":"frame-snapshot"}'],
    ["trace.network", '{"type":"resource-snapshot"}'],
    ["resources/page.html", "safe browser content"],
    ["src/probe.mjs", 'const canary = "private-proof-canary";'],
  ]));
  const inspected = await inspectTraceArchive(tracePath, ["private-proof-canary"]);
  assert.equal(inspected.entries, 4);
});

test("trace inspection rejects credential headers without matching ordinary UI words", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "vsk-browser-privacy-test-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const safeTrace = path.join(directory, "safe.zip");
  await writeFile(safeTrace, storedArchive([
    ["trace.trace", '{"type":"frame-snapshot","text":"Authorization is current"}'],
    ["trace.network", '{"type":"resource-snapshot","request":{"headers":[{"name":"Accept","value":"application/json"}]}}'],
    ["resources/page.html", "safe browser content"],
  ]));
  await inspectTraceArchive(safeTrace, [], ["Authorization", "Cookie", "Set-Cookie", "Cf-Access-Jwt-Assertion"]);
  const unsafeTrace = path.join(directory, "unsafe.zip");
  await writeFile(unsafeTrace, storedArchive([
    ["trace.trace", '{"type":"frame-snapshot"}'],
    ["trace.network", '{"type":"resource-snapshot","request":{"headers":[{"name":"Cookie","value":"private"}]}}'],
    ["resources/page.html", "safe browser content"],
  ]));
  await assert.rejects(
    inspectTraceArchive(unsafeTrace, [], ["Authorization", "Cookie", "Set-Cookie", "Cf-Access-Jwt-Assertion"]),
    /credential header reached trace entry trace\.network/,
  );
});
