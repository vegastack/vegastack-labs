import assert from "node:assert/strict";
import { access, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { phase3WorkerLimit } from "../../web/playwright.config.ts";
import { phase3FailureDiagnostic, phase3LinkerFlags, runPhase3, summarizePhase3BrowserFailure, verifyPhase3 } from "../verify-phase-3.mjs";

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

test("Phase 3 evidence capture is serial while ordinary browser work stays parallel", () => {
  assert.equal(phase3WorkerLimit("/tmp/sanitized-evidence"), 1);
  assert.equal(phase3WorkerLimit(undefined), undefined);
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

test("Phase 3 browser report reduces a failed assertion without private values", () => {
  const report = { suites: [{ specs: [{ title: "skip link, focus order", file: "console.spec.ts", tests: [{
    results: [{ status: "failed", errors: [{
      message: "expect(received).toEqual(private-provider-canary)",
      location: { file: path.join(ROOT, "web/e2e/console.spec.ts"), line: 23 },
    }], stdout: [{ text: "private-provider-canary" }] }],
  }] }] }] };
  const safe = summarizePhase3BrowserFailure(report, ROOT);
  assert.equal(safe.location, "web/e2e/console.spec.ts:23");
  assert.equal(safe.status, "failed");
  assert.doesNotMatch(JSON.stringify(safe), /private-provider-canary/);
  assert.equal(summarizePhase3BrowserFailure({ suites: [{ specs: [{ ...report.suites[0].specs[0],
    tests: [{ results: [{ status: "failed", errors: [{ location: { file: "/home/private/secret.ts", line: 1 } }] }] }],
  }] }] }, ROOT).location, "unknown");
  const unsafe = phase3FailureDiagnostic({
    message: "PHASE3_FAILED:browser-suite",
    browserFailed: true,
    browserSummary: { title: "private-provider-canary", location: "web/e2e/private-provider-canary.spec.ts:3", status: "private-provider-canary", matcher: "private-provider-canary" },
    sanitizerCodes: ["PHASE3_PRIVATE_CANARY", "PHASE3_PRIVATE_CANARY", "PHASE3_PRIVATE_CANARY_private-provider-canary"],
  });
  assert.match(unsafe, /test=unknown location=unknown matcher=unknown/);
  assert.doesNotMatch(unsafe, /private-provider-canary/);
});

test("Phase 3 preserves browser and sanitizer failures independently and deletes private reports", async (t) => {
  const fixture = await evidenceFixture(t, {
    "fake-pnpm.mjs": `import { chmod, writeFile } from "node:fs/promises";
import path from "node:path";
const failing = process.env.PHASE3_TEST_BROWSER_FAIL === "yes";
const report = { suites: [{ specs: [{ title: "skip link, focus order, and named landmarks work", tests: [{ results: [{ status: failing ? "failed" : "passed", errors: failing ? [{ location: { file: path.join(process.cwd(), "web/e2e/console.spec.ts"), line: 23 }, message: "private-provider-canary" }] : [] }] }] }] }], errors: [], stats: { expected: failing ? 0 : 1, skipped: 0, unexpected: failing ? 1 : 0, flaky: 0 } };
await writeFile(process.env.PHASE3_TEST_REPORT_MARKER, process.env.PLAYWRIGHT_JSON_OUTPUT_NAME);
if (process.env.PHASE3_TEST_REPORT !== "missing") await writeFile(process.env.PLAYWRIGHT_JSON_OUTPUT_NAME, process.env.PHASE3_TEST_REPORT === "malformed" ? "{private-provider-canary" : JSON.stringify(report));
if (process.env.PHASE3_TEST_CANARY === "yes") await writeFile(path.join(process.env.VSK_PHASE3_PLAYWRIGHT_OUTPUT, "canary.txt"), "private-provider-canary");
if (process.env.PHASE3_TEST_CANARY === "unreadable") { const artifact = path.join(process.env.VSK_PHASE3_PLAYWRIGHT_OUTPUT, "unreadable.txt"); await writeFile(artifact, "public assertion artifact"); await chmod(artifact, 0); }
process.exitCode = process.env.PHASE3_TEST_BROWSER_FAIL === "yes" ? 1 : 0;`,
  });
  const original = process.env.npm_execpath;
  process.env.npm_execpath = path.join(fixture, "fake-pnpm.mjs");
  t.after(() => { if (original === undefined) delete process.env.npm_execpath; else process.env.npm_execpath = original; });
  for (const [name, browserFail, canary, report, browserExpected, sanitizerCode, missingExpected] of [
    ["both", "yes", "yes", "valid", true, "PHASE3_PRIVATE_CANARY", false],
    ["browser", "yes", "no", "valid", true, null, false],
    ["unreadable", "yes", "unreadable", "valid", true, "PHASE3_ARTIFACT_READ_FAILED", false],
    ["sanitizer", "no", "yes", "valid", false, "PHASE3_PRIVATE_CANARY", false],
    ["missing", "no", "no", "missing", false, null, true],
    ["malformed", "yes", "no", "malformed", false, null, true],
  ]) {
    const marker = path.join(fixture, `${name}-report-path.txt`);
    Object.assign(process.env, {
      PHASE3_TEST_REPORT_MARKER: marker,
      PHASE3_TEST_BROWSER_FAIL: browserFail,
      PHASE3_TEST_CANARY: canary,
      PHASE3_TEST_REPORT: report,
    });
    await assert.rejects(runPhase3(ROOT, { prepared: true }), (error) => {
      const line = phase3FailureDiagnostic(error);
      assert.equal(line.includes("web/e2e/console.spec.ts:23"), browserExpected, name);
      assert.equal(line.includes(sanitizerCode ?? "sanitizer="), Boolean(sanitizerCode), name);
      assert.equal(line.includes("report-unavailable"), missingExpected, name);
      assert.doesNotMatch(line, /private-provider-canary/, name);
      return true;
    });
    await assert.rejects(access((await readFile(marker, "utf8")).trim()), /ENOENT/);
  }
  for (const key of ["PHASE3_TEST_REPORT_MARKER", "PHASE3_TEST_BROWSER_FAIL", "PHASE3_TEST_CANARY", "PHASE3_TEST_REPORT"]) delete process.env[key];
});
