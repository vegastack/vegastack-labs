import { lstat, mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { packageManagerInvocation, runCommand } from "./lib/process.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CANARY_FILE = "tooling/testdata/phase-3/private-canaries.json";
const ALLOWED_ARTIFACTS = /\.(?:json|txt)$/;
const MAX_FILE_BYTES = 256 * 1024;
const MAX_FILES = 32;
const PRIVATE_MARKERS = [
  /\bauthorization\b/i,
  /\bcookie\b/i,
  /cf-access-jwt-assertion/i,
  /\bbearer\s+[a-z0-9._~-]+/i,
  /\b(?:gh[opsu]_|github_pat_)[a-z0-9_]+/i,
  /\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b/,
  /(?:^|[\s"'])(?:\/Users\/|\/home\/|[A-Za-z]:\\)/m,
  /https?:\/\/(?!127\.0\.0\.1(?::\d+)?(?:[\/"'\s]|$)|localhost(?::\d+)?(?:[\/"'\s]|$))[^\s"']+/i,
];

function safeFailureStage(error, fallback) {
  const captured = `${error?.stdout ?? ""}\n${error?.stderr ?? ""}`;
  const probe = captured.match(/PROBE_FAILED:([a-z]+(?:-[a-z]+)*)/);
  if (probe) return probe[1];
  if (/built vsk-labs server did not become ready/.test(captured)) return "server-startup";
  if (/built vsk-labs server (?:stopped|did not stop)/.test(captured)) return "server-lifecycle";
  return fallback;
}

async function canaries(root) {
  const parsed = JSON.parse(await readFile(path.join(root, CANARY_FILE), "utf8"));
  if (parsed?.schemaVersion !== 1 || !Array.isArray(parsed.canaries) ||
      parsed.canaries.some((value) => typeof value !== "string" || value.length < 8)) {
    throw new Error("invalid Phase 3 private-canary fixture");
  }
  return parsed.canaries;
}

async function artifactFiles(directory) {
  const found = [];
  async function walk(current) {
    const entries = await readdir(current, { withFileTypes: true });
    for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
      const target = path.join(current, entry.name);
      const metadata = await lstat(target);
      if (metadata.isSymbolicLink() || (!metadata.isDirectory() && !metadata.isFile())) {
        throw new Error("PHASE3_ARTIFACT_UNSAFE_TYPE");
      }
      if (metadata.isDirectory()) await walk(target);
      else found.push({ target, size: metadata.size });
      if (found.length > MAX_FILES) throw new Error("PHASE3_ARTIFACT_LIMIT");
    }
  }
  await walk(directory);
  return found;
}

export async function verifyPhase3({ artifacts, root = ROOT } = {}) {
  const errors = [];
  if (artifacts) {
    let files = [];
    try {
      files = await artifactFiles(artifacts);
    } catch (error) {
      errors.push(error.message.startsWith("PHASE3_") ? error.message : "PHASE3_ARTIFACT_READ_FAILED");
    }
    const secretCanaries = await canaries(root);
    for (const { target, size } of files) {
      if (!ALLOWED_ARTIFACTS.test(target)) errors.push("PHASE3_ARTIFACT_TYPE");
      if (size > MAX_FILE_BYTES) errors.push("PHASE3_ARTIFACT_SIZE");
      if (!ALLOWED_ARTIFACTS.test(target) || size > MAX_FILE_BYTES) continue;
      const content = await readFile(target, "utf8");
      if (secretCanaries.some((value) => content.includes(value))) errors.push("PHASE3_PRIVATE_CANARY");
      if (PRIVATE_MARKERS.some((pattern) => pattern.test(content))) errors.push("PHASE3_PRIVATE_MATERIAL");
    }
  }
  return {
    status: errors.length === 0 ? "pass" : "failed",
    errors: [...new Set(errors)].sort(),
  };
}

async function verifyRequiredSources(root) {
  const [goFixture, browserProbe, evidence, consoleTests, readTests, domainTests] = await Promise.all([
    readFile(path.join(root, "internal/server/phase3_acceptance_linux_test.go"), "utf8"),
    readFile(path.join(root, "web/e2e/real-server-probe.mjs"), "utf8"),
    readFile(path.join(root, "docs/development/phase-3-browser-evidence.md"), "utf8"),
    readFile(path.join(root, "web/e2e/console.spec.ts"), "utf8"),
    readFile(path.join(root, "web/e2e/read-views.spec.ts"), "utf8"),
    readFile(path.join(root, "web/e2e/domain-status-views.spec.ts"), "utf8"),
  ]);
  for (const [source, patterns] of [
    [goFixture, [/TestPhase3AcceptanceServerFailsClosedAndKeepsLocalRecovery/, /TestPhase3AcceptanceChromiumUsesRealTLSAndSessionBoundary/]],
    [browserProbe, [/axe\.run/, /provider-outage/, /local-status/, /cross-origin data request/]],
    [evidence, [/manual keyboard/i, /Chromium/i, /Phase 11/i, /saniti[sz]/i]],
    [consoleTests, [/skip link, focus order/i, /mobile drawer/i, /light and dark themes/i]],
    [readTests, [/loading, unavailable, and rejected/i, /stale, partial, unknown/i, /serious accessibility/i]],
    [domainTests, [/distinguishes every safe status/i, /accessible on mobile/i, /private domain backing records/i]],
  ]) {
    if (patterns.some((pattern) => !pattern.test(source))) throw new Error("required Phase 3 evidence is incomplete");
  }
}

export async function runPhase3(root = ROOT, { prepared = false } = {}) {
  await verifyRequiredSources(root);
  if (!prepared) {
    const build = packageManagerInvocation(["--filter", "@vegastack/labs-web", "build"]);
    await runCommand(build.command, build.args, { cwd: root, timeoutMs: 180_000 });
  }
  const browser = packageManagerInvocation(["--filter", "@vegastack/labs-web", "test:e2e"]);
  const browserArtifacts = await mkdtemp(path.join(tmpdir(), "vsk-phase3-browser-"));
  let browserFailure;
  let sanitized;
  try {
    try {
      await runCommand(browser.command, browser.args, {
        cwd: root,
        capture: true,
        env: { ...process.env, VSK_PHASE3_PLAYWRIGHT_OUTPUT: browserArtifacts },
        timeoutMs: 180_000,
      });
    } catch (error) {
      browserFailure = error;
    }
    sanitized = await verifyPhase3({ artifacts: browserArtifacts, root });
  } finally {
    await rm(browserArtifacts, { recursive: true, force: true });
  }
  if (sanitized.status !== "pass") throw new Error("PHASE3_FAILED:evidence-sanitizer");
  if (browserFailure) throw new Error(`PHASE3_FAILED:${safeFailureStage(browserFailure, "browser-suite")}`);
  if (process.platform === "linux") {
    const runtimeRoot = await mkdtemp(path.join(tmpdir(), "vsk-phase3-runtime-"));
    const binary = path.join(runtimeRoot, "vsk-labs");
    const database = path.join(runtimeRoot, "control.db");
    try {
      await runCommand("go", ["build", "-race", "-ldflags", `-X github.com/vegastack/vegastack-labs/internal/server.productionDatabasePath=${database}`, "-o", binary, "./cmd/vsk-labs"], {
        cwd: root,
        capture: true,
        timeoutMs: 180_000,
      });
      try {
        await runCommand("go", ["test", "-race", "-count=1", "./internal/server", "./internal/api", "-run", "Phase3Acceptance"], {
          cwd: root,
          capture: true,
          env: { ...process.env, VSK_PHASE3_BINARY: binary, VSK_PHASE3_RUNTIME_ROOT: runtimeRoot },
          timeoutMs: 180_000,
        });
      } catch (error) {
        throw new Error(`PHASE3_FAILED:${safeFailureStage(error, "real-server")}`);
      }
    } finally {
      await rm(runtimeRoot, { recursive: true, force: true });
    }
  }
  return { schemaVersion: 1, check: "phase-3", status: "pass" };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    if (args.some((value) => value !== "--prepared") || args.filter((value) => value === "--prepared").length > 1) {
      throw new Error("invalid Phase 3 verifier arguments");
    }
    const result = await runPhase3(ROOT, { prepared: args.includes("--prepared") });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    const stage = /^PHASE3_FAILED:([a-z]+(?:-[a-z]+)*)$/.exec(error?.message ?? "")?.[1] ?? "verification";
    process.stderr.write(`Phase 3 verification failed at ${stage}\n`);
    process.exitCode = 1;
  }
}
