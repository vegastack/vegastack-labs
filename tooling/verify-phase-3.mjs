import { lstat, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { packageManagerInvocation, runCommand } from "./lib/process.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CANARY_FILE = "tooling/testdata/phase-3/private-canaries.json";
const ALLOWED_ARTIFACTS = /\.(?:json|txt)$/;
const MAX_FILE_BYTES = 256 * 1024;
const MAX_FILES = 32;
const MAX_REPORT_BYTES = 2 * 1024 * 1024;
const PUBLIC_TEST_TITLES = new Set([
  "skip link, focus order, and named landmarks work",
  "each route has a unique browser title",
  "generated Gates GET stays clean while unreviewed gate requests are detected",
  "truthful empty, loading, error, and unavailable states render",
  "desktop sidebar is visible and mobile drawer opens and closes",
  "same-origin server requests are detected",
  "Overview keeps only retryable per-query stale data and hides it after denial",
  "Overview renders every domain and marks omitted domains unknown",
  "Overview preserves source statuses when its summary is temporarily unavailable",
  "Overview treats zero drafts with missing sources as partial, not empty",
  "Overview distinguishes loading, unavailable, and rejected responses",
  "Nodes pages independently with opaque cursors and opens every detail kind",
  "leaving a screen cancels its superseded generated reads",
  "Gates reads derived records and classifies every failure family",
  "Nodes classifies loading, empty, unavailable, denied, and rejected responses",
  "Nodes distinguishes stale, partial, unknown, and scope denial after successful reads",
  "private fixture records remain behind the authorized response boundary",
  "Overview, Nodes, Gates, and the details overlay have no serious accessibility violations",
  "Nodes remains readable and operable on a narrow screen",
  "Phase 4 acceptance keeps exact plan facts and protected authority out of the browser",
  "deferred not-applicable gate shows its reason without a pass or mutation control",
  "a valid but wrong source response is rejected",
  "private domain backing records never reach the browser",
  "declaration save, plan review, approval observation, and durable run stay server-owned",
  "save cancels the old revision read and mounts the exact returned revision",
  "refresh restores the exact durable plan and run without resubmitting",
  "a lost execute response resolves one durable run without resubmitting",
  "pending approval polling survives reload while the plan is still planned",
  "a cached running response waits for the fresh terminal GET before opening SSE",
  "a fresh terminal run never opens an SSE watcher",
  "focus follows an explicit save into the new immutable revision",
  "approval expiry and a final server recheck fail closed",
  "SSE reconnect carries the last event and re-reads without resubmitting",
  "a one-shot durable GET failure retries before opening SSE without resubmitting",
  "authorization loss clears every mounted change projection",
  "stale authorization is disabled and private fields never reach browser-visible state",
  "every change state preserves keyboard focus, accessibility, themes, mobile layout, and 200% reflow",
]);
const BROWSER_STATUSES = new Set(["failed", "timedOut", "interrupted"]);
const PUBLIC_SPEC_FILES = new Set([
  "console.spec.ts", "read-views.spec.ts", "domain-status-views.spec.ts", "phase4-acceptance.spec.ts",
  "gates.spec.ts", "change-workflow.spec.ts",
]);
const MATCHERS = new Set(["toBe", "toEqual", "toBeTruthy", "toHaveText", "toHaveURL", "toBeVisible"]);
const SANITIZER_CODES = new Set([
  "PHASE3_ARTIFACT_UNSAFE_TYPE", "PHASE3_ARTIFACT_LIMIT", "PHASE3_ARTIFACT_READ_FAILED",
  "PHASE3_ARTIFACT_TYPE", "PHASE3_ARTIFACT_SIZE", "PHASE3_PRIVATE_CANARY", "PHASE3_PRIVATE_MATERIAL",
]);
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
  const startup = captured.match(/REMOTE_REASON:([a-z]+(?:-[a-z]+)*)/);
  if (startup) return `server-startup-${startup[1]}`;
  if (/built vsk-labs server did not become ready/.test(captured)) return "server-startup";
  if (/built vsk-labs server (?:stopped|did not stop)/.test(captured)) return "server-lifecycle";
  return fallback;
}

function playwrightSpecs(suite, found) {
  if (!suite || typeof suite !== "object") return;
  if (Array.isArray(suite.specs)) found.push(...suite.specs);
  if (Array.isArray(suite.suites)) for (const child of suite.suites) playwrightSpecs(child, found);
}

export function summarizePhase3BrowserFailure(report, root = ROOT) {
  const unknown = { title: "unknown", location: "unknown", status: "unknown", matcher: "unknown" };
  if (!report || !Array.isArray(report.suites)) return unknown;
  const specs = [];
  for (const suite of report.suites) playwrightSpecs(suite, specs);
  for (const spec of specs) {
    if (!Array.isArray(spec?.tests)) continue;
    for (const test of spec.tests) {
      for (const result of Array.isArray(test?.results) ? test.results : []) {
        if (!BROWSER_STATUSES.has(result?.status)) continue;
        const error = Array.isArray(result.errors) ? result.errors[0] : undefined;
        const file = error?.location?.file;
        const line = error?.location?.line;
        let location = "unknown";
        if (typeof file === "string" && path.isAbsolute(file) && Number.isSafeInteger(line) && line > 0 && line <= 1_000_000) {
          const relative = path.relative(path.join(root, "web/e2e"), file);
          if (PUBLIC_SPEC_FILES.has(relative)) {
            location = `web/e2e/${relative}:${line}`;
          }
        }
        return {
          title: PUBLIC_TEST_TITLES.has(spec.title) ? spec.title : "unknown",
          location,
          status: result.status,
          matcher: MATCHERS.has(error?.matcherName) ? error.matcherName : "unknown",
        };
      }
    }
  }
  return unknown;
}

export function phase3FailureDiagnostic(error) {
  const stage = /^PHASE3_FAILED:([a-z]+(?:-[a-z]+)*)$/.exec(error?.message ?? "")?.[1] ?? "verification";
  const safe = error?.browserSummary;
  const browser = safe && typeof safe === "object" ? {
    title: PUBLIC_TEST_TITLES.has(safe.title) ? safe.title : "unknown",
    location: typeof safe.location === "string" &&
      PUBLIC_SPEC_FILES.has(/^web\/e2e\/([^:]+):[1-9][0-9]{0,6}$/.exec(safe.location)?.[1]) ? safe.location : "unknown",
    status: BROWSER_STATUSES.has(safe.status) ? safe.status : "unknown",
    matcher: MATCHERS.has(safe.matcher) ? safe.matcher : "unknown",
  } : undefined;
  const codes = Array.isArray(error?.sanitizerCodes) ? [...new Set(error.sanitizerCodes.filter(code => SANITIZER_CODES.has(code)))].sort() : [];
  const details = [
    error?.browserFailed ? `browser=${browser?.status ?? "unknown"} test=${browser?.title ?? "unknown"} location=${browser?.location ?? "unknown"} matcher=${browser?.matcher ?? "unknown"}` : undefined,
    error?.reportUnavailable ? "report=report-unavailable" : undefined,
    codes.length ? `sanitizer=${codes.join(",")}` : undefined,
  ].filter(Boolean);
  return `Phase 3 verification failed at ${stage}${details.length ? ` (${details.join("; ")})` : ""}\n`;
}

async function privateBrowserReport(file, root) {
  try {
    const metadata = await lstat(file);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > MAX_REPORT_BYTES) return undefined;
    const report = JSON.parse(await readFile(file, "utf8"));
    if (!Array.isArray(report?.suites) || !Array.isArray(report?.errors) ||
        !["expected", "skipped", "unexpected", "flaky"].every(key =>
          Number.isSafeInteger(report?.stats?.[key]) && report.stats[key] >= 0)) return undefined;
    return {
      summary: summarizePhase3BrowserFailure(report, root),
      failed: report.errors.length > 0 || report.stats.unexpected > 0 || report.stats.flaky > 0,
    };
  } catch { return undefined; }
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

export function phase3LinkerFlags({ database, osRelease }) {
  return [
    `-X github.com/vegastack/vegastack-labs/internal/server.productionDatabasePath=${database}`,
    `-X github.com/vegastack/vegastack-labs/internal/server.runtimeOSReleasePath=${osRelease}`,
  ].join(" ");
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
  const browser = packageManagerInvocation(["--filter", "@vegastack/labs-web", "exec", "playwright", "test", "--reporter=json"]);
  const browserArtifacts = await mkdtemp(path.join(tmpdir(), "vsk-phase3-browser-"));
  let reportRoot;
  let browserFailure;
  let sanitized;
  let browserReport;
  try {
    reportRoot = await mkdtemp(path.join(tmpdir(), "vsk-phase3-report-"));
    const reportPath = path.join(reportRoot, "report.json");
    try {
      await runCommand(browser.command, browser.args, {
        cwd: root,
        capture: true,
        env: { ...process.env, VSK_PHASE3_PLAYWRIGHT_OUTPUT: browserArtifacts, PLAYWRIGHT_JSON_OUTPUT_NAME: reportPath },
        timeoutMs: 180_000,
      });
    } catch (error) {
      browserFailure = error;
    }
    browserReport = await privateBrowserReport(reportPath, root);
    sanitized = await verifyPhase3({ artifacts: browserArtifacts, root });
  } finally {
    await Promise.all([
      rm(browserArtifacts, { recursive: true, force: true }),
      reportRoot ? rm(reportRoot, { recursive: true, force: true }) : Promise.resolve(),
    ]);
  }
  if (sanitized.status !== "pass" || browserFailure || !browserReport || browserReport.failed) {
    const failure = new Error(`PHASE3_FAILED:${sanitized.status !== "pass" ? "evidence-sanitizer" :
      browserFailure || browserReport?.failed ? "browser-suite" : "report-unavailable"}`);
    failure.browserFailed = Boolean(browserFailure || browserReport?.failed);
    failure.browserSummary = browserReport?.summary;
    failure.reportUnavailable = !browserReport;
    failure.sanitizerCodes = sanitized.errors;
    throw failure;
  }
  if (process.platform === "linux") {
    const runtimeRoot = await mkdtemp(path.join(tmpdir(), "vsk-phase3-runtime-"));
    const binary = path.join(runtimeRoot, "vsk-labs");
    const database = path.join(runtimeRoot, "control.db");
    const osRelease = path.join(runtimeRoot, "os-release");
    try {
      await writeFile(osRelease, "ID=debian\nVERSION_ID=13\n", { mode: 0o600 });
      await runCommand("go", ["build", "-race", "-ldflags", phase3LinkerFlags({ database, osRelease }), "-o", binary, "./cmd/vsk-labs"], {
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
    process.stderr.write(phase3FailureDiagnostic(error));
    process.exitCode = 1;
  }
}
