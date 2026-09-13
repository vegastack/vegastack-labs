import { createHash } from "node:crypto";
import { lstat, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { phase3LinkerFlags, verifyPhase3 } from "./verify-phase-3.mjs";
import { packageManagerInvocation, runCommand } from "./lib/process.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const SCENARIO_ID_PATTERN = /^[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const SCENARIO_KINDS = new Set(["browser-test", "go-test", "node-test"]);
const SCENARIO_ENVIRONMENTS = new Set(["built-linux", "chromium", "fixture"]);
const TEST_PATHS = { "browser-test": /\.spec\.ts$/, "go-test": /_test\.go$/, "node-test": /\.test\.mjs$/ };

// This code-owned list prevents coordinated edits to the two JSON files from
// silently shrinking the closed Phase 4 acceptance set.
export const REQUIRED_PHASE4_SCENARIO_IDS = Object.freeze([
  "adapter.closed-operation-surface", "adapter.production-fake-denied", "api.browser-no-direct-mutation",
  "api.executor-binding-theft", "approval.agent-self-denied", "approval.expired-stale-denied",
  "approval.replay-denied", "approval.wrong-action-denied", "authorization.branch-mix-denied",
  "authorization.preauthorization-no-extra-target", "authorization.production-like-needs-human",
  "browser.artifact-private-free", "browser.client-plan-parity", "browser.no-alternate-authority",
  "browser.reconnect-no-resubmit", "cli.plan-digest-parity", "declaration.intent-remains-inert",
  "executor.lease-loss-requires-recovery", "executor.lease-theft-denied",
  "executor.receipt-crash-requires-recovery", "plan.expired-denied", "plan.fact-drift-denied",
  "plan.revision-drift-denied", "plan.stale-epoch-denied", "plan.superseded-denied",
  "privacy.secret-and-private-artifacts-denied", "run.cancel-safe-boundary", "run.crash-restart-no-repeat",
  "run.duplicate-apply-inert", "run.partial-ambiguous-receipt", "server.built-executable-real-sqlite",
  "slack.server-owned-request", "store.plan-commit-atomic", "suite.no-hidden-quarantine",
]);

function exactKeys(value, expected) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort());
}

function validRelativePath(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 4096 && !value.startsWith("/") &&
    !value.includes("\\") && !value.includes("\0") && !value.split("/").includes("..");
}

function canonicalJSON(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJSON).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJSON(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function phase4ScenarioDigest(definition) {
  return `sha256:${createHash("sha256").update(canonicalJSON(definition)).digest("hex")}`;
}

export async function validatePhase4AcceptanceDefinition(root, definition, evidence) {
  const fail = () => { throw new Error("PHASE4_FAILED:definition"); };
  if (!exactKeys(definition, ["schemaVersion", "scenarios"]) || definition.schemaVersion !== 1 ||
      !Array.isArray(definition.scenarios) ||
      !exactKeys(evidence, ["check", "quarantined", "requiredScenarioIds", "schemaVersion"]) ||
      evidence.schemaVersion !== 1 || evidence.check !== "phase-4" || !Array.isArray(evidence.requiredScenarioIds) ||
      !Array.isArray(evidence.quarantined) || evidence.quarantined.length !== 0) fail();
  const ids = definition.scenarios.map(({ id }) => id);
  if (new Set(ids).size !== ids.length || JSON.stringify(ids) !== JSON.stringify(REQUIRED_PHASE4_SCENARIO_IDS) ||
      JSON.stringify(evidence.requiredScenarioIds) !== JSON.stringify(REQUIRED_PHASE4_SCENARIO_IDS)) fail();
  for (const scenario of definition.scenarios) {
    if (!exactKeys(scenario, ["environment", "id", "kind", "path", "selector"]) ||
        !SCENARIO_ID_PATTERN.test(scenario.id) || !SCENARIO_KINDS.has(scenario.kind) ||
        !SCENARIO_ENVIRONMENTS.has(scenario.environment) || !validRelativePath(scenario.path) ||
        !TEST_PATHS[scenario.kind].test(scenario.path) || typeof scenario.selector !== "string" ||
        scenario.selector.length < 8 || scenario.selector.length > 200 || /[\r\n\0]/.test(scenario.selector)) fail();
    try {
      const metadata = await lstat(path.join(root, scenario.path));
      if (!metadata.isFile() || metadata.isSymbolicLink()) fail();
    } catch { fail(); }
  }
  return true;
}

async function phase4Definitions(root) {
  const [definition, evidence] = await Promise.all([
    readFile(path.join(root, "tooling/testdata/phase-4/acceptance-scenarios.json"), "utf8").then(JSON.parse),
    readFile(path.join(root, "tooling/phase-4-evidence.json"), "utf8").then(JSON.parse),
  ]);
  await validatePhase4AcceptanceDefinition(root, definition, evidence);
  return { definition, evidence };
}

// These composition guards complement the executed scenario map: they keep
// the real server, generated client, and browser recovery proof wired into the
// single Phase 4 lane even when a focused scenario selector remains valid.
export async function verifyPhase4Sources(root = ROOT) {
  const [fixture, probe, client] = await Promise.all([
    readFile(path.join(root, "internal/server/phase4_console_acceptance_linux_test.go"), "utf8"),
    readFile(path.join(root, "web/e2e/real-change-server-probe.mjs"), "utf8"),
    readFile(path.join(root, "web/generated/read-api.ts"), "utf8"),
  ]);
  for (const pattern of [/CompleteApprovedResumeAndCancelLoopsOverRealTLS/, /phase4ApprovalBridge/, /phase4ResumableAdapter/, /cli-plan/]) {
    if (!pattern.test(fixture)) throw new Error("PHASE4_FAILED:fixture-definition");
  }
  for (const pattern of [/protected approval material was disclosed/, /browser-cli-plan-parity/, /approval-status/, /execute-interrupted/, /resume-run/, /cancelled/]) {
    if (!pattern.test(probe)) throw new Error("PHASE4_FAILED:browser-proof");
  }
  for (const pattern of [/requestApproval/, /getApprovalStatus/, /preparePlan/, /reviseDeclaration/]) {
    if (!pattern.test(client)) throw new Error("PHASE4_FAILED:generated-client");
  }
  return true;
}

async function cleanSourceState(root) {
  const [revision, status] = await Promise.all([
    runCommand("git", ["rev-parse", "HEAD"], { cwd: root, capture: true, timeoutMs: 30_000 }),
    runCommand("git", ["status", "--porcelain=v1", "--untracked-files=no"], { cwd: root, capture: true, timeoutMs: 30_000 }),
  ]);
  const commit = revision.stdout.trim();
  if (!SHA_PATTERN.test(commit)) throw new Error("PHASE4_FAILED:source-commit");
  if (status.stdout.trim() !== "") throw new Error("PHASE4_FAILED:source-dirty");
  return commit;
}

function regexEscape(value) { return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
function exactGoPattern(selector) { return selector.split("/").map(part => `^${regexEscape(part)}$`).join("/"); }

export function parseGoScenarioPass(stdout, selector) {
  let passed = 0;
  for (const line of stdout.split("\n")) {
    if (!line.startsWith("{")) continue;
    let event;
    try { event = JSON.parse(line); } catch { throw new Error("PHASE4_FAILED:scenario-result"); }
    if (event.Test !== selector) continue;
    if (event.Action === "skip" || event.Action === "fail") throw new Error("PHASE4_FAILED:scenario-result");
    if (event.Action === "pass") passed++;
  }
  if (passed !== 1) throw new Error("PHASE4_FAILED:scenario-result");
}

async function runGoScenario(root, scenario, runtime) {
  let result;
  try {
    result = await runCommand("go", ["test", "-json", "-race", "-count=1", `./${path.dirname(scenario.path)}`, "-run", exactGoPattern(scenario.selector)], {
      cwd: root, capture: true,
      env: runtime ? { ...process.env, VSK_PHASE3_BINARY: runtime.binary, VSK_PHASE3_RUNTIME_ROOT: runtime.root } : process.env,
      timeoutMs: 300_000,
    });
  } catch { throw new Error("PHASE4_FAILED:scenario-execution"); }
  parseGoScenarioPass(result.stdout, scenario.selector);
}

function collectPlaywrightSpecs(suite, found = []) {
  for (const spec of suite.specs ?? []) found.push(spec);
  for (const child of suite.suites ?? []) collectPlaywrightSpecs(child, found);
  return found;
}

async function runBrowserScenario(root, scenario, artifacts) {
  const reportRoot = await mkdtemp(path.join(tmpdir(), "vsk-phase4-report-"));
  const reportPath = path.join(reportRoot, "report.json");
  const invocation = packageManagerInvocation([
    "--filter", "@vegastack/labs-web", "exec", "playwright", "test", scenario.path.replace(/^web\//, ""),
    "--grep", regexEscape(scenario.selector), "--reporter=json", "--workers=1",
  ]);
  try {
    await runCommand(invocation.command, invocation.args, {
      cwd: root, capture: true,
      env: { ...process.env, PLAYWRIGHT_JSON_OUTPUT_NAME: reportPath, VSK_PHASE3_PLAYWRIGHT_OUTPUT: artifacts },
      timeoutMs: 180_000,
    });
    const report = JSON.parse(await readFile(reportPath, "utf8"));
    parsePlaywrightScenarioPass(report, scenario.selector);
  } catch (error) {
    if (error?.message === "PHASE4_FAILED:scenario-result") throw error;
    throw new Error("PHASE4_FAILED:scenario-execution");
  } finally {
    await rm(reportRoot, { recursive: true, force: true });
  }
}

export function parsePlaywrightScenarioPass(report, selector) {
  const allSpecs = collectPlaywrightSpecs(report);
  const matches = allSpecs.filter(spec => spec.title === selector);
  if (allSpecs.length !== 1 || matches.length !== 1 || matches[0].tests?.length === 0 ||
      report.errors?.length !== 0 || report.stats?.expected !== 1 || report.stats?.skipped !== 0 ||
      report.stats?.unexpected !== 0 || report.stats?.flaky !== 0) throw new Error("PHASE4_FAILED:scenario-result");
  for (const test of matches[0].tests) {
    if (test.status !== "expected" || test.expectedStatus !== "passed" || test.results?.length === 0 ||
        test.results.some(item => item.status !== "passed")) throw new Error("PHASE4_FAILED:scenario-result");
  }
}

async function runNodeScenario(root, scenario) {
  let result;
  try {
    result = await runCommand(process.execPath, ["--test", "--test-reporter=tap", `--test-name-pattern=^${regexEscape(scenario.selector)}$`, scenario.path], {
      cwd: root, capture: true, timeoutMs: 60_000,
    });
  } catch { throw new Error("PHASE4_FAILED:scenario-execution"); }
  parseNodeScenarioPass(result.stdout, scenario.selector);
}

export function parseNodeScenarioPass(stdout, selector) {
  const escaped = regexEscape(selector);
  const passed = stdout.match(new RegExp(`^ok \\d+ - ${escaped}(?: \\(.+\\))?$`, "gm")) ?? [];
  if (passed.length !== 1 || new RegExp(`^(?:not ok \\d+ - ${escaped}|ok \\d+ - ${escaped}.*# (?:SKIP|TODO))`, "im").test(stdout)) {
    throw new Error("PHASE4_FAILED:scenario-result");
  }
}

async function createLinuxRuntime(root) {
  const runtimeRoot = await mkdtemp(path.join(tmpdir(), "vsk-phase4-runtime-"));
  const binary = path.join(runtimeRoot, "vsk-labs");
  const database = path.join(runtimeRoot, "control.db");
  const osRelease = path.join(runtimeRoot, "os-release");
  try {
    await writeFile(osRelease, "ID=debian\nVERSION_ID=13\n", { mode: 0o600 });
    await runCommand("go", ["build", "-race", "-ldflags", phase3LinkerFlags({ database, osRelease }), "-o", binary, "./cmd/vsk-labs"], {
      cwd: root, capture: true, timeoutMs: 180_000,
    });
  } catch {
    await rm(runtimeRoot, { recursive: true, force: true });
    throw new Error("PHASE4_FAILED:real-server");
  }
  return { root: runtimeRoot, binary };
}

export async function executePhase4Scenarios(root, definition) {
  const artifacts = await mkdtemp(path.join(tmpdir(), "vsk-phase4-browser-"));
  const runtime = process.platform === "linux" ? await createLinuxRuntime(root) : undefined;
  const proofResults = new Map();
  const outcomes = {};
  let sanitized;
  try {
    for (const scenario of definition.scenarios) {
      if (scenario.environment === "built-linux" && process.platform !== "linux") {
        outcomes[scenario.id] = { environment: scenario.environment, status: "linux-required" };
        continue;
      }
      const proof = `${scenario.kind}:${scenario.path}:${scenario.selector}`;
      if (!proofResults.has(proof)) {
        if (scenario.kind === "go-test") await runGoScenario(root, scenario, runtime);
        else if (scenario.kind === "browser-test") await runBrowserScenario(root, scenario, artifacts);
        else await runNodeScenario(root, scenario);
        proofResults.set(proof, true);
      }
      outcomes[scenario.id] = { environment: scenario.environment, status: "pass" };
    }
    sanitized = await verifyPhase3({ artifacts, root });
  } finally {
    await rm(artifacts, { recursive: true, force: true });
    if (runtime) await rm(runtime.root, { recursive: true, force: true });
  }
  if (sanitized?.status !== "pass") throw new Error("PHASE4_FAILED:evidence-sanitizer");
  return outcomes;
}

export async function runPhase4(root = ROOT, { prepared = false } = {}) {
  const sourceCommit = await cleanSourceState(root);
  await verifyPhase4Sources(root);
  const { definition } = await phase4Definitions(root);
  if (!prepared) {
    const build = packageManagerInvocation(["--filter", "@vegastack/labs-web", "build"]);
    await runCommand(build.command, build.args, { cwd: root, capture: true, timeoutMs: 180_000 });
  }
  await runCommand("go", ["run", "./tooling/generate-contracts", "--check"], { cwd: root, capture: true, timeoutMs: 180_000 });
  await runCommand(process.execPath, ["tooling/verify-cli.mjs"], { cwd: root, capture: true, timeoutMs: 180_000 });
  await runCommand(process.execPath, ["tooling/verify-static.mjs"], { cwd: root, capture: true, timeoutMs: 180_000 });
  const scenarioOutcomes = await executePhase4Scenarios(root, definition);
  if (await cleanSourceState(root) !== sourceCommit) throw new Error("PHASE4_FAILED:source-drift");
  return {
    schemaVersion: 1, check: "phase-4", status: "pass",
    executionEnvironment: process.platform === "linux" ? "linux" : "portable",
    sourceCommit, scenarioDigest: phase4ScenarioDigest(definition), scenarioOutcomes,
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    if (args.some(value => value !== "--prepared") || args.filter(value => value === "--prepared").length > 1) throw new Error("PHASE4_FAILED:arguments");
    process.stdout.write(`${JSON.stringify(await runPhase4(ROOT, { prepared: args.includes("--prepared") }))}\n`);
  } catch (error) {
    const stage = /^PHASE4_FAILED:([a-z]+(?:-[a-z]+)*)$/.exec(error?.message ?? "")?.[1] ?? "verification";
    process.stderr.write(`Phase 4 verification failed at ${stage}\n`);
    process.exitCode = 1;
  }
}
