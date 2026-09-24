import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { phase3LinkerFlags, verifyPhase3 } from "./verify-phase-3.mjs";
import {
  acceptanceScenarioDigest,
  executeAcceptanceScenarios,
  parseGoScenarioPass as parseGenericGoScenarioPass,
  parseNodeScenarioPass as parseGenericNodeScenarioPass,
  parsePlaywrightScenarioPass as parseGenericPlaywrightScenarioPass,
  validateAcceptanceDefinition,
} from "./lib/acceptance-scenarios.mjs";
import { packageManagerInvocation, runCommand } from "./lib/process.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const SCENARIO_ID_PATTERN = /^[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const SCENARIO_KINDS = new Set(["browser-test", "go-test", "node-test"]);
const SCENARIO_ENVIRONMENTS = new Set(["built-linux", "chromium", "fixture"]);
const TEST_PATHS = { "browser-test": /\.spec\.ts$/, "go-test": /_test\.go$/, "node-test": /\.test\.mjs$/ };
const BROWSER_TITLES = new Set([
  "Phase 4 acceptance keeps exact plan facts and protected authority out of the browser",
  "SSE reconnect carries the last event and re-reads without resubmitting",
]);
const BROWSER_MATCHERS = new Set(["toBe", "toBeEnabled", "toBeVisible", "toContainText", "toEqual", "toHaveCount", "toHaveText", "toMatch"]);

export function validBrowserSummary(summary) {
  const match = /^browser title (.+); assertion (web\/e2e\/(?:[a-z0-9-]+\/)*[a-z0-9-]+\.spec\.ts:[1-9][0-9]{0,4}|unknown); status (failed|timedOut|interrupted|unknown); class (assertion|timeout|browser|other); message (expect\.(to[A-Za-z]+) failed|unknown)$/.exec(summary ?? "");
  return Boolean(match && (match[1] === "unknown" || BROWSER_TITLES.has(match[1])) &&
    (match[5] === "unknown" || BROWSER_MATCHERS.has(match[6])));
}

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
const REQUIRED_PHASE4_SCENARIO_ID_SET = new Set(REQUIRED_PHASE4_SCENARIO_IDS);

export function phase4FailureDiagnostic(error) {
  const match = /^PHASE4_FAILED:([a-z]+(?:-[a-z]+)*)(?::([a-z0-9]+(?:[.-][a-z0-9]+)*))?$/.exec(error?.message ?? "");
  if (!match) return "Phase 4 verification failed at verification\n";
  const [, stage, scenarioID] = match;
  if (scenarioID !== undefined) {
    if (!stage.startsWith("scenario-") || !REQUIRED_PHASE4_SCENARIO_ID_SET.has(scenarioID)) {
      return "Phase 4 verification failed at verification\n";
    }
    const summary = validBrowserSummary(error.browserSummary) ? `; ${error.browserSummary}` : "";
    return `Phase 4 verification failed at ${stage} (scenario ${scenarioID}${summary})\n`;
  }
  return `Phase 4 verification failed at ${stage}\n`;
}

export function phase4ScenarioDigest(definition) {
  return acceptanceScenarioDigest(definition);
}

export async function validatePhase4AcceptanceDefinition(root, definition, evidence) {
  return validateAcceptanceDefinition({ root, phase: 4, definition, evidence, requiredScenarios: REQUIRED_PHASE4_SCENARIO_IDS });
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
  for (const pattern of [/CompleteApprovedResumeAndCancelLoopsOverRealTLS/, /phase4ApprovalBridge/, /phase4ResumableAdapter/, /cli-plan/, /VSK_PHASE4_CLI_PARITY=1/]) {
    if (!pattern.test(fixture)) throw new Error("PHASE4_FAILED:fixture-definition");
  }
  for (const pattern of [/protected approval material was disclosed/, /const cliParity/, /browser-cli-plan-parity/, /approval-status/, /execute-interrupted/, /resume-run/, /cancelled/]) {
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

export function parseGoScenarioPass(stdout, selector, expectedPasses = 1) {
  return parseGenericGoScenarioPass(stdout, selector, expectedPasses, 4);
}

function collectPlaywrightSpecs(suite, found = []) {
  for (const spec of suite.specs ?? []) found.push(spec);
  for (const child of suite.suites ?? []) collectPlaywrightSpecs(child, found);
  return found;
}

export function summarizeBrowserFailure(report, selector, root = ROOT) {
  const matches = collectPlaywrightSpecs(report).filter(spec => spec.title === selector);
  const spec = matches.length === 1 ? matches[0] : undefined;
  const result = spec?.tests?.flatMap(test => test.results ?? []).find(item => item.status !== "passed");
  const status = ["failed", "timedOut", "interrupted"].includes(result?.status) ? result.status : "unknown";
  const messages = (result?.errors ?? []).map(item => String(item?.message ?? "").slice(0, 4096).replace(/\x1b\[[0-9;]*m/g, ""));
  const failureClass = status === "timedOut" || messages.some(message => /TimeoutError|timed out|timeout .* exceeded/i.test(message)) ? "timeout" :
    messages.some(message => /expect\(|AssertionError/.test(message)) ? "assertion" :
    messages.some(message => /browser has been closed|net::|Target closed/i.test(message)) ? "browser" : "other";
  const error = result?.errors?.[0];
  const relative = typeof error?.location?.file === "string" ? path.relative(path.join(root, "web/e2e"), error.location.file) : "";
  const assertion = /^(?:[a-z0-9-]+\/)*[a-z0-9-]+\.spec\.ts$/.test(relative) &&
    Number.isInteger(error.location.line) && error.location.line > 0 && error.location.line <= 99_999 ?
    `web/e2e/${relative}:${error.location.line}` : "unknown";
  const matcher = /\)\.(to[A-Za-z]+)\(/.exec(messages[0] ?? "")?.[1];
  const message = BROWSER_MATCHERS.has(matcher) ? `expect.${matcher} failed` : "unknown";
  const title = BROWSER_TITLES.has(selector) ? selector : "unknown";
  return `browser title ${title}; assertion ${assertion}; status ${status}; class ${failureClass}; message ${message}`;
}


export function parsePlaywrightScenarioPass(report, selector, expectedPasses = 1) {
  return parseGenericPlaywrightScenarioPass(report, selector, expectedPasses, 4);
}

export function parseNodeScenarioPass(stdout, selector, expectedPasses = 1) {
  return parseGenericNodeScenarioPass(stdout, selector, expectedPasses, 4);
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
  let sanitized;
  try {
    const ordered = await executeAcceptanceScenarios({
      root, phase: 4, definition, runtime, artifactRoot: artifacts,
      browserFailureSummary: summarizeBrowserFailure,
    });
    sanitized = await verifyPhase3({ artifacts, root });
    return Object.fromEntries(ordered.map(({ id, ...outcome }) => [id, outcome]));
  } finally {
    await rm(artifacts, { recursive: true, force: true });
    if (runtime) await rm(runtime.root, { recursive: true, force: true });
    if (sanitized !== undefined && sanitized?.status !== "pass") throw new Error("PHASE4_FAILED:evidence-sanitizer");
  }
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
    process.stderr.write(phase4FailureDiagnostic(error));
    process.exitCode = 1;
  }
}
