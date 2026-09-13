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

function exactKeys(value, expected) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort());
}

function validRelativePath(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 4096 &&
    !value.startsWith("/") && !value.includes("\\") && !value.includes("\0") &&
    !value.split("/").includes("..");
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
      !Array.isArray(definition.scenarios) || definition.scenarios.length < 30 ||
      !exactKeys(evidence, ["check", "quarantined", "requiredScenarioIds", "schemaVersion"]) ||
      evidence.schemaVersion !== 1 || evidence.check !== "phase-4" ||
      !Array.isArray(evidence.requiredScenarioIds) || !Array.isArray(evidence.quarantined) || evidence.quarantined.length !== 0) fail();
  const ids = definition.scenarios.map(({ id }) => id);
  if (new Set(ids).size !== ids.length || JSON.stringify([...ids].sort()) !== JSON.stringify(ids) ||
      JSON.stringify(ids) !== JSON.stringify(evidence.requiredScenarioIds)) fail();
  for (const scenario of definition.scenarios) {
    if (!exactKeys(scenario, ["environment", "id", "kind", "path", "selector"]) ||
        !SCENARIO_ID_PATTERN.test(scenario.id) || !SCENARIO_KINDS.has(scenario.kind) ||
        !SCENARIO_ENVIRONMENTS.has(scenario.environment) || !validRelativePath(scenario.path) ||
        typeof scenario.selector !== "string" || scenario.selector.length < 8 || scenario.selector.length > 160 ||
        /[\r\n\0]/.test(scenario.selector)) fail();
    let metadata;
    let source;
    try {
      const target = path.join(root, scenario.path);
      metadata = await lstat(target);
      source = await readFile(target, "utf8");
    } catch {
      fail();
    }
    if (!metadata.isFile() || metadata.isSymbolicLink() || !source.includes(scenario.selector)) fail();
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

function safeFailureStage(error, fallback) {
  const captured = `${error?.stdout ?? ""}\n${error?.stderr ?? ""}`;
  const probe = captured.match(/PROBE_FAILED:([a-z]+(?:-[a-z]+)*)/);
  return probe?.[1] ?? fallback;
}

export async function verifyPhase4Sources(root = ROOT) {
  const [fixture, probe, client] = await Promise.all([
    readFile(path.join(root, "internal/server/phase4_console_acceptance_linux_test.go"), "utf8"),
    readFile(path.join(root, "web/e2e/real-change-server-probe.mjs"), "utf8"),
    readFile(path.join(root, "web/generated/read-api.ts"), "utf8"),
  ]);
  for (const pattern of [/CompleteApprovedResumeAndCancelLoopsOverRealTLS/, /phase4ApprovalBridge/, /phase4ResumableAdapter/]) {
    if (!pattern.test(fixture)) throw new Error("PHASE4_FAILED:fixture-definition");
  }
  for (const pattern of [/protected approval material was disclosed/, /approval-status/, /execute-interrupted/, /resume-run/, /cancelled/]) {
    if (!pattern.test(probe)) throw new Error("PHASE4_FAILED:browser-proof");
  }
  for (const pattern of [/requestApproval/, /getApprovalStatus/, /preparePlan/, /reviseDeclaration/]) {
    if (!pattern.test(client)) throw new Error("PHASE4_FAILED:generated-client");
  }
  return true;
}

async function sourceCommit(root) {
  const result = await runCommand("git", ["rev-parse", "HEAD"], { cwd: root, capture: true, timeoutMs: 30_000 });
  const commit = result.stdout.trim();
  if (!SHA_PATTERN.test(commit)) throw new Error("PHASE4_FAILED:source-commit");
  return commit;
}

async function runPhase4Browser(root) {
  const artifacts = await mkdtemp(path.join(tmpdir(), "vsk-phase4-browser-"));
  let browserFailure;
  let sanitized;
  try {
    const browser = packageManagerInvocation([
      "--filter", "@vegastack/labs-web", "exec", "playwright", "test",
      "e2e/phase4-acceptance.spec.ts", "e2e/change-workflow.spec.ts",
    ]);
    try {
      await runCommand(browser.command, browser.args, {
        cwd: root,
        capture: true,
        env: { ...process.env, VSK_PHASE3_PLAYWRIGHT_OUTPUT: artifacts },
        timeoutMs: 180_000,
      });
    } catch (error) {
      browserFailure = error;
    }
    sanitized = await verifyPhase3({ artifacts, root });
  } finally {
    await rm(artifacts, { recursive: true, force: true });
  }
  if (sanitized?.status !== "pass") throw new Error("PHASE4_FAILED:evidence-sanitizer");
  if (browserFailure) throw new Error(`PHASE4_FAILED:${safeFailureStage(browserFailure, "browser-suite")}`);
}

async function runPhase4Go(root) {
  await runCommand("go", ["test", "-race", "-count=1",
    "./internal/adapter", "./internal/acknowledgement", "./internal/api", "./internal/authorization",
    "./internal/cli", "./internal/plan", "./internal/run", "./internal/store"], {
    cwd: root, capture: true, timeoutMs: 600_000,
  });
  const runtimeRoot = await mkdtemp(path.join(tmpdir(), "vsk-phase4-runtime-"));
  const binary = path.join(runtimeRoot, "vsk-labs");
  const database = path.join(runtimeRoot, "control.db");
  const osRelease = path.join(runtimeRoot, "os-release");
  try {
    await writeFile(osRelease, "ID=debian\nVERSION_ID=13\n", { mode: 0o600 });
    await runCommand("go", ["build", "-race", "-ldflags", phase3LinkerFlags({ database, osRelease }), "-o", binary, "./cmd/vsk-labs"], {
      cwd: root, capture: true, timeoutMs: 180_000,
    });
    await runCommand("go", ["test", "-race", "-count=1", "./internal/server", "-run", "^(TestPhase4Acceptance|TestPhase4ConsoleChangesComplete)"], {
      cwd: root,
      capture: true,
      env: { ...process.env, VSK_PHASE3_BINARY: binary, VSK_PHASE3_RUNTIME_ROOT: runtimeRoot },
      timeoutMs: 300_000,
    });
  } catch (error) {
    throw new Error(`PHASE4_FAILED:${safeFailureStage(error, "real-server")}`);
  } finally {
    await rm(runtimeRoot, { recursive: true, force: true });
  }
}

export async function runPhase4(root = ROOT, { prepared = false } = {}) {
  await verifyPhase4Sources(root);
  const { definition } = await phase4Definitions(root);
  if (!prepared) {
    const build = packageManagerInvocation(["--filter", "@vegastack/labs-web", "build"]);
    await runCommand(build.command, build.args, { cwd: root, capture: true, timeoutMs: 180_000 });
  }
  await runCommand("go", ["run", "./tooling/generate-contracts", "--check"], { cwd: root, capture: true, timeoutMs: 180_000 });
  await runCommand(process.execPath, ["tooling/verify-cli.mjs"], { cwd: root, capture: true, timeoutMs: 180_000 });
  await runCommand(process.execPath, ["tooling/verify-static.mjs"], { cwd: root, capture: true, timeoutMs: 180_000 });
  await runPhase4Browser(root);
  if (process.platform === "linux") {
    await runPhase4Go(root);
  }
  return {
    schemaVersion: 1,
    check: "phase-4",
    status: "pass",
    sourceCommit: await sourceCommit(root),
    scenarioDigest: phase4ScenarioDigest(definition),
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
