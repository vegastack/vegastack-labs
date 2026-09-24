import { createHash } from "node:crypto";
import { lstat, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { packageManagerInvocation, runCommand } from "./process.mjs";

const SCENARIO_ID_PATTERN = /^[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const SCENARIO_KINDS = new Set(["browser-test", "go-test", "node-test"]);
const SCENARIO_ENVIRONMENTS = new Set(["built-linux", "chromium", "fixture"]);
const TEST_PATHS = { "browser-test": /\.spec\.ts$/, "go-test": /_test\.go$/, "node-test": /\.test\.mjs$/ };

function prefix(phase) {
  if (!Number.isInteger(phase) || phase < 1 || phase > 99) throw new TypeError("invalid acceptance phase");
  return `PHASE${phase}`;
}

export function exactKeys(value, expected) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort());
}

function validRelativePath(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 4096 && !value.startsWith("/") &&
    !value.includes("\\") && !value.includes("\0") && !value.split("/").includes("..");
}

export function canonicalJSON(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJSON).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJSON(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function acceptanceScenarioDigest(definition) {
  return `sha256:${createHash("sha256").update(canonicalJSON(definition)).digest("hex")}`;
}

function requiredIDs(requiredScenarios) {
  return requiredScenarios.map(item => typeof item === "string" ? item : item.id);
}

function validCommonScenario(scenario) {
  return scenario !== null && typeof scenario === "object" && SCENARIO_ID_PATTERN.test(scenario.id) && SCENARIO_KINDS.has(scenario.kind) &&
    SCENARIO_ENVIRONMENTS.has(scenario.environment) && validRelativePath(scenario.path) &&
    TEST_PATHS[scenario.kind].test(scenario.path) && typeof scenario.selector === "string" &&
    scenario.selector.length >= 8 && scenario.selector.length <= 200 && !/[\r\n\0]/.test(scenario.selector);
}

export async function validateAcceptanceDefinition({ root, phase, definition, evidence, requiredScenarios }) {
  const failure = `${prefix(phase)}_FAILED:definition`;
  const fail = () => { throw new Error(failure); };
  const fullDefinition = requiredScenarios.every(item => item !== null && typeof item === "object");
  const required = requiredIDs(requiredScenarios);
  if (!exactKeys(definition, ["schemaVersion", "scenarios"]) || definition.schemaVersion !== 1 ||
      !Array.isArray(definition.scenarios) ||
      !exactKeys(evidence, ["check", "quarantined", "requiredScenarioIds", "schemaVersion"]) ||
      evidence.schemaVersion !== 1 || evidence.check !== `phase-${phase}` ||
      !Array.isArray(evidence.requiredScenarioIds) || !Array.isArray(evidence.quarantined) ||
      evidence.quarantined.length !== 0) fail();
  const ids = definition.scenarios.map(scenario => scenario?.id);
  if (new Set(ids).size !== ids.length || canonicalJSON(ids) !== canonicalJSON(required) ||
      canonicalJSON(evidence.requiredScenarioIds) !== canonicalJSON(required) ||
      (fullDefinition && canonicalJSON(definition.scenarios) !== canonicalJSON(requiredScenarios))) fail();
  for (const scenario of definition.scenarios) {
    if (!validCommonScenario(scenario)) fail();
    if (fullDefinition) {
      if (!exactKeys(scenario, ["cleanup", "environment", "expected", "id", "kind", "ownerIssue", "path", "proofClass", "repeat", "requirementId", "sanitizer", "seam", "seed", "selector"]) ||
          !exactKeys(scenario.expected, ["errorCode", "result", "state"]) || scenario.expected.result !== "pass" ||
          (scenario.expected.errorCode !== null && typeof scenario.expected.errorCode !== "string") ||
          (scenario.expected.state !== null && typeof scenario.expected.state !== "string") ||
          !Number.isInteger(scenario.ownerIssue) || scenario.ownerIssue <= 0 ||
          typeof scenario.requirementId !== "string" || !scenario.requirementId.endsWith(`.${scenario.id}`) ||
          !["gate", "credential", "backup-local", "backup-offsite", "audit", "restore", "schedule", "surface", "suite"].includes(scenario.seam) ||
          scenario.proofClass !== "fixture" || !Number.isInteger(scenario.repeat) || scenario.repeat < 1 || scenario.repeat > 10 ||
          (scenario.repeat === 1 ? scenario.seed !== null :
            (typeof scenario.seed !== "string" || scenario.seed.length < 1 || scenario.seed.length > 128 || /[\r\n\0]/.test(scenario.seed))) ||
          typeof scenario.cleanup !== "string" || scenario.cleanup.length < 3 ||
          typeof scenario.sanitizer !== "string" || scenario.sanitizer.length < 3) fail();
    } else if (!exactKeys(scenario, ["environment", "id", "kind", "path", "selector"])) fail();
    try {
      const metadata = await lstat(path.join(root, scenario.path));
      if (!metadata.isFile() || metadata.isSymbolicLink()) fail();
    } catch { fail(); }
  }
  return true;
}

function regexEscape(value) { return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
function exactGoPattern(selector) { return selector.split("/").map(part => `^${regexEscape(part)}$`).join("/"); }

export function parseGoScenarioPass(stdout, selector, expectedPasses = 1, phase = 4) {
  let passed = 0;
  for (const line of stdout.split("\n")) {
    if (!line.startsWith("{")) continue;
    let event;
    try { event = JSON.parse(line); } catch { throw new Error(`${prefix(phase)}_FAILED:scenario-result`); }
    if (event.Test !== selector) continue;
    if (event.Action === "skip" || event.Action === "fail") throw new Error(`${prefix(phase)}_FAILED:scenario-result`);
    if (event.Action === "pass") passed++;
  }
  if (passed !== expectedPasses) throw new Error(`${prefix(phase)}_FAILED:scenario-result`);
}

function collectPlaywrightSpecs(suite, found = []) {
  for (const spec of suite.specs ?? []) found.push(spec);
  for (const child of suite.suites ?? []) collectPlaywrightSpecs(child, found);
  return found;
}

export function parsePlaywrightScenarioPass(report, selector, expectedPasses = 1, phase = 4) {
  const allSpecs = collectPlaywrightSpecs(report);
  const matches = allSpecs.filter(spec => spec.title === selector);
  const tests = matches.flatMap(spec => spec.tests ?? []);
  if (allSpecs.length !== expectedPasses || matches.length !== expectedPasses || tests.length === 0 ||
      report.errors?.length !== 0 || report.stats?.expected !== expectedPasses || report.stats?.skipped !== 0 ||
      report.stats?.unexpected !== 0 || report.stats?.flaky !== 0) throw new Error(`${prefix(phase)}_FAILED:scenario-result`);
  for (const test of tests) {
    if (test.status !== "expected" || test.expectedStatus !== "passed" || test.results?.length === 0 ||
        test.results.some(item => item.status !== "passed")) throw new Error(`${prefix(phase)}_FAILED:scenario-result`);
  }
}

export function parseNodeScenarioPass(stdout, selector, expectedPasses = 1, phase = 4) {
  const escaped = regexEscape(selector);
  const passed = stdout.match(new RegExp(`^ok \\d+ - ${escaped}(?: \\(.+\\))?$`, "gm")) ?? [];
  if (passed.length !== expectedPasses || new RegExp(`^(?:not ok \\d+ - ${escaped}|ok \\d+ - ${escaped}.*# (?:SKIP|TODO))`, "im").test(stdout)) {
    throw new Error(`${prefix(phase)}_FAILED:scenario-result`);
  }
}

async function scanCommandFailure(scanCaptured, error) {
  if (scanCaptured && (typeof error?.stdout === "string" || typeof error?.stderr === "string")) {
    await scanCaptured({ stdout: error.stdout ?? "", stderr: error.stderr ?? "" });
  }
}

async function runGoScenario(root, phase, scenario, runtime, scanCaptured) {
  const outputs = [];
  for (let index = 0; index < (scenario.repeat ?? 1); index++) {
    let result;
    try {
      result = await runCommand("go", ["test", "-json", "-race", "-count=1", `./${path.dirname(scenario.path)}`, "-run", exactGoPattern(scenario.selector)], {
        cwd: root, capture: true,
        env: { ...process.env, ...(runtime ? { VSK_PHASE3_BINARY: runtime.binary, VSK_PHASE3_RUNTIME_ROOT: runtime.root } : {}),
          ...(scenario.seed === null || scenario.seed === undefined ? {} : {
            [`VSK_PHASE${phase}_SEED`]: scenario.seed,
            [`VSK_PHASE${phase}_REPEAT`]: String(index),
          }) },
        timeoutMs: 300_000,
      });
    } catch (error) {
      await scanCommandFailure(scanCaptured, error);
      throw new Error(`${prefix(phase)}_FAILED:scenario-execution`);
    }
    await scanCaptured?.(result);
    outputs.push(result.stdout);
  }
  parseGoScenarioPass(outputs.join(""), scenario.selector, scenario.repeat ?? 1, phase);
}

async function runBrowserScenario(root, phase, scenario, artifactRoot, scanCaptured, browserFailureSummary) {
  const reportRoot = await mkdtemp(path.join(tmpdir(), `vsk-phase${phase}-report-`));
  const reportPath = path.join(reportRoot, "report.json");
  const invocation = packageManagerInvocation([
    "--filter", "@vegastack/labs-web", "exec", "playwright", "test", scenario.path.replace(/^web\//, ""),
    "--grep", regexEscape(scenario.selector), "--reporter=json", "--workers=1",
  ]);
  try {
    const result = await runCommand(invocation.command, invocation.args, {
      cwd: root, capture: true,
      env: { ...process.env, PLAYWRIGHT_JSON_OUTPUT_NAME: reportPath, VSK_PHASE3_PLAYWRIGHT_OUTPUT: artifactRoot },
      timeoutMs: 180_000,
    });
    await scanCaptured?.(result);
    const rawReport = await readFile(reportPath, "utf8");
    await scanCaptured?.({ stdout: rawReport, stderr: "" });
    parsePlaywrightScenarioPass(JSON.parse(rawReport), scenario.selector, 1, phase);
  } catch (error) {
    await scanCommandFailure(scanCaptured, error);
    let report = {};
    try {
      const rawReport = await readFile(reportPath, "utf8");
      await scanCaptured?.({ stdout: rawReport, stderr: "" });
      report = JSON.parse(rawReport);
    } catch (reportError) {
      if (reportError?.message?.startsWith(`${prefix(phase)}_FAILED:`)) throw reportError;
    }
    const failure = error?.message?.startsWith(`${prefix(phase)}_FAILED:`) ? error : new Error(`${prefix(phase)}_FAILED:scenario-execution`);
    if (browserFailureSummary) failure.browserSummary = browserFailureSummary(report, scenario.selector, root);
    throw failure;
  } finally {
    await rm(reportRoot, { recursive: true, force: true });
  }
}

async function runNodeScenario(root, phase, scenario, scanCaptured) {
  const outputs = [];
  for (let index = 0; index < (scenario.repeat ?? 1); index++) {
    let result;
    try {
      const env = { ...process.env, ...(scenario.seed === null || scenario.seed === undefined ? {} : {
        [`VSK_PHASE${phase}_SEED`]: scenario.seed,
        [`VSK_PHASE${phase}_REPEAT`]: String(index),
      }) };
      // A verifier can itself run under `node --test`; the nested proof must
      // start a new test runner instead of inheriting the parent's IPC mode.
      delete env.NODE_TEST_CONTEXT;
      result = await runCommand(process.execPath, ["--test", "--test-reporter=tap", `--test-name-pattern=^${regexEscape(scenario.selector)}$`, scenario.path], {
        cwd: root, capture: true,
        env,
        timeoutMs: 60_000,
      });
    } catch (error) {
      await scanCommandFailure(scanCaptured, error);
      throw new Error(`${prefix(phase)}_FAILED:scenario-execution`);
    }
    await scanCaptured?.(result);
    outputs.push(result.stdout);
  }
  parseNodeScenarioPass(outputs.join(""), scenario.selector, scenario.repeat ?? 1, phase);
}

export async function executeAcceptanceScenarios({ root, phase, definition, runtime, artifactRoot, scanCaptured, browserFailureSummary }) {
  const proofResults = new Map();
  const outcomes = [];
  for (const scenario of definition.scenarios) {
    if (scenario.environment === "built-linux" && process.platform !== "linux") {
      outcomes.push({ id: scenario.id, environment: scenario.environment, status: "linux-required" });
      continue;
    }
    const proof = canonicalJSON({ kind: scenario.kind, path: scenario.path, selector: scenario.selector, repeat: scenario.repeat ?? 1, seed: scenario.seed ?? null });
    if (!proofResults.has(proof)) {
      try {
        if (scenario.kind === "go-test") await runGoScenario(root, phase, scenario, runtime, scanCaptured);
        else if (scenario.kind === "browser-test") await runBrowserScenario(root, phase, scenario, artifactRoot, scanCaptured, browserFailureSummary);
        else await runNodeScenario(root, phase, scenario, scanCaptured);
      } catch (error) {
        const failure = new RegExp(`^${prefix(phase)}_FAILED:(scenario-(?:execution|result))$`).exec(error?.message ?? "");
        if (failure) {
          const tagged = new Error(`${error.message}:${scenario.id}`);
          tagged.browserSummary = error.browserSummary;
          throw tagged;
        }
        throw error;
      }
      proofResults.set(proof, true);
    }
    outcomes.push({ id: scenario.id, environment: scenario.environment, status: "pass" });
  }
  return outcomes;
}
