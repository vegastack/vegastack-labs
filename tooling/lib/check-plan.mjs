import path from "node:path";
import { fileURLToPath } from "node:url";
import { packageManagerInvocation, runCommand } from "./process.mjs";

const DEFAULT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const STATUS_PATTERN = /^(?:[AMDTUXB]|[RC][0-9]{1,3})$/;

export const CHECK_GROUPS = Object.freeze(["always", "phase", "go", "tooling", "web", "browser"]);

function commandStep(name, group, command, args, options = {}) {
  return Object.freeze({ name, group, run: (root) => runCommand(command, args, { cwd: root, ...options }) });
}

function packageStep(name, group, args) {
  return Object.freeze({
    name,
    group,
    run: (root) => {
      const invocation = packageManagerInvocation(args);
      return runCommand(invocation.command, invocation.args, { cwd: root });
    },
  });
}

function checkStep(name, group, check) {
  return Object.freeze({ name, group, run: check });
}

const steps = Object.freeze([
  commandStep("repository safety and tool pins", "always", process.execPath, ["tooling/verify-repository.mjs"]),
  commandStep("public CI policy", "always", process.execPath, ["tooling/verify-workflow.mjs"]),
  commandStep("documentation and JSON", "always", process.execPath, ["tooling/verify-docs.mjs"]),
  commandStep("Phase 0.3 contract fixtures", "phase", process.execPath, ["tooling/verify-phase-0-3.mjs"]),
  commandStep("Phase 0.4 contract fixtures", "phase", process.execPath, ["tooling/verify-phase-0-4.mjs"]),
  commandStep("Phase 0.5 exit evidence", "phase", process.execPath, ["tooling/verify-phase-0-5.mjs"]),
  commandStep("Phase 2 integrated evidence", "phase", process.execPath, ["tooling/verify-phase-2.mjs"]),
  commandStep("historical artifacts", "phase", process.execPath, ["tooling/historical.mjs", "--check"]),
  commandStep("pinned Design System source", "tooling", process.execPath, ["tooling/design-system.mjs", "--check"]),
  commandStep("dependency provenance", "tooling", process.execPath, ["tooling/provenance.mjs", "--check"]),
  commandStep("Go dependency provenance", "go", process.execPath, ["tooling/verify-go-dependencies.mjs", "--check"]),
  checkStep("Go version", "go", async (root) => {
    const result = await runCommand("go", ["version"], { cwd: root, capture: true });
    if (!/\bgo1\.27\.0\b/.test(result.stdout)) throw new Error(`Go 1.27.0 is required, found ${result.stdout.trim()}`);
  }),
  checkStep("Go formatting", "go", async (root) => {
    const result = await runCommand("gofmt", ["-l", "."], { cwd: root, capture: true });
    if (result.stdout.trim()) throw new Error(`Go files require formatting:\n${result.stdout.trim()}`);
  }),
  commandStep("generated contracts", "go", "go", ["run", "./tooling/generate-contracts", "--check"]),
  packageStep("web static build", "web", ["--filter", "@vegastack/labs-web", "build"]),
  commandStep("static export and embedded asset contract", "web", process.execPath, ["tooling/verify-static.mjs"]),
  commandStep("authorized read API boundary", "web", process.execPath, ["tooling/verify-read-api.mjs"]),
  commandStep("portable CLI boundary and target builds", "go", process.execPath, ["tooling/verify-cli.mjs"]),
  commandStep("local control service boundary", "go", process.execPath, ["tooling/verify-server.mjs"]),
  commandStep("Go vet", "go", "go", ["vet", "./..."]),
  commandStep("Go unit tests", "go", "go", ["test", "./..."]),
  commandStep("Go package build", "go", "go", ["build", "./..."]),
  packageStep("tooling tests", "tooling", ["test:tooling"]),
  packageStep("web lint", "web", ["--filter", "@vegastack/labs-web", "lint"]),
  packageStep("web typecheck", "web", ["--filter", "@vegastack/labs-web", "typecheck"]),
  packageStep("web unit tests", "web", ["--filter", "@vegastack/labs-web", "test"]),
  packageStep("Console browser evidence", "browser", ["--filter", "@vegastack/labs-web", "test:e2e"]),
  commandStep("Git whitespace", "always", "git", ["diff", "--check"]),
]);

function freezePlan(value) {
  return Object.freeze({
    ...value,
    changedPaths: Object.freeze([...value.changedPaths]),
    groups: Object.freeze([...value.groups]),
    reasons: Object.freeze([...value.reasons]),
  });
}

function orderedGroups(selected) {
  return CHECK_GROUPS.filter((group) => selected.has(group));
}

function completePlan(reason, changedPaths = []) {
  return freezePlan({
    schemaVersion: 1,
    mode: "full",
    failClosed: Boolean(reason),
    reasons: [reason || "complete-lane"],
    changedPaths,
    groups: CHECK_GROUPS,
    browser: true,
  });
}

export function fullCheckPlan(reason) {
  return completePlan(reason);
}

function validPath(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 4096 &&
    !value.startsWith("/") && !value.includes("\\") && !value.includes("\0") &&
    !value.split("/").includes("..");
}

function browserServerPath(file) {
  return /^internal\/api\//.test(file) ||
    /^internal\/server\/(?:application|browser_auth|console|remote)/.test(file) ||
    /^internal\/(?:metadata|contractgen|generated)\//.test(file) ||
    /^internal\/serverconfig\//.test(file);
}

function browserWebPath(file) {
  return /^web\/(?:app|components|lib|generated|e2e)\//.test(file) ||
    /^web\/(?:playwright\.config\.ts|next\.config\.|scripts\/preview\.mjs)/.test(file);
}

function browserToolingPath(file) {
  return /^tooling\/(?:console-assets|verify-static|verify-read-api)\.mjs$/.test(file) ||
    /^tooling\/test\/(?:console-assets|static|read-api)\.test\.mjs$/.test(file) ||
    /^tooling\/testdata\/(?:static|generated-read-client)/.test(file);
}

function knownDocumentationPath(file) {
  return /^(?:AGENTS\.md|README\.md|CONTRIBUTING\.md|LICENSE|HANDOFF\.md)$/.test(file) ||
    /^docs\//.test(file) || /^\.vegastack\/(?:chronicle|dev|review-known-patterns)\.md$/.test(file);
}

function testPolicyPath(file) {
  return file === "AGENTS.md" || file === "docs/development/operating-mandate.md" ||
    file === ".vegastack/dev.md";
}

function selfPolicyPath(file) {
  return file === "tooling/lib/check-plan.mjs" || file === "tooling/check-affected.mjs" ||
    file === "tooling/check.mjs" || file === ".github/workflows/ci.yml" ||
    file === "package.json" || file === "pnpm-lock.yaml" || file === "go.mod" || file === "go.sum" ||
    file === "web/package.json";
}

function classifyPath(file, selected, reasons) {
  if (selfPolicyPath(file)) return "selector-or-dependency-change";
  if (testPolicyPath(file)) {
    selected.add("tooling");
    reasons.add("test-policy-documentation");
    return null;
  }
  if (knownDocumentationPath(file) || file === ".gitignore" || file === ".gitattributes") {
    reasons.add("documentation-or-repository-metadata");
    return null;
  }
  if (file.startsWith("schemas/")) {
    for (const group of ["go", "tooling", "web", "browser"]) selected.add(group);
    reasons.add("generated-browser-contract");
    return null;
  }
  if (/^internal\/(?:metadata|contractgen|generated)\//.test(file)) {
    for (const group of ["go", "tooling", "web", "browser"]) selected.add(group);
    reasons.add("generated-browser-contract");
    return null;
  }
  if (file.startsWith("internal/") || file.startsWith("cmd/") || file.endsWith(".go")) {
    selected.add("go");
    reasons.add("go-source");
    if (browserServerPath(file)) {
      for (const group of ["tooling", "web", "browser"]) selected.add(group);
      reasons.add("browser-facing-server");
    }
    return null;
  }
  if (file.startsWith("web/")) {
    selected.add("tooling");
    selected.add("web");
    reasons.add("web-source");
    if (browserWebPath(file)) {
      selected.add("browser");
      reasons.add("browser-facing-web");
    }
    return null;
  }
  if (file.startsWith("tooling/")) {
    selected.add("tooling");
    reasons.add("tooling-source");
    if (/^tooling\/(?:verify-phase-|phase-)|^tooling\/(?:test|testdata)\/phase-/.test(file)) {
      selected.add("phase");
      reasons.add("phase-evidence");
    }
    if (browserToolingPath(file)) {
      selected.add("web");
      selected.add("browser");
      reasons.add("browser-facing-tooling");
    }
    return null;
  }
  if (file.startsWith(".github/")) return "workflow-change";
  if (file.startsWith("scripts/")) {
    selected.add("tooling");
    reasons.add("repository-script");
    return null;
  }
  return "unmapped-path";
}

export function classifyChangedPaths(changes) {
  if (!Array.isArray(changes)) return completePlan("invalid-change-list");
  const paths = new Set();
  for (const change of changes) {
    if (!change || !STATUS_PATTERN.test(change.status) || !validPath(change.path) ||
        (change.previousPath !== undefined && !validPath(change.previousPath))) {
      return completePlan("invalid-change-entry", [...paths].sort());
    }
    paths.add(change.path);
    if (change.previousPath) paths.add(change.previousPath);
  }
  const changedPaths = [...paths].sort();
  const selected = new Set(["always"]);
  const reasons = new Set();
  for (const file of changedPaths) {
    const failReason = classifyPath(file, selected, reasons);
    if (failReason) return completePlan(failReason, changedPaths);
  }
  return freezePlan({
    schemaVersion: 1,
    mode: "affected",
    failClosed: false,
    reasons: [...reasons].sort(),
    changedPaths,
    groups: orderedGroups(selected),
    browser: selected.has("browser"),
  });
}

export function checkStepsForPlan(plan) {
  if (!plan || plan.schemaVersion !== 1 || !Array.isArray(plan.groups) ||
      plan.groups.some((group) => !CHECK_GROUPS.includes(group))) {
    throw new Error("invalid check plan");
  }
  const selected = new Set(plan.groups);
  return Object.freeze(steps.filter((step) => selected.has(step.group)));
}

export async function runCheckPlan(plan, { root = DEFAULT_ROOT } = {}) {
  for (const step of checkStepsForPlan(plan)) {
    process.stderr.write(`check: ${step.name}\n`);
    await step.run(root);
  }
}

export function validCommit(value) {
  return SHA_PATTERN.test(value);
}
