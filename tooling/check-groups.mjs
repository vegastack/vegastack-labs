import path from "node:path";
import { fileURLToPath } from "node:url";
import { packageManagerInvocation, runCommand } from "./lib/process.mjs";

const DEFAULT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export const CHECK_GROUP_NAMES = Object.freeze(["always", "phase", "go", "tooling", "web", "browser"]);

function commandStep(name, group, command, args, options = {}) {
  return Object.freeze({
    name,
    group,
    run: (root) => runCommand(command, args, { cwd: root, ...options }),
  });
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
    if (!/\bgo1\.27\.0\b/.test(result.stdout)) {
      throw new Error(`Go 1.27.0 is required, found ${result.stdout.trim()}`);
    }
  }),
  checkStep("Go formatting", "go", async (root) => {
    const result = await runCommand("gofmt", ["-l", "."], { cwd: root, capture: true });
    if (result.stdout.trim()) {
      throw new Error(`Go files require formatting:\n${result.stdout.trim()}`);
    }
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

function freezeSegments(selected) {
  const segments = [];
  for (const step of steps) {
    if (!selected.has(step.group)) continue;
    const prior = segments.at(-1);
    if (prior?.name === step.group) {
      prior.steps.push(step);
    } else {
      segments.push({ name: step.group, steps: [step] });
    }
  }
  return Object.freeze(segments.map((segment) => Object.freeze({
    name: segment.name,
    steps: Object.freeze(segment.steps),
  })));
}

export function checkPlan(groupNames) {
  const selected = new Set(groupNames);
  for (const name of selected) {
    if (!CHECK_GROUP_NAMES.includes(name)) throw new Error(`unknown check group: ${name}`);
  }
  selected.add("always");
  return freezeSegments(selected);
}

export function fullCheckPlan() {
  return freezeSegments(new Set(CHECK_GROUP_NAMES));
}

export async function runCheckPlan(plan, { root = DEFAULT_ROOT } = {}) {
  for (const segment of plan) {
    for (const step of segment.steps) {
      process.stderr.write(`check: ${step.name}\n`);
      await step.run(root);
    }
  }
}
