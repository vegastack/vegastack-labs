import path from "node:path";
import { fileURLToPath } from "node:url";
import { packageManagerInvocation, runCommand } from "./lib/process.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

async function stage(name, command, args, options = {}) {
  process.stderr.write(`check: ${name}\n`);
  await runCommand(command, args, { cwd: ROOT, ...options });
}

async function packageStage(name, args) {
  const invocation = packageManagerInvocation(args);
  await stage(name, invocation.command, invocation.args);
}

try {
  await stage("repository safety and tool pins", process.execPath, ["tooling/verify-repository.mjs"]);
  await stage("public CI policy", process.execPath, ["tooling/verify-workflow.mjs"]);
  await stage("documentation and JSON", process.execPath, ["tooling/verify-docs.mjs"]);
  await stage("Phase 0.3 contract fixtures", process.execPath, ["tooling/verify-phase-0-3.mjs"]);
  await stage("Phase 0.4 contract fixtures", process.execPath, ["tooling/verify-phase-0-4.mjs"]);
  await stage("Phase 0.5 exit evidence", process.execPath, ["tooling/verify-phase-0-5.mjs"]);
  await stage("historical artifacts", process.execPath, ["tooling/historical.mjs", "--check"]);
  await stage("dependency provenance", process.execPath, ["tooling/provenance.mjs", "--check"]);
  await stage("Go dependency provenance", process.execPath, ["tooling/verify-go-dependencies.mjs", "--check"]);

  const goVersion = await runCommand("go", ["version"], { cwd: ROOT, capture: true });
  if (!/\bgo1\.27\.0\b/.test(goVersion.stdout)) {
    throw new Error(`Go 1.27.0 is required, found ${goVersion.stdout.trim()}`);
  }
  const gofmt = await runCommand("gofmt", ["-l", "."], { cwd: ROOT, capture: true });
  if (gofmt.stdout.trim()) {
    throw new Error(`Go files require formatting:\n${gofmt.stdout.trim()}`);
  }
  await stage("generated contracts", "go", ["run", "./tooling/generate-contracts", "--check"]);
  await stage("authorized read API boundary", process.execPath, ["tooling/verify-read-api.mjs"]);
  await stage("portable CLI boundary and target builds", process.execPath, ["tooling/verify-cli.mjs"]);
  await stage("local control service boundary", process.execPath, ["tooling/verify-server.mjs"]);
  await stage("Go vet", "go", ["vet", "./..."]);
  await stage("Go unit tests", "go", ["test", "./..."]);
  await stage("Go package build", "go", ["build", "./..."]);

  await packageStage("tooling tests", ["test:tooling"]);
  await packageStage("web lint", ["--filter", "@vegastack/labs-web", "lint"]);
  await packageStage("web typecheck", ["--filter", "@vegastack/labs-web", "typecheck"]);
  await packageStage("web unit tests", ["--filter", "@vegastack/labs-web", "test"]);
  await packageStage("web static build", ["--filter", "@vegastack/labs-web", "build"]);
  await stage("static export contract", process.execPath, ["tooling/verify-static.mjs"]);
  await stage("Git whitespace", "git", ["diff", "--check"]);

  process.stdout.write(
    `${JSON.stringify({ schemaVersion: 1, check: "foundation", status: "pass" })}\n`,
  );
} catch (error) {
  process.stderr.write(`foundation check failed: ${error.message}\n`);
  process.exitCode = 1;
}
