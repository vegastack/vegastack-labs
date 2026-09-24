import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WORKFLOW = path.join(ROOT, ".github/workflows/ci.yml");
const ACTIONS = new Map([
  ["actions/checkout", "3d3c42e5aac5ba805825da76410c181273ba90b1"],
  ["actions/setup-go", "b7ad1dad31e06c5925ef5d2fc7ad053ef454303e"],
  ["actions/setup-node", "820762786026740c76f36085b0efc47a31fe5020"],
  ["pnpm/action-setup", "0977fd99725f1db4007ccb2928dbb4e90d06cc86"],
]);

export function verifyWorkflowDocument(workflow, source = "") {
  if (workflow.permissions?.contents !== "read" || Object.keys(workflow.permissions).length !== 1) {
    throw new Error("workflow permissions must contain only contents: read");
  }
  if (Object.keys(workflow.on ?? {}).join(",") !== "workflow_dispatch") {
    throw new Error("public CI must be manual-only during the Phase 5 batch");
  }
  const inputs = workflow.on.workflow_dispatch?.inputs ?? {};
  if (Object.hasOwn(inputs, "base_sha") ||
      inputs.full_check?.type !== "boolean" || inputs.full_check?.required !== false ||
      inputs.full_check?.default !== false ||
      inputs.native_credential_sha?.type !== "string" ||
      inputs.backup_acceptance?.type !== "boolean") {
    throw new Error("manual CI must expose only explicit final-full and named native acceptance selections");
  }
  if (/\$\{\{\s*secrets\./.test(source)) throw new Error("public workflow must not reference secrets");

  const jobs = workflow.jobs ?? {};
  if (Object.keys(jobs).sort().join(",") !== "plan,verify_trusted") {
    throw new Error("manual CI must contain only plan and trusted disposable jobs");
  }
  const expectedJobs = {
    plan: { runner: "ubuntu-24.04", timeout: 5, actions: ["actions/checkout", "actions/setup-node"] },
    verify_trusted: { runner: ["self-hosted", "linux", "x64"], timeout: 15, actions: [...ACTIONS.keys()] },
  };
  let actionCount = 0;
  for (const [jobName, expected] of Object.entries(expectedJobs)) {
    const job = jobs[jobName];
    if (JSON.stringify(job?.["runs-on"]) !== JSON.stringify(expected.runner)) {
      throw new Error(`${jobName} job must use ${JSON.stringify(expected.runner)}`);
    }
    if (!Number.isInteger(job["timeout-minutes"]) || job["timeout-minutes"] > expected.timeout) {
      throw new Error(`${jobName} job timeout must be at most ${expected.timeout} minutes`);
    }
    const seen = new Set();
    for (const step of job.steps ?? []) {
      if (!step.uses) continue;
      const match = step.uses.match(/^([^@]+)@([0-9a-f]{40})$/);
      if (!match || ACTIONS.get(match[1]) !== match[2]) {
        throw new Error(`action is not in the approved immutable set: ${step.uses}`);
      }
      if (seen.has(match[1])) throw new Error(`action appears more than once in ${jobName}: ${match[1]}`);
      seen.add(match[1]);
      actionCount++;
      if (match[1] === "actions/checkout" &&
          (step.with?.["persist-credentials"] !== false || step.with?.["fetch-depth"] !== 0)) {
        throw new Error("checkout must disable credentials and retain complete commit history");
      }
    }
    if ([...expected.actions].sort().join(",") !== [...seen].sort().join(",")) {
      throw new Error(`${jobName} job does not use its exact approved Action set`);
    }
  }

  const plan = jobs.plan.steps?.find((step) => step.id === "check-plan");
  if (!plan || /pull_request|github\.event\.before|inputs\.base_sha/.test(JSON.stringify(plan)) ||
      plan.env?.HEAD_SHA !== "${{ github.sha }}" ||
      !/dispatch must explicitly select final full_check or a named native acceptance lane/.test(plan.run ?? "") ||
      !/native credential acceptance SHA must equal the dispatch head/.test(plan.run ?? "") ||
      !/native credential acceptance requires its reviewed branch/.test(plan.run ?? "") ||
      !/node tooling\/check-affected\.mjs --base "" --head "\$HEAD_SHA" --dry-run/.test(plan.run ?? "")) {
    throw new Error("manual plan must require an explicit lane and bind the exact dispatch head");
  }

  const steps = jobs.verify_trusted.steps ?? [];
  const chromium = steps.find((step) => step.name === "Install pinned Chromium");
  const affected = steps.find((step) => step.name === "Run affected public checks");
  const phase5 = steps.find((step) => step.name === "Run exact Phase 5 exit acceptance");
  const dependencies = steps.find((step) => step.name === "Install public dependencies");
  const branchFullCheck = "inputs.full_check && github.ref != 'refs/heads/main'";
  const mainFullCheck = "inputs.full_check && github.ref == 'refs/heads/main'";
  if (chromium?.if !== "inputs.full_check" || affected?.if !== branchFullCheck ||
      affected.run !== "pnpm check:affected --execute-plan" ||
      affected.env?.VSK_CHECK_PLAN_B64 !== "${{ needs.plan.outputs.check_plan }}" ||
      phase5?.if !== mainFullCheck ||
      phase5.run !== "pnpm --silent check:phase-5-exit --commit \"$GITHUB_SHA\"" ||
      dependencies?.if !== "inputs.full_check") {
    throw new Error("full_check must select exactly the branch affected lane or the main Phase 5 exit lane");
  }
  if (steps.some((step) => step.name === "Run exact Phase 4 exit acceptance" ||
      step.name === "Verify generated contracts and embedded Console stay unchanged") ||
      steps.filter((step) => /check:phase-5-exit/.test(step.run ?? "")).length !== 1 ||
      steps.filter((step) => /check:affected --execute-plan/.test(step.run ?? "")).length !== 1) {
    throw new Error("full_check must not duplicate or retain an earlier phase exit lane");
  }
  const backup = steps.find((step) => step.name === "Run pinned local-backup acceptance");
  const native = steps.find((step) => step.name === "Run exact #143 disposable native credential acceptance");
  if (!/inputs\.backup_acceptance/.test(backup?.if ?? "") ||
      !/inputs\.native_credential_sha/.test(native?.if ?? "")) {
    throw new Error("named native acceptance lanes must remain explicitly selected");
  }
  const trustedNode = steps.find((step) => step.uses?.startsWith("actions/setup-node@"));
  if (trustedNode?.with?.cache !== undefined) throw new Error("trusted runner must not restore remote pnpm cache");
  if (!/hostname/.test(steps[0]?.run ?? "") || !/vsk-node-01\|vsk-node-06/.test(steps[0]?.run ?? "") ||
      steps[1]?.name !== "Prepare protected local test storage" ||
      steps.findIndex((step) => step.uses?.startsWith("actions/checkout@")) !== 2) {
    throw new Error("self-hosted checks must verify the allowed hostname before repository checkout");
  }
  const cleanup = steps.find((step) => step.name === "Remove protected local test storage");
  if (cleanup?.if !== "always()" || !/rm -rf -- "\$TMPDIR"/.test(cleanup.run ?? "")) {
    throw new Error("self-hosted checks must safely remove protected temporary storage");
  }
  if (/^\s*(pull_request|push):/m.test(source) || /github\.event_name\s*==\s*['"](?:pull_request|push)/.test(source)) {
    throw new Error("automatic pull-request and push CI are forbidden during the Phase 5 batch");
  }
  if (/run:\s*pnpm check\s*$/m.test(source)) {
    throw new Error("workflow must not add a second complete check lane");
  }
  return { actionCount, jobCount: Object.keys(jobs).length };
}

const source = await readFile(WORKFLOW, "utf8");
const result = verifyWorkflowDocument(parseYaml(source), source);
console.log(JSON.stringify({ schemaVersion: 1, check: "workflow", status: "pass",
  actions: result.actionCount, jobs: result.jobCount }));
