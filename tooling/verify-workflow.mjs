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
  for (const trigger of ["pull_request", "push", "workflow_dispatch"]) {
    if (!Object.hasOwn(workflow.on ?? {}, trigger)) {
      throw new Error(`workflow is missing ${trigger} trigger`);
    }
  }
  if (!workflow.on.push?.branches?.includes("main")) {
    throw new Error("workflow push trigger must be limited to main");
  }
  if (/\$\{\{\s*secrets\./.test(source)) {
    throw new Error("public workflow must not reference secrets");
  }

  const jobs = Object.values(workflow.jobs ?? {});
  if (jobs.length !== 1) {
    throw new Error("public workflow must contain exactly one job");
  }
  const [job] = jobs;
  if (job["runs-on"] !== "ubuntu-24.04") {
    throw new Error("public workflow must pin ubuntu-24.04");
  }
  if (!Number.isInteger(job["timeout-minutes"]) || job["timeout-minutes"] > 15) {
    throw new Error("public workflow must have a timeout of at most 15 minutes");
  }

  const seen = new Set();
  for (const step of job.steps ?? []) {
    if (!step.uses) {
      continue;
    }
    const match = step.uses.match(/^([^@]+)@([0-9a-f]{40})$/);
    if (!match) {
      throw new Error(`action is not pinned by full commit: ${step.uses}`);
    }
    const [, action, commit] = match;
    if (ACTIONS.get(action) !== commit) {
      throw new Error(`action is not in the approved immutable set: ${action}`);
    }
    if (seen.has(action)) {
      throw new Error(`action appears more than once: ${action}`);
    }
    seen.add(action);

    if (action === "actions/checkout" && step.with?.["persist-credentials"] !== false) {
      throw new Error("checkout must disable persisted credentials");
    }
    if (action === "actions/checkout" && step.with?.["fetch-depth"] !== 0) {
      throw new Error("checkout must retain complete commit history for ancestry evidence");
    }
  }
  if (seen.size !== ACTIONS.size) {
    throw new Error("workflow does not use the complete approved Action set");
  }

  const steps = job.steps ?? [];
  const plan = steps.find((step) => step.id === "check-plan");
  const chromium = steps.find((step) => step.name === "Install pinned Chromium");
  const affected = steps.find((step) => step.name === "Run affected public checks");
  if (!plan || !/pnpm check:affected:plan/.test(plan.run ?? "") ||
      !/github\.event\.pull_request\.base\.sha/.test(plan.env?.BASE_SHA ?? "") ||
      !/github\.event\.before/.test(plan.env?.BASE_SHA ?? "") ||
      !/github\.event\.pull_request\.head\.sha/.test(plan.env?.HEAD_SHA ?? "")) {
    throw new Error("workflow must calculate an affected check plan from explicit event base/head SHAs");
  }
  if (chromium?.if !== "steps.check-plan.outputs.browser == 'true'") {
    throw new Error("workflow must install Chromium only when the affected plan selects browser checks");
  }
  if (!affected || !/pnpm check:affected\s+--\s+--base/.test(affected.run ?? "")) {
    throw new Error("workflow must execute the affected check plan");
  }
  if (/run:\s*pnpm check\s*$/m.test(source)) {
    throw new Error("workflow must not repeat the complete local check lane");
  }

  return { actions: seen.size, jobs: jobs.length };
}

export async function verifyWorkflow(workflowPath = WORKFLOW) {
  const source = await readFile(workflowPath, "utf8");
  return verifyWorkflowDocument(parseYaml(source), source);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const result = await verifyWorkflow();
    process.stdout.write(
      `${JSON.stringify({ schemaVersion: 1, check: "workflow", status: "pass", ...result })}\n`,
    );
  } catch (error) {
    process.stderr.write(`workflow verification failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
