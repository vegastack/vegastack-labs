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
  if (Object.keys(workflow.on ?? {}).sort().join(",") !== "pull_request,push,workflow_dispatch") {
    throw new Error("unsupported workflow trigger");
  }
  if (JSON.stringify(workflow.on.push?.branches) !== JSON.stringify(["main"])) {
    throw new Error("workflow push trigger must be limited to main");
  }
  if (/\$\{\{\s*secrets\./.test(source)) {
    throw new Error("public workflow must not reference secrets");
  }

  const jobs = workflow.jobs ?? {};
  if (Object.keys(jobs).sort().join(",") !== "plan,verify_pr,verify_trusted") {
    throw new Error("public workflow must contain only plan, hosted PR, and trusted disposable jobs");
  }
  const expectedJobs = {
    plan: { runner: "ubuntu-24.04", timeout: 5, actions: ["actions/checkout", "actions/setup-node"] },
    verify_pr: { runner: "ubuntu-24.04", timeout: 15, actions: [...ACTIONS.keys()] },
    verify_trusted: { runner: ["self-hosted", "linux", "x64"], timeout: 15, actions: [...ACTIONS.keys()] },
  };
  let actionCount = 0;
  for (const [jobName, expected] of Object.entries(expectedJobs)) {
    const job = jobs[jobName];
    if (JSON.stringify(job["runs-on"]) !== JSON.stringify(expected.runner)) {
      throw new Error(`${jobName} job must use ${JSON.stringify(expected.runner)}`);
    }
    if (!Number.isInteger(job["timeout-minutes"]) || job["timeout-minutes"] > expected.timeout) {
      throw new Error(`${jobName} job timeout must be at most ${expected.timeout} minutes`);
    }
    const seen = new Set();
    for (const step of job.steps ?? []) {
      if (!step.uses) continue;
      const match = step.uses.match(/^([^@]+)@([0-9a-f]{40})$/);
      if (!match) throw new Error(`action is not pinned by full commit: ${step.uses}`);
      const [, action, commit] = match;
      if (ACTIONS.get(action) !== commit) {
        throw new Error(`action is not in the approved immutable set: ${action}`);
      }
      if (seen.has(action)) throw new Error(`action appears more than once in ${jobName}: ${action}`);
      seen.add(action);
      actionCount++;
      if (action === "actions/checkout" && step.with?.["persist-credentials"] !== false) {
        throw new Error("checkout must disable persisted credentials");
      }
      if (action === "actions/checkout" && step.with?.["fetch-depth"] !== 0) {
        throw new Error("checkout must retain complete commit history for ancestry evidence");
      }
    }
    if ([...expected.actions].sort().join(",") !== [...seen].sort().join(",")) {
      throw new Error(`${jobName} job does not use its exact approved Action set`);
    }
  }

  if (jobs.verify_pr.name !== "Public foundation checks" ||
      jobs.verify_trusted.name !== "Public foundation checks") {
    throw new Error("both execution paths must retain the Public foundation checks name");
  }
  const planSteps = jobs.plan.steps ?? [];
  const plan = planSteps.find((step) => step.id === "check-plan");
  if (!plan || !/node tooling\/check-affected\.mjs[\s\S]*--format github/.test(plan.run ?? "") ||
      !/github\.event\.pull_request\.base\.sha/.test(plan.env?.BASE_SHA ?? "") ||
      !/github\.event\.before/.test(plan.env?.BASE_SHA ?? "") ||
      !/github\.event\.pull_request\.head\.sha/.test(plan.env?.HEAD_SHA ?? "")) {
    throw new Error("workflow must calculate an affected check plan from explicit event base/head SHAs");
  }
  if (jobs.verify_pr.needs !== "plan" || jobs.verify_pr.if !== "github.event_name == 'pull_request'") {
    throw new Error("hosted checks must run only for pull requests");
  }
  if (jobs.verify_trusted.needs !== "plan" ||
      jobs.verify_trusted.if !== "github.event_name == 'workflow_dispatch' || (github.event_name == 'push' && github.ref == 'refs/heads/main')") {
    throw new Error("self-hosted checks must exclude pull requests");
  }
  for (const jobName of ["verify_pr", "verify_trusted"]) {
    const steps = jobs[jobName].steps ?? [];
    const chromium = steps.find((step) => step.name === "Install pinned Chromium");
    const affected = steps.find((step) => step.name === "Run affected public checks");
    if (chromium?.if !== "needs.plan.outputs.browser == 'true'") {
      throw new Error("workflow must install Chromium only when the affected plan selects browser checks");
    }
    if (!affected || !/^pnpm check:affected --execute-plan$/.test(affected.run ?? "") ||
        affected.env?.VSK_CHECK_PLAN_B64 !== "${{ needs.plan.outputs.check_plan }}" ||
        Object.keys(affected.env ?? {}).length !== 1) {
      throw new Error("workflow must execute the exact affected check plan");
    }
  }
  const trustedSteps = jobs.verify_trusted.steps ?? [];
  const guard = trustedSteps[0];
  const temporary = trustedSteps[1];
  const checkoutIndex = trustedSteps.findIndex((step) => step.uses?.startsWith("actions/checkout@"));
  if (!guard?.run || !/hostname/.test(guard.run) || !/vsk-node-01\|vsk-node-06/.test(guard.run) ||
      checkoutIndex !== 2) {
    throw new Error("self-hosted checks must verify the allowed hostname before repository checkout");
  }
  if (temporary?.name !== "Prepare protected local test storage" ||
      !/TMPDIR="\$\(mktemp -d -p \/var\/tmp vsk\.XXXXXX\)"/.test(temporary.run ?? "") ||
      !/umask 077/.test(temporary.run ?? "") ||
      !/trap cleanup_unexported_temp EXIT/.test(temporary.run ?? "") ||
      !/trap - EXIT/.test(temporary.run ?? "") ||
      !/stat -c '%a:%u'/.test(temporary.run ?? "") ||
      !/stat -f -c '%T'/.test(temporary.run ?? "") ||
      !/ext2\/ext3\|xfs\|btrfs\|f2fs\|zfs/.test(temporary.run ?? "") ||
      !/printf 'TMPDIR=%s\\n' "\$TMPDIR" >> "\$GITHUB_ENV"/.test(temporary.run ?? "")) {
    throw new Error("self-hosted checks must use protected temporary storage on an approved local filesystem");
  }
  const cleanup = trustedSteps.find((step) => step?.name === "Remove protected local test storage");
  if (cleanup?.if !== "always()" ||
      !/\/var\/tmp\/vsk\.\?\?\?\?\?\?/.test(cleanup.run ?? "") ||
      !/rm -rf -- "\$TMPDIR"/.test(cleanup.run ?? "")) {
    throw new Error("self-hosted checks must safely remove protected temporary storage");
  }
  for (const output of ["base_sha", "browser", "check_plan", "fail_closed", "head_sha", "mode"]) {
    if (jobs.plan.outputs?.[output] !== `\${{ steps.check-plan.outputs.${output} }}`) {
      throw new Error(`planning job must expose ${output}`);
    }
  }
  if (/run:\s*pnpm check\s*$/m.test(source)) {
    throw new Error("workflow must not repeat the complete local check lane");
  }

  return { actions: actionCount, jobs: Object.keys(jobs).length };
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
