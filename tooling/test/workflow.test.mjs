import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { parse as parseYaml } from "yaml";
import { verifyWorkflowDocument } from "../verify-workflow.mjs";

test("an overprivileged workflow with mutable Actions fails closed", async () => {
  const source = await readFile(
    new URL("../testdata/unsafe-workflow.yaml", import.meta.url),
    "utf8",
  );
  assert.throws(() => verifyWorkflowDocument(parseYaml(source), source), /permissions/);
});

test("the public workflow retains the commit history required by Phase 2 evidence", async () => {
  const source = await readFile(
    new URL("../../.github/workflows/ci.yml", import.meta.url),
    "utf8",
  );
  const workflow = parseYaml(source);
  assert.doesNotThrow(() => verifyWorkflowDocument(workflow, source));
  delete workflow.jobs.verify_pr.steps.find(({ uses }) => uses?.startsWith("actions/checkout@"))
    .with["fetch-depth"];
  assert.throws(
    () => verifyWorkflowDocument(workflow, source),
    /retain complete commit history/,
  );
});

test("CI uses affected checks and installs Chromium only when selected", async () => {
  const source = await readFile(
    new URL("../../.github/workflows/ci.yml", import.meta.url),
    "utf8",
  );
  const workflow = parseYaml(source);
  const planSteps = workflow.jobs.plan.steps;
  const hostedSteps = workflow.jobs.verify_pr.steps;
  const trustedSteps = workflow.jobs.verify_trusted.steps;
  const plan = planSteps.find(({ id }) => id === "check-plan");
  const hostedChromium = hostedSteps.find(({ name }) => name === "Install pinned Chromium");
  const trustedChromium = trustedSteps.find(({ name }) => name === "Install pinned Chromium");
  const hostedChecks = hostedSteps.find(({ name }) => name === "Run affected public checks");
  const trustedChecks = trustedSteps.find(({ name }) => name === "Run affected public checks");

  assert.ok(plan);
  assert.match(plan.run, /node tooling\/check-affected\.mjs[\s\S]*--format github/);
  assert.equal(workflow.jobs.plan["runs-on"], "ubuntu-24.04");
  assert.equal(workflow.jobs.verify_pr["runs-on"], "ubuntu-24.04");
  assert.deepEqual(workflow.jobs.verify_trusted["runs-on"], ["self-hosted", "linux", "x64"]);
  assert.equal(workflow.jobs.verify_pr.if, "github.event_name == 'pull_request'");
  assert.equal(
    workflow.jobs.verify_trusted.if,
    "github.event_name == 'workflow_dispatch' || (github.event_name == 'push' && github.ref == 'refs/heads/main')",
  );
  assert.equal(hostedChromium.if, "needs.plan.outputs.browser == 'true'");
  assert.equal(trustedChromium.if, "needs.plan.outputs.browser == 'true'");
  assert.equal(hostedChecks.run, "pnpm check:affected --execute-plan");
  assert.equal(trustedChecks.run, "pnpm check:affected --execute-plan");
  assert.equal(hostedChecks.env.VSK_CHECK_PLAN_B64, "${{ needs.plan.outputs.check_plan }}");
  assert.equal(trustedChecks.env.VSK_CHECK_PLAN_B64, "${{ needs.plan.outputs.check_plan }}");
  assert.match(trustedSteps[0].run, /vsk-node-01\|vsk-node-06/);
  assert.equal(workflow.jobs.verify_trusted.env.TMPDIR, "${{ runner.temp }}/vsk-labs-${{ github.run_id }}-${{ github.run_attempt }}");
  assert.equal(trustedSteps[1].name, "Prepare protected local test storage");
  assert.match(trustedSteps[1].run, /install -d -m 700/);
  assert.match(trustedSteps[1].run, /ext2\/ext3\|xfs\|btrfs\|f2fs\|zfs/);
  assert.equal(trustedSteps[2].name, "Check out repository");
  assert.doesNotMatch(source, /run:\s*pnpm check\s*$/m);
  assert.doesNotThrow(() => verifyWorkflowDocument(workflow, source));
});

test("the workflow guard rejects unconditional Chromium and a repeated full lane", async () => {
  const source = await readFile(
    new URL("../../.github/workflows/ci.yml", import.meta.url),
    "utf8",
  );
  const unconditional = parseYaml(source);
  delete unconditional.jobs.verify_pr.steps.find(({ name }) => name === "Install pinned Chromium").if;
  assert.throws(
    () => verifyWorkflowDocument(unconditional, source),
    /Chromium only when the affected plan selects browser/,
  );

  const repeated = parseYaml(source);
  repeated.jobs.verify_pr.steps.find(({ name }) => name === "Run affected public checks").run = "pnpm check";
  assert.throws(
    () => verifyWorkflowDocument(repeated, `${source}\n- run: pnpm check\n`),
    /execute the exact affected check plan|must not repeat the complete local check lane/,
  );

  const literalSeparator = parseYaml(source);
  literalSeparator.jobs.verify_pr.steps.find(
    ({ name }) => name === "Run affected public checks",
  ).run = "pnpm check:affected -- --execute-plan";
  assert.throws(
    () => verifyWorkflowDocument(literalSeparator, source),
    /execute the exact affected check plan/,
  );
});

test("the workflow guard keeps pull requests off disposable machines and checks hostname before checkout", async () => {
  const source = await readFile(
    new URL("../../.github/workflows/ci.yml", import.meta.url),
    "utf8",
  );
  const unsafeEvent = parseYaml(source);
  unsafeEvent.jobs.verify_trusted.if = "github.event_name == 'pull_request'";
  assert.throws(
    () => verifyWorkflowDocument(unsafeEvent, source),
    /self-hosted checks must exclude pull requests/,
  );

  const lateGuard = parseYaml(source);
  const steps = lateGuard.jobs.verify_trusted.steps;
  [steps[0], steps[1]] = [steps[1], steps[0]];
  assert.throws(
    () => verifyWorkflowDocument(lateGuard, source),
    /hostname before repository checkout/,
  );

  const unsafeTemporary = parseYaml(source);
  unsafeTemporary.jobs.verify_trusted.env.TMPDIR = "/tmp";
  assert.throws(
    () => verifyWorkflowDocument(unsafeTemporary, source),
    /protected temporary storage/,
  );

  for (const trigger of ["schedule", "repository_dispatch", "pull_request_target"]) {
    const extraTrigger = parseYaml(source);
    extraTrigger.on[trigger] = trigger === "schedule" ? [{ cron: "0 0 * * *" }] : {};
    assert.throws(
      () => verifyWorkflowDocument(extraTrigger, source),
      /unsupported workflow trigger/,
      trigger,
    );
  }
});
