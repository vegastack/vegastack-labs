import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { parse as parseYaml } from "yaml";
import { verifyWorkflowDocument } from "../verify-workflow.mjs";

async function fixture() {
  const source = await readFile(new URL("../../.github/workflows/ci.yml", import.meta.url), "utf8");
  return { source, workflow: parseYaml(source) };
}

test("Public CI is dispatch-only during the Phase 5 batch", async () => {
  const { source, workflow } = await fixture();
  assert.deepEqual(Object.keys(workflow.on), ["workflow_dispatch"]);
  assert.equal(Object.hasOwn(workflow.on.workflow_dispatch.inputs, "base_sha"), false);
  assert.equal(workflow.on.workflow_dispatch.inputs.full_check.default, false);
  assert.doesNotMatch(source, /^\s*(pull_request|push):/m);
  assert.doesNotThrow(() => verifyWorkflowDocument(workflow, source));
});

test("manual CI routes full_check exclusively by main versus non-main", async () => {
  const { source, workflow } = await fixture();
  const plan = workflow.jobs.plan.steps.find(({ id }) => id === "check-plan");
  assert.match(plan.run, /dispatch must explicitly select final full_check or a named native acceptance lane/);
  assert.match(plan.run, /native credential acceptance SHA must equal the dispatch head/);
  assert.match(plan.run, /native credential acceptance requires its reviewed branch/);
  assert.equal(plan.env.HEAD_SHA, "${{ github.sha }}");
  assert.doesNotMatch(JSON.stringify(plan), /base_sha|pull_request|github\.event\.before/);

  const trusted = workflow.jobs.verify_trusted.steps;
  assert.equal(trusted.find(({ name }) => name === "Install pinned Chromium").if, "inputs.full_check");
  assert.equal(trusted.find(({ name }) => name === "Run affected public checks").if,
    "inputs.full_check && github.ref != 'refs/heads/main'");
  assert.equal(trusted.find(({ name }) => name === "Install public dependencies").if, "inputs.full_check");
  const phase5 = trusted.find(({ name }) => name === "Run exact Phase 5 exit acceptance");
  assert.equal(phase5.if,
    "inputs.full_check && github.ref == 'refs/heads/main'");
  assert.equal(phase5.run, "pnpm --silent check:phase-5-exit --commit \"$GITHUB_SHA\"");
  assert.equal(trusted.some(({ name }) => name === "Verify generated contracts and embedded Console stay unchanged"), false);
  assert.equal(trusted.some(({ name }) => name === "Run exact Phase 4 exit acceptance"), false);
  assert.match(trusted.find(({ name }) => name === "Run pinned local-backup acceptance").if,
    /inputs\.backup_acceptance/);
  assert.match(trusted.find(({ name }) => name === "Run exact #143 disposable native credential acceptance").if,
    /inputs\.native_credential_sha/);
  assert.doesNotThrow(() => verifyWorkflowDocument(workflow, source));
});

test("the guard rejects an automatic trigger or broad non-final execution", async () => {
  const { source, workflow } = await fixture();
  workflow.on.pull_request = {};
  assert.throws(() => verifyWorkflowDocument(workflow, source), /manual-only/);

  const second = await fixture();
  second.workflow.jobs.verify_trusted.steps.find(({ name }) => name === "Run affected public checks").if = undefined;
  assert.throws(() => verifyWorkflowDocument(second.workflow, second.source), /branch affected lane or the main Phase 5 exit lane/);

  const secret = await fixture();
  assert.throws(
    () => verifyWorkflowDocument(secret.workflow, `${secret.source}\ntoken: \${{ secrets.CI_TOKEN }}\n`),
    /must not reference secrets/,
  );
});

test("the trusted manual runner stays bounded and checks its host before checkout", async () => {
  const { source, workflow } = await fixture();
  const job = workflow.jobs.verify_trusted;
  assert.deepEqual(job["runs-on"], ["self-hosted", "linux", "x64"]);
  assert.equal(job["timeout-minutes"], 15);
  assert.match(job.steps[0].run, /vsk-node-01\|vsk-node-06/);
  assert.equal(job.steps[1].name, "Prepare protected local test storage");
  assert.equal(job.steps[2].name, "Check out repository");
  assert.doesNotThrow(() => verifyWorkflowDocument(workflow, source));

  job.steps[0].run = "true";
  assert.throws(() => verifyWorkflowDocument(workflow, source), /hostname/);
});
