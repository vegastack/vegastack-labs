import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { parse as parseYaml } from "yaml";
import { verifyWorkflowDocument } from "../verify-workflow.mjs";

async function fixture() {
  const source = await readFile(new URL("../../.github/workflows/ci.yml", import.meta.url), "utf8");
  return { source, workflow: parseYaml(source) };
}

test("Public CI remains explicitly dispatched after Phase 5", async () => {
  const { source, workflow } = await fixture();
  assert.deepEqual(Object.keys(workflow.on), ["workflow_dispatch"]);
  assert.equal(Object.hasOwn(workflow.on.workflow_dispatch.inputs, "base_sha"), false);
  assert.equal(workflow.on.workflow_dispatch.inputs.full_check.default, false);
  assert.doesNotMatch(source, /^\s*(pull_request|push):/m);
  assert.doesNotThrow(() => verifyWorkflowDocument(workflow, source));
});

test("manual full_check runs the routine plan on branch or main", async () => {
  const { source, workflow } = await fixture();
  const plan = workflow.jobs.plan.steps.find(({ id }) => id === "check-plan");
  assert.match(plan.run, /dispatch must explicitly select routine full_check or a named native acceptance lane/);
  assert.match(plan.run, /native credential acceptance SHA must equal the dispatch head/);
  assert.match(plan.run, /native credential acceptance requires its reviewed branch/);
  assert.equal(plan.env.HEAD_SHA, "${{ github.sha }}");
  assert.doesNotMatch(JSON.stringify(plan), /base_sha|pull_request|github\.event\.before/);

  const trusted = workflow.jobs.verify_trusted.steps;
  assert.equal(trusted.find(({ name }) => name === "Install pinned Chromium").if, "inputs.full_check");
  assert.equal(trusted.find(({ name }) => name === "Run affected public checks").if, "inputs.full_check");
  assert.equal(trusted.find(({ name }) => name === "Install public dependencies").if, "inputs.full_check");
  assert.equal(trusted.some(({ name }) => name === "Run exact Phase 5 exit acceptance"), false);
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
  assert.throws(() => verifyWorkflowDocument(second.workflow, second.source), /routine affected lane/);

  const secret = await fixture();
  assert.throws(
    () => verifyWorkflowDocument(secret.workflow, `${secret.source}\ntoken: \${{ secrets.CI_TOKEN }}\n`),
    /must not reference secrets/,
  );
});

test("the trusted manual runner stays bounded and checks its host before checkout", async () => {
  const { source, workflow } = await fixture();
  const job = workflow.jobs.verify_trusted;
  assert.deepEqual(job["runs-on"], ["self-hosted", "linux", "x64", "vsk-runner"]);
  assert.equal(job["timeout-minutes"], 25);
  assert.match(job.steps[0].run, /vsk-node-01\|vsk-node-06/);
  assert.equal(job.steps[1].name, "Prepare protected local test storage");
  assert.equal(job.steps[2].name, "Check out repository");
  assert.doesNotThrow(() => verifyWorkflowDocument(workflow, source));

  job.steps[0].run = "true";
  assert.throws(() => verifyWorkflowDocument(workflow, source), /hostname/);
});

test("ordinary CI accepts the documented active pool while native checks retain their narrow host boundary", async () => {
  const { workflow } = await fixture();
  const script = workflow.jobs.verify_trusted.steps[0].run;
  for (const [host, full, native, backup, allowed] of [
    ["vsk-node-01", "true", "", "false", true],
    ["vsk-node-05", "true", "", "false", false],
    ["vsk-node-06", "true", "", "false", true],
    ["vsk-node-07", "true", "", "false", true],
    ["vsk-node-08", "true", "", "false", true],
    ["vsk-node-04", "true", "", "false", false],
    ["vsk-node-09", "true", "", "false", false],
    ["unknown", "true", "", "false", false],
    ["vsk-node-08", "false", "a".repeat(40), "false", false],
    ["vsk-node-08", "true", "", "true", false],
    ["vsk-node-08", "true", "a".repeat(40), "false", false],
    ["vsk-node-06", "false", "", "true", true],
    ["vsk-node-01", "false", "a".repeat(40), "false", true],
  ]) {
    const result = spawnSync("bash", ["-c", 'hostname() { printf "%s\\n" "$TEST_HOST"; };\n' + script], {
      encoding: "utf8",
      env: { ...process.env, TEST_HOST: host, FULL_CHECK: full, NATIVE_CREDENTIAL_SHA: native, BACKUP_ACCEPTANCE: backup },
    });
    assert.equal(result.status === 0, allowed, `${host}: full=${full}, native=${native}, backup=${backup}: ${result.stderr}`);
  }
});

test("the workflow verifier rejects a native-input bypass of the hostname boundary", async () => {
  const { source, workflow } = await fixture();
  workflow.jobs.verify_trusted.steps[0].env.NATIVE_CREDENTIAL_SHA = "";
  assert.throws(() => verifyWorkflowDocument(workflow, source), /hostname guard/);
});


test("shared-pool scheduling is blocked before any protected host can receive work", async () => {
  const { source, workflow } = await fixture();
  assert.equal(workflow.jobs.verify_trusted.if, "${{ false }}");
  for (const unsafe of [undefined, true, "${{ true }}", "inputs.full_check"]) {
    workflow.jobs.verify_trusted.if = unsafe;
    assert.throws(() => verifyWorkflowDocument(workflow, source), /protected nodes/);
  }
});
