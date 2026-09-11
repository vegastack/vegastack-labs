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
  delete workflow.jobs.verify.steps.find(({ uses }) => uses?.startsWith("actions/checkout@"))
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
  const steps = workflow.jobs.verify.steps;
  const plan = steps.find(({ id }) => id === "check-plan");
  const chromium = steps.find(({ name }) => name === "Install pinned Chromium");
  const checks = steps.find(({ name }) => name === "Run affected public checks");

  assert.ok(plan);
  assert.match(plan.run, /pnpm check:affected:plan/);
  assert.equal(chromium.if, "steps.check-plan.outputs.browser == 'true'");
  assert.match(checks.run, /pnpm check:affected/);
  assert.doesNotMatch(source, /run:\s*pnpm check\s*$/m);
  assert.doesNotThrow(() => verifyWorkflowDocument(workflow, source));
});

test("the workflow guard rejects unconditional Chromium and a repeated full lane", async () => {
  const source = await readFile(
    new URL("../../.github/workflows/ci.yml", import.meta.url),
    "utf8",
  );
  const unconditional = parseYaml(source);
  delete unconditional.jobs.verify.steps.find(({ name }) => name === "Install pinned Chromium").if;
  assert.throws(
    () => verifyWorkflowDocument(unconditional, source),
    /Chromium only when the affected plan selects browser/,
  );

  const repeated = parseYaml(source);
  repeated.jobs.verify.steps.find(({ name }) => name === "Run affected public checks").run = "pnpm check";
  assert.throws(
    () => verifyWorkflowDocument(repeated, `${source}\n- run: pnpm check\n`),
    /execute the affected check plan|must not repeat the complete local check lane/,
  );
});
