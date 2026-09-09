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
