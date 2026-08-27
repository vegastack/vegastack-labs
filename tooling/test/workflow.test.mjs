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
