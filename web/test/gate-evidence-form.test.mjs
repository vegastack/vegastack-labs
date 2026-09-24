import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("gate evidence form accepts bounded digests without pass, secret, or free JSON fields", async () => {
  const source = await readFile(new URL("../components/gate-evidence-form.tsx", import.meta.url), "utf8");
  assert.match(source, /artifactDigest/);
  assert.match(source, /valueDigest/);
  assert.match(source, /resultDigest/);
  assert.match(source, /observedAt/);
  assert.doesNotMatch(source, /textarea|secret|password|setPassed|force/i);
});

test("gate evidence success remains an inert draft", async () => {
  const source = await readFile(new URL("../components/gate-evidence-form.tsx", import.meta.url), "utf8");
  assert.match(source, /draftId/);
  assert.match(source, /changeId/);
  assert.match(source, /plan flow/i);
  assert.doesNotMatch(source, /executePlan|humanAcknowledgementId/);
});
