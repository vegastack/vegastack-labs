import assert from "node:assert/strict";
import test from "node:test";

import { createReadClient, ReadClientError } from "../generated/read-api.ts";

const summary = {
  databaseMode: "ready",
  readAvailable: true,
  mutationAvailable: false,
  draftCount: 1,
  validDraftCount: 1,
  blockedDraftCount: 0,
  lastEventId: 4,
  recoveryEpoch: 2,
  stateRevision: 8,
};

function envelope(data, schemaVersion = "1.7.0") {
  return {
    schema: "vegastack-labs.dev/run-result",
    schemaVersion,
    toolVersion: "test",
    command: "api.v1.summary.get",
    requestId: "request-1",
    runId: null,
    status: "succeeded",
    changed: false,
    recoveryEpoch: 2,
    stateRevision: 8,
    snapshotDigest: null,
    releaseBuildId: "test",
    sourceRevision: null,
    planId: null,
    errors: [],
    data,
  };
}

test("generated decoder rejects closed-object additions", async () => {
  const client = createReadClient(async () => new Response(JSON.stringify(envelope({ ...summary, unexpected: true }))));
  await assert.rejects(
    () => client.getSummary(),
    (error) => error instanceof ReadClientError && error.kind === "schema-mismatch",
  );
});

test("generated decoder rejects another contract major", async () => {
  const client = createReadClient(async () => new Response(JSON.stringify(envelope(summary, "2.0.0"))));
  await assert.rejects(
    () => client.getSummary(),
    (error) => error instanceof ReadClientError && error.kind === "unsupported-version",
  );
});
