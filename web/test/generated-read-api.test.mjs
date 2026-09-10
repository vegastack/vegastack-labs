import assert from "node:assert/strict";
import test from "node:test";

import { createReadClient, ReadClientError, STABLE_ERROR_CODES } from "../generated/read-api.ts";

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

function envelope(data, schemaVersion = "1.0.0") {
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
    (error) => error instanceof ReadClientError && error.kind === "schema-mismatch" &&
      error.code === "INTEGRITY_FAILURE" && STABLE_ERROR_CODES.includes(error.code),
  );
});

test("generated decoder rejects another contract major", async () => {
  const client = createReadClient(async () => new Response(JSON.stringify(envelope(summary, "2.0.0"))));
  await assert.rejects(
    () => client.getSummary(),
    (error) => error instanceof ReadClientError && error.kind === "unsupported-version" &&
      error.code === "SCHEMA_UNSUPPORTED" && STABLE_ERROR_CODES.includes(error.code),
  );
});

test("finite reads use only generated same-origin GET paths and encoded queries", async () => {
  let seen;
  const client = createReadClient(async (url, init) => {
    seen = { url, init };
    return new Response(JSON.stringify(envelope(summary)));
  });
  const result = await client.getSummary();
  assert.deepEqual(result.data, summary);
  assert.equal(seen.url, "/api/v1/summary");
  assert.equal(seen.init.method, "GET");
  assert.equal(seen.init.cache, "no-store");
  assert.equal(seen.init.credentials, "same-origin");

  const listClient = createReadClient(async (url, init) => {
    seen = { url, init };
    return new Response(JSON.stringify(envelope({ items: [], nextCursor: null, stateRevision: 8, recoveryEpoch: 2 })));
  });
  await listClient.listInventoryDrafts({ limit: 25, sort: "created-at", cursor: "opaque/value" });
  assert.equal(seen.url, "/api/v1/inventory-drafts?limit=25&sort=created-at&cursor=opaque%2Fvalue");
  assert.equal(seen.init.method, "GET");
});

test("path values are encoded inside a generated route", async () => {
  let seen;
  const client = createReadClient(async (url) => {
    seen = url;
    return new Response(JSON.stringify(envelope({
      authority: "draft",
      draftId: "draft/one",
      revision: 2,
      validationStatus: "valid",
      contentDigest: "sha256:" + "a".repeat(64),
      createdAt: "2026-09-10T08:00:00Z",
      counts: { assets: 0, nodes: 0, aliases: 0, addresses: 0, observations: 0, hardwareFacts: 0, provenance: 0, findings: 0 },
    })));
  });
  await client.getInventoryDraft({ draftId: "draft/one", revision: 2 });
  assert.equal(seen, "/api/v1/inventory-drafts/draft%2Fone/revisions/2");
});

test("stable API failures preserve code, target, retryability, and correlation", async () => {
  const failed = envelope({});
  failed.status = "failed";
  failed.errors = [{ code: "AUTHORIZATION_DENIED", target: "read", retryable: false }];
  const denied = createReadClient(async () => new Response(JSON.stringify(failed), { status: 403 }));
  await assert.rejects(
    () => denied.getSummary(),
    (error) => error instanceof ReadClientError && error.kind === "api" &&
      error.code === "AUTHORIZATION_DENIED" && error.target === "read" &&
      error.retryable === false && error.correlationId === "request-1" && STABLE_ERROR_CODES.includes(error.code),
  );

  failed.errors = [{ code: "DEPENDENCY_UNAVAILABLE", target: "source", retryable: true }];
  const unavailable = createReadClient(async () => new Response(JSON.stringify(failed), { status: 503 }));
  await assert.rejects(
    () => unavailable.getSummary(),
    (error) => error.kind === "api" && error.code === "DEPENDENCY_UNAVAILABLE" && error.retryable === true,
  );
});

test("malformed JSON, expired cursors, cancellation, and network loss stay distinct", async () => {
  const malformed = createReadClient(async () => new Response("{"));
  await assert.rejects(() => malformed.getSummary(), (error) => error.kind === "malformed-json" &&
    error.code === "INTEGRITY_FAILURE" && STABLE_ERROR_CODES.includes(error.code));

  const expiredEnvelope = envelope({});
  expiredEnvelope.status = "failed";
  expiredEnvelope.errors = [{ code: "STATE_CONFLICT", target: "cursor", retryable: false }];
  const expired = createReadClient(async () => new Response(JSON.stringify(expiredEnvelope), { status: 409 }));
  await assert.rejects(() => expired.listInventoryDrafts({ cursor: "expired" }), (error) => error.kind === "api" && error.code === "STATE_CONFLICT" && error.target === "cursor");

  const controller = new AbortController();
  controller.abort();
  const cancelled = createReadClient(async (_url, init) => {
    throw init.signal.reason;
  });
  await assert.rejects(() => cancelled.getSummary({ signal: controller.signal }), (error) => error.kind === "cancelled" &&
    error.code === "INTERRUPTED" && STABLE_ERROR_CODES.includes(error.code));

  const offline = createReadClient(async () => { throw new TypeError("offline detail"); });
  await assert.rejects(() => offline.getSummary(), (error) => error.kind === "network" &&
    error.code === "DEPENDENCY_UNAVAILABLE" && STABLE_ERROR_CODES.includes(error.code) && !error.message.includes("offline detail"));

  const lostBody = createReadClient(async () => new Response(new ReadableStream({
    start(controller) { controller.error(new TypeError("socket detail")); },
  })));
  await assert.rejects(() => lostBody.getSummary(), (error) => error.kind === "network" && !error.message.includes("socket detail"));
});

function auditEvent(eventId = 42) {
  return {
    event: {
      schema: "vegastack-labs.dev/audit-event",
      schemaVersion: "1.0.0",
      eventId,
      occurredAt: "2026-09-10T08:00:00Z",
      recoveryEpoch: 2,
      stateRevision: 8,
      type: "inventory.draft-created",
      correlationId: "request-1",
      causationEventId: null,
      correctionOfEventId: null,
      principalId: "person-1",
      principalMethod: "local-peer",
      responsibleHumanPrincipalId: "person-1",
      agentName: null,
      agentSessionId: null,
      agentSource: null,
      target: { kind: "inventory-draft", id: "draft-1" },
      beforeFingerprint: null,
      afterFingerprint: null,
    },
  };
}

function chunkedResponse(chunks, status = 200, headers = { "content-type": "text/event-stream" }) {
  const encoder = new TextEncoder();
  return new Response(new ReadableStream({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(encoder.encode(chunk));
      controller.close();
    },
  }), { status, headers });
}

test("event streaming parses split frames and sends an explicit resume header", async () => {
  let seen;
  const payload = JSON.stringify(auditEvent());
  const client = createReadClient(async (url, init) => {
    seen = { url, init };
    return chunkedResponse(["id: 42\nevent: audit-", "event\ndata: " + payload.slice(0, 23), payload.slice(23) + "\n\n"]);
  });
  const iterator = client.streamEvents({ lastEventId: "41" })[Symbol.asyncIterator]();
  const next = await iterator.next();
  assert.equal(seen.url, "/api/v1/events");
  assert.equal(seen.init.method, "GET");
  assert.equal(seen.init.headers["Last-Event-ID"], "41");
  assert.equal(next.value.event.eventId, 42);
});

test("event streaming distinguishes denied, malformed, cancelled, and lost streams", async () => {
  const deniedEnvelope = envelope({});
  deniedEnvelope.status = "failed";
  deniedEnvelope.errors = [{ code: "AUTHORIZATION_DENIED", target: "read", retryable: false }];
  const denied = createReadClient(async () => new Response(JSON.stringify(deniedEnvelope), { status: 403 }));
  await assert.rejects(() => denied.streamEvents()[Symbol.asyncIterator]().next(), (error) => error.kind === "api" && error.code === "AUTHORIZATION_DENIED");

  const malformed = createReadClient(async () => chunkedResponse(["id: 42\nevent: audit-event\ndata: {\n\n"]));
  await assert.rejects(() => malformed.streamEvents()[Symbol.asyncIterator]().next(), (error) => error.kind === "malformed-json");

  const controller = new AbortController();
  controller.abort();
  const cancelled = createReadClient(async () => chunkedResponse([]));
  await assert.rejects(() => cancelled.streamEvents({ signal: controller.signal })[Symbol.asyncIterator]().next(), (error) => error.kind === "cancelled");

  const activeController = new AbortController();
  const active = createReadClient(async () => new Response(new ReadableStream({}), { headers: { "content-type": "text/event-stream" } }));
  const pending = active.streamEvents({ signal: activeController.signal })[Symbol.asyncIterator]().next();
  activeController.abort();
  await assert.rejects(() => pending, (error) => error.kind === "cancelled");

  const lost = createReadClient(async () => chunkedResponse([]));
  await assert.rejects(() => lost.streamEvents()[Symbol.asyncIterator]().next(), (error) => error.kind === "network");
});

test("event streaming rejects mismatched IDs and never reconnects", async () => {
  let calls = 0;
  const client = createReadClient(async () => {
    calls += 1;
    return chunkedResponse(["id: 43\nevent: audit-event\ndata: " + JSON.stringify(auditEvent(42)) + "\n\n"]);
  });
  await assert.rejects(() => client.streamEvents()[Symbol.asyncIterator]().next(), (error) => error.kind === "schema-mismatch");
  assert.equal(calls, 1);
});
