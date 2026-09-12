import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const read = (name) => readFile(path.join(ROOT, name), "utf8");

test("local acknowledgement request and status endpoints are generated", async () => {
  const registry = JSON.parse(await read("schemas/v1/endpoint-registry.json"));
  const endpoint = registry.endpoints.find((item) => item.id === "api.v1.plans.acknowledgements.create");
  assert.deepEqual(endpoint, {
    id: "api.v1.plans.acknowledgements.create",
    method: "POST",
    path: "/api/v1/plans/{planId}/acknowledgements",
    availability: "available",
    ownerPhase: "4",
    requestSchema: "vegastack-labs.dev/acknowledgement-request",
    dataSchema: "vegastack-labs.dev/acknowledgement",
    stream: "finite",
    audiences: ["operator", "server-adapter"],
  });
  const status = registry.endpoints.find((item) => item.id === "api.v1.plans.acknowledgements.get");
  assert.equal(status.method, "GET");
  assert.equal(status.path, endpoint.path);
  assert.equal(status.availability, "available");
  assert.deepEqual(status.audiences, ["operator", "server-adapter"]);
});

test("Slack remains outside provider-neutral acknowledgement and stored contracts", async () => {
  const [types, service, migration, schema] = await Promise.all([
    read("internal/acknowledgement/types.go"),
    read("internal/acknowledgement/service.go"),
    read("internal/store/migrations/0008_acknowledgements.sql"),
    read("schemas/v1/acknowledgement.schema.json"),
  ]);
  for (const source of [types, service, migration, schema]) {
    assert.doesNotMatch(source, /workspace[_-]?id|slack[_-]?user|websocket[_-]?url|app[_-]?token|bot[_-]?token/i);
  }
  assert.doesNotMatch(migration, /raw_payload|plaintext|nonce\s+TEXT/i);
  assert.match(migration, /nonce_digest TEXT NOT NULL UNIQUE/);
  assert.match(migration, /acknowledgement_proofs_no_update/);
});

test("remote admission does not add acknowledgement mutation", async () => {
  const router = await read("internal/api/router.go");
  assert.doesNotMatch(router, /remoteSessionEndpoints[\s\S]{0,300}acknowledgement/);
  assert.match(router, /method != http\.MethodGet && !remoteSessionEndpoints/);
});
