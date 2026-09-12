import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { verifyReadAPI } from "../verify-read-api.mjs";

async function fixtureRepo(t, files) {
  const root = await mkdtemp(path.join(tmpdir(), "vsk-read-api-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await Promise.all(Object.entries(files).map(async ([relative, source]) => {
    const destination = path.join(root, relative);
    await mkdir(path.dirname(destination), { recursive: true });
    await writeFile(destination, source, "utf8");
  }));
  return root;
}

test("the read API verifier accepts reviewed source, session, plan, and run endpoints", async () => {
  const result = await verifyReadAPI();
  assert.ok(!result.codes.includes("READ_API_ENDPOINT_DRIFT"), JSON.stringify(result));
});

test("the read API verifier rejects a registry without the source health endpoint", async (t) => {
  const registry = JSON.parse(await readFile(path.join(process.cwd(), "schemas/v1/endpoint-registry.json"), "utf8"));
  registry.endpoints = registry.endpoints.filter((endpoint) => endpoint.id !== "api.v1.sources.list");
  const root = await fixtureRepo(t, {
    "schemas/v1/endpoint-registry.json": `${JSON.stringify(registry)}\n`,
  });
  const result = await verifyReadAPI(root);
  assert.ok(result.codes.includes("READ_API_ENDPOINT_DRIFT"), JSON.stringify(result));
});

test("the read API verifier rejects a registry without a browser session endpoint", async (t) => {
  const registry = JSON.parse(await readFile(path.join(process.cwd(), "schemas/v1/endpoint-registry.json"), "utf8"));
  registry.endpoints = registry.endpoints.filter((endpoint) => endpoint.id !== "api.v1.session.renew");
  const root = await fixtureRepo(t, {
    "schemas/v1/endpoint-registry.json": `${JSON.stringify(registry)}\n`,
  });
  const result = await verifyReadAPI(root);
  assert.ok(result.codes.includes("READ_API_ENDPOINT_DRIFT"), JSON.stringify(result));
});

test("the read API verifier requires the exact authorized run read endpoint", async (t) => {
  const registry = JSON.parse(await readFile(path.join(process.cwd(), "schemas/v1/endpoint-registry.json"), "utf8"));
  registry.endpoints = registry.endpoints.filter((endpoint) => endpoint.id !== "api.v1.runs.get");
  const root = await fixtureRepo(t, {
    "schemas/v1/endpoint-registry.json": `${JSON.stringify(registry)}\n`,
  });
  const result = await verifyReadAPI(root);
  assert.ok(result.codes.includes("READ_API_ENDPOINT_DRIFT"), JSON.stringify(result));
});

test("the read API verifier rejects query-before-authorization and offset SQL", async (t) => {
  const root = await fixtureRepo(t, {
    "internal/api/handler.go": "package api\nfunc handle(r *http.Request) { _ = r.URL.Query(); AuthorizeRead(r.Context()) }\n",
    "internal/store/read_repository.go": "package store\nconst q = `SELECT id FROM inventory_drafts LIMIT ? OFFSET ?`\n",
  });
  const result = await verifyReadAPI(root);
  assert.deepEqual(result.codes, ["READ_API_AUTH_ORDER", "READ_API_OFFSET_PAGINATION"]);
});

test("the read API verifier rejects browser/remote listeners and SQLite outside store", async (t) => {
  const root = await fixtureRepo(t, {
    "internal/api/handler.go": "package api\nfunc handle() { AuthorizeRead(); Query() }\n",
    "internal/server/remote.go": 'package server\nimport "net/http"\nfunc run(){ http.ListenAndServe(":443", nil) }\n',
    "internal/client/read.go": 'package client\nimport "database/sql"\nvar _ *sql.DB\n',
  });
  const result = await verifyReadAPI(root);
  assert.deepEqual(result.codes, ["READ_API_BROWSER_REMOTE", "READ_API_SQLITE_SCOPE"]);
});
