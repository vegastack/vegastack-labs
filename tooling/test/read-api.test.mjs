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

test("the read API verifier accepts source health and browser session endpoints", async () => {
  const result = await verifyReadAPI();
  assert.ok(!result.codes.includes("READ_API_ENDPOINT_DRIFT"), JSON.stringify(result));
});

test("the reviewed #104 gate routes add only their exact registry IDs", async (t) => {
  const registry = JSON.parse(await readFile(path.join(process.cwd(), "schemas/v1/endpoint-registry.json"), "utf8"));
  assert.equal((await verifyReadAPI()).status, "pass");
  for (const id of ["api.v1.gate-evidence.create", "api.v1.gate-profile-drafts.create", "api.v1.gates.check", "api.v1.gates.get", "api.v1.gates.list"]) {
    const copy = structuredClone(registry);
    copy.endpoints = copy.endpoints.filter((endpoint) => endpoint.id !== id);
    const root = await fixtureRepo(t, {"schemas/v1/endpoint-registry.json": `${JSON.stringify(copy)}\n`});
    assert.ok((await verifyReadAPI(root)).codes.includes("READ_API_ENDPOINT_DRIFT"), id);
  }
  const extra = structuredClone(registry);
  const added = structuredClone(extra.endpoints.find((endpoint) => endpoint.id === "api.v1.gates.get"));
  added.id = "api.v1.gates.pass";
  extra.endpoints.push(added);
  const root = await fixtureRepo(t, {"schemas/v1/endpoint-registry.json": `${JSON.stringify(extra)}\n`});
  assert.ok((await verifyReadAPI(root)).codes.includes("READ_API_ENDPOINT_DRIFT"), "direct gate pass route");
});

test("the reviewed #124 credential wave allows only the local import route", async (t) => {
  const registry = JSON.parse(await readFile(path.join(process.cwd(), "schemas/v1/endpoint-registry.json"), "utf8"));
  const missing = structuredClone(registry);
  missing.endpoints = missing.endpoints.filter((endpoint) => endpoint.id !== "api.v1.credential-references.import-stream");
  let root = await fixtureRepo(t, {"schemas/v1/endpoint-registry.json": `${JSON.stringify(missing)}\n`});
  assert.ok((await verifyReadAPI(root)).codes.includes("READ_API_ENDPOINT_DRIFT"), "missing local import");

  for (const id of ["api.v1.credential-references.activate", "api.v1.credential-references.get"]) {
    const extra = structuredClone(registry);
    const added = structuredClone(extra.endpoints.find((endpoint) => endpoint.id === "api.v1.credential-references.import-stream"));
    added.id = id;
    extra.endpoints.push(added);
    root = await fixtureRepo(t, {"schemas/v1/endpoint-registry.json": `${JSON.stringify(extra)}\n`});
    assert.ok((await verifyReadAPI(root)).codes.includes("READ_API_ENDPOINT_DRIFT"), id);
  }
});

test("the reviewed #107 audit routes add only their exact registry IDs", async (t) => {
  const registry = JSON.parse(await readFile(path.join(process.cwd(), "schemas/v1/endpoint-registry.json"), "utf8"));
  for (const id of ["api.v1.audit-checkpoints.create", "api.v1.audit-checkpoints.list", "api.v1.audit-history.verification"]) {
    const copy = structuredClone(registry);
    copy.endpoints = copy.endpoints.filter((endpoint) => endpoint.id !== id);
    const root = await fixtureRepo(t, {"schemas/v1/endpoint-registry.json": `${JSON.stringify(copy)}\n`});
    assert.ok((await verifyReadAPI(root)).codes.includes("READ_API_ENDPOINT_DRIFT"), id);
  }
  const extra = structuredClone(registry);
  const added = structuredClone(extra.endpoints.find((endpoint) => endpoint.id === "api.v1.audit-history.verification"));
  added.id = "api.v1.audit-history.rewrite";
  extra.endpoints.push(added);
  const root = await fixtureRepo(t, {"schemas/v1/endpoint-registry.json": `${JSON.stringify(extra)}\n`});
  assert.ok((await verifyReadAPI(root)).codes.includes("READ_API_ENDPOINT_DRIFT"), "audit rewrite route");
});

test("the reviewed #117 backup routes add only status, run, and verify", async (t) => {
  const registry = JSON.parse(await readFile(path.join(process.cwd(), "schemas/v1/endpoint-registry.json"), "utf8"));
  for (const id of ["api.v1.backups.run", "api.v1.backups.status", "api.v1.backups.verify"]) {
    const missing = structuredClone(registry);
    missing.endpoints = missing.endpoints.filter((endpoint) => endpoint.id !== id);
    const root = await fixtureRepo(t, {"schemas/v1/endpoint-registry.json": `${JSON.stringify(missing)}\n`});
    assert.ok((await verifyReadAPI(root)).codes.includes("READ_API_ENDPOINT_DRIFT"), id);
  }
  const extra = structuredClone(registry);
  const added = structuredClone(extra.endpoints.find((endpoint) => endpoint.id === "api.v1.backups.verify"));
  added.id = "api.v1.backups.delete";
  extra.endpoints.push(added);
  const root = await fixtureRepo(t, {"schemas/v1/endpoint-registry.json": `${JSON.stringify(extra)}\n`});
  assert.ok((await verifyReadAPI(root)).codes.includes("READ_API_ENDPOINT_DRIFT"), "unreviewed delete route");
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

test("the read API verifier requires every exact executor protocol endpoint", async (t) => {
  const registry = JSON.parse(await readFile(path.join(process.cwd(), "schemas/v1/endpoint-registry.json"), "utf8"));
  for (const id of [
    "api.v1.executor-leases.claim",
    "api.v1.executor-leases.renew",
    "api.v1.execution-receipts.create",
  ]) {
    const copy = structuredClone(registry);
    copy.endpoints = copy.endpoints.filter((endpoint) => endpoint.id !== id);
    const root = await fixtureRepo(t, {
      "schemas/v1/endpoint-registry.json": `${JSON.stringify(copy)}\n`,
    });
    const result = await verifyReadAPI(root);
    assert.ok(result.codes.includes("READ_API_ENDPOINT_DRIFT"), `${id}: ${JSON.stringify(result)}`);
  }
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
