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

test("the reviewed backup routes remain exact", async (t) => {
  const registry = JSON.parse(await readFile(path.join(process.cwd(), "schemas/v1/endpoint-registry.json"), "utf8"));
  for (const id of ["api.v1.backup-jobs.create", "api.v1.backup-verifications.create", "api.v1.backups.status"]) {
    const missing = structuredClone(registry);
    missing.endpoints = missing.endpoints.filter((endpoint) => endpoint.id !== id);
    const root = await fixtureRepo(t, {"schemas/v1/endpoint-registry.json": `${JSON.stringify(missing)}\n`});
    assert.ok((await verifyReadAPI(root)).codes.includes("READ_API_ENDPOINT_DRIFT"), id);
  }
  const extra = structuredClone(registry);
  const added = structuredClone(extra.endpoints.find((endpoint) => endpoint.id === "api.v1.backups.status"));
  added.id = "api.v1.backups.delete";
  extra.endpoints.push(added);
  const root = await fixtureRepo(t, {"schemas/v1/endpoint-registry.json": `${JSON.stringify(extra)}\n`});
  assert.ok((await verifyReadAPI(root)).codes.includes("READ_API_ENDPOINT_DRIFT"), "unreviewed delete route");
});

test("the reviewed #110 operator routes remain exact", async (t) => {
  const registry = JSON.parse(await readFile(path.join(process.cwd(), "schemas/v1/endpoint-registry.json"), "utf8"));
  for (const id of ["api.v1.database-exports.create", "api.v1.recovery-points.list", "api.v1.restores.run", "api.v1.scheduled-jobs.list"]) {
    const missing = structuredClone(registry);
    missing.endpoints = missing.endpoints.filter((endpoint) => endpoint.id !== id);
    const root = await fixtureRepo(t, {"schemas/v1/endpoint-registry.json": `${JSON.stringify(missing)}\n`});
    assert.ok((await verifyReadAPI(root)).codes.includes("READ_API_ENDPOINT_DRIFT"), id);
  }
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

test("the reviewed discovery routes remain exact", async (t) => {
  const registry = JSON.parse(await readFile(path.join(process.cwd(), "schemas/v1/endpoint-registry.json"), "utf8"));
  for (const id of ["api.v1.host-discovery-targets.draft", "api.v1.host-observations.create", "api.v1.host-observations.get"]) {
    const copy = structuredClone(registry);
    copy.endpoints = copy.endpoints.filter((endpoint) => endpoint.id !== id);
    const root = await fixtureRepo(t, {"schemas/v1/endpoint-registry.json": JSON.stringify(copy)});
    assert.ok((await verifyReadAPI(root)).codes.includes("READ_API_ENDPOINT_DRIFT"), id);
  }
  const extra = structuredClone(registry);
  const added = structuredClone(extra.endpoints.find((endpoint) => endpoint.id === "api.v1.host-observations.get"));
  added.id = "api.v1.host-observations.admit";
  extra.endpoints.push(added);
  const root = await fixtureRepo(t, {"schemas/v1/endpoint-registry.json": JSON.stringify(extra)});
  assert.ok((await verifyReadAPI(root)).codes.includes("READ_API_ENDPOINT_DRIFT"));
});

test("the reviewed #222 registration routes remain closed and exact", async (t) => {
  const registry = JSON.parse(await readFile(path.join(process.cwd(), "schemas/v1/endpoint-registry.json"), "utf8"));
  assert.equal((await verifyReadAPI()).status, "pass");
  for (const id of ["api.v1.host-adoptions.draft", "api.v1.hosts.get", "api.v1.hosts.list"]) {
    for (const mutation of ["remove", "method", "path", "dataSchema", "audiences", "extra"]) {
      const copy = structuredClone(registry);
      const endpoint = copy.endpoints.find((value) => value.id === id);
      if (mutation === "remove") copy.endpoints = copy.endpoints.filter((value) => value.id !== id);
      else if (mutation === "extra") copy.endpoints.push({...endpoint, id: "api.v1.hosts.admit"});
      else endpoint[mutation] = mutation === "audiences" ? ["operator", "browser", "agent"] : "unreviewed";
      const root = await fixtureRepo(t, {"schemas/v1/endpoint-registry.json": JSON.stringify(copy)});
      assert.ok((await verifyReadAPI(root)).codes.includes("READ_API_ENDPOINT_DRIFT"), `${id}/${mutation}`);
    }
  }
});


for (const family of ["host-actions", "host-access"]) {
test(`the reviewed ${family} draft requires its complete exact endpoint metadata`, async (t) => {
  const registry = JSON.parse(await readFile(path.join(process.cwd(), "schemas/v1/endpoint-registry.json"), "utf8"));
  assert.equal((await verifyReadAPI()).status, "pass");
  const id = `api.v1.${family}.draft`;
  for (const mutation of ["remove", "id", "method", "path", "availability", "ownerPhase", "requestSchema", "dataSchema", "stream", "audiences", "extra-field", "duplicate", "direct-execute", "unrelated-route", "historical-route"]) {
    const copy = structuredClone(registry);
    const endpoint = copy.endpoints.find((value) => value.id === id);
    if (mutation === "remove") copy.endpoints = copy.endpoints.filter((value) => value.id !== id);
    else if (mutation === "extra-field") endpoint.allowDirectExecution = true;
    else if (mutation === "duplicate") copy.endpoints.push({...endpoint});
    else if (mutation === "direct-execute") copy.endpoints.push({...endpoint, id: `api.v1.${family}.execute`, path: `/api/v1/${family}/execute`});
    else if (mutation === "unrelated-route") copy.endpoints.push({...endpoint, id: "api.v1.unreviewed.draft", path: "/api/v1/unreviewed/draft"});
    else if (mutation === "historical-route") copy.endpoints = copy.endpoints.filter((value) => value.id !== "api.v1.summary.get");
    else endpoint[mutation] = mutation === "audiences" ? ["operator", "browser", "agent"] : "unreviewed";
    const root = await fixtureRepo(t, {"schemas/v1/endpoint-registry.json": JSON.stringify(copy)});
    assert.ok((await verifyReadAPI(root)).codes.includes("READ_API_ENDPOINT_DRIFT"), mutation);
  }
});
}

for (const action of ["create", "get"]) {
  test(`the #239 replacement ${action} endpoint stays exact with reviewed browser access`, async (t) => {
    const registry = JSON.parse(await readFile(path.join(process.cwd(), "schemas/v1/endpoint-registry.json"), "utf8"));
    assert.equal((await verifyReadAPI()).status, "pass");
    const id = `api.v1.host-replacements.${action}`;
    for (const mutation of ["remove", "id", "method", "path", "availability", "ownerPhase", "requestSchema", "dataSchema", "stream", "audiences", "extra-field", "duplicate", "direct-execute", "alias-claim", "historical-route"]) {
      const copy = structuredClone(registry);
      const endpoint = copy.endpoints.find(value => value.id === id);
      if (mutation === "remove") copy.endpoints = copy.endpoints.filter(value => value.id !== id);
      else if (mutation === "extra-field") endpoint.allowDirectExecution = true;
      else if (mutation === "duplicate") copy.endpoints.push({...endpoint});
      else if (mutation === "direct-execute") copy.endpoints.push({...endpoint, id: "api.v1.host-replacements.execute", path: "/api/v1/host-replacements/execute"});
      else if (mutation === "alias-claim") copy.endpoints.push({...endpoint, id: "api.v1.host-aliases.claim", path: "/api/v1/host-aliases/claim"});
      else if (mutation === "historical-route") copy.endpoints = copy.endpoints.filter(value => value.id !== "api.v1.summary.get");
      else endpoint[mutation] = mutation === "audiences" ? ["operator", "browser", "agent"] : "unreviewed";
      const root = await fixtureRepo(t, {"schemas/v1/endpoint-registry.json": JSON.stringify(copy)});
      assert.ok((await verifyReadAPI(root)).codes.includes("READ_API_ENDPOINT_DRIFT"), mutation);
    }
  });
}


test("the reviewed #247 grants route remains an exact inert operator draft", async (t) => {
  const registry = JSON.parse(await readFile(path.join(process.cwd(), "schemas/v1/endpoint-registry.json"), "utf8"));
  for (const variant of ["missing", "extra-apply", "browser", "wrong-method", "wrong-schema"]) {
    const copy = structuredClone(registry);
    const endpoint = copy.endpoints.find(({id}) => id === "api.v1.authorization.grant-batches.create");
    if (variant === "missing") copy.endpoints = copy.endpoints.filter((item) => item !== endpoint);
    if (variant === "extra-apply") copy.endpoints.push({...endpoint, id: "api.v1.authorization.grant-batches.apply"});
    if (variant === "browser") endpoint.audiences.push("browser");
    if (variant === "wrong-method") endpoint.method = "PUT";
    if (variant === "wrong-schema") endpoint.requestSchema = "vegastack-labs.dev/plan-reference-request";
    const root = await fixtureRepo(t, {"schemas/v1/endpoint-registry.json": JSON.stringify(copy)});
    assert.ok((await verifyReadAPI(root)).codes.includes("READ_API_ENDPOINT_DRIFT"), variant);
  }
});

// Qualification remains local/operator-only; no field or sibling route is implied.
test("the reviewed #228 qualification endpoints retain exact bounded metadata", async (t) => {
  const registry = JSON.parse(await readFile(path.join(process.cwd(), "schemas/v1/endpoint-registry.json"), "utf8"));
  assert.equal((await verifyReadAPI()).status, "pass");
  for (const action of ["collect", "inspect", "producer"]) {
    const id = `api.v1.qualification.${action}`;
    const fields = ["id", "method", "path", "availability", "ownerPhase", "requestSchema", "dataSchema", "stream", "audiences"];
    if (action === "producer") fields.push("transportScope", "maxRequestBytes");
    for (const mutation of ["remove", "duplicate", "extra-field", "sibling", "historical", ...fields]) {
      const copy = structuredClone(registry);
      const endpoint = copy.endpoints.find(value => value.id === id);
      if (mutation === "remove") copy.endpoints = copy.endpoints.filter(value => value.id !== id);
      else if (mutation === "duplicate") copy.endpoints.push({...endpoint});
      else if (mutation === "extra-field") endpoint.allowDirectExecution = true;
      else if (mutation === "sibling") copy.endpoints.push({...endpoint, id: "api.v1.qualification.execute"});
      else if (mutation === "historical") copy.endpoints = copy.endpoints.filter(value => value.id !== "api.v1.summary.get");
      else endpoint[mutation] = mutation === "audiences" ? ["operator", "browser"] : mutation === "maxRequestBytes" ? 16384 : "unreviewed";
      const root = await fixtureRepo(t, {"schemas/v1/endpoint-registry.json": JSON.stringify(copy)});
      assert.ok((await verifyReadAPI(root)).codes.includes("READ_API_ENDPOINT_DRIFT"), `${id}/${mutation}`);
    }
  }
});

test("the reviewed #276 operator reads require exact bounded GET contracts", async (t) => {
  const registry = JSON.parse(await readFile(path.join(process.cwd(), "schemas/v1/endpoint-registry.json"), "utf8"));
  assert.equal((await verifyReadAPI()).status, "pass");
  for (const family of ["people", "devices", "grants", "providers"]) {
    const id = `api.v1.${family}.list`;
    for (const mutation of ["remove", "id", "method", "path", "availability", "ownerPhase", "querySchema", "requestSchema", "dataSchema", "stream", "audiences", "permission-field", "extra-field", "duplicate", "direct-mutation", "planned-extra", "historical-route"]) {
      const copy = structuredClone(registry);
      const endpoint = copy.endpoints.find(value => value.id === id);
      if (mutation === "remove") copy.endpoints = copy.endpoints.filter(value => value.id !== id);
      else if (mutation === "permission-field") endpoint.capability = "authorization.policy.write";
      else if (mutation === "extra-field") endpoint.allowDirectExecution = true;
      else if (mutation === "duplicate") copy.endpoints.push({...endpoint});
      else if (mutation === "direct-mutation") copy.endpoints.push({...endpoint, id: `api.v1.${family}.revoke`, path: `/api/v1/${family}/revoke`, method: "POST"});
      else if (mutation === "planned-extra") copy.endpoints.push({...endpoint, id: `api.v1.${family}.unreviewed`, availability: "planned"});
      else if (mutation === "historical-route") copy.endpoints = copy.endpoints.filter(value => value.id !== "api.v1.summary.get");
      else endpoint[mutation] = mutation === "audiences" ? ["operator", "browser", "agent"] : "unreviewed";
      const root = await fixtureRepo(t, {"schemas/v1/endpoint-registry.json": JSON.stringify(copy)});
      assert.ok((await verifyReadAPI(root)).codes.includes("READ_API_ENDPOINT_DRIFT"), `${id}/${mutation}`);
    }
  }
});


test("approved #277 endpoints retain exact operator-only transport contracts", async (t) => {
  const registry = JSON.parse(await readFile(path.join(process.cwd(), "schemas/v1/endpoint-registry.json"), "utf8"));
  for (const id of ["api.v1.hosts.connection-descriptor.get", "api.v1.network.endpoint-drafts.create"]) {
    for (const change of ["remove", "audience", "method", "path", "schema", "extra"]) {
      const copy = structuredClone(registry);
      const endpoint = copy.endpoints.find((entry) => entry.id === id);
      if (change === "remove") copy.endpoints = copy.endpoints.filter((entry) => entry.id !== id);
      if (change === "audience") endpoint.audiences.push("browser");
      if (change === "method") endpoint.method = "DELETE";
      if (change === "path") endpoint.path += "/execute";
      if (change === "schema") endpoint.dataSchema = "vegastack-labs.dev/run-result";
      if (change === "extra") copy.endpoints.push({...endpoint, id: "api.v1.network.unapproved"});
      const root = await fixtureRepo(t, {"schemas/v1/endpoint-registry.json": `${JSON.stringify(copy)}\n`});
      assert.ok((await verifyReadAPI(root)).codes.includes("READ_API_ENDPOINT_DRIFT"), `${id}: ${change}`);
    }
  }
});


test("approved Mesh and ingress routes retain exact finite endpoint contracts", async (t) => {
  const registry = JSON.parse(await readFile(path.join(process.cwd(), "schemas/v1/endpoint-registry.json"), "utf8"));
  const approved = registry.endpoints.filter(({id}) => /^api\.v1\.network\.(mesh|ingress)\./.test(id));
  assert.equal(approved.length, 7, "all approved Mesh and ingress endpoints must be present");
  for (const original of approved) {
    for (const change of ["remove", "audience", "method", "path", "schema", "extra"]) {
      const copy = structuredClone(registry);
      const endpoint = copy.endpoints.find(({id}) => id === original.id);
      if (change === "remove") copy.endpoints = copy.endpoints.filter(({id}) => id !== original.id);
      if (change === "audience") endpoint.audiences.push("server-adapter");
      if (change === "method") endpoint.method = "DELETE";
      if (change === "path") endpoint.path += "/unapproved";
      if (change === "schema") endpoint.dataSchema = "vegastack-labs.dev/run-result";
      if (change === "extra") copy.endpoints.push({...endpoint, id: original.id + ".unapproved"});
      const root = await fixtureRepo(t, {"schemas/v1/endpoint-registry.json": `${JSON.stringify(copy)}\n`});
      assert.ok((await verifyReadAPI(root)).codes.includes("READ_API_ENDPOINT_DRIFT"), `${original.id}: ${change}`);
    }
  }
});


test("host adoption and connection descriptor contracts classify distinct exact routes", async (t) => {
  assert.equal((await verifyReadAPI()).status, "pass");
  const registry = JSON.parse(await readFile(path.join(process.cwd(), "schemas/v1/endpoint-registry.json"), "utf8"));
  const descriptor = registry.endpoints.find(({id}) => id === "api.v1.hosts.connection-descriptor.get");
  for (const id of ["api.v1.hosts.unapproved", "api.v1.hosts.connection-descriptor.unapproved"]) {
    const copy = structuredClone(registry);
    copy.endpoints.push({...descriptor, id});
    const root = await fixtureRepo(t, {"schemas/v1/endpoint-registry.json": `${JSON.stringify(copy)}\n`});
    assert.ok((await verifyReadAPI(root)).codes.includes("READ_API_ENDPOINT_DRIFT"), id);
  }
});

test("approved #286 services admit only scoped reads and an operator import draft", async (t) => {
  const registry = JSON.parse(await readFile(path.join(process.cwd(), "schemas/v1/endpoint-registry.json"), "utf8"));
  const initial = registry.endpoints.find(({id}) => id === "api.v1.services.import-drafts.create");
  for (const mutate of [
    (copy) => { copy.endpoints = copy.endpoints.filter(({id}) => id !== "api.v1.services.observation.get"); },
    (copy) => { copy.endpoints.find(({id}) => id === initial.id).audiences.push("browser"); },
    (copy) => { copy.endpoints.push({...structuredClone(initial), id: "api.v1.services.deploy", path: "/api/v1/services/deploy"}); },
    (copy) => { copy.endpoints.find(({id}) => id === "api.v1.services.list").querySchema = "vegastack-labs.dev/operator-read-query"; },
  ]) {
    const copy = structuredClone(registry); mutate(copy);
    const root = await fixtureRepo(t, {"schemas/v1/endpoint-registry.json": `${JSON.stringify(copy)}\n`});
    assert.ok((await verifyReadAPI(root)).codes.includes("READ_API_ENDPOINT_DRIFT"));
  }
});

test("approved #288 deployment routes stay exact and exclude direct mutation", async (t) => {
  const registry = JSON.parse(await readFile(path.join(process.cwd(), "schemas/v1/endpoint-registry.json"), "utf8"));
  assert.equal((await verifyReadAPI()).status, "pass");
  for (const id of ["api.v1.services.deployment-drafts.create", "api.v1.services.deployment.get"]) {
    const original = registry.endpoints.find(endpoint => endpoint.id === id);
    assert.ok(original, id);
    for (const mutation of ["remove", "duplicate", "extra-field", "direct-execute", "unknown-sibling", ...Object.keys(original)]) {
      const copy = structuredClone(registry);
      const endpoint = copy.endpoints.find(endpoint => endpoint.id === id);
      if (mutation === "remove") copy.endpoints = copy.endpoints.filter(endpoint => endpoint.id !== id);
      else if (mutation === "duplicate") copy.endpoints.push({...endpoint});
      else if (mutation === "extra-field") endpoint.allowDirectExecution = true;
      else if (mutation === "direct-execute") copy.endpoints.push({...endpoint, id: "api.v1.services.deployment.execute", method: "POST", path: "/api/v1/services/{serviceID}/deployment/execute"});
      else if (mutation === "unknown-sibling") copy.endpoints.push({...endpoint, id: "api.v1.services.deployment.unapproved"});
      else endpoint[mutation] = mutation === "audiences" ? ["browser", "operator", "agent"] : "unapproved";
      const root = await fixtureRepo(t, {"schemas/v1/endpoint-registry.json": `${JSON.stringify(copy)}\n`});
      assert.ok((await verifyReadAPI(root)).codes.includes("READ_API_ENDPOINT_DRIFT"), `${id}/${mutation}`);
    }
  }
  const browserDraft = structuredClone(registry);
  browserDraft.endpoints.find(endpoint => endpoint.id === "api.v1.services.deployment-drafts.create").audiences = ["browser", "operator"];
  const root = await fixtureRepo(t, {"schemas/v1/endpoint-registry.json": `${JSON.stringify(browserDraft)}\n`});
  assert.ok((await verifyReadAPI(root)).codes.includes("READ_API_ENDPOINT_DRIFT"), "browser deployment draft");
});


test("Phase8 finish admits only exact reads and inert operator drafts", async(t) => {
 const registry=JSON.parse(await readFile(path.join(process.cwd(),"schemas/v1/endpoint-registry.json"),"utf8"));
 for(const id of ["api.v1.services.configuration.get","api.v1.services.recovery.get","api.v1.services.recovery-drafts.create","api.v1.hosting.lifecycle.get","api.v1.hosting.lifecycle-drafts.create"]){
  const original=registry.endpoints.find(e=>e.id===id); assert.ok(original,id);
  for(const change of ["remove","duplicate","direct-write","browser-draft","unknown-field"]){
   const copy=structuredClone(registry);const e=copy.endpoints.find(e=>e.id===id);
   if(change==="remove")copy.endpoints=copy.endpoints.filter(e=>e.id!==id);
   if(change==="duplicate")copy.endpoints.push({...e});
   if(change==="direct-write") {e.method="POST";e.path+="/execute";}
   if(change==="browser-draft")e.audiences=e.method==="POST"?["browser","operator"]:["browser","operator","unknown"];
   if(change==="unknown-field")e.directExecute=true;
   const root=await fixtureRepo(t,{"schemas/v1/endpoint-registry.json":JSON.stringify(copy)+"\n"});
   assert.ok((await verifyReadAPI(root)).codes.includes("READ_API_ENDPOINT_DRIFT"),id+"/"+change);
  }
 }
});


test("approved #313 CI job draft retains its exact finite operator contract", async (t) => {
  const registry = JSON.parse(await readFile(path.join(process.cwd(), "schemas/v1/endpoint-registry.json"), "utf8"));
  const id = "api.v1.ci.jobs.drafts.create";
  assert.equal((await verifyReadAPI()).status, "pass");
  for (const mutation of ["method", "path", "request-schema", "data-schema", "sibling"]) {
    const copy = structuredClone(registry);
    const endpoint = copy.endpoints.find((endpoint) => endpoint.id === id);
    assert.ok(endpoint);
    if (mutation === "method") endpoint.method = "GET";
    else if (mutation === "path") endpoint.path = "/api/v1/ci/jobs/execute";
    else if (mutation === "request-schema") endpoint.requestSchema = "vegastack-labs.dev/ci-enrollment-draft-request";
    else if (mutation === "data-schema") endpoint.dataSchema = "vegastack-labs.dev/run";
    else copy.endpoints.push({...endpoint, id: "api.v1.ci.jobs.execute", path: "/api/v1/ci/jobs/execute"});
    const root = await fixtureRepo(t, {"schemas/v1/endpoint-registry.json": `${JSON.stringify(copy)}\n`});
    assert.ok((await verifyReadAPI(root)).codes.includes("READ_API_ENDPOINT_DRIFT"), mutation);
  }
});
