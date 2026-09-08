import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { verifyServer } from "../verify-server.mjs";

const BASE_FILES = {
  "cmd/vsk-labs/main.go": "package main\nfunc main() {}\n",
  "internal/generated/contracts_gen.go": "package generated\nconst CommandNameServerRun = \"server run\"\n",
  "internal/identity/local.go": "package identity\nfunc WithVerifiedPrincipal() {}\n",
  "internal/server/service.go": [
    "package server",
    "func support(osName, arch, distro string, major int) bool {",
    '  return osName == "linux" && arch == "amd64" && distro == "debian" && major == 13',
    "}",
    "",
  ].join("\n"),
  "schemas/v1/command-registry.json": JSON.stringify({
    commands: [{ path: ["server", "run"], availability: "available" }],
  }),
};

async function fixtureRepo(t, files = {}) {
  const root = await mkdtemp(path.join(tmpdir(), "vegastack-server-fixture-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  for (const [relative, content] of Object.entries({ ...BASE_FILES, ...files })) {
    const destination = path.join(root, relative);
    await mkdir(path.dirname(destination), { recursive: true });
    await writeFile(destination, content, "utf8");
  }
  return root;
}

test("the server verifier accepts the single Unix service boundary", async (t) => {
  const root = await fixtureRepo(t);
  assert.deepEqual(await verifyServer(root), { status: "pass", codes: [] });
});

test("the server verifier accepts SQLite and Linux filesystem access only in the store", async (t) => {
  const root = await fixtureRepo(t, {
    "internal/store/store.go": "package store\nimport _ \"database/sql\"\n",
    "internal/store/filesystem_linux.go":
      "package store\nimport _ \"golang.org/x/sys/unix\"\n",
  });
  assert.deepEqual(await verifyServer(root), { status: "pass", codes: [] });
});

test("the server verifier rejects a TCP control listener", async (t) => {
  const root = await fixtureRepo(t, {
    "internal/server/service.go": [
      "package server",
      'import "net"',
      'func support() { _, _ = net.Listen("tcp", "127.0.0.1:8080"); _ = "linux/amd64/debian/13" }',
      "",
    ].join("\n"),
  });
  const result = await verifyServer(root);
  assert.deepEqual(result.codes, ["SERVER_TCP_LISTENER", "SERVER_PLATFORM_SCOPE"]);
});

test("the server verifier rejects identity headers used outside the authenticated server bridge", async (t) => {
  const root = await fixtureRepo(t, {
    "internal/other/trust.go": [
      "package other",
      'import "net/http"',
      'func trust(request *http.Request) string { return request.Header.Get("X-VSK-UID") }',
      "",
    ].join("\n"),
  });
  const result = await verifyServer(root);
  assert.deepEqual(result.codes, ["SERVER_IDENTITY_HEADER_TRUST"]);
});

test("the server verifier confines context setters, SQLite, and x/sys", async (t) => {
  const root = await fixtureRepo(t, {
    "internal/other/bad.go": [
      "package other",
      'import _ "database/sql"',
      'import "example.test/internal/identity"',
      "func bad() { identity.WithVerifiedPrincipal() }",
      "",
    ].join("\n"),
    "internal/other/sys.go": "package other\nimport _ \"golang.org/x/sys/unix\"\n",
  });
  const result = await verifyServer(root);
  assert.deepEqual(result.codes, ["SERVER_CONTEXT_SETTER", "SERVER_SQLITE_ACCESS", "SERVER_XSYS_SCOPE"]);
});

test("the server verifier requires exactly one executable and available entrypoint", async (t) => {
  const root = await fixtureRepo(t, {
    "cmd/helper/main.go": "package main\nfunc main() {}\n",
    "schemas/v1/command-registry.json": JSON.stringify({ commands: [] }),
  });
  const result = await verifyServer(root);
  assert.deepEqual(result.codes, ["SERVER_EXECUTABLE_COUNT", "SERVER_ENTRYPOINT_COUNT"]);
});
