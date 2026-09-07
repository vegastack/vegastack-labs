import assert from "node:assert/strict";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { verifyCLI } from "../verify-cli.mjs";

async function fixtureRepo(files) {
  const root = await mkdtemp(path.join(tmpdir(), "vegastack-cli-fixture-"));
  await Promise.all(
    Object.entries(files).map(async ([relative, content]) => {
      const destination = path.join(root, relative);
      await mkdir(path.dirname(destination), { recursive: true });
      await writeFile(destination, content, "utf8");
    }),
  );
  return root;
}

test("the CLI verifier accepts one generated-registry consumer", async () => {
  const root = await fixtureRepo({
    "cmd/vsk-labs/main.go": "package main\nfunc main() {}\n",
    "internal/cli/run.go":
      'package cli\nimport "example.test/internal/generated"\nfunc commands(){ _ = generated.Commands }\n',
  });
  const result = await verifyCLI(root, { crossBuild: false });
  assert.deepEqual(result, { status: "pass", codes: [], targetsBuilt: [] });
});

test("the CLI verifier rejects a second executable and shell dispatch", async () => {
  const root = await fixtureRepo({
    "cmd/vsk-labs/main.go": "package main\nfunc main() {}\n",
    "cmd/helper/main.go": "package main\nfunc main() {}\n",
    "internal/cli/run.go":
      'package cli\nimport "os/exec"\nfunc run(){ _ = exec.Command("sh", "-c", "status") }\n',
  });
  const result = await verifyCLI(root, { crossBuild: false });
  assert.equal(result.status, "fail");
  assert.deepEqual(result.codes, ["CLI_EXECUTABLE_COUNT", "CLI_SHELL_DISPATCH"]);
});

test("the CLI verifier rejects handwritten registries and direct SQLite access", async () => {
  const root = await fixtureRepo({
    "cmd/vsk-labs/main.go": "package main\nfunc main() {}\n",
    "internal/cli/run.go": [
      "package cli",
      'import "database/sql"',
      "var Commands = []string{\"help\"}",
      "func open(){ _ = sql.ErrNoRows }",
      "",
    ].join("\n"),
  });
  const result = await verifyCLI(root, { crossBuild: false });
  assert.equal(result.status, "fail");
  assert.deepEqual(result.codes, ["CLI_HANDWRITTEN_REGISTRY", "CLI_SQLITE_ACCESS"]);
});

test("the CLI verifier requires cmd/vsk-labs as the sole executable", async () => {
  const root = await fixtureRepo({
    "cmd/helper/main.go": "package main\nfunc main() {}\n",
  });
  const result = await verifyCLI(root, { crossBuild: false });
  assert.deepEqual(result.codes, ["CLI_EXECUTABLE_COUNT"]);
});
