import assert from "node:assert/strict";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { runCommand } from "../lib/process.mjs";
import {
  assertExactDependencySpec,
  findSecretMarkers,
  isSecretEnvironmentFile,
  verifyRepository,
} from "../verify-repository.mjs";

test("exact dependency specifications pass", () => {
  assert.doesNotThrow(() => assertExactDependencySpec("example", "1.2.3"));
});

test("unpinned dependency specifications fail", () => {
  assert.throws(() => assertExactDependencySpec("example", "^1.2.3"), /exact semantic version/);
  assert.throws(() => assertExactDependencySpec("example", "latest"), /exact semantic version/);
});

test("secret markers detect a nonempty registry secret without echoing it", () => {
  const markers = findSecretMarkers(["CF_ACCESS_CLIENT_SECRET", "fixture-secret-value"].join("="));
  assert.deepEqual(markers, ["Cloudflare Access secret value"]);
});

test("empty registry placeholders are accepted", () => {
  assert.deepEqual(findSecretMarkers("CF_ACCESS_CLIENT_SECRET=\n"), []);
  assert.deepEqual(findSecretMarkers("CF_ACCESS_CLIENT_SECRET=\nNEXT_VALUE=safe\n"), []);
  assert.deepEqual(findSecretMarkers('"CF-Access-Client-Secret": "${CF_ACCESS_CLIENT_SECRET}"'), []);
});

test("environment filename classification distinguishes redacted examples", () => {
  assert.equal(isSecretEnvironmentFile("web/.env.local"), true);
  assert.equal(isSecretEnvironmentFile("web/.env"), true);
  assert.equal(isSecretEnvironmentFile("web/.env.example"), false);
});

test("ignored local credentials pass while the same tracked file fails", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "vegastack-repository-"));
  await mkdir(path.join(root, "web"));
  const packageJson = JSON.stringify({
    private: true,
    packageManager: "pnpm@11.24.0",
    engines: { node: "24.20.0", pnpm: "11.24.0" },
  });
  const webPackageJson = JSON.stringify({
    private: true,
    engines: { node: "24.20.0", pnpm: "11.24.0" },
  });
  await Promise.all([
    writeFile(path.join(root, ".gitignore"), ".env.local\n", "utf8"),
    writeFile(path.join(root, ".node-version"), "24.20.0\n", "utf8"),
    writeFile(path.join(root, "go.mod"), "module example.test/foundation\n\ngo 1.27.0\n", "utf8"),
    writeFile(path.join(root, "package.json"), `${packageJson}\n`, "utf8"),
    writeFile(path.join(root, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n", "utf8"),
    writeFile(
      path.join(root, "web/components.json"),
      `${JSON.stringify({
        registries: {
          "@vegastack": {
            headers: {
              "CF-Access-Client-Id": "${CF_ACCESS_CLIENT_ID}",
              "CF-Access-Client-Secret": "${CF_ACCESS_CLIENT_SECRET}",
            },
          },
        },
      })}\n`,
      "utf8",
    ),
    writeFile(path.join(root, "web/package.json"), `${webPackageJson}\n`, "utf8"),
    writeFile(path.join(root, "web/.env.local"), "CF_ACCESS_CLIENT_SECRET=fixture-value\n", "utf8"),
  ]);
  await runCommand("git", ["init", "--quiet"], { capture: true, cwd: root });
  await runCommand("git", ["add", "."], { capture: true, cwd: root });

  await assert.doesNotReject(verifyRepository(root));

  await runCommand("git", ["add", "--force", "web/.env.local"], { capture: true, cwd: root });
  await assert.rejects(verifyRepository(root), /secret-bearing environment file must not be tracked/);
});
