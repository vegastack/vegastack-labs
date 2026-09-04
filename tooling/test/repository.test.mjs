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
  const envName = ["CF", "ACCESS", "CLIENT", "SECRET"].join("_");
  const headerName = ["CF", "Access", "Client", "Secret"].join("-");
  const secretMarker = ["Cloudflare Access secret value"];
  const inputs = [
    [envName, "fixture-secret-value"].join("="),
    ["export ", envName, "=fixture-secret-value"].join(""),
    [headerName, "fixture-secret-value"].join(": "),
    ["- ", headerName, ": fixture-secret-value"].join(""),
    ["curl -H \"", headerName, ": fixture-secret-value\""].join(""),
    JSON.stringify({ [headerName]: "fixture-secret-value" }),
  ];

  for (const input of inputs) {
    assert.deepEqual(findSecretMarkers(input), secretMarker);
  }
});

test("empty registry placeholders are accepted", () => {
  const envName = ["CF", "ACCESS", "CLIENT", "SECRET"].join("_");
  assert.deepEqual(findSecretMarkers(`${envName}=\n`), []);
  assert.deepEqual(findSecretMarkers(`${envName}=\nNEXT_VALUE=safe\n`), []);
  assert.deepEqual(findSecretMarkers('"CF-Access-Client-Secret": "${CF_ACCESS_CLIENT_SECRET}"'), []);
});

test("Slack credential markers are rejected without echoing their value", () => {
  const credential = ["xapp", "example", "credential", "must", "not", "echo"].join("-");
  const markers = findSecretMarkers(`expected reason: ${credential}`);
  assert.deepEqual(markers, ["Slack credential value"]);
  assert.doesNotMatch(markers.join(" "), /must-not-echo/);
});

test("private contract values are classified without echoing their contents", () => {
  const cases = [
    [
      [["signing", "secret"].join("_"), ["material", "must", "not", "echo"].join("-")].join("="),
      "signing-secret value",
    ],
    [
      [["T", "123456789"].join(""), ["U", "123456789"].join("")].join("->"),
      "private Slack user mapping",
    ],
    [
      [["private", "user", "mapping"].join("_"), ["person", "must", "not", "echo"].join("-")].join(":"),
      "private user mapping",
    ],
    [
      [["host", "fact"].join("_"), ["host", "must", "not", "echo"].join("-")].join("="),
      "private host fact",
    ],
    [
      [["operational", "evidence"].join("_"), ["evidence", "must", "not", "echo"].join("-")].join(":"),
      "private operational evidence",
    ],
  ];
  for (const [input, marker] of cases) {
    assert.deepEqual(findSecretMarkers(input), [marker]);
    assert.doesNotMatch(findSecretMarkers(input).join(" "), /must-not-echo|123456789/);
  }
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
    writeFile(
      path.join(root, "web/.env.local"),
      `${[["CF", "ACCESS", "CLIENT", "SECRET"].join("_"), "fixture-value"].join("=")}\n`,
      "utf8",
    ),
  ]);
  await runCommand("git", ["init", "--quiet"], { capture: true, cwd: root });
  await runCommand("git", ["add", "."], { capture: true, cwd: root });

  await assert.doesNotReject(verifyRepository(root));

  await runCommand("git", ["add", "--force", "web/.env.local"], { capture: true, cwd: root });
  await assert.rejects(verifyRepository(root), /secret-bearing environment file must not be tracked/);

  await runCommand("git", ["rm", "--cached", "--force", "web/.env.local"], {
    capture: true,
    cwd: root,
  });
  const headerFixture = path.join(root, "registry-header.yaml");
  await writeFile(
    headerFixture,
    `${["- ", ["CF", "Access", "Client", "Secret"].join("-"), ": fixture-secret-value"].join("")}\n`,
    "utf8",
  );
  await runCommand("git", ["add", "registry-header.yaml"], { capture: true, cwd: root });
  await assert.rejects(verifyRepository(root), /contains prohibited Cloudflare Access secret value/);

  await runCommand("git", ["rm", "--cached", "registry-header.yaml"], {
    capture: true,
    cwd: root,
  });
  const slackFixture = path.join(root, "slack-proof.json");
  const credential = ["xapp", "example", "credential", "must", "not", "echo"].join("-");
  await writeFile(slackFixture, `${JSON.stringify({ reason: credential })}\n`, "utf8");
  await runCommand("git", ["add", "slack-proof.json"], { capture: true, cwd: root });
  let message = "";
  try {
    await verifyRepository(root);
    assert.fail("expected the tracked Slack credential to fail repository verification");
  } catch (error) {
    message = error.message;
  }
  assert.match(message, /contains prohibited Slack credential value/);
  assert.doesNotMatch(message, /must-not-echo/);

  await runCommand("git", ["rm", "--cached", "slack-proof.json"], {
    capture: true,
    cwd: root,
  });
  const privateCases = [
    [["signing", "secret"].join("_"), ["material", "must", "not", "echo"].join("-")].join("="),
    [["T", "123456789"].join(""), ["U", "123456789"].join("")].join("->"),
    [["private", "user", "mapping"].join("_"), ["person", "must", "not", "echo"].join("-")].join(":"),
    [["host", "fact"].join("_"), ["host", "must", "not", "echo"].join("-")].join("="),
    [["operational", "evidence"].join("_"), ["evidence", "must", "not", "echo"].join("-")].join(":"),
  ];
  for (const [index, privateValue] of privateCases.entries()) {
    const file = `private-value-${index}.txt`;
    await writeFile(path.join(root, file), `${privateValue}\n`, "utf8");
    await runCommand("git", ["add", file], { capture: true, cwd: root });
    let privateMessage = "";
    try {
      await verifyRepository(root);
      assert.fail("expected tracked private contract value to fail repository verification");
    } catch (error) {
      privateMessage = error.message;
    }
    assert.match(privateMessage, /contains prohibited/);
    assert.doesNotMatch(privateMessage, /must-not-echo|123456789/);
    await runCommand("git", ["rm", "--cached", file], { capture: true, cwd: root });
  }
});
