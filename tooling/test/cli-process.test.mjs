import assert from "node:assert/strict";
import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { constants } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const ROOT = path.resolve(import.meta.dirname, "../..");
const RESULT_KEYS = [
  "schema",
  "schemaVersion",
  "toolVersion",
  "command",
  "requestId",
  "runId",
  "status",
  "changed",
  "recoveryEpoch",
  "stateRevision",
  "snapshotDigest",
  "releaseBuildId",
  "sourceRevision",
  "planId",
  "errors",
  "data",
];

function run(binary, args = []) {
  const result = spawnSync(binary, args, {
    cwd: ROOT,
    encoding: "utf8",
    shell: false,
  });
  assert.equal(result.error, undefined, `failed to invoke binary: ${result.error?.message}`);
  assert.equal(result.signal, null);
  return { code: result.status, stdout: result.stdout, stderr: result.stderr };
}

function assertHumanFailure(actual, code, target) {
  assert.deepEqual(actual, {
    code,
    stdout: "",
    stderr: `vsk-labs: ${target.code} (${target.field})\n`,
  });
}

function assertEnvelope(actual, expected) {
  assert.equal(actual.code, expected.exitCode);
  assert.equal(actual.stderr, "");
  assert.equal((actual.stdout.match(/\n/g) ?? []).length, 1, "machine output must be one line");
  assert.ok(actual.stdout.endsWith("\n"));
  const result = JSON.parse(actual.stdout);
  assert.deepEqual(Object.keys(result), RESULT_KEYS);
  assert.equal(result.schema, "vegastack-labs.dev/run-result");
  assert.equal(result.schemaVersion, "1.0.0");
  assert.equal(result.toolVersion, "0.0.0-dev");
  assert.equal(result.command, expected.command);
  assert.match(result.requestId, /^request-[0-9a-f]{32}$/);
  assert.equal(result.runId, null);
  assert.equal(result.status, expected.status);
  assert.equal(result.changed, false);
  assert.equal(result.recoveryEpoch, 0);
  assert.equal(result.stateRevision, 0);
  assert.equal(result.snapshotDigest, null);
  assert.equal(result.releaseBuildId, "development");
  assert.equal(result.sourceRevision, null);
  assert.equal(result.planId, null);
  assert.deepEqual(result.data, expected.data);
  if (expected.error === undefined) {
    assert.deepEqual(result.errors, []);
  } else {
    assert.deepEqual(result.errors, [
      { code: expected.error.code, target: expected.error.target, retryable: false },
    ]);
  }
  return result;
}

function expectedHumanHelp(registry) {
  const available = registry.commands.filter((command) => command.availability === "available");
  const planned = registry.commands.filter((command) => command.availability === "planned");
  const lines = ["vsk-labs commands", "", "Available commands:"];
  for (const command of available) {
    lines.push(`  ${command.path.join(" ").padEnd(24)} ${command.summary}`);
    for (const flag of command.flags ?? []) {
      let line = `    ${`${flag.name} <${flag.valueName}>`.padEnd(22)} ${flag.summary}`;
      if ((flag.enum ?? []).length !== 0) line += ` Allowed: ${flag.enum.join(", ")}.`;
      lines.push(line);
    }
  }
  lines.push("", "Planned commands (unavailable):");
  for (const command of planned) {
    lines.push(`  ${command.path.join(" ").padEnd(24)} ${command.summary}`);
  }
  return `${lines.join("\n")}\n`;
}

test("the built vsk-labs executable preserves its complete process contract", async (t) => {
  const temporary = await mkdtemp(path.join(tmpdir(), "vegastack-cli-process-"));
  t.after(() => rm(temporary, { recursive: true, force: true }));
  const binary = path.join(temporary, process.platform === "win32" ? "vsk-labs.exe" : "vsk-labs");
  const build = spawnSync("go", ["build", "-o", binary, "./cmd/vsk-labs"], {
    cwd: ROOT,
    encoding: "utf8",
    shell: false,
  });
  assert.deepEqual(
    { status: build.status, signal: build.signal, stdout: build.stdout, stderr: build.stderr },
    { status: 0, signal: null, stdout: "", stderr: "" },
  );

  const registry = JSON.parse(
    await readFile(path.join(ROOT, "schemas/v1/command-registry.json"), "utf8"),
  );
  assert.deepEqual(run(binary, ["help"]), {
    code: 0,
    stdout: expectedHumanHelp(registry),
    stderr: "",
  });
  assert.deepEqual(run(binary, ["version"]), {
    code: 0,
    stdout: "vsk-labs 0.0.0-dev\ncontract 1.0.0\nbuild development\n",
    stderr: "",
  });

  const help = assertEnvelope(run(binary, ["help", "--output", "json"]), {
    exitCode: 0,
    command: "help",
    status: "succeeded",
    data: { commands: registry.commands },
  });
  assert.deepEqual(help.errors, []);
  assertEnvelope(run(binary, ["version", "--output", "json", "--schema-version", "1"]), {
    exitCode: 0,
    command: "version",
    status: "succeeded",
    data: {},
  });

  assertHumanFailure(run(binary), 2, { code: "INPUT_INVALID", field: "command" });
  assertHumanFailure(run(binary, ["unknown-command"]), 2, {
    code: "INPUT_INVALID",
    field: "command",
  });
  assertHumanFailure(run(binary, ["help", "--unknown", "value"]), 2, {
    code: "INPUT_INVALID",
    field: "arguments",
  });
  assertHumanFailure(run(binary, ["help", "--output"]), 2, {
    code: "INPUT_INVALID",
    field: "arguments",
  });
  assertHumanFailure(run(binary, ["help", "--output", "yaml"]), 2, {
    code: "INPUT_INVALID",
    field: "arguments",
  });
  assertHumanFailure(run(binary, ["status"]), 6, {
    code: "PREREQUISITE_BLOCKED",
    field: "command",
  });

  assertEnvelope(run(binary, ["help", "--output", "json", "--output", "json"]), {
    exitCode: 2,
    command: "help",
    status: "failed",
    error: { code: "INPUT_INVALID", target: "arguments" },
    data: {},
  });
  assertEnvelope(run(binary, ["help", "--output", "json", "--schema-version"]), {
    exitCode: 2,
    command: "help",
    status: "failed",
    error: { code: "INPUT_INVALID", target: "arguments" },
    data: {},
  });
  assertEnvelope(run(binary, ["version", "--output", "json", "--schema-version", "2"]), {
    exitCode: 2,
    command: "version",
    status: "failed",
    error: { code: "SCHEMA_UNSUPPORTED", target: "schema-version" },
    data: {},
  });

  const canary = path.join(temporary, "must-not-exist");
  const canaryArgument = `$(touch ${canary}) private-secret-canary`;
  const canaryResult = run(binary, ["help", "--output", "json", canaryArgument]);
  assertEnvelope(canaryResult, {
    exitCode: 2,
    command: "help",
    status: "failed",
    error: { code: "INPUT_INVALID", target: "arguments" },
    data: {},
  });
  assert.doesNotMatch(canaryResult.stdout + canaryResult.stderr, /private-secret-canary|must-not-exist/);
  await assert.rejects(access(canary, constants.F_OK), { code: "ENOENT" });
});
