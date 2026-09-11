import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { access, chmod, cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
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
  assert.equal(result.schemaVersion, "1.7.0");
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

function apiEnvelope(command, changed, recoveryEpoch, stateRevision, data) {
  return `${JSON.stringify({
    schema: "vegastack-labs.dev/run-result",
    schemaVersion: "1.7.0",
    toolVersion: "0.0.0-dev",
    command,
    requestId: `request-${command.replaceAll(/[^a-z0-9]/g, "").padEnd(32, "0").slice(0, 32)}`,
    runId: null,
    status: "succeeded",
    changed,
    recoveryEpoch,
    stateRevision,
    snapshotDigest: null,
    releaseBuildId: "development",
    sourceRevision: null,
    planId: null,
    errors: [],
    data,
  })}\n`;
}

function expectedHumanHelp(registry) {
  const available = registry.commands.filter((command) => command.availability === "available");
  const planned = registry.commands.filter((command) => command.availability === "planned");
  const lines = ["vsk-labs commands", "", "Available commands:"];
  for (const command of available) {
    lines.push(`  ${command.path.join(" ").padEnd(24)} ${command.summary}`);
    for (const flag of command.flags ?? []) {
      const label = flag.kind === "switch" ? flag.name : `${flag.name} <${flag.valueName}>`;
      let line = `    ${label.padEnd(22)} ${flag.summary}`;
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
    stdout: "vsk-labs 0.0.0-dev\ncontract 1.7.0\nbuild development\n",
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

  if (process.platform !== "linux" || process.arch !== "x64") {
    const privatePath = path.join(temporary, "private-profile-canary.json");
    for (const command of [["server", "run"], ["server", "status"]]) {
      const unsupported = run(binary, [
        ...command,
        "--config",
        privatePath,
        "--output",
        "json",
      ]);
      assertEnvelope(unsupported, {
        exitCode: 2,
        command: command.join(" "),
        status: "failed",
        error: { code: "UNSUPPORTED_PLATFORM", target: "server-platform" },
        data: {},
      });
      assert.doesNotMatch(unsupported.stdout + unsupported.stderr, /private-profile-canary/);
    }
    await assert.rejects(access(privatePath, constants.F_OK), { code: "ENOENT" });
  }

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
  assertHumanFailure(run(binary, ["status"]), 2, {
    code: "INPUT_INVALID",
    field: "arguments",
  });

  const releaseDirectory = path.join(temporary, "release $(not-a-shell) ; private-canary");
  const policyPath = path.join(temporary, "policy.json");
  await cp(path.join(ROOT, "internal/release/testdata/release-valid"), releaseDirectory, {
    recursive: true,
  });
  await cp(path.join(ROOT, "internal/release/testdata/policy-valid.json"), policyPath);
  const manifestPath = path.join(releaseDirectory, "manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  const policyRaw = await readFile(policyPath);
  const policySha256 = `sha256:${createHash("sha256").update(policyRaw).digest("hex")}`;

  assertEnvelope(
    run(binary, [
      "release", "verify", "--manifest", manifestPath, "--policy", policyPath,
      "--asset", "linux-amd64", "--output", "json",
    ]),
    {
      exitCode: 0,
      command: "release verify",
      status: "succeeded",
      data: {
        releaseId: manifest.releaseId,
        buildId: manifest.buildId,
        sourceRevision: manifest.sourceRevision,
        manifestStatus: "verified",
        verificationStatus: "verified-against-supplied-policy",
        policySha256,
        assets: [{
          assetId: manifest.assets[0].id,
          os: manifest.assets[0].os,
          architecture: manifest.assets[0].architecture,
          digest: manifest.assets[0].digest,
          size: manifest.assets[0].size,
          status: "verified",
        }],
      },
    },
  );
  assert.doesNotMatch(
    run(binary, ["release", "verify", "--manifest", manifestPath, "--policy", policyPath, "--all"]).stdout,
    /official VegaStack release/i,
  );
  await assert.rejects(access(path.join(temporary, "not-a-shell"), constants.F_OK), { code: "ENOENT" });

  const currentManifest = structuredClone(manifest);
  currentManifest.assets[0].os = process.platform === "win32" ? "windows" : process.platform;
  currentManifest.assets[0].architecture = process.arch === "x64" ? "amd64" : process.arch;
  const currentManifestPath = path.join(releaseDirectory, "manifest-current.json");
  await writeFile(currentManifestPath, `${JSON.stringify(currentManifest, null, 2)}\n`);
  const inspected = assertEnvelope(
    run(binary, ["release", "inspect", "--manifest", currentManifestPath, "--output", "json"]),
    {
      exitCode: 0,
      command: "release inspect",
      status: "succeeded",
      data: {
        releaseId: currentManifest.releaseId,
        buildId: currentManifest.buildId,
        sourceRevision: currentManifest.sourceRevision,
        minimumSchemaMajor: 1,
        maximumSchemaMajor: 1,
        platformOs: currentManifest.assets[0].os,
        platformArchitecture: currentManifest.assets[0].architecture,
        platformSchemaMajor: 1,
        compatibleAssetIds: [currentManifest.assets[0].id],
        assets: currentManifest.assets,
        verificationStatus: "not-verified",
      },
    },
  );
  assert.equal(inspected.data.verificationStatus, "not-verified");

  const wrongPolicy = JSON.parse(policyRaw.toString("utf8"));
  wrongPolicy.certificateIdentity = "https://example.invalid/private-canary";
  const wrongPolicyPath = path.join(temporary, "wrong-policy.json");
  await writeFile(wrongPolicyPath, `${JSON.stringify(wrongPolicy)}\n`);
  const wrongSigner = run(binary, [
    "release", "verify", "--manifest", manifestPath, "--policy", wrongPolicyPath,
    "--all", "--output", "json",
  ]);
  assertEnvelope(wrongSigner, {
    exitCode: 2, command: "release verify", status: "failed",
    error: { code: "EVIDENCE_INVALID", target: "manifest-signature" }, data: {},
  });
  assert.doesNotMatch(wrongSigner.stdout + wrongSigner.stderr, /private-canary/);

  await writeFile(path.join(releaseDirectory, "artifacts/vsk-labs"), "tampered artifact!\n");
  assertEnvelope(run(binary, [
    "release", "verify", "--manifest", manifestPath, "--policy", policyPath,
    "--all", "--output", "json",
  ]), {
    exitCode: 2, command: "release verify", status: "failed",
    error: { code: "EVIDENCE_INVALID", target: "asset-digest" }, data: {},
  });

  assertEnvelope(run(binary, [
    "release", "inspect", "--manifest", path.join(temporary, "missing-private-canary.json"),
    "--output", "json",
  ]), {
    exitCode: 6, command: "release inspect", status: "blocked",
    error: { code: "PREREQUISITE_BLOCKED", target: "manifest" }, data: {},
  });

  const incompatible = structuredClone(currentManifest);
  incompatible.minimumSchemaMajor = 2;
  incompatible.maximumSchemaMajor = 2;
  const incompatiblePath = path.join(releaseDirectory, "incompatible.json");
  await writeFile(incompatiblePath, `${JSON.stringify(incompatible)}\n`);
  assertEnvelope(run(binary, [
    "release", "inspect", "--manifest", incompatiblePath, "--output", "json",
  ]), {
    exitCode: 5, command: "release inspect", status: "failed",
    error: { code: "VERSION_INCOMPATIBLE", target: "platform" }, data: {},
  });

  for (const selectionArguments of [
    [],
    ["--asset", "linux-amd64", "--all"],
  ]) {
    assertEnvelope(run(binary, [
      "release", "verify", "--manifest", manifestPath, "--policy", policyPath,
      ...selectionArguments, "--output", "json",
    ]), {
      exitCode: 2, command: "release verify", status: "failed",
      error: { code: "INPUT_INVALID", target: "selection" }, data: {},
    });
  }

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

test("five operator commands preserve protected API bytes in the built process", async (t) => {
  if (process.platform !== "linux" || process.arch !== "x64" || typeof process.getuid !== "function") return;
  const temporary = await mkdtemp(path.join(tmpdir(), "vegastack-cli-api-"));
  t.after(() => rm(temporary, { recursive: true, force: true }));
  const binary = path.join(temporary, "vsk-labs");
  const build = spawnSync("go", ["build", "-o", binary, "./cmd/vsk-labs"], { cwd: ROOT, encoding: "utf8", shell: false });
  assert.equal(build.status, 0, build.stderr);

  const socketPath = path.join(temporary, "control.sock");
  const exportRoot = path.join(temporary, "exports");
  await mkdir(exportRoot, { mode: 0o700 });
  await chmod(exportRoot, 0o700);
  const profilePath = path.join(temporary, "profile.json");
  await writeFile(profilePath, `${JSON.stringify({
    schema: "vegastack-labs.dev/server-profile",
    schemaVersion: "1.0.0",
    socketPath,
    socketOwnerUid: process.getuid(),
    socketGroupGid: null,
    socketMode: "0600",
    shutdownGraceSeconds: 5,
    inventoryExportRoot: exportRoot,
    principalBindings: [{ uid: process.getuid(), principalId: "principal.synthetic" }],
  })}\n`, { mode: 0o600 });
  await chmod(profilePath, 0o600);
  const candidatePath = path.join(temporary, "inventory π.json");
  await writeFile(candidatePath, "{\"synthetic\":true}\n", { mode: 0o600 });
  await chmod(candidatePath, 0o600);

  const responses = {
    "GET /api/v1/summary": apiEnvelope("api.v1.summary.get", false, 2, 7, {
      databaseMode: "read-write", readAvailable: true, mutationAvailable: false,
      draftCount: 2, validDraftCount: 1, blockedDraftCount: 1, lastEventId: 9,
      recoveryEpoch: 2, stateRevision: 7,
    }),
    "GET /api/v1/database/status": apiEnvelope("api.v1.database-status.get", false, 2, 7, {
      mode: "read-write", schemaVersion: 1, sqliteVersion: "3.synthetic", mutationEnabled: false,
      recoveryPending: false, integrityStatus: "ok", lastIntegrityCheckAt: null, safeModeReason: "",
    }),
    "POST /api/v1/inventory-drafts/import": apiEnvelope("api.v1.inventory-drafts.import", true, 2, 8, {
      draftId: "draft-test", draftRevision: 1, validationStatus: "valid",
      sourceDigest: `sha256:${"1".repeat(64)}`, contentDigest: `sha256:${"2".repeat(64)}`,
      stateRevision: 8, recoveryEpoch: 2, eventId: 10, created: true,
      counts: { assets: 0, nodes: 0, aliases: 0, addresses: 0, observations: 0, hardwareFacts: 0, provenance: 0, findings: 0 }, findings: [],
    }),
    "POST /api/v1/inventory-diffs": apiEnvelope("api.v1.inventory-diffs.create", false, 2, 8, {
      candidateKind: "draft", candidateDraft: { draftId: "draft-test", draftRevision: 2 }, candidateDigest: `sha256:${"3".repeat(64)}`,
      baselineKind: "draft", baselineDraft: { draftId: "draft-base", draftRevision: 1 }, stateRevision: 8, recoveryEpoch: 2,
      counts: { added: 0, removed: 0, changed: 0, unchanged: 0 }, records: [], findings: [],
    }),
    "POST /api/v1/inventory-exports": apiEnvelope("api.v1.inventory-exports.create", true, 2, 9, {
      exportId: `sha256:${"4".repeat(64)}`, subjectKind: "draft", draft: { draftId: "draft-test", draftRevision: 1 },
      stateRevision: 9, recoveryEpoch: 2, contentDigest: `sha256:${"5".repeat(64)}`, algorithm: "ed25519", keyId: "synthetic-key",
      keyFingerprint: `sha256:${"6".repeat(64)}`, verificationStatus: "verified", publicationStatus: "published", signedBytesBase64: "e30K",
    }),
  };
  const serverScript = path.join(temporary, "fixture-server.mjs");
  await writeFile(serverScript, [
    'import http from "node:http";',
    'import { rmSync } from "node:fs";',
    'const [socketPath, encoded] = process.argv.slice(2);',
    'const responses = JSON.parse(encoded);',
    'try { rmSync(socketPath); } catch {}',
    'const server = http.createServer((request, response) => {',
    '  request.resume();',
    '  request.on("end", () => {',
    '    const body = responses[`${request.method} ${request.url}`];',
    '    if (body === undefined) { response.writeHead(404); response.end(); return; }',
    '    response.writeHead(200, { "Content-Type": "application/json" });',
    '    response.end(body);',
    '  });',
    '});',
    'server.listen(socketPath);',
    'process.on("SIGTERM", () => server.close(() => process.exit(0)));',
    '',
  ].join("\n"));
  const fixture = spawn(process.execPath, [serverScript, socketPath, JSON.stringify(responses)], { stdio: "ignore" });
  t.after(() => fixture.kill("SIGTERM"));
  const deadline = Date.now() + 5000;
  while (true) {
    try { await access(socketPath, constants.F_OK); break; } catch {}
    if (Date.now() > deadline) throw new Error("fixture API did not become ready");
    await new Promise((resolve) => setTimeout(resolve, 10));
  }

  const scenarios = [
    [["status", "--config", profilePath, "--output", "json"], responses["GET /api/v1/summary"]],
    [["database", "status", "--config", profilePath, "--output", "json"], responses["GET /api/v1/database/status"]],
    [["inventory", "import", "--config", profilePath, "--file", candidatePath, "--format", "typed-json", "--source-revision", "synthetic-1", "--captured-at", "2026-09-08T06:00:00Z", "--idempotency-key", "opaque-1", "--output", "json"], responses["POST /api/v1/inventory-drafts/import"]],
    [["inventory", "diff", "--config", profilePath, "--draft-id", "draft-test", "--draft-revision", "2", "--output", "json"], responses["POST /api/v1/inventory-diffs"]],
    [["inventory", "export", "--config", profilePath, "--draft-id", "draft-test", "--draft-revision", "1", "--output", "json"], responses["POST /api/v1/inventory-exports"]],
  ];
  for (const [args, expected] of scenarios) {
    assert.deepEqual(run(binary, args), { code: 0, stdout: expected, stderr: "" });
  }
});
