import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { access, chmod, cp, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import test from "node:test";

const ROOT = path.resolve(import.meta.dirname, "../..");
const CONTRACT_VERSION = JSON.parse(
  readFileSync(path.join(ROOT, "schemas/v1/command-registry.json"), "utf8"),
).schemaVersion;
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
  assert.equal(result.schemaVersion, CONTRACT_VERSION);
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
    schemaVersion: CONTRACT_VERSION,
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
    stdout: `vsk-labs 0.0.0-dev\ncontract ${CONTRACT_VERSION}\nbuild development\n`,
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

  if (process.platform !== "linux") {
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
  if (process.platform !== "linux" || typeof process.getuid !== "function") return;
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
    schemaVersion: "1.1.0",
    socketPath,
    socketOwnerUid: process.getuid(),
    socketGroupGid: null,
    socketMode: "0600",
    shutdownGraceSeconds: 5,
    inventoryExportRoot: exportRoot,
    principalBindings: [{ uid: process.getuid(), principalId: "principal.synthetic" }],
    remoteRead: {
      enabled: false,
      bindAddress: null,
      publicOrigin: null,
      tlsCertificatePath: null,
      tlsPrivateKeyPath: null,
      identityAdapter: null,
      identityConfigPath: null,
    },
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
      sourceCounts: { total: 7, healthy: 2, stale: 0, unknown: 0, unavailable: 5, failed: 0 },
      worstSourceState: "unavailable",
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

test("Phase 4 commands preserve server facts, request bytes, exits, and disconnect safety in the built process", async (t) => {
  if (process.platform !== "linux" || typeof process.getuid !== "function") return;
  // The fixture below is an HTTP server bound only to the protected local Unix
  // socket. Every assertion invokes the compiled executable as a new process.
  const temporary = await mkdtemp(path.join(tmpdir(), "vegastack cli π phase4-matrix-"));
  t.after(() => rm(temporary, { recursive: true, force: true }));
  const binary = path.join(temporary, "vsk-labs");
  const build = spawnSync("go", ["build", "-o", binary, "./cmd/vsk-labs"], {
    cwd: ROOT, encoding: "utf8", shell: false,
  });
  assert.deepEqual(
    { status: build.status, signal: build.signal, stdout: build.stdout },
    { status: 0, signal: null, stdout: "" },
    build.stderr,
  );

  const socketPath = path.join(temporary, "control.sock");
  const profilePath = path.join(temporary, "profile ; $(not-a-shell) π.json");
  const requestLog = path.join(temporary, "requests.jsonl");
  await writeFile(requestLog, "");
  await writeFile(profilePath, `${JSON.stringify({
    schema: "vegastack-labs.dev/server-profile",
    schemaVersion: "1.1.0",
    socketPath,
    socketOwnerUid: process.getuid(),
    socketGroupGid: null,
    socketMode: "0600",
    shutdownGraceSeconds: 5,
    inventoryExportRoot: temporary,
    principalBindings: [{ uid: process.getuid(), principalId: "principal.synthetic" }],
    remoteRead: {
      enabled: false, bindAddress: null, publicOrigin: null,
      tlsCertificatePath: null, tlsPrivateKeyPath: null,
      identityAdapter: null, identityConfigPath: null,
    },
  })}\n`, { mode: 0o600 });
  await chmod(profilePath, 0o600);

  const planCreatedAt = new Date(Math.floor(Date.now() / 1000) * 1000);
  const planExpiresAt = new Date(planCreatedAt.getTime() + (30 * 60 * 1000));
  const fixturePlanCreatedAt = planCreatedAt.toISOString().replace(".000Z", "Z");
  const fixturePlanExpiresAt = planExpiresAt.toISOString().replace(".000Z", "Z");
  assert.ok(planExpiresAt.getTime() > Date.now(), "fixture plan must remain current for the test");

  const serverScript = path.join(temporary, "phase4-cli-fixture.mjs");
  await writeFile(serverScript, [
    'import http from "node:http";',
    'import { createHash } from "node:crypto";',
    'import { appendFileSync, rmSync } from "node:fs";',
    'const [socketPath, requestLog, contractVersion, planCreatedAt, planExpiresAt] = process.argv.slice(2);',
    'try { rmSync(socketPath); } catch {}',
    'const digest = (character) => `sha256:${character.repeat(64)}`;',
    'const operation = { sequence: 1, operationId: "operation-1", operationType: "application.deploy.low-risk", adapterId: "adapter.synthetic", executorId: "executor-central", targetId: "target-1", inputDigest: digest("e"), artifactDigest: digest("f"), idempotent: true };',
    'const planFor = (planId = "plan-1") => ({',
    '  schema: "vegastack-labs.dev/plan", schemaVersion: "1.0.0", planId, planDigest: digest("a"), declarationId: "declaration-1",',
    '  binding: { recoveryEpoch: 2, priorStateRevision: 6, stateRevision: 7, declarationRevision: 1, observationFingerprint: digest("b"), targetDigest: digest("c"), reasonDigest: digest("d"), policyVersion: "1.0.0", toolVersion: "0.0.0-dev", contractVersion },',
    '  operations: [operation], status: "planned", risk: "routine", authorizationBranch: "preauthorized", executorMode: "central", executorId: null, createdAt: planCreatedAt, expiresAt: planExpiresAt, readableDigest: digest("1"), extensions: [],',
    '});',
    'const presentPlan = (plan) => ({ plan, readablePlan: "fixture readable plan", canonicalPlan: JSON.stringify(plan) });',
    'const step = (sequence, status, effectState) => ({ sequence, operationId: `operation-${sequence}`, operationType: operation.operationType, targetId: `target-${sequence}`, stepId: `step-${sequence}`, status, progressState: ({ "not-started": "not-started", "intent-recorded": "started", "receipt-recorded": "unverified", verified: "verified", "effect-unknown": "unknown" })[effectState] });',
    'const runFor = (runId, planId, status = "running") => {',
    '  const states = status === "succeeded" ? [step(1, "succeeded", "verified")] : status === "partial" ? [step(1, "succeeded", "verified"), step(2, "partial", "effect-unknown")] : status === "cancelled" ? [step(1, "cancelled", "not-started")] : status === "interrupted" ? [step(1, "interrupted", "effect-unknown")] : [step(1, "running", "intent-recorded")];',
    '  return { schema: "vegastack-labs.dev/browser-run", schemaVersion: "1.0.0", runId, planId, planDigest: digest("a"), status, steps: states, cancellationRequested: status === "cancelled", rollbackStatus: status === "partial" ? "required" : "not-requested", verificationStatus: status === "succeeded" ? "verified" : status === "partial" ? "incomplete" : "pending", verificationDigest: status === "succeeded" ? digest("9") : null, changed: status === "succeeded" || status === "partial", stateRevision: 7, recoveryEpoch: 2, createdAt: "2026-09-13T06:01:00Z", updatedAt: "2026-09-13T06:01:01Z", extensions: [] };',
    '};',
    'const present = (run) => { const completedWork = run.steps.filter((item) => ["succeeded", "failed", "cancelled"].includes(item.status)); const incompleteWork = run.steps.filter((item) => !completedWork.includes(item)); let nextSafeAction = "inspect the durable run"; if (run.status === "partial" || run.rollbackStatus === "required" || run.verificationStatus === "incomplete") nextSafeAction = "recovery required; inspect the durable run"; else if (run.status === "succeeded") nextSafeAction = "none; execution completed"; else if (run.status === "cancelled") nextSafeAction = "inspect before creating another plan"; else if (run.status === "interrupted") nextSafeAction = "inspect, then resume or cancel through the server"; else if (["queued", "running"].includes(run.status)) nextSafeAction = "inspect or cancel through the server"; return { run, completedWork, incompleteWork, nextSafeAction }; };',
    'const requestId = (command) => `request-${command.replaceAll(/[^a-z0-9]/g, "").padEnd(32, "0").slice(0, 32)}`;',
    'const success = (command, data, options = {}) => `${JSON.stringify({ schema: "vegastack-labs.dev/run-result", schemaVersion: contractVersion, toolVersion: "0.0.0-dev", command, requestId: requestId(command), runId: options.runId ?? null, status: "succeeded", changed: options.changed ?? false, recoveryEpoch: options.epoch ?? 2, stateRevision: options.revision ?? 7, snapshotDigest: null, releaseBuildId: "development", sourceRevision: null, planId: options.planId ?? null, errors: [], data })}\n`;',
    'const failure = (command, code, target, status, data = {}, options = {}) => `${JSON.stringify({ schema: "vegastack-labs.dev/run-result", schemaVersion: contractVersion, toolVersion: "0.0.0-dev", command, requestId: requestId(`${command}-${code}`), runId: options.runId ?? null, status, changed: options.changed ?? false, recoveryEpoch: options.epoch ?? 2, stateRevision: options.revision ?? 7, snapshotDigest: null, releaseBuildId: "development", sourceRevision: null, planId: options.planId ?? null, errors: [{ code, target, retryable: false }], data })}\n`;',
    'const httpStatus = { APPROVAL_REQUIRED: 412, AUTHORIZATION_DENIED: 403, DEPENDENCY_UNAVAILABLE: 503, EXECUTION_PARTIAL: 409, INTERRUPTED: 408, PLAN_STALE: 409, RECOVERY_EPOCH_MISMATCH: 409, RECOVERY_REQUIRED: 409 };',
    'const disconnected = new Map();',
    'const respond = (response, payload, statusCode = 200) => { response.writeHead(statusCode, { "Content-Type": "application/json", "Connection": "close" }); response.end(payload); };',
    'const server = http.createServer((request, response) => {',
    '  const chunks = []; request.on("data", (chunk) => chunks.push(chunk));',
    '  request.on("end", () => {',
    '    const body = Buffer.concat(chunks).toString("utf8");',
    '    appendFileSync(requestLog, `${JSON.stringify({ method: request.method, path: request.url, body })}\n`);',
    '    const planMatch = request.url.match(/^\\/api\\/v1\\/plans\\/([^/]+)$/);',
    '    const executeMatch = request.url.match(/^\\/api\\/v1\\/plans\\/([^/]+)\\/execute$/);',
    '    const runMatch = request.url.match(/^\\/api\\/v1\\/runs\\/([^/]+)$/);',
    '    const actionMatch = request.url.match(/^\\/api\\/v1\\/runs\\/([^/]+)\\/(cancel|resume)$/);',
    '    if (request.method === "GET" && request.url === "/api/v1/declarations/declaration-1/revisions/1/plan-preparation") { respond(response, success("api.v1.declarations.plan-preparation.get", { schema: "vegastack-labs.dev/plan-preparation", schemaVersion: "1.0.0", declarationId: "declaration-1", declarationRevision: 1, expectedStateRevision: 6, recoveryEpoch: 2, observationFingerprint: digest("b") }, { revision: 6 })); return; }',
    '    if (request.method === "POST" && request.url === "/api/v1/declarations/declaration-1/plans") { respond(response, success("api.v1.plans.create", presentPlan(planFor()), { changed: true })); return; }',
    '    if (request.method === "GET" && planMatch) { respond(response, success("api.v1.plans.get", presentPlan(planFor(planMatch[1])))); return; }',
    '    if (request.method === "POST" && executeMatch) {',
    '      const planId = executeMatch[1]; const input = JSON.parse(body); const suffix = createHash("sha256").update(["run", planId, input.idempotencyKey].join("\\0")).digest("hex").slice(0, 32); const runId = `run-${suffix}`;',
    '      if (planId === "plan-stale") { respond(response, failure("api.v1.plans.execute", "PLAN_STALE", "plan", "failed"), httpStatus.PLAN_STALE); return; }',
    '      if (planId === "plan-completed") { respond(response, failure("api.v1.plans.execute", "PLAN_STALE", "read", "failed", {}, { epoch: 0, revision: 0 }), httpStatus.PLAN_STALE); return; }',
    '      if (planId === "plan-wrong-epoch") { respond(response, failure("api.v1.plans.execute", "RECOVERY_EPOCH_MISMATCH", "read", "failed", {}, { epoch: 0, revision: 0 }), httpStatus.RECOVERY_EPOCH_MISMATCH); return; }',
    '      if (planId === "plan-ack-missing") { respond(response, failure("api.v1.plans.execute", "APPROVAL_REQUIRED", "acknowledgement", "failed"), httpStatus.APPROVAL_REQUIRED); return; }',
    '      if (planId === "plan-ack-rejected") { respond(response, failure("api.v1.plans.execute", "AUTHORIZATION_DENIED", "acknowledgement", "failed"), httpStatus.AUTHORIZATION_DENIED); return; }',
    '      if (planId === "plan-partial" || planId === "plan-recovery") { const run = runFor(runId, planId, "partial"); const code = planId === "plan-partial" ? "EXECUTION_PARTIAL" : "RECOVERY_REQUIRED"; respond(response, failure("api.v1.plans.execute", code, "run", "partial", present(run), { runId, planId, changed: true }), httpStatus[code]); return; }',
    '      if (planId.startsWith("plan-disconnect-")) { disconnected.set(runId, planId); response.writeHead(200, { "Content-Type": "application/json", "Content-Length": "4096" }); response.write("{\\\"durableRunAccepted\\\":true"); response.socket.destroy(); return; }',
    '      const run = runFor(runId, planId); respond(response, success("api.v1.plans.execute", present(run), { runId, planId, changed: run.changed })); return;',
    '    }',
    '    if (request.method === "GET" && runMatch) {',
    '      const runId = runMatch[1]; const disconnectedPlan = disconnected.get(runId);',
    '      if (disconnectedPlan === "plan-disconnect-unknown") { respond(response, failure("api.v1.runs.get", "DEPENDENCY_UNAVAILABLE", "read", "failed", {}, { epoch: 0, revision: 0 }), 503); return; }',
    '      if (disconnectedPlan === "plan-disconnect-success") { const run = runFor(runId, disconnectedPlan); respond(response, success("api.v1.runs.get", present(run), { runId, planId: disconnectedPlan })); return; }',
    '      const named = { "run-running": "running", "run-partial": "partial", "run-cancel": "running", "run-resume": "interrupted" }[runId];',
    '      if (named !== undefined) { const run = runFor(runId, "plan-1", named); respond(response, success("api.v1.runs.get", present(run), { runId, planId: "plan-1" })); return; }',
    '    }',
    '    if (request.method === "POST" && actionMatch) { const [runId, action] = actionMatch.slice(1); const status = action === "cancel" ? "cancelled" : "running"; const run = runFor(runId, "plan-1", status); if (action === "cancel") respond(response, failure("api.v1.runs.cancel", "INTERRUPTED", "run", "cancelled", present(run), { runId, planId: "plan-1" }), httpStatus.INTERRUPTED); else respond(response, success("api.v1.runs.resume", present(run), { runId, planId: "plan-1" })); return; }',
    '    response.writeHead(404); response.end();',
    '  });',
    '});',
    'server.listen(socketPath);',
    'process.on("SIGTERM", () => server.close(() => process.exit(0)));',
    '',
  ].join("\n"));

  const fixture = spawn(process.execPath, [
    serverScript, socketPath, requestLog, CONTRACT_VERSION, fixturePlanCreatedAt, fixturePlanExpiresAt,
  ], { stdio: "ignore" });
  t.after(() => fixture.kill("SIGTERM"));
  const deadline = Date.now() + 5000;
  while (true) {
    try { await access(socketPath, constants.F_OK); break; } catch {}
    if (Date.now() > deadline) throw new Error("Phase 4 fixture API did not become ready");
    await new Promise((resolve) => setTimeout(resolve, 10));
  }

  async function allRequests() {
    const raw = await readFile(requestLog, "utf8");
    return raw === "" ? [] : raw.trim().split("\n").map(JSON.parse);
  }

  async function invoke(args) {
    const before = (await allRequests()).length;
    const result = run(binary, args);
    const requests = (await allRequests()).slice(before);
    return { result, requests };
  }

  function machineResult(result, exitCode) {
    assert.equal(result.code, exitCode, JSON.stringify(result));
    assert.equal(result.stderr, "");
    assert.equal((result.stdout.match(/\n/g) ?? []).length, 1);
    assert.ok(result.stdout.endsWith("\n"));
    const envelope = JSON.parse(result.stdout);
    assert.equal(`${JSON.stringify(envelope)}\n`, result.stdout, "server JSON bytes must pass through unchanged");
    assert.equal(envelope.schema, "vegastack-labs.dev/run-result");
    assert.equal(envelope.schemaVersion, CONTRACT_VERSION);
    return envelope;
  }

  function assertGet(request, expectedPath) {
    assert.deepEqual(request, { method: "GET", path: expectedPath, body: "" });
  }

  function exactRequest(request, expectedPath, template) {
    assert.equal(request.method, "POST");
    assert.equal(request.path, expectedPath);
    const input = JSON.parse(request.body);
    assert.match(input.idempotencyKey, /^request-[0-9a-f]{32}$/);
    assert.equal(request.body, template.replace("<request-id>", input.idempotencyKey));
    return input;
  }

  function assertApplyRequests(requests, planId, template) {
    assert.equal(requests.length, 2);
    assertGet(requests[0], `/api/v1/plans/${planId}`);
    return exactRequest(
      requests[1],
      `/api/v1/plans/${planId}/execute`,
      template.replaceAll("plan-1", planId),
    );
  }

  const golden = JSON.parse(
    await readFile(path.join(ROOT, "internal/cli/testdata/phase4.golden.json"), "utf8"),
  );

  // Planning reads exact server-owned bindings first. Human and JSON modes expose
  // the same returned plan while preserving the two exact request bodies.
  for (const output of ["human", "json"]) {
    const args = ["plan", "--declaration-id", "declaration-1", "--revision", "1", "--config", profilePath];
    if (output === "json") args.push("--output", "json");
    const { result, requests } = await invoke(args);
    assert.equal(requests.length, 2);
    assertGet(requests[0], "/api/v1/declarations/declaration-1/revisions/1/plan-preparation");
    const input = exactRequest(requests[1], "/api/v1/declarations/declaration-1/plans", golden.requests.plan);
    assert.deepEqual(
      { expectedStateRevision: input.expectedStateRevision, recoveryEpoch: input.recoveryEpoch, observationFingerprint: input.observationFingerprint },
      { expectedStateRevision: 6, recoveryEpoch: 2, observationFingerprint: `sha256:${"b".repeat(64)}` },
    );
    if (output === "human") {
      assert.deepEqual(result, {
        code: golden.exits.success,
        stdout: golden.human.plan.replace("<plan-expires-at>", fixturePlanExpiresAt),
        stderr: "",
      });
    } else {
      const envelope = machineResult(result, golden.exits.success);
      assert.equal(envelope.command, "api.v1.plans.create");
      assert.equal(envelope.data.plan.planId, "plan-1");
      assert.equal(envelope.data.plan.binding.observationFingerprint, `sha256:${"b".repeat(64)}`);
      assert.equal(envelope.data.plan.operations[0].targetId, "target-1");
      assert.equal(envelope.data.readablePlan, "fixture readable plan");
      assert.equal(envelope.data.canonicalPlan, JSON.stringify(envelope.data.plan));
    }
  }

  // A normal apply returns the server-owned durable run. The executable submits
  // once, and human output is a rendering of those same facts.
  const normalJSON = await invoke(["apply", "--plan-id", "plan-normal", "--config", profilePath, "--output", "json"]);
  const normalInput = assertApplyRequests(normalJSON.requests, "plan-normal", golden.requests.apply);
  const normalEnvelope = machineResult(normalJSON.result, golden.exits.success);
  assert.equal(normalEnvelope.data.run.status, "running");
  assert.equal(normalEnvelope.data.incompleteWork[0].targetId, "target-1");
  assert.equal(normalEnvelope.data.incompleteWork[0].progressState, "started");
  assert.equal(normalEnvelope.data.nextSafeAction, "inspect or cancel through the server");
  const normalRunId = `run-${createHash("sha256").update(["run", "plan-normal", normalInput.idempotencyKey].join("\0")).digest("hex").slice(0, 32)}`;
  assert.equal(normalEnvelope.runId, normalRunId);
  assert.equal(normalEnvelope.data.run.runId, normalRunId);

  const normalHuman = await invoke(["apply", "--plan-id", "plan-normal", "--config", profilePath]);
  const normalHumanInput = assertApplyRequests(normalHuman.requests, "plan-normal", golden.requests.apply);
  const normalHumanRunId = `run-${createHash("sha256").update(["run", "plan-normal", normalHumanInput.idempotencyKey].join("\0")).digest("hex").slice(0, 32)}`;
  assert.deepEqual(normalHuman.result, {
    code: golden.exits.success,
    stdout: golden.human.runRunning.replace("<run-id>", normalHumanRunId),
    stderr: "",
  });

  // A fresh submission of an already-completed plan is stale because the first
  // durable run advanced state. This is distinct from an exact idempotency replay,
  // which the server returns as the same successful durable run.
  for (const output of ["human", "json"]) {
    const args = ["apply", "--plan-id", "plan-completed", "--config", profilePath];
    if (output === "json") args.push("--output", "json");
    const completed = await invoke(args);
    assertApplyRequests(completed.requests, "plan-completed", golden.requests.apply);
    if (output === "human") {
      assert.deepEqual(completed.result, {
        code: golden.exits.alreadyCompleted,
        stdout: "",
        stderr: golden.human.alreadyCompletedStderr,
      });
    } else {
      const envelope = machineResult(completed.result, golden.exits.alreadyCompleted);
      assert.deepEqual(envelope.errors, [{ code: "PLAN_STALE", target: "read", retryable: false }]);
      assert.deepEqual(envelope.data, {});
      assert.equal(envelope.runId, null);
      assert.equal(envelope.planId, null);
      assert.equal(envelope.status, "failed");
      assert.equal(envelope.changed, false);
      assert.equal(envelope.recoveryEpoch, 0);
      assert.equal(envelope.stateRevision, 0);
    }
  }

  // Recovery may advance after the plan read but before execute. The built CLI
  // must preserve the server's RECOVERY_EPOCH_MISMATCH envelope and exit in both
  // output modes without inventing run state.
  for (const output of ["human", "json"]) {
    const args = ["apply", "--plan-id", "plan-wrong-epoch", "--config", profilePath];
    if (output === "json") args.push("--output", "json");
    const mismatched = await invoke(args);
    assertApplyRequests(mismatched.requests, "plan-wrong-epoch", golden.requests.apply);
    if (output === "human") {
      assert.deepEqual(mismatched.result, {
        code: golden.exits.wrongRecoveryEpoch,
        stdout: "",
        stderr: golden.human.wrongRecoveryEpochStderr,
      });
    } else {
      const envelope = machineResult(mismatched.result, golden.exits.wrongRecoveryEpoch);
      assert.deepEqual(envelope.errors, [{ code: "RECOVERY_EPOCH_MISMATCH", target: "read", retryable: false }]);
      assert.deepEqual(envelope.data, {});
      assert.equal(envelope.runId, null);
      assert.equal(envelope.planId, null);
      assert.equal(envelope.status, "failed");
      assert.equal(envelope.changed, false);
      assert.equal(envelope.recoveryEpoch, 0);
      assert.equal(envelope.stateRevision, 0);
    }
  }

  // Authorization and freshness failures carry no invented run data and keep
  // the server's stable error, stream, and exit mappings byte-for-byte.
  for (const scenario of [
    { planId: "plan-stale", code: "PLAN_STALE", target: "plan", exit: golden.exits.stale },
    { planId: "plan-ack-missing", code: "APPROVAL_REQUIRED", target: "acknowledgement", exit: golden.exits.missingAcknowledgement },
    { planId: "plan-ack-rejected", code: "AUTHORIZATION_DENIED", target: "acknowledgement", exit: golden.exits.rejected },
  ]) {
    const invoked = await invoke(["apply", "--plan-id", scenario.planId, "--config", profilePath, "--output", "json"]);
    assertApplyRequests(invoked.requests, scenario.planId, golden.requests.apply);
    const envelope = machineResult(invoked.result, scenario.exit);
    assert.deepEqual(envelope.errors, [{ code: scenario.code, target: scenario.target, retryable: false }]);
    assert.deepEqual(envelope.data, {});
    assert.equal(envelope.runId, null);
  }

  // Partial execution and recovery-required results preserve the complete run
  // body instead of collapsing it into a generic error.
  for (const scenario of [
    { planId: "plan-partial", code: "EXECUTION_PARTIAL", exit: golden.exits.partial },
    { planId: "plan-recovery", code: "RECOVERY_REQUIRED", exit: golden.exits.recoveryRequired },
  ]) {
    const invoked = await invoke(["apply", "--plan-id", scenario.planId, "--config", profilePath, "--output", "json"]);
    const input = assertApplyRequests(invoked.requests, scenario.planId, golden.requests.apply);
    const envelope = machineResult(invoked.result, scenario.exit);
    const expectedRunId = `run-${createHash("sha256").update(["run", scenario.planId, input.idempotencyKey].join("\0")).digest("hex").slice(0, 32)}`;
    assert.deepEqual(envelope.errors, [{ code: scenario.code, target: "run", retryable: false }]);
    assert.equal(envelope.runId, expectedRunId);
    assert.equal(envelope.data.run.runId, expectedRunId);
    assert.equal(envelope.data.run.status, "partial");
    assert.equal(envelope.data.completedWork[0].status, "succeeded");
    assert.equal(envelope.data.incompleteWork[0].progressState, "unknown");
    assert.equal(envelope.data.run.rollbackStatus, "required");
    assert.equal(envelope.data.run.verificationStatus, "incomplete");
    assert.equal(envelope.data.nextSafeAction, "recovery required; inspect the durable run");
  }

  // Inspect uses one exact GET. Human and JSON modes expose the same partial
  // step, verification, rollback, and next-action facts from the response.
  const partialHuman = await invoke(["run", "inspect", "--run-id", "run-partial", "--config", profilePath]);
  assert.deepEqual(partialHuman.requests, [{ method: "GET", path: "/api/v1/runs/run-partial", body: "" }]);
  assert.deepEqual(partialHuman.result, { code: 0, stdout: golden.human.runPartial, stderr: "" });
  const partialJSON = await invoke(["run", "inspect", "--run-id", "run-partial", "--config", profilePath, "--output", "json"]);
  assert.deepEqual(partialJSON.requests, [{ method: "GET", path: "/api/v1/runs/run-partial", body: "" }]);
  const partialInspectEnvelope = machineResult(partialJSON.result, 0);
  assert.equal(partialInspectEnvelope.data.run.status, "partial");
  assert.equal(partialInspectEnvelope.data.run.steps.length, 2);
  assert.equal(partialInspectEnvelope.data.run.rollbackStatus, "required");
  assert.equal(partialInspectEnvelope.data.run.verificationStatus, "incomplete");
  assert.equal(partialInspectEnvelope.data.completedWork.length, 1);
  assert.equal(partialInspectEnvelope.data.incompleteWork.length, 1);

  // Cancel and resume both inspect first, then send one exact server mutation.
  // A cancelled/interrupted result retains its durable run while exiting 9.
  const cancelled = await invoke(["run", "cancel", "--run-id", "run-cancel", "--config", profilePath, "--output", "json"]);
  assert.equal(cancelled.requests.length, 2);
  assertGet(cancelled.requests[0], "/api/v1/runs/run-cancel");
  const cancelInput = exactRequest(cancelled.requests[1], "/api/v1/runs/run-cancel/cancel", golden.requests.cancel);
  assert.equal(cancelInput.recoveryEpoch, 2);
  const cancelledEnvelope = machineResult(cancelled.result, golden.exits.cancelled);
  assert.equal(cancelledEnvelope.errors[0].code, "INTERRUPTED");
  assert.equal(cancelledEnvelope.data.run.status, "cancelled");
  assert.equal(cancelledEnvelope.data.run.cancellationRequested, true);
  assert.equal(cancelledEnvelope.data.nextSafeAction, "inspect before creating another plan");

  const resumed = await invoke(["run", "resume", "--run-id", "run-resume", "--config", profilePath, "--output", "json"]);
  assert.equal(resumed.requests.length, 2);
  assertGet(resumed.requests[0], "/api/v1/runs/run-resume");
  const resumeInput = exactRequest(resumed.requests[1], "/api/v1/runs/run-resume/resume", golden.requests.resume);
  assert.equal(resumeInput.recoveryEpoch, 2);
  const resumedEnvelope = machineResult(resumed.result, golden.exits.success);
  assert.equal(resumedEnvelope.data.run.status, "running");
  assert.equal(resumedEnvelope.data.incompleteWork[0].progressState, "started");

  // A submit disconnect permits exactly one deterministic inspection and never
  // another POST. One case finds the durable run; the other remains unknown.
  const recovered = await invoke(["apply", "--plan-id", "plan-disconnect-success", "--config", profilePath, "--output", "json"]);
  assert.equal(recovered.requests.length, 3);
  assertGet(recovered.requests[0], "/api/v1/plans/plan-disconnect-success");
  const recoveredInput = exactRequest(
    recovered.requests[1],
    "/api/v1/plans/plan-disconnect-success/execute",
    golden.requests.apply.replaceAll("plan-1", "plan-disconnect-success"),
  );
  const recoveredRunId = `run-${createHash("sha256").update(["run", "plan-disconnect-success", recoveredInput.idempotencyKey].join("\0")).digest("hex").slice(0, 32)}`;
  assertGet(recovered.requests[2], `/api/v1/runs/${recoveredRunId}`);
  assert.equal(recovered.requests.filter((request) => request.method === "POST").length, 1);
  const recoveredEnvelope = machineResult(recovered.result, 0);
  assert.equal(recoveredEnvelope.runId, recoveredRunId);
  assert.equal(recoveredEnvelope.data.run.runId, recoveredRunId);

  const unknown = await invoke(["apply", "--plan-id", "plan-disconnect-unknown", "--config", profilePath, "--output", "json"]);
  assert.equal(unknown.requests.length, 3);
  assertGet(unknown.requests[0], "/api/v1/plans/plan-disconnect-unknown");
  const unknownInput = exactRequest(
    unknown.requests[1],
    "/api/v1/plans/plan-disconnect-unknown/execute",
    golden.requests.apply.replaceAll("plan-1", "plan-disconnect-unknown"),
  );
  const unknownRunId = `run-${createHash("sha256").update(["run", "plan-disconnect-unknown", unknownInput.idempotencyKey].join("\0")).digest("hex").slice(0, 32)}`;
  assertGet(unknown.requests[2], `/api/v1/runs/${unknownRunId}`);
  assert.equal(unknown.requests.filter((request) => request.method === "POST").length, 1);
  const unknownEnvelope = machineResult(unknown.result, golden.exits.disconnectUnknown);
  assert.equal(unknownEnvelope.runId, unknownRunId);
  assert.equal(unknownEnvelope.errors[0].code, "DEPENDENCY_UNAVAILABLE");
  assert.equal(unknownEnvelope.errors[0].target, "control-service");
  assert.deepEqual(unknownEnvelope.data, { runId: unknownRunId, action: "inspect-only", command: "run inspect" });
});

test("built CLI uses the same API frame through a constrained SSH profile", async (t) => {
  const temporary = await realpath(await mkdtemp(path.join(tmpdir(), "vegastack-cli-remote-")));
  t.after(() => rm(temporary, { recursive: true, force: true }));
  const binary = path.join(temporary, "vsk-labs");
  const ssh = path.join(temporary, "ssh");
  const capture = path.join(temporary, "capture.json");
  const knownHostsPath = path.join(temporary, "known-hosts.literal");
  const profilePath = path.join(temporary, "remote profile.json");
  const helperSource = path.join(temporary, "ssh.go");
  await writeFile(helperSource, `package main
import ("bufio"; "encoding/json"; "io"; "os")
type requestHeader struct { Protocol string \`json:"protocol"\`; Version string \`json:"version"\`; RequestID string \`json:"requestId"\`; SSHPrincipalID string \`json:"sshPrincipalId"\`; DeviceID string \`json:"deviceId"\`; Operation string \`json:"operation"\`; Arguments []string \`json:"arguments"\`; PayloadDigest string \`json:"payloadDigest"\`; DeclaredPayloadBytes int64 \`json:"declaredPayloadBytes"\`; ActualPayloadBytes int64 \`json:"actualPayloadBytes"\`; RecoveryEpoch int64 \`json:"recoveryEpoch"\` }
type responseHeader struct { Protocol string \`json:"protocol"\`; Version string \`json:"version"\`; RequestID string \`json:"requestId"\`; DeclaredPayloadBytes int64 \`json:"declaredPayloadBytes"\`; ActualPayloadBytes int64 \`json:"actualPayloadBytes"\` }
type runResult struct { Schema string \`json:"schema"\`; SchemaVersion string \`json:"schemaVersion"\`; ToolVersion string \`json:"toolVersion"\`; Command string \`json:"command"\`; RequestID string \`json:"requestId"\`; RunID any \`json:"runId"\`; Status string \`json:"status"\`; Changed bool \`json:"changed"\`; RecoveryEpoch int64 \`json:"recoveryEpoch"\`; StateRevision int64 \`json:"stateRevision"\`; SnapshotDigest any \`json:"snapshotDigest"\`; ReleaseBuildID string \`json:"releaseBuildId"\`; SourceRevision any \`json:"sourceRevision"\`; PlanID any \`json:"planId"\`; Errors []any \`json:"errors"\`; Data any \`json:"data"\` }
func main(){ reader:=bufio.NewReader(os.Stdin); line,err:=reader.ReadBytes('\\n'); if err!=nil { os.Exit(2) }; var header requestHeader; if json.Unmarshal(line[:len(line)-1],&header)!=nil { os.Exit(2) }; payload:=make([]byte,header.DeclaredPayloadBytes); if _,err=io.ReadFull(reader,payload); err!=nil { os.Exit(2) }; encoded,_:=json.Marshal(struct{Arguments []string \`json:"arguments"\`; Header requestHeader \`json:"header"\`; Payload string \`json:"payload"\`}{os.Args[1:],header,string(payload)}); _=os.WriteFile(os.Getenv("VSK_CAPTURE"),encoded,0600); command:="server status"; data:=any(map[string]any{"state":"ready","readAvailable":true,"mutationAvailable":false,"recoveryEpoch":2,"stateRevision":7,"remoteReadState":"disabled","remoteReadReason":"none"}); if header.Operation=="GET /api/v1/summary" { command="api.v1.summary.get"; data=map[string]any{"databaseMode":"read-write","readAvailable":true,"mutationAvailable":false,"draftCount":0,"validDraftCount":0,"blockedDraftCount":0,"lastEventId":0,"recoveryEpoch":2,"stateRevision":7,"sourceCounts":map[string]any{"total":7,"healthy":0,"stale":0,"unknown":0,"unavailable":7,"failed":0},"worstSourceState":"unavailable"} }; envelope,_:=json.Marshal(runResult{"vegastack-labs.dev/run-result","${CONTRACT_VERSION}","0.0.0-dev",command,header.RequestID,nil,"succeeded",false,2,7,nil,"development",nil,nil,[]any{},data}); envelope=append(envelope,'\\n'); response:=responseHeader{"vegastack-labs.api-ssh","1.0.0",header.RequestID,int64(len(envelope)),int64(len(envelope))}; raw,_:=json.Marshal(response); os.Stdout.Write(append(raw,'\\n')); os.Stdout.Write(envelope) }
`);
  for (const [output, target] of [[binary, "./cmd/vsk-labs"], [ssh, helperSource]]) {
    const built = spawnSync("go", ["build", "-o", output, target], { cwd: ROOT, encoding: "utf8", shell: false });
    assert.equal(built.status, 0, built.stderr);
  }
  await writeFile(knownHostsPath, "control ssh-ed25519 synthetic\n");
  await chmod(knownHostsPath, 0o600);
  await writeFile(profilePath, `${JSON.stringify({
    schema: "vegastack-labs.dev/client-profile", schemaVersion: "1.0.0",
    transport: { kind: "constrained-ssh", executable: ssh, destination: "operator@control-plane", knownHostsPath, sshPrincipalId: "principal.operator", deviceId: "device.operator", recoveryEpoch: 2 },
  })}\n`);
  await chmod(profilePath, 0o600);
  const oldPath = process.env.PATH;
  const oldCapture = process.env.VSK_CAPTURE;
  // The protected absolute executable must remain usable even when PATH cannot
  // resolve ssh; this also proves a PATH-precedence binary cannot intercept it.
  process.env.PATH = path.join(temporary, "empty-path");
  process.env.VSK_CAPTURE = capture;
  t.after(() => { process.env.PATH = oldPath; if (oldCapture === undefined) delete process.env.VSK_CAPTURE; else process.env.VSK_CAPTURE = oldCapture; });
  const result = run(binary, ["server", "status", "--config", profilePath, "--output", "json"]);
  assert.equal(result.code, 0, JSON.stringify(result));
  assert.equal(result.stderr, "");
  const resultEnvelope = JSON.parse(result.stdout);
  assert.equal(resultEnvelope.command, "server status");
  assert.match(resultEnvelope.requestId, /^request-[0-9a-f]{32}$/);
  assert.equal(resultEnvelope.recoveryEpoch, 2);
  assert.equal(resultEnvelope.stateRevision, 7);
  const recorded = JSON.parse(await readFile(capture, "utf8"));
  assert.deepEqual(recorded.arguments, [
    "-F", "none", "-T",
    "-o", "AddKeysToAgent=no",
    "-o", "BatchMode=yes",
    "-o", "CanonicalizeHostname=no",
    "-o", "CheckHostIP=yes",
    "-o", "ClearAllForwardings=yes",
    "-o", "ControlMaster=no",
    "-o", "EscapeChar=none",
    "-o", "ExitOnForwardFailure=yes",
    "-o", "ForwardAgent=no",
    "-o", "ForwardX11=no",
    "-o", "GatewayPorts=no",
    "-o", "GlobalKnownHostsFile=none",
    "-o", "HostbasedAuthentication=no",
    "-o", "IdentityAgent=none",
    "-o", "IdentitiesOnly=yes",
    "-o", "KbdInteractiveAuthentication=no",
    "-o", "PasswordAuthentication=no",
    "-o", "PermitLocalCommand=no",
    "-o", "ProxyCommand=none",
    "-o", "ProxyJump=none",
    "-o", "RemoteCommand=none",
    "-o", "RequestTTY=no",
    "-o", "StrictHostKeyChecking=yes",
    "-o", "UpdateHostKeys=no",
    "-o", `UserKnownHostsFile=${knownHostsPath}`,
    "-o", "VerifyHostKeyDNS=no",
    "operator@control-plane",
  ]);
  assert.equal(recorded.header.protocol, "vegastack-labs.api-ssh");
  assert.equal(recorded.header.version, "1.0.0");
  assert.equal(recorded.header.requestId, resultEnvelope.requestId);
  assert.equal(recorded.header.sshPrincipalId, "principal.operator");
  assert.equal(recorded.header.deviceId, "device.operator");
  assert.equal(recorded.header.operation, "GET /api/v1/health");
  assert.deepEqual(recorded.header.arguments, ["server", "status"]);
  assert.equal(recorded.header.recoveryEpoch, 2);
  assert.equal(recorded.header.declaredPayloadBytes, 0);
  assert.equal(recorded.header.actualPayloadBytes, 0);
  assert.equal(recorded.header.payloadDigest, `sha256:${createHash("sha256").update("").digest("hex")}`);
  assert.equal(recorded.payload, "");

  const summary = run(binary, ["status", "--config", profilePath, "--output", "json"]);
  assert.equal(summary.code, 0, JSON.stringify(summary));
  assert.equal(summary.stderr, "");
  const summaryEnvelope = JSON.parse(summary.stdout);
  assert.equal(summaryEnvelope.command, "api.v1.summary.get");
  assert.equal(summaryEnvelope.recoveryEpoch, 2);
  assert.equal(summaryEnvelope.data.databaseMode, "read-write");
  const recordedSummary = JSON.parse(await readFile(capture, "utf8"));
  assert.equal(recordedSummary.header.requestId, summaryEnvelope.requestId);
  assert.equal(recordedSummary.header.operation, "GET /api/v1/summary");
  assert.deepEqual(recordedSummary.header.arguments, ["--output", "json"]);
});

test("built server api-ssh forced command verifies and forwards one framed operation", async (t) => {
  if (process.platform !== "linux" || typeof process.getuid !== "function") return;
  const temporary = await mkdtemp(path.join(tmpdir(), "vegastack-api-ssh-handler-"));
  t.after(() => rm(temporary, { recursive: true, force: true }));
  const binary = path.join(temporary, "vsk-labs");
  const helper = path.join(temporary, "local-api");
  const helperSource = path.join(temporary, "local-api.go");
  const socketPath = path.join(temporary, "control.sock");
  const capturePath = path.join(temporary, "requests.json");
  const exportRoot = path.join(temporary, "exports");
  const profilePath = path.join(temporary, "server-profile.json");
  await mkdir(exportRoot, { mode: 0o700 });
  await chmod(exportRoot, 0o700);
  await writeFile(helperSource, `package main
import ("bufio"; "encoding/json"; "fmt"; "net"; "net/http"; "os")
type result struct { Schema string \`json:"schema"\`; SchemaVersion string \`json:"schemaVersion"\`; ToolVersion string \`json:"toolVersion"\`; Command string \`json:"command"\`; RequestID string \`json:"requestId"\`; RunID any \`json:"runId"\`; Status string \`json:"status"\`; Changed bool \`json:"changed"\`; RecoveryEpoch int64 \`json:"recoveryEpoch"\`; StateRevision int64 \`json:"stateRevision"\`; SnapshotDigest any \`json:"snapshotDigest"\`; ReleaseBuildID string \`json:"releaseBuildId"\`; SourceRevision any \`json:"sourceRevision"\`; PlanID any \`json:"planId"\`; Errors []any \`json:"errors"\`; Data any \`json:"data"\` }
func main(){ listener,err:=net.Listen("unix",os.Args[1]); if err!=nil { panic(err) }; defer listener.Close(); _=os.Chmod(os.Args[1],0600); seen:=[]string{}; for index:=0; index<2; index++ { connection,err:=listener.Accept(); if err!=nil { panic(err) }; request,err:=http.ReadRequest(bufio.NewReader(connection)); if err!=nil { panic(err) }; seen=append(seen,request.Method+" "+request.URL.Path); envelope,_:=json.Marshal(result{"vegastack-labs.dev/run-result","${CONTRACT_VERSION}","0.0.0-dev","server status",fmt.Sprintf("request-local-%d",index),nil,"succeeded",false,2,7,nil,"development",nil,nil,[]any{},map[string]any{"state":"ready","readAvailable":true,"mutationAvailable":false,"recoveryEpoch":2,"stateRevision":7,"remoteReadState":"disabled","remoteReadReason":"none"}}); envelope=append(envelope,'\\n'); fmt.Fprintf(connection,"HTTP/1.1 200 OK\\r\\nContent-Type: application/json\\r\\nContent-Length: %d\\r\\nConnection: close\\r\\n\\r\\n",len(envelope)); _,_=connection.Write(envelope); _=connection.Close() }; raw,_:=json.Marshal(seen); _=os.WriteFile(os.Args[2],raw,0600) }
`);
  for (const [output, target] of [[binary, "./cmd/vsk-labs"], [helper, helperSource]]) {
    const built = spawnSync("go", ["build", "-o", output, target], { cwd: ROOT, encoding: "utf8", shell: false });
    assert.equal(built.status, 0, built.stderr);
  }
  await writeFile(profilePath, `${JSON.stringify({
    schema: "vegastack-labs.dev/server-profile", schemaVersion: "1.1.0",
    socketPath, socketOwnerUid: process.getuid(), socketGroupGid: null, socketMode: "0600", shutdownGraceSeconds: 5,
    principalBindings: [{ uid: process.getuid(), principalId: "principal.operator" }], inventoryExportRoot: exportRoot,
    remoteRead: { enabled: false, bindAddress: null, publicOrigin: null, tlsCertificatePath: null, tlsPrivateKeyPath: null, identityAdapter: null, identityConfigPath: null },
  })}\n`);
  await chmod(profilePath, 0o600);
  const localServer = spawn(helper, [socketPath, capturePath], { cwd: ROOT, stdio: "ignore", shell: false });
  t.after(() => { if (localServer.exitCode === null) localServer.kill("SIGKILL"); });
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try { await access(socketPath, constants.F_OK); break; } catch {
      if (attempt === 99) assert.fail("local API fixture did not create its socket");
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
  }
  const requestId = "request-forced-handler";
  const header = {
    protocol: "vegastack-labs.api-ssh", version: "1.0.0", requestId,
    sshPrincipalId: "principal.operator", deviceId: "device.operator", operation: "GET /api/v1/health",
    arguments: ["server", "status"], payloadDigest: `sha256:${createHash("sha256").update("").digest("hex")}`,
    declaredPayloadBytes: 0, actualPayloadBytes: 0, recoveryEpoch: 2,
  };
  const invoked = spawnSync(binary, ["server", "api-ssh", "--config", profilePath, "--ssh-principal-id", "principal.operator", "--device-id", "device.operator"], {
    cwd: ROOT, encoding: "utf8", shell: false, input: `${JSON.stringify(header)}\n`,
  });
  assert.deepEqual({ status: invoked.status, signal: invoked.signal, stderr: invoked.stderr }, { status: 0, signal: null, stderr: "" });
  const separator = invoked.stdout.indexOf("\n");
  assert.ok(separator > 0);
  const responseHeader = JSON.parse(invoked.stdout.slice(0, separator));
  const payload = invoked.stdout.slice(separator + 1);
  assert.deepEqual(responseHeader, {
    protocol: "vegastack-labs.api-ssh", version: "1.0.0", requestId,
    declaredPayloadBytes: Buffer.byteLength(payload), actualPayloadBytes: Buffer.byteLength(payload),
  });
  const envelope = JSON.parse(payload);
  assert.equal(envelope.command, "server status");
  assert.equal(envelope.requestId, requestId);
  assert.equal(envelope.recoveryEpoch, 2);
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try { await access(capturePath, constants.F_OK); break; } catch {
      if (attempt === 99) assert.fail("local API fixture did not finish");
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
  }
  assert.deepEqual(JSON.parse(await readFile(capturePath, "utf8")), ["GET /api/v1/health", "GET /api/v1/health"]);
});
