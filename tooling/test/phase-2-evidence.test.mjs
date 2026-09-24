import assert from "node:assert/strict";
import { cp, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { collectIntegratedFacts, postPhase2MutationBoundaryDigest, postPhase2MutationBoundaryFiles, postPhase2SourceOverride, validateEvidence } from "../verify-phase-2.mjs";

const ROOT = path.resolve(import.meta.dirname, "../..");

async function loadManifest() {
  return JSON.parse(await readFile(path.join(ROOT, "tooling/phase-2-evidence.json"), "utf8"));
}

test("the original Phase 2 baseline stays immutable while Phase 5 waves through #109 have exact reviewed closures", async () => {
  const manifest = await loadManifest();
  const facts = await collectIntegratedFacts(ROOT);
  assert.equal(manifest.contract.postPhase2MutationBoundaryDigest, "sha256:e530e3139c9f06995389c39c28dc2c9758f96030c073c40e1b5000d44d32994c");
  assert.equal(manifest.contract.productionDependencyDigest, "sha256:a9e8788558fa5c3347b5b8464d8d5e4a67dcc9357e5ae07478b606a806f78133");
  assert.equal(manifest.contract.mutationAvailable, false);
  assert.equal(manifest.contract.reviewedWaves?.length, 27);
  assert.equal(manifest.contract.reviewedWaves[0].id, "phase5-issue104-v1");
  assert.deepEqual(manifest.contract.reviewedWaves[0].commands, ["gate check", "gate evidence", "gate inspect", "gate list", "gate profile draft"]);
  assert.deepEqual(manifest.contract.reviewedWaves[0].imports, ["github.com/vegastack/vegastack-labs/internal/gate"]);
  assert.equal(manifest.contract.reviewedWaves[1].id, "phase5-issue123-v1");
  assert.equal(manifest.contract.reviewedWaves[1].issue, 123);
  assert.deepEqual(manifest.contract.reviewedWaves[1].commands, []);
  assert.deepEqual(manifest.contract.reviewedWaves[1].imports, [
    "github.com/vegastack/vegastack-labs/internal/adapter/nativecredential",
    "github.com/vegastack/vegastack-labs/internal/adapter/onepassword",
  ]);
  // #128 re-sealed the boundary after the design-system 0.9.1 embedded-asset refresh:
  // no new command, no new import, only the new boundary digest.
  assert.equal(manifest.contract.reviewedWaves[2].id, "designsystem-issue128-v1");
  assert.equal(manifest.contract.reviewedWaves[2].issue, 128);
  assert.deepEqual(manifest.contract.reviewedWaves[2].commands, []);
  assert.deepEqual(manifest.contract.reviewedWaves[2].imports, []);
  // #124 credential-import wave carries the head-closure digest at its landing.
  assert.equal(manifest.contract.reviewedWaves[3].id, "phase5-issue124-v1");
  assert.equal(manifest.contract.reviewedWaves[3].issue, 124);
  assert.deepEqual(manifest.contract.reviewedWaves[3].commands, ["credential import"]);
  assert.deepEqual(manifest.contract.reviewedWaves[3].imports, []);
  // #107 audit read wave preserves the historical main closure digest.
  assert.equal(manifest.contract.reviewedWaves[4].id, "phase5-issue107-v1");
  assert.equal(manifest.contract.reviewedWaves[4].issue, 107);
  assert.deepEqual(manifest.contract.reviewedWaves[4].commands, ["audit checkpoints", "audit verify"]);
  // #125 credential lifecycle EXECUTION CORE lands last: no available command and no
  // new import (its five commands and endpoint are deferred to a Task-5 follow-up),
  // carrying only the added lifecycle source in the combined head-closure digest.
  assert.equal(manifest.contract.reviewedWaves[5].id, "phase5-issue125-v1");
  assert.equal(manifest.contract.reviewedWaves[5].issue, 125);
  assert.deepEqual(manifest.contract.reviewedWaves[5].commands, []);
  assert.deepEqual(manifest.contract.reviewedWaves[4].imports, []);
  assert.deepEqual(manifest.contract.reviewedWaves[5].imports, []);
  assert.equal(manifest.contract.reviewedWaves[6].id, "phase5-issue132-v1");
  assert.equal(manifest.contract.reviewedWaves[6].issue, 132);
  assert.deepEqual(manifest.contract.reviewedWaves[6].commands, ["credential activate", "credential recover", "credential revoke", "credential rotate", "credential stage"]);
  assert.deepEqual(manifest.contract.reviewedWaves[6].imports, []);
  assert.equal(manifest.contract.reviewedWaves[7].id, "phase5-issue133-v1");
  assert.equal(manifest.contract.reviewedWaves[7].issue, 133);
  assert.deepEqual(manifest.contract.reviewedWaves[7].commands, []);
  assert.deepEqual(manifest.contract.reviewedWaves[7].imports, []);
  assert.equal(manifest.contract.reviewedWaves[8].id, "phase5-issue134-v1");
  assert.equal(manifest.contract.reviewedWaves[8].issue, 134);
  assert.deepEqual(manifest.contract.reviewedWaves[8].commands, []);
  assert.deepEqual(manifest.contract.reviewedWaves[8].imports, []);
  assert.equal(manifest.contract.reviewedWaves[9].id, "phase5-issue106-v1");
  assert.deepEqual(manifest.contract.reviewedWaves[9].commands, ["backup policy draft"]);
  assert.deepEqual(manifest.contract.reviewedWaves[9].imports, [
    "github.com/vegastack/vegastack-labs/internal/adapter/localbackup",
    "github.com/vegastack/vegastack-labs/internal/backup",
    "github.com/vegastack/vegastack-labs/internal/backupidentity",
  ]);
  assert.equal(manifest.contract.reviewedWaves[10].id, "phase5-issue146-v1");
  assert.deepEqual(manifest.contract.reviewedWaves[10].commands, []);
  assert.deepEqual(manifest.contract.reviewedWaves[10].imports, ["github.com/vegastack/vegastack-labs/internal/recovery"]);
  assert.equal(manifest.contract.reviewedWaves[11].id, "phase5-issue140-v1");
  assert.equal(manifest.contract.reviewedWaves[11].issue, 140);
  assert.deepEqual(manifest.contract.reviewedWaves[11].commands, []);
  assert.deepEqual(manifest.contract.reviewedWaves[11].imports, []);
  assert.equal(manifest.contract.reviewedWaves[12].id, "phase5-issue143-v1");
  assert.equal(manifest.contract.reviewedWaves[12].issue, 143);
  assert.deepEqual(manifest.contract.reviewedWaves[12].commands, []);
  assert.deepEqual(manifest.contract.reviewedWaves[12].imports, []);
  assert.equal(manifest.contract.reviewedWaves[13].id, "phase5-issue141-v1");
  assert.equal(manifest.contract.reviewedWaves[13].issue, 141);
  assert.deepEqual(manifest.contract.reviewedWaves[13].commands, []);
  assert.deepEqual(manifest.contract.reviewedWaves[13].imports, []);
  assert.equal(manifest.contract.reviewedWaves[14].id, "phase5-issue153-v1");
  assert.deepEqual(manifest.contract.reviewedWaves[14].commands, ["recovery witness collect"]);
  assert.deepEqual(manifest.contract.reviewedWaves[14].imports, ["github.com/vegastack/vegastack-labs/internal/adapter/recoverydenial"]);
  assert.equal(manifest.contract.reviewedWaves[15].id, "phase5-issue156-v1");
  assert.equal(manifest.contract.reviewedWaves[15].issue, 156);
  assert.deepEqual(manifest.contract.reviewedWaves[15].commands, []);
  assert.deepEqual(manifest.contract.reviewedWaves[15].imports, []);
  assert.equal(manifest.contract.reviewedWaves[16].id, "phase5-issue117-v1");
  assert.equal(manifest.contract.reviewedWaves[16].issue, 117);
  assert.deepEqual(manifest.contract.reviewedWaves[16].commands, ["backup run", "backup status", "backup verify"]);
  assert.deepEqual(manifest.contract.reviewedWaves[16].imports, []);
  assert.equal(manifest.contract.reviewedWaves[17].id, "phase5-issue159-v1");
  assert.equal(manifest.contract.reviewedWaves[17].issue, 159);
  assert.deepEqual(manifest.contract.reviewedWaves[17].commands, []);
  assert.deepEqual(manifest.contract.reviewedWaves[17].imports, []);
  assert.equal(manifest.contract.reviewedWaves[18].id, "phase5-issue144-v1");
  assert.equal(manifest.contract.reviewedWaves[18].issue, 144);
  assert.deepEqual(manifest.contract.reviewedWaves[18].commands, []);
  assert.deepEqual(manifest.contract.reviewedWaves[18].imports, []);
  assert.equal(manifest.contract.reviewedWaves[19].id, "phase5-issue163-v1");
  assert.equal(manifest.contract.reviewedWaves[19].issue, 163);
  assert.deepEqual(manifest.contract.reviewedWaves[19].commands, []);
  assert.deepEqual(manifest.contract.reviewedWaves[19].imports, []);
  assert.equal(manifest.contract.reviewedWaves[20].id, "phase5-issue154-v1");
  assert.equal(manifest.contract.reviewedWaves[20].issue, 154);
  assert.deepEqual(manifest.contract.reviewedWaves[20].commands, []);
  assert.deepEqual(manifest.contract.reviewedWaves[20].imports, ["github.com/vegastack/vegastack-labs/internal/adapter/backuptrust"]);
  assert.equal(manifest.contract.reviewedWaves[21].id, "phase5-issue135-v1");
  assert.equal(manifest.contract.reviewedWaves[21].issue, 135);
  assert.deepEqual(manifest.contract.reviewedWaves[21].commands, []);
  assert.deepEqual(manifest.contract.reviewedWaves[21].imports, []);
  assert.equal(manifest.contract.reviewedWaves[21].mutationBoundaryDigest, "sha256:0baef2613b97b94b88439b2098f508d24dbe34777dd818e117fa0d1ccd8b8a8a");
  assert.equal(manifest.contract.reviewedWaves[22].id, "phase5-issue115-v1");
  assert.equal(manifest.contract.reviewedWaves[22].issue, 115);
  assert.deepEqual(manifest.contract.reviewedWaves[22].commands, ["backup retention-locks draft", "backup retirement draft"]);
  assert.deepEqual(manifest.contract.reviewedWaves[22].imports, ["github.com/vegastack/vegastack-labs/internal/adapter/localretention"]);
  assert.equal(manifest.contract.reviewedWaves[22].mutationBoundaryDigest, "sha256:f012f10bb2cb917423afac31aea31a2021ce1de488f3fbc1cdb47ef1f0c3d38d");
  assert.equal(manifest.contract.reviewedWaves[23].id, "phase5-issue114-v1");
  assert.equal(manifest.contract.reviewedWaves[23].issue, 114);
  assert.deepEqual(manifest.contract.reviewedWaves[23].commands, []);
  assert.deepEqual(manifest.contract.reviewedWaves[23].imports, ["github.com/vegastack/vegastack-labs/internal/adapters/r2"]);
  assert.equal(manifest.contract.reviewedWaves[23].mutationBoundaryDigest, "sha256:6c6a3ab5f366603d73c1bd07d91097d0062f49a48231aca42a4c1f500af0455d");
  assert.equal(manifest.contract.reviewedWaves[24].id, "phase5-issue108-v1");
  assert.equal(manifest.contract.reviewedWaves[24].issue, 108);
  assert.deepEqual(manifest.contract.reviewedWaves[24].commands, ["restore plan", "restore run", "restore verify"]);
  assert.deepEqual(manifest.contract.reviewedWaves[24].imports, ["github.com/vegastack/vegastack-labs/internal/adapter/recoverydenial"]);
  assert.equal(manifest.contract.reviewedWaves[24].mutationBoundaryDigest, "sha256:d6aeb5bc5a09d0f5ca3d23f574d72542a9e99aa7613668f611bf01deeb9c5312");
  assert.equal(manifest.contract.reviewedWaves[25].id, "phase5-issue118-v1");
  assert.equal(manifest.contract.reviewedWaves[25].issue, 118);
  assert.deepEqual(manifest.contract.reviewedWaves[25].commands, ["backup offsite-retirement dry-run", "backup offsite-retirement stage"]);
  assert.deepEqual(manifest.contract.reviewedWaves[25].imports, ["github.com/vegastack/vegastack-labs/internal/adapter/r2retention"]);
  assert.equal(manifest.contract.reviewedWaves[25].mutationBoundaryDigest, "sha256:85e6ba71118938c37b8e2ce90b4d2b8ca17941b8a39d1ad8234008bdb681b64a");
  assert.equal(manifest.contract.reviewedWaves[26].id, "phase5-issue109-v1");
  assert.equal(manifest.contract.reviewedWaves[26].issue, 109);
  assert.deepEqual(manifest.contract.reviewedWaves[26].commands, ["schedule dispatch", "schedule policy draft"]);
  assert.deepEqual(manifest.contract.reviewedWaves[26].imports, ["github.com/vegastack/vegastack-labs/internal/schedule"]);
  assert.equal(manifest.contract.reviewedWaves[26].mutationBoundaryDigest, "sha256:8aa99e20da8e1d11111e30218a874f95bf74764a5d6bf86ea906c0cc63dff8dc");
  assert.equal(facts.postPhase2MutationBoundaryDigest, manifest.contract.reviewedWaves[26].mutationBoundaryDigest);
  assert.equal(validateEvidence(manifest, facts).status, "pass");
});

test("the #107 audit wave rejects command, import, and fingerprint drift", async () => {
  const manifest = await loadManifest();
  const facts = await collectIntegratedFacts(ROOT);
  const cases = [
    ["changed command", (m) => { m.contract.reviewedWaves[2].commands[0] = "audit rewrite"; }, "PHASE2_TRACEABILITY_GAP"],
    ["extra audit command", (m, f) => { f.availableCommands.push("audit rewrite"); }, "PHASE2_MUTATION_AVAILABLE"],
    ["extra production import", (m, f) => { f.productionImports.push("github.com/vegastack/vegastack-labs/internal/testsupport"); }, "PHASE2_PRODUCTION_BYPASS"],
    ["changed current fingerprint", (m, f) => { f.postPhase2MutationBoundaryDigest = `sha256:${"0".repeat(64)}`; }, "PHASE2_MUTATION_AVAILABLE"],
  ];
  for (const [name, mutate, code] of cases) {
    const changedManifest = structuredClone(manifest);
    const changedFacts = structuredClone(facts);
    mutate(changedManifest, changedFacts);
    const result = validateEvidence(changedManifest, changedFacts);
    assert.equal(result.status, "fail", `${name}: ${JSON.stringify(result)}`);
    assert.ok(result.codes.includes(code), `${name}: ${JSON.stringify(result)}`);
  }
});

test("the #123 credential wave rejects independent import and fingerprint drift", async () => {
  const manifest = await loadManifest();
  const facts = await collectIntegratedFacts(ROOT);
  const cases = [
    ["missing wave", (m) => { m.contract.reviewedWaves.pop(); }, "PHASE2_TRACEABILITY_GAP"],
    ["reordered waves", (m) => { m.contract.reviewedWaves.reverse(); }, "PHASE2_TRACEABILITY_GAP"],
    ["extra wave field", (m) => { m.contract.reviewedWaves[1].unknown = true; }, "PHASE2_TRACEABILITY_GAP"],
    ["changed import", (m) => { m.contract.reviewedWaves[1].imports.push("github.com/vegastack/vegastack-labs/internal/api"); }, "PHASE2_TRACEABILITY_GAP"],
    ["changed sdk pin", (m, f) => { f.onePasswordSDKVersion = "v0.4.2"; }, "PHASE2_PRODUCTION_BYPASS"],
    ["changed current fingerprint", (m, f) => { f.postPhase2MutationBoundaryDigest = `sha256:${"0".repeat(64)}`; }, "PHASE2_MUTATION_AVAILABLE"],
    ["foundation wave changed", (m) => { m.contract.reviewedWaves[1].commands.push("credential import"); }, "PHASE2_TRACEABILITY_GAP"],
  ];
  for (const [name, mutate, code] of cases) {
    const changedManifest = structuredClone(manifest);
    const changedFacts = structuredClone(facts);
    mutate(changedManifest, changedFacts);
    const result = validateEvidence(changedManifest, changedFacts);
    assert.equal(result.status, "fail", `${name}: ${JSON.stringify(result)}`);
    assert.ok(result.codes.includes(code), `${name}: ${JSON.stringify(result)}`);
  }
});

test("the #124 wave rejects import activation outside the local inert boundary", async () => {
  const manifest = await loadManifest();
  const facts = await collectIntegratedFacts(ROOT);
  const cases = [
    ["extra command", (m) => { m.contract.reviewedWaves.find((wave) => wave.issue === 124).commands.push("credential activate"); }, "PHASE2_TRACEABILITY_GAP"],
    ["private flag", (m, f) => { f.credentialImportFlags.push("--value"); }, "PHASE2_MUTATION_AVAILABLE"],
    ["unrelated credential read", (m, f) => { f.credentialEndpointIds.push("api.v1.credential-references.get"); }, "PHASE2_MUTATION_AVAILABLE"],
    ["remote transport", (m, f) => { f.credentialImportRemoteAllowed = true; }, "PHASE2_PRODUCTION_BYPASS"],
    ["production resolver", (m, f) => { f.credentialProductionResolverEnabled = true; }, "PHASE2_PRODUCTION_BYPASS"],
    ["missing reviewed live gate", (m, f) => { f.credentialLiveGateEnabled = false; }, "PHASE2_PRODUCTION_BYPASS"],
    ["draft as authority", (m, f) => { f.credentialImportTouchesCurrentAuthority = true; }, "PHASE2_PRODUCTION_BYPASS"],
    ["foundation migration drift", (m, f) => { f.migrations.find(({ file }) => file === "0012_credential_refs.sql").sha256 = `sha256:${"0".repeat(64)}`; }, "PHASE2_MUTATION_AVAILABLE"],
    ["import migration drift", (m, f) => { f.migrations.find(({ file }) => file === "0013_credential_import_drafts.sql").sha256 = `sha256:${"0".repeat(64)}`; }, "PHASE2_MUTATION_AVAILABLE"],
    ["source fingerprint drift", (m, f) => { f.postPhase2MutationBoundaryDigest = `sha256:${"0".repeat(64)}`; }, "PHASE2_MUTATION_AVAILABLE"],
  ];
  for (const [name, mutate, code] of cases) {
    const changedManifest = structuredClone(manifest);
    const changedFacts = structuredClone(facts);
    mutate(changedManifest, changedFacts);
    const result = validateEvidence(changedManifest, changedFacts);
    assert.equal(result.status, "fail", `${name}: ${JSON.stringify(result)}`);
    assert.ok(result.codes.includes(code), `${name}: ${JSON.stringify(result)}`);
  }
});

test("the #135 seal rejects lifecycle surface widening and older-wave drift", async () => {
  const manifest = await loadManifest();
  const facts = await collectIntegratedFacts(ROOT);
  const cases = [
    ["older fingerprint", (m) => { m.contract.reviewedWaves[20].mutationBoundaryDigest = `sha256:${"0".repeat(64)}`; }, "PHASE2_TRACEABILITY_GAP"],
    ["reordered final waves", (m) => { [m.contract.reviewedWaves[20], m.contract.reviewedWaves[21]] = [m.contract.reviewedWaves[21], m.contract.reviewedWaves[20]]; }, "PHASE2_TRACEABILITY_GAP"],
    ["extra final-wave field", (m) => { m.contract.reviewedWaves[21].authority = "live"; }, "PHASE2_TRACEABILITY_GAP"],
    ["credential reveal", (_m, f) => { f.availableCommands.push("credential reveal"); }, "PHASE2_MUTATION_AVAILABLE"],
    ["credential direct status", (_m, f) => { f.availableCommands.push("credential status direct"); }, "PHASE2_MUTATION_AVAILABLE"],
    ["credential scheduled mutation", (_m, f) => { f.availableCommands.push("credential schedule"); }, "PHASE2_MUTATION_AVAILABLE"],
    ["browser or remote import", (_m, f) => { f.credentialImportRemoteAllowed = true; }, "PHASE2_PRODUCTION_BYPASS"],
    ["production fixture import", (_m, f) => { f.productionImports.push("github.com/vegastack/vegastack-labs/internal/phase2fixture"); }, "PHASE2_PRODUCTION_BYPASS"],
    ["private fixture admitted", (_m, f) => { f.privateFixture = true; }, "PHASE2_PRIVATE_FIXTURE"],
  ];
  for (const [name, mutate, code] of cases) {
    const changedManifest = structuredClone(manifest);
    const changedFacts = structuredClone(facts);
    mutate(changedManifest, changedFacts);
    const result = validateEvidence(changedManifest, changedFacts);
    assert.equal(result.status, "fail", `${name}: ${JSON.stringify(result)}`);
    assert.ok(result.codes.includes(code), `${name}: ${JSON.stringify(result)}`);
  }
});

test("the #104 reviewed wave rejects independent command, import, fingerprint and manifest drift", async () => {
  const manifest = await loadManifest();
  const facts = await collectIntegratedFacts(ROOT);
  const cases = [
    ["extra gate command", (m, f) => { f.availableCommands.push("gate close"); }, "PHASE2_MUTATION_AVAILABLE"],
    ["missing reviewed command", (m, f) => { f.availableCommands = f.availableCommands.filter((command) => command !== "gate evidence"); }, "PHASE2_MUTATION_AVAILABLE"],
    ["changed reviewed command", (m) => { m.contract.reviewedWaves[0].commands[0] = "gate close"; }, "PHASE2_TRACEABILITY_GAP"],
    ["extra reviewed command", (m) => { m.contract.reviewedWaves[0].commands.push("gate close"); }, "PHASE2_TRACEABILITY_GAP"],
    ["changed reviewed import", (m) => { m.contract.reviewedWaves[0].imports[0] = "github.com/vegastack/vegastack-labs/internal/run"; }, "PHASE2_TRACEABILITY_GAP"],
    ["missing reviewed production import", (m, f) => { f.productionImports = f.productionImports.filter((name) => name !== "github.com/vegastack/vegastack-labs/internal/gate"); }, "PHASE2_PRODUCTION_BYPASS"],
    ["extra production import", (m, f) => { f.productionImports.push("github.com/vegastack/vegastack-labs/internal/testsupport"); }, "PHASE2_PRODUCTION_BYPASS"],
    ["changed reviewed fingerprint", (m) => { m.contract.reviewedWaves[0].mutationBoundaryDigest = `sha256:${"0".repeat(64)}`; }, "PHASE2_MUTATION_AVAILABLE"],
    ["changed current fingerprint", (m, f) => { f.postPhase2MutationBoundaryDigest = `sha256:${"0".repeat(64)}`; }, "PHASE2_MUTATION_AVAILABLE"],
    ["changed original dependency golden", (m) => { m.contract.productionDependencyDigest = `sha256:${"0".repeat(64)}`; }, "PHASE2_TRACEABILITY_GAP"],
    ["changed original source golden", (m) => { m.contract.postPhase2MutationBoundaryDigest = `sha256:${"0".repeat(64)}`; }, "PHASE2_TRACEABILITY_GAP"],
    ["missing reviewed wave", (m) => { delete m.contract.reviewedWaves; }, "PHASE2_TRACEABILITY_GAP"],
    ["stale wave id", (m) => { m.contract.reviewedWaves[0].id = "phase5-issue104-v0"; }, "PHASE2_TRACEABILITY_GAP"],
    ["stale wave issue", (m) => { m.contract.reviewedWaves[0].issue = 105; }, "PHASE2_TRACEABILITY_GAP"],
    ["malformed wave fingerprint", (m) => { m.contract.reviewedWaves[0].mutationBoundaryDigest = "sha256:oops"; }, "PHASE2_TRACEABILITY_GAP"],
    ["extra wave", (m) => { m.contract.reviewedWaves.push(structuredClone(m.contract.reviewedWaves[0])); }, "PHASE2_TRACEABILITY_GAP"],
    ["extra wave field", (m) => { m.contract.reviewedWaves[0].unknown = true; }, "PHASE2_TRACEABILITY_GAP"],
  ];
  for (const [name, mutate, code] of cases) {
    const changedManifest = structuredClone(manifest);
    const changedFacts = structuredClone(facts);
    mutate(changedManifest, changedFacts);
    const result = validateEvidence(changedManifest, changedFacts);
    assert.equal(result.status, "fail", `${name}: ${JSON.stringify(result)}`);
    assert.ok(result.codes.includes(code), `${name}: ${JSON.stringify(result)}`);
  }
});

test("every Phase 2 requirement has one owner and evidence", async () => {
  const manifest = await loadManifest();
  const broken = structuredClone(manifest);
  broken.requirements[0].scenarioIds = [];
  const result = validateEvidence(broken, await collectIntegratedFacts(ROOT));
  assert.equal(result.status, "fail");
  assert.deepEqual(result.codes, ["PHASE2_TRACEABILITY_GAP"]);
});

test("contract drift, mutation availability, fixture reachability, and stale children fail closed", async () => {
  const manifest = await loadManifest();
  const facts = await collectIntegratedFacts(ROOT);
  const acceptedRoute = manifest.contract.endpointIds[0];
  assert.ok(acceptedRoute && facts.endpointIds.includes(acceptedRoute), "accepted Phase 2 route is present");

  for (const [field, mutate, expected] of [
    ["routes", (copy) => { copy.endpointIds = copy.endpointIds.filter((id) => id !== acceptedRoute); }, "PHASE2_CONTRACT_DRIFT"],
    ["commands", (copy) => { copy.mutationAvailable = true; }, "PHASE2_MUTATION_AVAILABLE"],
    ["production", (copy) => { copy.productionImports.push("github.com/vegastack/vegastack-labs/internal/testsupport"); }, "PHASE2_PRODUCTION_BYPASS"],
    ["source override", (copy) => { copy.postPhase2SourceOverride = "vendor"; }, "PHASE2_PRODUCTION_BYPASS"],
    ["children", (copy) => { copy.children[0].state = "OPEN"; }, "PHASE2_CHILD_INCOMPLETE"],
  ]) {
    const copy = structuredClone(facts);
    mutate(copy);
    const result = validateEvidence(manifest, copy);
    assert.ok(result.codes.includes(expected), `${field}: ${JSON.stringify(result)}`);
  }
});

test("later additive contracts do not rewrite accepted Phase 2 evidence", async () => {
  const manifest = await loadManifest();
  const facts = await collectIntegratedFacts(ROOT);
  assert.ok(facts.endpointIds.includes("api.v1.sources.list"));
  assert.ok(facts.productionImports.includes("github.com/vegastack/vegastack-labs/internal/consoleassets"));
  assert.ok(facts.productionImports.includes("github.com/vegastack/vegastack-labs/internal/adapter"));
  assert.ok(facts.productionImports.includes("github.com/vegastack/vegastack-labs/internal/run"));
  assert.ok(facts.productionImports.includes("github.com/vegastack/vegastack-labs/internal/localtransport"));
  assert.ok(facts.productionImports.includes("github.com/vegastack/vegastack-labs/internal/runprotocol"));
  for (const command of ["apply", "plan", "run cancel", "run inspect", "run resume", "server api-ssh"]) {
    assert.ok(facts.availableCommands.includes(command), command);
  }
  facts.endpointIds.push("api.v1.future-read.get");
  facts.availableCommands.push("future read");
  facts.migrations.push({ file: "0005_future.sql", sha256: "future" });
  const result = validateEvidence(manifest, facts);
  assert.equal(result.status, "pass", JSON.stringify(result));
});

test("Phase 4 mutation commands require the exact reviewed safety boundary", async () => {
  const manifest = await loadManifest();
  const facts = await collectIntegratedFacts(ROOT);
  const protectedFiles = await postPhase2MutationBoundaryFiles(ROOT, facts.productionImports);
  for (const required of [
    "cmd/vsk-labs/main.go",
    "internal/api/plans.go",
    "internal/api/acknowledgements.go",
    "internal/api/runs.go",
    "internal/authorization/policy.go",
    "internal/identity/local.go",
    "internal/localapi/client.go",
    "internal/server/api_ssh.go",
    "internal/run/admission.go",
    "internal/run/engine.go",
  ]) {
    assert.ok(protectedFiles.includes(required), required);
  }
  assert.ok(protectedFiles.includes("internal/consoleassets/dist/index.html"));
  assert.ok(protectedFiles.includes("internal/metadata/phase4.go"));
  assert.ok(protectedFiles.includes("schemas/v1/command-registry.json"));
  assert.ok(protectedFiles.includes("internal/store/migrations/0009_runs.sql"));
  assert.ok(protectedFiles.every((filename) => !filename.endsWith("_test.go") && !filename.includes("/testdata/")));
  assert.equal(facts.postPhase2MutationBoundaryDigest, manifest.contract.reviewedWaves.at(-1).mutationBoundaryDigest);

  facts.postPhase2MutationBoundaryDigest = `sha256:${"0".repeat(64)}`;
  const result = validateEvidence(manifest, facts);
  assert.ok(result.codes.includes("PHASE2_MUTATION_AVAILABLE"), JSON.stringify(result));
});

test("the mutation boundary detects changed and added production source files", async () => {
  const manifest = await loadManifest();
  const facts = await collectIntegratedFacts(ROOT);
  assert.equal(facts.postPhase2MutationBoundaryDigest, manifest.contract.reviewedWaves.at(-1).mutationBoundaryDigest);
  const protectedFiles = await postPhase2MutationBoundaryFiles(ROOT, facts.productionImports);
  const temporary = await mkdtemp(path.join(tmpdir(), "vsk-phase2-boundary-"));
  try {
    for (const relative of protectedFiles) {
      const target = path.join(temporary, relative);
      await mkdir(path.dirname(target), { recursive: true });
      await cp(path.join(ROOT, relative), target);
    }

    const plans = path.join(temporary, "internal/api/plans.go");
    await writeFile(plans, `${await readFile(plans, "utf8")}\n// unauthorized mutation seam\n`);
    let changed = structuredClone(facts);
    changed.postPhase2MutationBoundaryDigest = await postPhase2MutationBoundaryDigest(temporary, facts.productionImports);
    assert.ok(validateEvidence(manifest, changed).codes.includes("PHASE2_MUTATION_AVAILABLE"));

    await cp(path.join(ROOT, "internal/api/plans.go"), plans);
    await writeFile(path.join(temporary, "internal/api/phase2_bypass.go"), "package api\n");
    changed = structuredClone(facts);
    changed.postPhase2MutationBoundaryDigest = await postPhase2MutationBoundaryDigest(temporary, facts.productionImports);
    assert.ok(validateEvidence(manifest, changed).codes.includes("PHASE2_MUTATION_AVAILABLE"));

    await rm(path.join(temporary, "internal/api/phase2_bypass.go"));
    await rm(path.join(temporary, "internal/api/plans.go"));
    changed = structuredClone(facts);
    changed.postPhase2MutationBoundaryDigest = await postPhase2MutationBoundaryDigest(temporary, facts.productionImports);
    assert.ok(validateEvidence(manifest, changed).codes.includes("PHASE2_MUTATION_AVAILABLE"));

    const lifecycleSchema = path.join(temporary, "schemas/v1/credential-lifecycle-request.schema.json");
    const schema = JSON.parse(await readFile(lifecycleSchema, "utf8"));
    schema.properties.providerId = { type: "string" };
    await writeFile(lifecycleSchema, `${JSON.stringify(schema, null, 2)}\n`);
    changed = structuredClone(facts);
    changed.postPhase2MutationBoundaryDigest = await postPhase2MutationBoundaryDigest(temporary, facts.productionImports);
    assert.ok(validateEvidence(manifest, changed).codes.includes("PHASE2_MUTATION_AVAILABLE"), "provider field in core credential schema");

    await cp(path.join(ROOT, "schemas/v1/credential-lifecycle-request.schema.json"), lifecycleSchema);
    const auditSource = path.join(temporary, "internal/audit/canonical.go");
    await writeFile(auditSource, `${await readFile(auditSource, "utf8")}\n// weakened redaction seam\n`);
    changed = structuredClone(facts);
    changed.postPhase2MutationBoundaryDigest = await postPhase2MutationBoundaryDigest(temporary, facts.productionImports);
    assert.ok(validateEvidence(manifest, changed).codes.includes("PHASE2_MUTATION_AVAILABLE"), "audit redaction source drift");
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("vendor, workspaces, and local source replacements fail the production proof closed", async () => {
  const temporary = await mkdtemp(path.join(tmpdir(), "vsk-phase2-source-"));
  try {
    await writeFile(path.join(temporary, "go.mod"), "module example.com/root\n\ngo 1.27\n");
    await mkdir(path.join(temporary, "vendor"));
    assert.equal(await postPhase2SourceOverride(temporary), "vendor");
    await rm(path.join(temporary, "vendor"), { recursive: true });

    await writeFile(path.join(temporary, "go.work"), "go 1.27\nuse .\n");
    assert.equal(await postPhase2SourceOverride(temporary), "go.work");
    await rm(path.join(temporary, "go.work"));

    await mkdir(path.join(temporary, "dependency"));
    await writeFile(path.join(temporary, "dependency/go.mod"), "module example.com/dependency\n\ngo 1.27\n");
    await writeFile(path.join(temporary, "go.mod"), "module example.com/root\n\ngo 1.27\n\nrequire example.com/dependency v0.0.0\nreplace example.com/dependency => ./dependency\n");
    assert.equal(await postPhase2SourceOverride(temporary), "local-replace");
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("a symlinked production source file cannot escape the reviewed boundary", async (t) => {
  if (process.platform === "win32") return t.skip("ordinary Windows test users cannot create source symlinks");
  const temporary = await mkdtemp(path.join(tmpdir(), "vsk-phase2-symlink-"));
  try {
    await writeFile(path.join(temporary, "go.mod"), "module github.com/vegastack/vegastack-labs\n\ngo 1.27\n");
    await writeFile(path.join(temporary, "go.sum"), "");
    await mkdir(path.join(temporary, "internal/api"), { recursive: true });
    await writeFile(path.join(temporary, "external.go"), "package api\n");
    await symlink(path.join(temporary, "external.go"), path.join(temporary, "internal/api/bypass.go"));
    assert.equal(await postPhase2SourceOverride(temporary, ["github.com/vegastack/vegastack-labs/internal/api"]), "non-regular-source");
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("a symlinked production source root cannot escape the reviewed boundary", async (t) => {
  if (process.platform === "win32") return t.skip("ordinary Windows test users cannot create source symlinks");
  const temporary = await mkdtemp(path.join(tmpdir(), "vsk-phase2-root-link-"));
  try {
    await writeFile(path.join(temporary, "go.mod"), "module github.com/vegastack/vegastack-labs\n\ngo 1.27\n");
    await writeFile(path.join(temporary, "go.sum"), "");
    await mkdir(path.join(temporary, "cmd/vsk-labs"), { recursive: true });
    await mkdir(path.join(temporary, "schemas/v1"), { recursive: true });
    await mkdir(path.join(temporary, "external/internal/metadata"), { recursive: true });
    await writeFile(path.join(temporary, "external/internal/api.go"), "package internal\n");
    await symlink(path.join(temporary, "external/internal"), path.join(temporary, "internal"));
    assert.equal(await postPhase2SourceOverride(temporary), "non-regular-source");
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("the checked manifest matches the merged Phase 2 contract", async () => {
  const manifest = await loadManifest();
  const first = validateEvidence(manifest, await collectIntegratedFacts(ROOT));
  const second = validateEvidence(manifest, await collectIntegratedFacts(ROOT));
  assert.deepEqual(first, second);
  assert.deepEqual(first, { status: "pass", codes: [], scenarios: manifest.scenarios.map(({ id }) => id) });
});
