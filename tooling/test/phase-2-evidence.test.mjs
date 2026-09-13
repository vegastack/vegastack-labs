import assert from "node:assert/strict";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { collectIntegratedFacts, postPhase2MutationBoundaryDigest, postPhase2MutationBoundaryFiles, validateEvidence } from "../verify-phase-2.mjs";

const ROOT = path.resolve(import.meta.dirname, "../..");

async function loadManifest() {
  return JSON.parse(await readFile(path.join(ROOT, "tooling/phase-2-evidence.json"), "utf8"));
}

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

  for (const [field, mutate, expected] of [
    ["routes", (copy) => copy.endpointIds.shift(), "PHASE2_CONTRACT_DRIFT"],
    ["commands", (copy) => { copy.mutationAvailable = true; }, "PHASE2_MUTATION_AVAILABLE"],
    ["production", (copy) => { copy.productionImports.push("github.com/vegastack/vegastack-labs/internal/testsupport"); }, "PHASE2_PRODUCTION_BYPASS"],
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
  assert.equal(facts.postPhase2MutationBoundaryDigest, manifest.contract.postPhase2MutationBoundaryDigest);

  facts.postPhase2MutationBoundaryDigest = `sha256:${"0".repeat(64)}`;
  const result = validateEvidence(manifest, facts);
  assert.ok(result.codes.includes("PHASE2_MUTATION_AVAILABLE"), JSON.stringify(result));
});

test("the mutation boundary detects changed and added production source files", async () => {
  const manifest = await loadManifest();
  const facts = await collectIntegratedFacts(ROOT);
  assert.equal(facts.postPhase2MutationBoundaryDigest, manifest.contract.postPhase2MutationBoundaryDigest);
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
