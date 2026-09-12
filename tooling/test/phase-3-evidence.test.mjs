import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

const ROOT = path.resolve(import.meta.dirname, "../..");
const DEFINITION_PATH = path.join(ROOT, "tooling/phase-3-evidence.json");

const TOP_LEVEL_KEYS = [
  "acceptance",
  "artifacts",
  "children",
  "commands",
  "limitations",
  "phase",
  "proofs",
  "requirements",
  "schema",
  "status",
  "version",
];

const REQUIREMENT_IDS = [
  "module-1.embedded-read-service",
  "module-3.protected-browser-transport",
  "module-8.health-source-freshness",
  "module-9.console-read-experience",
  "roadmap.phase-3",
  "shared.generated-browser-client",
  "shared.privacy-local-recovery",
];

const RUNTIME_ONLY_TOP_LEVEL_KEYS = new Set([
  "artifactDigests",
  "cleanTree",
  "evidenceDigest",
  "sourceCommit",
]);

export async function loadDefinition(root = ROOT) {
  return JSON.parse(await readFile(path.join(root, "tooling/phase-3-evidence.json"), "utf8"));
}

test("Phase 3 evidence definition has a closed static envelope", async () => {
  const definition = await loadDefinition();

  assert.deepEqual(Object.keys(definition).sort(), TOP_LEVEL_KEYS);
  assert.equal(definition.schema, "vegastack-labs.dev/phase-evidence-definition");
  assert.equal(definition.version, "1.0.0");
  assert.equal(definition.phase, 3);
  assert.equal(definition.status, "accepted");
  assert.deepEqual(definition.acceptance, {
    operator: "omkarmohanta09",
    acceptedOn: "12-09-2026",
    sourceCommit: "a0a07a425d6396703d8bec438634d9ec2c2ae980",
    evidenceDigest: "sha256:b051c6f0a81498c09a159c14e16999b7cc3b02cd9ed758376684d31022587f1f",
    run: "https://github.com/vegastack/vegastack-labs/actions/runs/34703617111",
  });

  const forbidden = Object.keys(definition).filter((key) => RUNTIME_ONLY_TOP_LEVEL_KEYS.has(key));
  assert.deepEqual(forbidden, [], "runtime facts must be generated for the commit being tested");
});

test("Phase 3 evidence binds every merged child to public evidence and review", async () => {
  const { children } = await loadDefinition();

  assert.deepEqual(children.map(({ issue }) => issue), [50, 51, 52, 53, 54, 55, 56, 57]);
  assert.equal(new Set(children.map(({ phaseIssue }) => phaseIssue)).size, children.length);
  for (const child of children) {
    assert.deepEqual(Object.keys(child).sort(), ["evidence", "issue", "mergeCommit", "phaseIssue", "pr", "review"]);
    assert.match(child.phaseIssue, /^3\.[1-8]$/);
    assert.match(child.mergeCommit, /^[0-9a-f]{40}$/);
    assert.match(child.evidence, new RegExp(`^https://github\\.com/vegastack/vegastack-labs/issues/${child.issue}#issuecomment-[0-9]+$`));
    assert.match(child.review, new RegExp(`^https://github\\.com/vegastack/vegastack-labs/issues/${child.issue}#issuecomment-[0-9]+$`));
  }
});

test("every Phase 3 requirement has unique fixture proof with an expected pass", async () => {
  const definition = await loadDefinition();
  const proofIds = new Set(definition.proofs.map(({ id }) => id));

  assert.equal(proofIds.size, definition.proofs.length);
  assert.deepEqual(definition.requirements.map(({ id }) => id).sort(), REQUIREMENT_IDS);
  for (const requirement of definition.requirements) {
    assert.deepEqual(Object.keys(requirement).sort(), ["environment", "expectedStatus", "id", "module", "ownerIssue", "proofIds"]);
    assert.equal(requirement.environment, "fixture");
    assert.equal(requirement.expectedStatus, "pass");
    assert.ok(requirement.proofIds.length > 0, `${requirement.id} has no proof`);
    for (const proofId of requirement.proofIds) {
      assert.ok(proofIds.has(proofId), `${requirement.id} names missing proof ${proofId}`);
    }
  }
});

test("proofs, commands, artifacts, and limitations stay reproducible and truthful", async () => {
  const definition = await loadDefinition();

  for (const proof of definition.proofs) {
    assert.deepEqual(Object.keys(proof).sort(), ["environment", "expectedStatus", "id", "kind", "path", "quarantined", "selector"]);
    assert.equal(proof.environment, "fixture");
    assert.equal(proof.expectedStatus, "pass");
    assert.equal(proof.quarantined, false);
    assert.ok(!path.isAbsolute(proof.path));
    const contents = await readFile(path.join(ROOT, proof.path), "utf8");
    if (proof.selector !== null) assert.match(contents, new RegExp(proof.selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }

  for (const command of definition.commands) {
    assert.deepEqual(Object.keys(command).sort(), ["argv", "environment", "expectedStatus", "id"]);
    assert.ok(Array.isArray(command.argv) && command.argv.length > 0);
    assert.equal(command.environment, "fixture");
    assert.equal(command.expectedStatus, "pass");
  }

  assert.deepEqual(
    definition.artifacts.map(({ path: artifactPath }) => artifactPath),
    [
      "tooling/phase-3-evidence.json",
      "schemas/v1/command-registry.json",
      "schemas/v1/endpoint-registry.json",
      "web/generated/read-api.ts",
      "internal/consoleassets/manifest.json",
    ],
  );
  for (const artifact of definition.artifacts) {
    assert.deepEqual(Object.keys(artifact).sort(), ["digestAtRuntime", "id", "path"]);
    assert.equal(artifact.digestAtRuntime, true);
    assert.ok(!path.isAbsolute(artifact.path));
    await readFile(path.join(ROOT, artifact.path));
  }

  assert.ok(definition.limitations.length >= 3);
  for (const limitation of definition.limitations) {
    assert.deepEqual(Object.keys(limitation).sort(), ["environment", "id", "statement", "status"]);
    assert.ok(["live", "operator", "phase-11"].includes(limitation.environment));
    assert.equal(limitation.status, "not-exercised");
    assert.ok(limitation.statement.length > 20);
  }
});

test("development records bind accepted Phase 3 to its exact main proof", async () => {
  const [phase, overview, roadmap, chronicle] = await Promise.all([
    readFile(path.join(ROOT, "docs/development/phases/03-secure-read-console-and-operator-access.md"), "utf8"),
    readFile(path.join(ROOT, "docs/development/README.md"), "utf8"),
    readFile(path.join(ROOT, "docs/development/roadmap.md"), "utf8"),
    readFile(path.join(ROOT, ".vegastack/chronicle.md"), "utf8"),
  ]);
  for (const document of [phase, overview, roadmap, chronicle]) {
    assert.match(document, /Phase 3.*accepted/is);
    assert.match(document, /a0a07a425d6396703d8bec438634d9ec2c2ae980/);
  }
  assert.match(phase, /34703617111/);
  assert.match(phase, /sha256:b051c6f0a81498c09a159c14e16999b7cc3b02cd9ed758376684d31022587f1f/);
});
