import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

const ROOT = path.resolve(import.meta.dirname, "../..");
const DEFINITION_PATH = path.join(ROOT, "tooling/phase-3-evidence.json");

const TOP_LEVEL_KEYS = [
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

const RUNTIME_ONLY_KEYS = new Set([
  "artifactDigests",
  "cleanTree",
  "evidenceDigest",
  "sourceCommit",
]);

export async function loadDefinition(root = ROOT) {
  return JSON.parse(await readFile(path.join(root, "tooling/phase-3-evidence.json"), "utf8"));
}

function collectKeys(value, found = []) {
  if (Array.isArray(value)) {
    for (const item of value) collectKeys(item, found);
  } else if (value && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      found.push(key);
      collectKeys(item, found);
    }
  }
  return found;
}

test("Phase 3 evidence definition has a closed static envelope", async () => {
  const definition = await loadDefinition();

  assert.deepEqual(Object.keys(definition).sort(), TOP_LEVEL_KEYS);
  assert.equal(definition.schema, "vegastack-labs.dev/phase-evidence-definition");
  assert.equal(definition.version, "1.0.0");
  assert.equal(definition.phase, 3);
  assert.equal(definition.status, "implemented-awaiting-operator-acceptance");

  const forbidden = collectKeys(definition).filter((key) => RUNTIME_ONLY_KEYS.has(key));
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
