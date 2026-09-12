import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { readFile as readFileAsync } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { fullCheckPlan, runCheckPlan } from "./lib/check-plan.mjs";
import { runCommand } from "./lib/process.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const EXPECTED_TOP_LEVEL_KEYS = [
  "artifacts", "children", "commands", "limitations", "phase", "proofs",
  "requirements", "schema", "status", "version",
];
const EXPECTED_CHILDREN = Object.freeze([
  Object.freeze({ issue: 50, phaseIssue: "3.1", pr: 59, mergeCommit: "8bc4e69eace0762eedacababcfaa4c16cdd515bf", evidence: "https://github.com/vegastack/vegastack-labs/issues/50#issuecomment-5623084179", review: "https://github.com/vegastack/vegastack-labs/issues/50#issuecomment-5623083205" }),
  Object.freeze({ issue: 51, phaseIssue: "3.2", pr: 60, mergeCommit: "64225ae60bd93e22fa1284643cc7894557627e20", evidence: "https://github.com/vegastack/vegastack-labs/issues/51#issuecomment-5617148376", review: "https://github.com/vegastack/vegastack-labs/issues/51#issuecomment-5630668657" }),
  Object.freeze({ issue: 52, phaseIssue: "3.3", pr: 61, mergeCommit: "81c875f2b95aea2b4a7f75edc476c3b5964afb24", evidence: "https://github.com/vegastack/vegastack-labs/issues/52#issuecomment-5630855928", review: "https://github.com/vegastack/vegastack-labs/issues/52#issuecomment-5617495894" }),
  Object.freeze({ issue: 53, phaseIssue: "3.4", pr: 63, mergeCommit: "b142359e27beb399ce25c8f595109648b7e16f66", evidence: "https://github.com/vegastack/vegastack-labs/issues/53#issuecomment-5633286695", review: "https://github.com/vegastack/vegastack-labs/issues/53#issuecomment-5635121993" }),
  Object.freeze({ issue: 54, phaseIssue: "3.5", pr: 62, mergeCommit: "b621b22be828d30e56ce5e7c97ddde1fd9bb7cbb", evidence: "https://github.com/vegastack/vegastack-labs/issues/54#issuecomment-5631040710", review: "https://github.com/vegastack/vegastack-labs/issues/54#issuecomment-5618249787" }),
  Object.freeze({ issue: 55, phaseIssue: "3.6", pr: 64, mergeCommit: "9d053b299136e8e9b2afa2bb2b1373ea013d9bf4", evidence: "https://github.com/vegastack/vegastack-labs/issues/55#issuecomment-5634067489", review: "https://github.com/vegastack/vegastack-labs/issues/55#issuecomment-5635286645" }),
  Object.freeze({ issue: 56, phaseIssue: "3.7", pr: 65, mergeCommit: "92dc2c0491839522fb89a25a89fd1c26c83fa512", evidence: "https://github.com/vegastack/vegastack-labs/issues/56#issuecomment-5634424565", review: "https://github.com/vegastack/vegastack-labs/issues/56#issuecomment-5634357108" }),
  Object.freeze({ issue: 57, phaseIssue: "3.8", pr: 84, mergeCommit: "156cf495de099a54307d55e81cf2469eebcb968f", evidence: "https://github.com/vegastack/vegastack-labs/issues/57#issuecomment-5646322625", review: "https://github.com/vegastack/vegastack-labs/issues/57#issuecomment-5646595446" }),
]);
const EXPECTED_REQUIREMENTS = Object.freeze([
  "roadmap.phase-3",
  "module-1.embedded-read-service",
  "module-3.protected-browser-transport",
  "module-8.health-source-freshness",
  "module-9.console-read-experience",
  "shared.generated-browser-client",
  "shared.privacy-local-recovery",
]);
const EXPECTED_COMMANDS = Object.freeze([
  Object.freeze({ id: "public-check-catalog", argv: Object.freeze(["pnpm", "check"]) }),
  Object.freeze({ id: "go-race-full", argv: Object.freeze(["go", "test", "-race", "-count=1", "./..."]) }),
]);
const EXPECTED_ARTIFACTS = Object.freeze([
  Object.freeze({ id: "static-definition", path: "tooling/phase-3-evidence.json" }),
  Object.freeze({ id: "command-registry", path: "schemas/v1/command-registry.json" }),
  Object.freeze({ id: "endpoint-registry", path: "schemas/v1/endpoint-registry.json" }),
  Object.freeze({ id: "generated-read-client", path: "web/generated/read-api.ts" }),
  Object.freeze({ id: "console-asset-manifest", path: "internal/consoleassets/manifest.json" }),
]);
const PROOF_KINDS = new Set(["go-test", "node-test", "browser-test", "browser-stage"]);
const LIMIT_ENVIRONMENTS = new Set(["live", "phase-11", "operator"]);
const SECRET_PATTERN = /(?:\b(?:gh[opsu]_|github_pat_)[A-Za-z0-9_]+|\bbearer\s+\S+|\bcookie\s*[=:]\s*\S+|\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b|-----BEGIN [A-Z ]*PRIVATE KEY-----)/i;
const PRIVATE_ENDPOINT_PATTERN = /(?:https?:\/\/(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|[^/\s]+\.(?:internal|local))(?:[:/\s]|$))/i;

class Phase3ExitError extends Error {
  constructor(stage) {
    super(stage);
    this.name = "Phase3ExitError";
  }
}

function fail(stage) {
  throw new Phase3ExitError(stage);
}

function exactKeys(value, expected) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort());
}

function unique(values) {
  return new Set(values).size === values.length;
}

function same(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function validID(value) {
  return typeof value === "string" && /^[a-z0-9]+(?:[.-][a-z0-9]+)*$/.test(value);
}

function validRelativePath(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 4096 &&
    !value.startsWith("/") && !/^[A-Za-z]:[\\/]/.test(value) && !value.includes("\\") &&
    !value.includes("\0") && !value.split("/").includes("..");
}

function safePublicText(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 1000 &&
    !/[\r\n\0]/.test(value) && !SECRET_PATTERN.test(value) && !PRIVATE_ENDPOINT_PATTERN.test(value) &&
    !/(?:^|[\s"'])(?:\/Users\/|\/home\/|[A-Za-z]:\\)/.test(value);
}

function canonicalRepositoryURL(value, kind, number) {
  if (typeof value !== "string") return false;
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  if (parsed.protocol !== "https:" || parsed.hostname !== "github.com" || parsed.username || parsed.password ||
      parsed.search || parsed.pathname !== `/vegastack/vegastack-labs/${kind}/${number}`) {
    return false;
  }
  return /^#issuecomment-\d+$/.test(parsed.hash);
}

function canonicalReviewURL(value, child) {
  return canonicalRepositoryURL(value, "issues", child.issue) ||
    canonicalRepositoryURL(value, "pull", child.pr);
}

function proofSource(root, proof, reader) {
  if (!validRelativePath(proof.path)) fail("PHASE3_EXIT_DEFINITION");
  let content;
  try {
    content = reader(path.join(root, proof.path), "utf8");
  } catch {
    fail("PHASE3_EXIT_DEFINITION");
  }
  if (proof.selector !== null && !content.includes(proof.selector)) fail("PHASE3_EXIT_DEFINITION");
}

export function parsePhase3ExitArgs(args) {
  if (!Array.isArray(args) || args.length !== 2 || args[0] !== "--commit" || !SHA_PATTERN.test(args[1])) {
    fail("PHASE3_EXIT_ARGUMENTS");
  }
  return { expectedCommit: args[1] };
}

export function validatePhase3EvidenceDefinition(definition, { root = ROOT, readProof = readFileSync } = {}) {
  try {
    if (!exactKeys(definition, EXPECTED_TOP_LEVEL_KEYS) ||
        definition.schema !== "vegastack-labs.dev/phase-evidence-definition" ||
        definition.version !== "1.0.0" || definition.phase !== 3 ||
        definition.status !== "implemented-awaiting-operator-acceptance") {
      fail("PHASE3_EXIT_DEFINITION");
    }

    if (!Array.isArray(definition.children) || definition.children.length !== EXPECTED_CHILDREN.length) {
      fail("PHASE3_EXIT_DEFINITION");
    }
    for (const [index, child] of definition.children.entries()) {
      const expected = EXPECTED_CHILDREN[index];
      if (!exactKeys(child, ["evidence", "issue", "mergeCommit", "phaseIssue", "pr", "review"]) ||
          !same(child, expected) || !canonicalRepositoryURL(child.evidence, "issues", child.issue) ||
          !canonicalReviewURL(child.review, child)) {
        fail("PHASE3_EXIT_DEFINITION");
      }
    }

    if (!Array.isArray(definition.proofs) || definition.proofs.length === 0 ||
        !unique(definition.proofs.map(({ id }) => id))) fail("PHASE3_EXIT_DEFINITION");
    const proofIDs = new Set();
    for (const proof of definition.proofs) {
      if (!exactKeys(proof, ["environment", "expectedStatus", "id", "kind", "path", "quarantined", "selector"]) ||
          !validID(proof.id) || !PROOF_KINDS.has(proof.kind) ||
          !(proof.selector === null || safePublicText(proof.selector)) || proof.environment !== "fixture" ||
          proof.expectedStatus !== "pass" || proof.quarantined !== false) {
        fail("PHASE3_EXIT_DEFINITION");
      }
      proofSource(root, proof, readProof);
      proofIDs.add(proof.id);
    }

    if (!Array.isArray(definition.requirements) || definition.requirements.length !== EXPECTED_REQUIREMENTS.length ||
        !same(definition.requirements.map(({ id }) => id), EXPECTED_REQUIREMENTS)) {
      fail("PHASE3_EXIT_DEFINITION");
    }
    const usedProofIDs = [];
    for (const requirement of definition.requirements) {
      if (!exactKeys(requirement, ["environment", "expectedStatus", "id", "module", "ownerIssue", "proofIds"]) ||
          !validID(requirement.id) || ![...EXPECTED_CHILDREN.map(({ issue }) => issue), 58].includes(requirement.ownerIssue) ||
          !safePublicText(requirement.module) || requirement.environment !== "fixture" ||
          requirement.expectedStatus !== "pass" || !Array.isArray(requirement.proofIds) ||
          requirement.proofIds.length === 0 || !unique(requirement.proofIds) ||
          requirement.proofIds.some((id) => !proofIDs.has(id))) {
        fail("PHASE3_EXIT_DEFINITION");
      }
      usedProofIDs.push(...requirement.proofIds);
    }
    if (definition.proofs.some(({ id }) => !usedProofIDs.includes(id))) fail("PHASE3_EXIT_DEFINITION");

    if (!Array.isArray(definition.commands) || definition.commands.length !== EXPECTED_COMMANDS.length) {
      fail("PHASE3_EXIT_DEFINITION");
    }
    for (const [index, command] of definition.commands.entries()) {
      const expected = EXPECTED_COMMANDS[index];
      if (!exactKeys(command, ["argv", "environment", "expectedStatus", "id"]) ||
          command.id !== expected.id || !same(command.argv, expected.argv) ||
          command.environment !== "fixture" || command.expectedStatus !== "pass") {
        fail("PHASE3_EXIT_DEFINITION");
      }
    }

    if (!Array.isArray(definition.artifacts) || definition.artifacts.length !== EXPECTED_ARTIFACTS.length) {
      fail("PHASE3_EXIT_DEFINITION");
    }
    for (const [index, artifact] of definition.artifacts.entries()) {
      const expected = EXPECTED_ARTIFACTS[index];
      if (!exactKeys(artifact, ["digestAtRuntime", "id", "path"]) || artifact.id !== expected.id ||
          artifact.path !== expected.path || artifact.digestAtRuntime !== true || !validRelativePath(artifact.path)) {
        fail("PHASE3_EXIT_DEFINITION");
      }
    }

    if (!Array.isArray(definition.limitations) || definition.limitations.length < 3 ||
        !unique(definition.limitations.map(({ id }) => id))) fail("PHASE3_EXIT_DEFINITION");
    const limitationEnvironments = new Set();
    for (const limitation of definition.limitations) {
      if (!exactKeys(limitation, ["environment", "id", "statement", "status"]) ||
          !validID(limitation.id) || !LIMIT_ENVIRONMENTS.has(limitation.environment) ||
          limitation.status !== "not-exercised" || !safePublicText(limitation.statement)) {
        fail("PHASE3_EXIT_DEFINITION");
      }
      limitationEnvironments.add(limitation.environment);
    }
    if ([...LIMIT_ENVIRONMENTS].some((environment) => !limitationEnvironments.has(environment))) {
      fail("PHASE3_EXIT_DEFINITION");
    }
    return true;
  } catch (error) {
    if (error instanceof Phase3ExitError) throw error;
    fail("PHASE3_EXIT_DEFINITION");
  }
}

export async function readGitState(root = ROOT) {
  try {
    const head = (await runCommand("git", ["rev-parse", "HEAD"], {
      cwd: root, capture: true, timeoutMs: 30_000,
    })).stdout.trim();
    const status = (await runCommand("git", ["status", "--porcelain=v1", "--untracked-files=all"], {
      cwd: root, capture: true, timeoutMs: 30_000,
    })).stdout;
    if (!SHA_PATTERN.test(head)) fail("PHASE3_EXIT_GIT_STATE");
    return { head, clean: status.length === 0 };
  } catch (error) {
    if (error instanceof Phase3ExitError) throw error;
    fail("PHASE3_EXIT_GIT_STATE");
  }
}

export function assertExactCleanCommit({ expected, before, after }) {
  if (!SHA_PATTERN.test(expected) || !before || !after || before.head !== expected || after.head !== expected) {
    fail("PHASE3_EXIT_COMMIT");
  }
  if (before.clean !== true || after.clean !== true) fail("PHASE3_EXIT_CLEAN_TREE");
  return true;
}

function canonicalJSON(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJSON).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJSON(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function digest(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

async function defaultRunChecks(root) {
  await runCheckPlan(fullCheckPlan(), { root, quiet: true });
  await runCommand("go", ["test", "-race", "-count=1", "./..."], {
    cwd: root, capture: true, timeoutMs: 600_000,
  });
  return EXPECTED_COMMANDS.map(({ id }) => ({ id, status: "pass", quarantined: false }));
}

function validateCheckResults(results) {
  if (!Array.isArray(results) || results.length !== EXPECTED_COMMANDS.length ||
      !same(results.map(({ id }) => id), EXPECTED_COMMANDS.map(({ id }) => id))) {
    fail("PHASE3_EXIT_CHECKS");
  }
  for (const result of results) {
    if (!exactKeys(result, ["id", "quarantined", "status"]) ||
        result.status !== "pass" || result.quarantined !== false) fail("PHASE3_EXIT_CHECKS");
  }
}

async function artifactDigests(root, definition, digestInputs) {
  const values = [];
  for (const artifact of definition.artifacts) {
    try {
      const content = digestInputs === undefined
        ? await readFileAsync(path.join(root, artifact.path))
        : digestInputs[artifact.path];
      if (!(typeof content === "string" || Buffer.isBuffer(content) || content instanceof Uint8Array)) {
        fail("PHASE3_EXIT_ARTIFACT");
      }
      values.push({ id: artifact.id, path: artifact.path, digest: digest(content) });
    } catch (error) {
      if (error instanceof Phase3ExitError) throw error;
      fail("PHASE3_EXIT_ARTIFACT");
    }
  }
  return values;
}

export async function runPhase3Exit(root = ROOT, {
  expectedCommit,
  definition,
  readGitState: readState = readGitState,
  runChecks = defaultRunChecks,
  digestInputs,
} = {}) {
  let before;
  try {
    before = await readState(root);
  } catch (error) {
    if (error instanceof Phase3ExitError) throw error;
    fail("PHASE3_EXIT_GIT_STATE");
  }
  assertExactCleanCommit({ expected: expectedCommit, before, after: before });

  let loaded = definition;
  try {
    if (loaded === undefined) {
      loaded = JSON.parse(await readFileAsync(path.join(root, "tooling/phase-3-evidence.json"), "utf8"));
    }
    validatePhase3EvidenceDefinition(loaded, { root });
  } catch (error) {
    if (error instanceof Phase3ExitError) throw error;
    fail("PHASE3_EXIT_DEFINITION");
  }

  let checkResults;
  try {
    checkResults = await runChecks(root, loaded);
    validateCheckResults(checkResults);
  } catch {
    fail("PHASE3_EXIT_CHECKS");
  }

  const artifactValues = await artifactDigests(root, loaded, digestInputs);
  let after;
  try {
    after = await readState(root);
  } catch (error) {
    if (error instanceof Phase3ExitError) throw error;
    fail("PHASE3_EXIT_GIT_STATE");
  }
  assertExactCleanCommit({ expected: expectedCommit, before, after });
  const runtimeEvidence = {
    schema: "vegastack-labs.dev/phase-evidence",
    version: "1.0.0",
    phase: 3,
    sourceCommit: expectedCommit,
    cleanTree: true,
    requirements: loaded.requirements.map((item) => ({
      id: item.id,
      environment: item.environment,
      proofIds: [...item.proofIds],
      status: "pass",
      quarantined: false,
    })),
    commands: checkResults.map((item) => ({ ...item })),
    artifactDigests: artifactValues,
    limitations: loaded.limitations.map((item) => ({ ...item })),
    status: "pass",
  };
  return { ...runtimeEvidence, evidenceDigest: digest(canonicalJSON(runtimeEvidence)) };
}

function summary(evidence) {
  return {
    schemaVersion: 1,
    check: "phase-3-exit",
    sourceCommit: evidence.sourceCommit,
    status: evidence.status,
    evidenceDigest: evidence.evidenceDigest,
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const args = parsePhase3ExitArgs(process.argv.slice(2));
    const evidence = await runPhase3Exit(ROOT, args);
    process.stdout.write(`${JSON.stringify(summary(evidence))}\n`);
  } catch (error) {
    const stage = error instanceof Phase3ExitError ? error.message : "PHASE3_EXIT_VERIFICATION";
    process.stderr.write(`phase-3-exit: ${stage}\n`);
    process.exitCode = 1;
  }
}
