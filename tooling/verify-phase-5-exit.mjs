import { createHash } from "node:crypto";
import { readFile as readFileAsync } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { checkStepsForPlan, fullCheckPlan, runCheckPlan } from "./lib/check-plan.mjs";
import { runCommand } from "./lib/process.mjs";
import {
  phase5ScenarioDigest,
  REQUIRED_PHASE5_SCENARIOS,
  validatePhase5AcceptanceDefinition,
} from "./verify-phase-5.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const TRUSTED_DEFAULT_BRANCH_REF = "refs/remotes/origin/main";
const EXPECTED_TOP_LEVEL_KEYS = [
  "artifacts", "children", "commands", "limitations", "maps", "phase", "proofCatalog",
  "requirements", "research", "schema", "status", "version",
];
const EXPECTED_CHILD_ISSUES = Object.freeze([102, 104, 123, 124, 125, 132, 133, 134, 135, 140, 141, 143, 144, 146, 153, 159, 106, 114, 115, 117, 118, 154, 107, 108, 109, 110, 111]);
const EXPECTED_RESEARCH_ISSUES = Object.freeze([103, 139, 145]);
const EXPECTED_CREDENTIAL_CHILDREN = Object.freeze([123, 124, 125, 132, 133, 134, 135, 140, 141, 143, 144, 146, 153, 159]);
const EXPECTED_BINDING_DIGESTS = Object.freeze({
  children: "sha256:b4395c8d6f95ca60b408843f48f49ff4e0cbb5ef666a23083952dc1a4ea26449",
  research: "sha256:c99cc6a9a8d1d2d42ad046c357f7c7b78dd949fb9dd83739ea95a450d236b0fb",
  maps: "sha256:12d38304bea15d3a72282882cd47b608d11aefe5cef2b457d613f606dc929c45",
});
const EXPECTED_REQUIREMENTS = Object.freeze([
  "roadmap.phase-5",
  "gates.evidence-readiness",
  "secrets.consumer-bound-resolution",
  "backup.local-recovery-points",
  "backup.offsite-generations-retention",
  "audit.tamper-evident-checkpoints",
  "recovery.authority-fencing",
  "scheduling.exact-policies",
  "surface.cli-api-console-parity",
  "shared.hostile-recovery-privacy",
  "shared.fixture-live-boundary",
]);
const EXPECTED_COMMANDS = Object.freeze([
  Object.freeze({ id: "public-check-catalog", argv: Object.freeze(["pnpm", "check"]) }),
  Object.freeze({ id: "go-race-phase-5", argv: Object.freeze(["go", "test", "-race", "-count=1", "./internal/backup", "./internal/recovery", "./internal/run", "./internal/schedule", "./internal/store"]) }),
]);
const EXPECTED_ARTIFACTS = Object.freeze([
  Object.freeze({ id: "static-definition", path: "tooling/phase-5-exit-evidence.json" }),
  Object.freeze({ id: "phase-5-definition", path: "tooling/testdata/phase-5/acceptance-scenarios.json" }),
  Object.freeze({ id: "phase-5-acceptance", path: "tooling/phase-5-evidence.json" }),
  Object.freeze({ id: "accepted-phase-4-definition", path: "tooling/phase-4-exit-evidence.json" }),
  Object.freeze({ id: "command-registry", path: "schemas/v1/command-registry.json" }),
  Object.freeze({ id: "endpoint-registry", path: "schemas/v1/endpoint-registry.json" }),
  Object.freeze({ id: "generated-browser-client", path: "web/generated/read-api.ts" }),
  Object.freeze({ id: "console-asset-manifest", path: "internal/consoleassets/manifest.json" }),
  Object.freeze({ id: "phase-document", path: "docs/development/phases/05-evidence-secrets-backups-recovery.md" }),
]);
const REQUIRED_PHASE5_SCENARIO_IDS = Object.freeze(REQUIRED_PHASE5_SCENARIOS.map(({ id }) => id));
const SECRET_PATTERN = /(?:\b(?:gh[opsu]_|github_pat_)[A-Za-z0-9_]+|\bbearer\s+\S+|\bcookie\s*[=:]\s*\S+|\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b|-----BEGIN [A-Z ]*PRIVATE KEY-----)/i;
const PRIVATE_PATTERN = /(?:https?:\/\/(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|[^/\s]+\.(?:internal|local))(?:[:/\s]|$)|(?:^|[\s"'])(?:\/Users\/|\/home\/|[A-Za-z]:\\))/i;

class Phase5ExitError extends Error {
  constructor(stage) {
    super(stage);
    this.name = "Phase5ExitError";
  }
}

function fail(stage) { throw new Phase5ExitError(stage); }
function same(left, right) { return JSON.stringify(left) === JSON.stringify(right); }
function unique(values) { return new Set(values).size === values.length; }
function exactKeys(value, expected) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    same(Object.keys(value).sort(), [...expected].sort());
}
function validID(value) { return typeof value === "string" && /^[a-z0-9]+(?:[.-][a-z0-9]+)*$/.test(value); }
function validRelativePath(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 4096 &&
    !value.startsWith("/") && !/^[A-Za-z]:[\\/]/.test(value) && !value.includes("\\") &&
    !value.includes("\0") && !value.split("/").includes("..");
}
function safePublicText(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 1000 &&
    !/[\r\n\0]/.test(value) && !SECRET_PATTERN.test(value) && !PRIVATE_PATTERN.test(value);
}
function canonicalCommentURL(value, issue) {
  if (typeof value !== "string") return false;
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" && parsed.hostname === "github.com" && !parsed.username && !parsed.password &&
      !parsed.search && parsed.pathname === `/vegastack/vegastack-labs/issues/${issue}` && /^#issuecomment-\d+$/.test(parsed.hash);
  } catch { return false; }
}
function canonicalActionsProof(value) {
  if (value === "epic-phase-5-exit") return true;
  if (typeof value !== "string") return false;
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" && parsed.hostname === "github.com" && !parsed.username && !parsed.password &&
      !parsed.search && !parsed.hash && /^\/vegastack\/vegastack-labs\/actions\/runs\/[1-9]\d*(?:\/job\/[1-9]\d*)?$/.test(parsed.pathname);
  } catch { return false; }
}

export function parsePhase5ExitArgs(args) {
  if (!Array.isArray(args) || args.length !== 2 || args[0] !== "--commit" || !SHA_PATTERN.test(args[1])) {
    fail("PHASE5_EXIT_ARGUMENTS");
  }
  return { expectedCommit: args[1] };
}

export function assertLinuxPlatform(platform) {
  if (platform !== "linux") fail("PHASE5_EXIT_LINUX_REQUIRED");
  return true;
}

export function validatePhase5ExitDefinition(definition) {
  try {
    if (!exactKeys(definition, EXPECTED_TOP_LEVEL_KEYS) ||
        definition.schema !== "vegastack-labs.dev/phase-evidence-definition" ||
        definition.version !== "1.0.0" || definition.phase !== 5 ||
        definition.status !== "implemented-awaiting-operator-acceptance" ||
        Object.hasOwn(definition, "acceptance")) fail("PHASE5_EXIT_DEFINITION");
    if (!Array.isArray(definition.children) ||
        !same(definition.children.map(({ issue }) => issue), EXPECTED_CHILD_ISSUES) ||
        digest(canonicalJSON(definition.children)) !== EXPECTED_BINDING_DIGESTS.children) fail("PHASE5_EXIT_DEFINITION");
    for (const child of definition.children) {
      if (!exactKeys(child, ["evidence", "issue", "mergeCommit", "phaseIssue", "postMergeProof", "pr", "review", "reviewedHead"]) ||
          !Number.isInteger(child.pr) || !safePublicText(child.phaseIssue) ||
          !canonicalCommentURL(child.evidence, child.issue) ||
          !canonicalCommentURL(child.review, child.issue) || !SHA_PATTERN.test(child.reviewedHead) ||
          !SHA_PATTERN.test(child.mergeCommit) || !canonicalActionsProof(child.postMergeProof)) fail("PHASE5_EXIT_DEFINITION");
    }
    if (!Array.isArray(definition.research) ||
        !same(definition.research.map(({ issue }) => issue), EXPECTED_RESEARCH_ISSUES) ||
        digest(canonicalJSON(definition.research)) !== EXPECTED_BINDING_DIGESTS.research) fail("PHASE5_EXIT_DEFINITION");
    for (const research of definition.research) {
      if (!exactKeys(research, ["evidence", "issue", "review", "sourceSnapshot", "status"]) ||
          research.status !== "closed" || !canonicalCommentURL(research.evidence, research.issue) ||
          !canonicalCommentURL(research.review, research.issue) || !SHA_PATTERN.test(research.sourceSnapshot)) {
        fail("PHASE5_EXIT_DEFINITION");
      }
    }
    if (!Array.isArray(definition.maps) || definition.maps.length !== 1 ||
        !exactKeys(definition.maps[0], ["childIssues", "evidence", "issue", "status"]) ||
        definition.maps[0].issue !== 105 || definition.maps[0].status !== "closed" ||
        !same(definition.maps[0].childIssues, EXPECTED_CREDENTIAL_CHILDREN) ||
        !canonicalCommentURL(definition.maps[0].evidence, 105) ||
        digest(canonicalJSON(definition.maps)) !== EXPECTED_BINDING_DIGESTS.maps) {
      fail("PHASE5_EXIT_DEFINITION");
    }
    if (!exactKeys(definition.proofCatalog, ["evidence", "expectedScenarioCount", "expectedStatus", "path", "quarantined"]) ||
        definition.proofCatalog.path !== "tooling/testdata/phase-5/acceptance-scenarios.json" ||
        definition.proofCatalog.evidence !== "tooling/phase-5-evidence.json" ||
        definition.proofCatalog.expectedScenarioCount !== REQUIRED_PHASE5_SCENARIO_IDS.length ||
        definition.proofCatalog.expectedStatus !== "pass" || definition.proofCatalog.quarantined !== false) fail("PHASE5_EXIT_DEFINITION");
    if (!Array.isArray(definition.requirements) || !same(definition.requirements.map(({ id }) => id), EXPECTED_REQUIREMENTS)) fail("PHASE5_EXIT_DEFINITION");
    const proofIDs = new Set(REQUIRED_PHASE5_SCENARIO_IDS);
    const owners = new Set([...EXPECTED_CHILD_ISSUES, 112]);
    const usedProofIDs = [];
    for (const requirement of definition.requirements) {
      if (!exactKeys(requirement, ["environment", "expectedStatus", "id", "module", "ownerIssue", "proofIds"]) ||
          !validID(requirement.id) || !owners.has(requirement.ownerIssue) || !safePublicText(requirement.module) ||
          requirement.environment !== "fixture" || requirement.expectedStatus !== "pass" ||
          !Array.isArray(requirement.proofIds) || requirement.proofIds.length === 0 || !unique(requirement.proofIds) ||
          requirement.proofIds.some((id) => !proofIDs.has(id))) fail("PHASE5_EXIT_DEFINITION");
      usedProofIDs.push(...requirement.proofIds);
    }
    if (REQUIRED_PHASE5_SCENARIO_IDS.some((id) => !usedProofIDs.includes(id))) fail("PHASE5_EXIT_DEFINITION");
    if (!Array.isArray(definition.commands) || definition.commands.length !== EXPECTED_COMMANDS.length) fail("PHASE5_EXIT_DEFINITION");
    for (const [index, command] of definition.commands.entries()) {
      if (!exactKeys(command, ["argv", "environment", "expectedStatus", "id"]) ||
          command.id !== EXPECTED_COMMANDS[index].id || !same(command.argv, EXPECTED_COMMANDS[index].argv) ||
          command.environment !== "fixture" || command.expectedStatus !== "pass") fail("PHASE5_EXIT_DEFINITION");
    }
    if (!Array.isArray(definition.artifacts) || definition.artifacts.length !== EXPECTED_ARTIFACTS.length) fail("PHASE5_EXIT_DEFINITION");
    for (const [index, artifact] of definition.artifacts.entries()) {
      if (!exactKeys(artifact, ["digestAtRuntime", "id", "path"]) || artifact.id !== EXPECTED_ARTIFACTS[index].id ||
          artifact.path !== EXPECTED_ARTIFACTS[index].path || artifact.digestAtRuntime !== true ||
          !validRelativePath(artifact.path)) fail("PHASE5_EXIT_DEFINITION");
    }
    if (!Array.isArray(definition.limitations) || definition.limitations.length !== 3 ||
        !unique(definition.limitations.map(({ id }) => id))) fail("PHASE5_EXIT_DEFINITION");
    for (const limitation of definition.limitations) {
      if (!exactKeys(limitation, ["environment", "id", "statement", "status"]) || !validID(limitation.id) ||
          !["live", "fixture"].includes(limitation.environment) || limitation.status !== "not-exercised" ||
          !safePublicText(limitation.statement)) fail("PHASE5_EXIT_DEFINITION");
    }
    if (!definition.limitations.some(({ id }) => id.startsWith("g-007.")) ||
        !definition.limitations.some(({ id }) => id.startsWith("g-008."))) fail("PHASE5_EXIT_DEFINITION");
    return true;
  } catch (error) {
    if (error instanceof Phase5ExitError) throw error;
    fail("PHASE5_EXIT_DEFINITION");
  }
}

export async function readGitState(root = ROOT) {
  try {
    const [revision, defaultRevision, status] = await Promise.all([
      runCommand("git", ["rev-parse", "HEAD"], { cwd: root, capture: true, timeoutMs: 30_000 }),
      runCommand("git", ["rev-parse", "--verify", TRUSTED_DEFAULT_BRANCH_REF], { cwd: root, capture: true, timeoutMs: 30_000 }),
      runCommand("git", ["status", "--porcelain=v1", "--untracked-files=all"], { cwd: root, capture: true, timeoutMs: 30_000 }),
    ]);
    const head = revision.stdout.trim();
    const defaultHead = defaultRevision.stdout.trim();
    if (!SHA_PATTERN.test(head) || !SHA_PATTERN.test(defaultHead)) fail("PHASE5_EXIT_GIT_STATE");
    return { head, defaultHead, clean: status.stdout.length === 0 };
  } catch (error) {
    if (error instanceof Phase5ExitError) throw error;
    fail("PHASE5_EXIT_GIT_STATE");
  }
}

export function assertExactCleanCommit({ expected, before, after }) {
  if (!SHA_PATTERN.test(expected) || !before || !after || before.head !== expected || after.head !== expected ||
      before.defaultHead !== expected || after.defaultHead !== expected) fail("PHASE5_EXIT_COMMIT");
  if (before.clean !== true || after.clean !== true) fail("PHASE5_EXIT_CLEAN_TREE");
  return true;
}

function canonicalJSON(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJSON).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJSON(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}
function digest(value) { return `sha256:${createHash("sha256").update(value).digest("hex")}`; }

const FULL_CHECK_STAGE_CODES = new Map(checkStepsForPlan(fullCheckPlan()).map(({ name }) => [
  name, `PHASE5_EXIT_CHECK_${name.toUpperCase().replace(/[^A-Z0-9]+/g, "_").replace(/^_|_$/g, "")}`,
]));

export async function defaultRunChecks(root, { runPlan = runCheckPlan, run = runCommand } = {}) {
  let currentStage = "PHASE5_EXIT_CHECK_PUBLIC_CHECK_CATALOG";
  try {
    await runPlan(fullCheckPlan(), {
      root,
      quiet: true,
      onStep: ({ name }) => { currentStage = FULL_CHECK_STAGE_CODES.get(name) ?? "PHASE5_EXIT_CHECK_PUBLIC_CHECK_CATALOG"; },
    });
  } catch { fail(currentStage); }
  try {
    await run("go", EXPECTED_COMMANDS[1].argv.slice(1), { cwd: root, capture: true, timeoutMs: 600_000 });
  } catch { fail("PHASE5_EXIT_CHECK_GO_RACE_PHASE_5"); }
  return EXPECTED_COMMANDS.map(({ id }) => ({ id, status: "pass", quarantined: false }));
}

function validateCheckResults(results) {
  if (!Array.isArray(results) || !same(results.map(({ id }) => id), EXPECTED_COMMANDS.map(({ id }) => id))) fail("PHASE5_EXIT_CHECKS");
  for (const result of results) {
    if (!exactKeys(result, ["id", "quarantined", "status"]) || result.status !== "pass" || result.quarantined !== false) fail("PHASE5_EXIT_CHECKS");
  }
}

export async function verifyPhase5Ancestry(root, definition, expectedCommit, { run = runCommand } = {}) {
  for (const child of definition.children) {
    try {
      await run("git", ["merge-base", "--is-ancestor", child.mergeCommit, expectedCommit], { cwd: root, capture: true, timeoutMs: 30_000 });
    } catch { fail("PHASE5_EXIT_CHILD_HISTORY"); }
  }
  let accepted;
  try {
    accepted = await Promise.all([
      readFileAsync(path.join(root, "tooling/phase-3-evidence.json"), "utf8"),
      readFileAsync(path.join(root, "tooling/phase-4-exit-evidence.json"), "utf8"),
    ]);
    accepted = accepted.map((value) => JSON.parse(value).acceptance?.sourceCommit);
    if (!accepted.every((value) => SHA_PATTERN.test(value))) fail("PHASE5_EXIT_ACCEPTANCE_HISTORY");
  } catch (error) {
    if (error instanceof Phase5ExitError) throw error;
    fail("PHASE5_EXIT_ACCEPTANCE_HISTORY");
  }
  for (const sourceCommit of accepted) {
    try {
      await run("git", ["merge-base", "--is-ancestor", sourceCommit, expectedCommit], { cwd: root, capture: true, timeoutMs: 30_000 });
    } catch { fail("PHASE5_EXIT_ACCEPTANCE_HISTORY"); }
  }
}

async function artifactDigests(root, definition, digestInputs) {
  const values = [];
  for (const artifact of definition.artifacts) {
    try {
      const content = digestInputs === undefined ? await readFileAsync(path.join(root, artifact.path)) : digestInputs[artifact.path];
      if (!(typeof content === "string" || Buffer.isBuffer(content) || content instanceof Uint8Array)) fail("PHASE5_EXIT_ARTIFACT");
      values.push({ id: artifact.id, path: artifact.path, digest: digest(content) });
    } catch (error) {
      if (error instanceof Phase5ExitError) throw error;
      fail("PHASE5_EXIT_ARTIFACT");
    }
  }
  return values;
}

export async function runPhase5Exit(root = ROOT, {
  expectedCommit,
  platform = process.platform,
  definition,
  acceptanceDefinition,
  acceptanceEvidence,
  readGitState: readState = readGitState,
  runChecks = defaultRunChecks,
  verifyChildren = verifyPhase5Ancestry,
  digestInputs,
} = {}) {
  assertLinuxPlatform(platform);
  const before = await readState(root);
  assertExactCleanCommit({ expected: expectedCommit, before, after: before });
  try {
    definition ??= JSON.parse(await readFileAsync(path.join(root, "tooling/phase-5-exit-evidence.json"), "utf8"));
    acceptanceDefinition ??= JSON.parse(await readFileAsync(path.join(root, definition.proofCatalog.path), "utf8"));
    acceptanceEvidence ??= JSON.parse(await readFileAsync(path.join(root, definition.proofCatalog.evidence), "utf8"));
    validatePhase5ExitDefinition(definition);
    await validatePhase5AcceptanceDefinition(root, acceptanceDefinition, acceptanceEvidence);
    if (acceptanceDefinition.scenarios.length !== definition.proofCatalog.expectedScenarioCount ||
        acceptanceEvidence.quarantined.length !== 0) fail("PHASE5_EXIT_DEFINITION");
  } catch (error) {
    if (error instanceof Phase5ExitError) throw error;
    fail("PHASE5_EXIT_DEFINITION");
  }
  await verifyChildren(root, definition, expectedCommit);
  const checkResults = await runChecks(root, definition);
  validateCheckResults(checkResults);
  const artifactValues = await artifactDigests(root, definition, digestInputs);
  const after = await readState(root);
  assertExactCleanCommit({ expected: expectedCommit, before, after });
  const runtimeEvidence = {
    schema: "vegastack-labs.dev/phase-evidence",
    version: "1.0.0",
    phase: 5,
    sourceCommit: expectedCommit,
    defaultBranchRef: TRUSTED_DEFAULT_BRANCH_REF,
    cleanTree: true,
    requirements: definition.requirements.map((item) => ({
      id: item.id,
      sourceCommit: expectedCommit,
      environment: item.environment,
      proofIds: [...item.proofIds],
      status: "pass",
      quarantined: false,
    })),
    proofCatalog: {
      scenarioCount: acceptanceDefinition.scenarios.length,
      scenarioDigest: phase5ScenarioDigest(acceptanceDefinition),
      status: "pass",
      quarantined: false,
    },
    commands: checkResults.map((item) => ({ ...item })),
    artifactDigests: artifactValues,
    limitations: definition.limitations.map((item) => ({ ...item })),
    status: "pass",
  };
  return { ...runtimeEvidence, evidenceDigest: digest(canonicalJSON(runtimeEvidence)) };
}

function summary(evidence) {
  return {
    schemaVersion: 1,
    check: "phase-5-exit",
    sourceCommit: evidence.sourceCommit,
    defaultBranchRef: evidence.defaultBranchRef,
    evidenceDigest: evidence.evidenceDigest,
    status: evidence.status,
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const evidence = await runPhase5Exit(ROOT, parsePhase5ExitArgs(process.argv.slice(2)));
    process.stdout.write(`${JSON.stringify(summary(evidence))}\n`);
  } catch (error) {
    const stage = error instanceof Phase5ExitError ? error.message : "PHASE5_EXIT_VERIFICATION";
    process.stderr.write(`phase-5-exit: ${stage}\n`);
    process.exitCode = 1;
  }
}
