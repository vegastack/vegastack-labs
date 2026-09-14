import { createHash } from "node:crypto";
import { readFile as readFileAsync } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { checkStepsForPlan, fullCheckPlan, runCheckPlan } from "./lib/check-plan.mjs";
import { runCommand } from "./lib/process.mjs";
import {
  phase4ScenarioDigest,
  REQUIRED_PHASE4_SCENARIO_IDS,
  validatePhase4AcceptanceDefinition,
} from "./verify-phase-4.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const TRUSTED_DEFAULT_BRANCH_REF = "refs/remotes/origin/main";
const EXPECTED_TOP_LEVEL_KEYS = [
  "acceptance", "artifacts", "children", "commands", "limitations", "phase", "proofCatalog",
  "requirements", "schema", "status", "version",
];
const EXPECTED_ACCEPTANCE = Object.freeze({
  operator: "omkarmohanta09",
  acceptedOn: "14-09-2026",
  sourceCommit: "6bbb81231644c84ef34c8633e9de5671a4186180",
  evidenceDigest: "sha256:fc4803ea63fd18f8685648e2d3dba00fbc8d3484ac1691b936d8232c076bb82a",
  runs: Object.freeze([
    "https://github.com/vegastack/vegastack-labs/actions/runs/34787342900",
    "https://github.com/vegastack/vegastack-labs/actions/runs/34787841878",
  ]),
});
const EXPECTED_CHILDREN = Object.freeze([
  Object.freeze({ issue: 66, phaseIssue: "4.1", pr: 87, reviewedHead: "c07d0c4f0fb0fa9c912f435cb89bd0cffb2b894b", mergeCommit: "5c49630efa10cd977414b6f5e671aa61d5233e5d", evidence: "https://github.com/vegastack/vegastack-labs/issues/66#issuecomment-5647755888", review: "https://github.com/vegastack/vegastack-labs/issues/66#issuecomment-5647642088", postMergeRun: "https://github.com/vegastack/vegastack-labs/actions/runs/34711095199" }),
  Object.freeze({ issue: 76, phaseIssue: "4.2", pr: 88, reviewedHead: "3b62edef38c9ed47192486142824d9dbc3191de1", mergeCommit: "f679edbc1fbdf7f0bf8b3069f2c104b972bbcb19", evidence: "https://github.com/vegastack/vegastack-labs/issues/76#issuecomment-5648189932", review: "https://github.com/vegastack/vegastack-labs/issues/76#issuecomment-5648105763", postMergeRun: "https://github.com/vegastack/vegastack-labs/actions/runs/34714891042" }),
  Object.freeze({ issue: 71, phaseIssue: "4.3", pr: 89, reviewedHead: "fd0ef803255c6ff4db91764bfa22a602995540ce", mergeCommit: "c80273a8efa33fbce8bd8ec4d0c7ca5106ab43fb", evidence: "https://github.com/vegastack/vegastack-labs/issues/71#issuecomment-5648456856", review: "https://github.com/vegastack/vegastack-labs/issues/71#issuecomment-5648385325", postMergeRun: "https://github.com/vegastack/vegastack-labs/actions/runs/34717409646" }),
  Object.freeze({ issue: 77, phaseIssue: "4.4", pr: 92, reviewedHead: "3d719631c001b5e354e0252983c04d56f9ca8da4", mergeCommit: "b1665d53ef8fcab0142b0e0702c7567616e8f093", evidence: "https://github.com/vegastack/vegastack-labs/issues/77#issuecomment-5648530190", review: "https://github.com/vegastack/vegastack-labs/issues/77#issuecomment-5648755482", postMergeRun: "https://github.com/vegastack/vegastack-labs/actions/runs/34723448306" }),
  Object.freeze({ issue: 74, phaseIssue: "4.5", pr: 93, reviewedHead: "8d6c2b130daadcedeaeee6590dc626ce6a0f646f", mergeCommit: "26aeb9c8e76e043ec23d6ddaf7d3bd6b09070a32", evidence: "https://github.com/vegastack/vegastack-labs/issues/74#issuecomment-5648530251", review: "https://github.com/vegastack/vegastack-labs/issues/74#issuecomment-5649443484", postMergeRun: "https://github.com/vegastack/vegastack-labs/actions/runs/34726403603" }),
  Object.freeze({ issue: 69, phaseIssue: "4.6", pr: 94, reviewedHead: "ca7e0297255f3da3c08c111ce0d65b04b849b121", mergeCommit: "deaf70d72a1dc3b79155a4397c3904866ae81121", evidence: "https://github.com/vegastack/vegastack-labs/issues/69#issuecomment-5651545026", review: "https://github.com/vegastack/vegastack-labs/issues/69#issuecomment-5651396049", postMergeRun: "https://github.com/vegastack/vegastack-labs/actions/runs/34742183733" }),
  Object.freeze({ issue: 78, phaseIssue: "4.7", pr: 95, reviewedHead: "32080eba270da888dd4afbeb636b853fea5f9d9f", mergeCommit: "722bcb4aa4fc04cc4ba03f43ee87d1308a893953", evidence: "https://github.com/vegastack/vegastack-labs/issues/78#issuecomment-5653208119", review: "https://github.com/vegastack/vegastack-labs/issues/78#issuecomment-5651818958", postMergeRun: "https://github.com/vegastack/vegastack-labs/actions/runs/34757663955" }),
  Object.freeze({ issue: 79, phaseIssue: "4.8", pr: 98, reviewedHead: "9be236cdf7c8dfc07c335ef759341c20ddaa6ba4", mergeCommit: "67295d0698691517249883932029fa0523de2076", evidence: "https://github.com/vegastack/vegastack-labs/issues/79#issuecomment-5656511261", review: "https://github.com/vegastack/vegastack-labs/issues/79#issuecomment-5656510042", postMergeRun: "https://github.com/vegastack/vegastack-labs/actions/runs/34779930380" }),
  Object.freeze({ issue: 80, phaseIssue: "4.9", pr: 99, reviewedHead: "2bcb25cf502196e651e2bf050ec5ebb86a7b76f7", mergeCommit: "454472328e22cd09e23640f27942e25a6856c2e9", evidence: "https://github.com/vegastack/vegastack-labs/issues/80#issuecomment-5656512504", review: "https://github.com/vegastack/vegastack-labs/issues/80#issuecomment-5655355962", postMergeRun: "https://github.com/vegastack/vegastack-labs/actions/runs/34783427593" }),
]);
const EXPECTED_REQUIREMENTS = Object.freeze([
  "roadmap.phase-4",
  "module-1.declarations-canonical-plans",
  "module-1.authorization-human-acknowledgement",
  "module-1.run-engine-idempotency",
  "module-1.external-executor-leases",
  "module-9.declaration-plan-review",
  "module-9.acknowledgement-execution",
  "module-9.run-recovery-experience",
  "shared.generated-phase-4-contracts",
  "shared.privacy-production-boundary",
]);
const EXPECTED_COMMANDS = Object.freeze([
  Object.freeze({ id: "public-check-catalog", argv: Object.freeze(["pnpm", "check"]) }),
  Object.freeze({ id: "go-race-full", argv: Object.freeze(["go", "test", "-race", "-count=1", "./..."]) }),
]);
const EXPECTED_ARTIFACTS = Object.freeze([
  Object.freeze({ id: "static-definition", path: "tooling/phase-4-exit-evidence.json" }),
  Object.freeze({ id: "phase-4-definition", path: "tooling/testdata/phase-4/acceptance-scenarios.json" }),
  Object.freeze({ id: "phase-4-acceptance", path: "tooling/phase-4-evidence.json" }),
  Object.freeze({ id: "command-registry", path: "schemas/v1/command-registry.json" }),
  Object.freeze({ id: "endpoint-registry", path: "schemas/v1/endpoint-registry.json" }),
  Object.freeze({ id: "generated-browser-client", path: "web/generated/read-api.ts" }),
  Object.freeze({ id: "console-asset-manifest", path: "internal/consoleassets/manifest.json" }),
]);
const LIMIT_ENVIRONMENTS = new Set(["live", "phase-5", "phase-11"]);
const SECRET_PATTERN = /(?:\b(?:gh[opsu]_|github_pat_)[A-Za-z0-9_]+|\bbearer\s+\S+|\bcookie\s*[=:]\s*\S+|\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b|-----BEGIN [A-Z ]*PRIVATE KEY-----)/i;
const PRIVATE_PATTERN = /(?:https?:\/\/(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|[^/\s]+\.(?:internal|local))(?:[:/\s]|$)|(?:^|[\s"'])(?:\/Users\/|\/home\/|[A-Za-z]:\\))/i;

class Phase4ExitError extends Error {
  constructor(stage) {
    super(stage);
    this.name = "Phase4ExitError";
  }
}

function fail(stage) { throw new Phase4ExitError(stage); }
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
function canonicalActionsRunURL(value) {
  if (typeof value !== "string") return false;
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" && parsed.hostname === "github.com" && !parsed.username && !parsed.password &&
      !parsed.search && !parsed.hash && /^\/vegastack\/vegastack-labs\/actions\/runs\/[1-9]\d*$/.test(parsed.pathname);
  } catch { return false; }
}

export function parsePhase4ExitArgs(args) {
  if (!Array.isArray(args) || args.length !== 2 || args[0] !== "--commit" || !SHA_PATTERN.test(args[1])) {
    fail("PHASE4_EXIT_ARGUMENTS");
  }
  return { expectedCommit: args[1] };
}

export function assertLinuxPlatform(platform) {
  if (platform !== "linux") fail("PHASE4_EXIT_LINUX_REQUIRED");
  return true;
}

export function validatePhase4ExitDefinition(definition) {
  try {
    if (!exactKeys(definition, EXPECTED_TOP_LEVEL_KEYS) ||
        definition.schema !== "vegastack-labs.dev/phase-evidence-definition" ||
        definition.version !== "1.0.0" || definition.phase !== 4 || definition.status !== "accepted" ||
        !same(definition.acceptance, EXPECTED_ACCEPTANCE) ||
        !exactKeys(definition.acceptance, ["acceptedOn", "evidenceDigest", "operator", "runs", "sourceCommit"]) ||
        !SHA_PATTERN.test(definition.acceptance.sourceCommit) ||
        !/^sha256:[0-9a-f]{64}$/.test(definition.acceptance.evidenceDigest) ||
        !Array.isArray(definition.acceptance.runs) || definition.acceptance.runs.length !== 2 ||
        !definition.acceptance.runs.every(canonicalActionsRunURL)) fail("PHASE4_EXIT_DEFINITION");
    if (!Array.isArray(definition.children) || definition.children.length !== EXPECTED_CHILDREN.length) fail("PHASE4_EXIT_DEFINITION");
    for (const [index, child] of definition.children.entries()) {
      if (!exactKeys(child, ["evidence", "issue", "mergeCommit", "phaseIssue", "postMergeRun", "pr", "review", "reviewedHead"]) ||
          !same(child, EXPECTED_CHILDREN[index]) || !canonicalCommentURL(child.evidence, child.issue) ||
          !canonicalCommentURL(child.review, child.issue) || !SHA_PATTERN.test(child.reviewedHead) ||
          !canonicalActionsRunURL(child.postMergeRun)) fail("PHASE4_EXIT_DEFINITION");
    }
    if (!exactKeys(definition.proofCatalog, ["evidence", "expectedScenarioCount", "expectedStatus", "path", "quarantined"]) ||
        definition.proofCatalog.path !== "tooling/testdata/phase-4/acceptance-scenarios.json" ||
        definition.proofCatalog.evidence !== "tooling/phase-4-evidence.json" ||
        definition.proofCatalog.expectedScenarioCount !== REQUIRED_PHASE4_SCENARIO_IDS.length ||
        definition.proofCatalog.expectedStatus !== "pass" || definition.proofCatalog.quarantined !== false) fail("PHASE4_EXIT_DEFINITION");
    if (!Array.isArray(definition.requirements) || !same(definition.requirements.map(({ id }) => id), EXPECTED_REQUIREMENTS)) fail("PHASE4_EXIT_DEFINITION");
    const proofIDs = new Set(REQUIRED_PHASE4_SCENARIO_IDS);
    const owners = new Set([...EXPECTED_CHILDREN.map(({ issue }) => issue), 67]);
    const usedProofIDs = [];
    for (const requirement of definition.requirements) {
      if (!exactKeys(requirement, ["environment", "expectedStatus", "id", "module", "ownerIssue", "proofIds"]) ||
          !validID(requirement.id) || !owners.has(requirement.ownerIssue) || !safePublicText(requirement.module) ||
          requirement.environment !== "fixture" || requirement.expectedStatus !== "pass" ||
          !Array.isArray(requirement.proofIds) || requirement.proofIds.length === 0 || !unique(requirement.proofIds) ||
          requirement.proofIds.some((id) => !proofIDs.has(id))) fail("PHASE4_EXIT_DEFINITION");
      usedProofIDs.push(...requirement.proofIds);
    }
    if (REQUIRED_PHASE4_SCENARIO_IDS.some((id) => !usedProofIDs.includes(id))) fail("PHASE4_EXIT_DEFINITION");
    if (!Array.isArray(definition.commands) || definition.commands.length !== EXPECTED_COMMANDS.length) fail("PHASE4_EXIT_DEFINITION");
    for (const [index, command] of definition.commands.entries()) {
      if (!exactKeys(command, ["argv", "environment", "expectedStatus", "id"]) ||
          command.id !== EXPECTED_COMMANDS[index].id || !same(command.argv, EXPECTED_COMMANDS[index].argv) ||
          command.environment !== "fixture" || command.expectedStatus !== "pass") fail("PHASE4_EXIT_DEFINITION");
    }
    if (!Array.isArray(definition.artifacts) || definition.artifacts.length !== EXPECTED_ARTIFACTS.length) fail("PHASE4_EXIT_DEFINITION");
    for (const [index, artifact] of definition.artifacts.entries()) {
      if (!exactKeys(artifact, ["digestAtRuntime", "id", "path"]) || artifact.id !== EXPECTED_ARTIFACTS[index].id ||
          artifact.path !== EXPECTED_ARTIFACTS[index].path || artifact.digestAtRuntime !== true ||
          !validRelativePath(artifact.path)) fail("PHASE4_EXIT_DEFINITION");
    }
    if (!Array.isArray(definition.limitations) || definition.limitations.length !== LIMIT_ENVIRONMENTS.size ||
        !unique(definition.limitations.map(({ id }) => id))) fail("PHASE4_EXIT_DEFINITION");
    const environments = new Set();
    for (const limitation of definition.limitations) {
      if (!exactKeys(limitation, ["environment", "id", "statement", "status"]) || !validID(limitation.id) ||
          !LIMIT_ENVIRONMENTS.has(limitation.environment) || limitation.status !== "not-exercised" ||
          !safePublicText(limitation.statement)) fail("PHASE4_EXIT_DEFINITION");
      environments.add(limitation.environment);
    }
    if ([...LIMIT_ENVIRONMENTS].some((environment) => !environments.has(environment))) fail("PHASE4_EXIT_DEFINITION");
    return true;
  } catch (error) {
    if (error instanceof Phase4ExitError) throw error;
    fail("PHASE4_EXIT_DEFINITION");
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
    if (!SHA_PATTERN.test(head) || !SHA_PATTERN.test(defaultHead)) fail("PHASE4_EXIT_GIT_STATE");
    return { head, defaultHead, clean: status.stdout.length === 0 };
  } catch (error) {
    if (error instanceof Phase4ExitError) throw error;
    fail("PHASE4_EXIT_GIT_STATE");
  }
}

export function assertExactCleanCommit({ expected, before, after }) {
  if (!SHA_PATTERN.test(expected) || !before || !after || before.head !== expected || after.head !== expected ||
      before.defaultHead !== expected || after.defaultHead !== expected) fail("PHASE4_EXIT_COMMIT");
  if (before.clean !== true || after.clean !== true) fail("PHASE4_EXIT_CLEAN_TREE");
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
  name, `PHASE4_EXIT_CHECK_${name.toUpperCase().replace(/[^A-Z0-9]+/g, "_").replace(/^_|_$/g, "")}`,
]));

export async function defaultRunChecks(root, { runPlan = runCheckPlan, run = runCommand } = {}) {
  let currentStage = "PHASE4_EXIT_CHECK_PUBLIC_CHECK_CATALOG";
  try {
    await runPlan(fullCheckPlan(), {
      root,
      quiet: true,
      onStep: ({ name }) => { currentStage = FULL_CHECK_STAGE_CODES.get(name) ?? "PHASE4_EXIT_CHECK_PUBLIC_CHECK_CATALOG"; },
    });
  } catch { fail(currentStage); }
  try {
    await run("go", ["test", "-race", "-count=1", "./..."], { cwd: root, capture: true, timeoutMs: 600_000 });
  } catch { fail("PHASE4_EXIT_CHECK_GO_RACE_FULL"); }
  return EXPECTED_COMMANDS.map(({ id }) => ({ id, status: "pass", quarantined: false }));
}

function validateCheckResults(results) {
  if (!Array.isArray(results) || !same(results.map(({ id }) => id), EXPECTED_COMMANDS.map(({ id }) => id))) fail("PHASE4_EXIT_CHECKS");
  for (const result of results) {
    if (!exactKeys(result, ["id", "quarantined", "status"]) || result.status !== "pass" || result.quarantined !== false) fail("PHASE4_EXIT_CHECKS");
  }
}

async function verifyChildAncestry(root, definition, expectedCommit) {
  for (const child of definition.children) {
    try {
      await runCommand("git", ["merge-base", "--is-ancestor", child.mergeCommit, expectedCommit], { cwd: root, capture: true, timeoutMs: 30_000 });
    } catch { fail("PHASE4_EXIT_CHILD_HISTORY"); }
  }
}

async function artifactDigests(root, definition, digestInputs) {
  const values = [];
  for (const artifact of definition.artifacts) {
    try {
      const content = digestInputs === undefined ? await readFileAsync(path.join(root, artifact.path)) : digestInputs[artifact.path];
      if (!(typeof content === "string" || Buffer.isBuffer(content) || content instanceof Uint8Array)) fail("PHASE4_EXIT_ARTIFACT");
      values.push({ id: artifact.id, path: artifact.path, digest: digest(content) });
    } catch (error) {
      if (error instanceof Phase4ExitError) throw error;
      fail("PHASE4_EXIT_ARTIFACT");
    }
  }
  return values;
}

export async function runPhase4Exit(root = ROOT, {
  expectedCommit,
  platform = process.platform,
  definition,
  acceptanceDefinition,
  acceptanceEvidence,
  readGitState: readState = readGitState,
  runChecks = defaultRunChecks,
  verifyChildren = verifyChildAncestry,
  digestInputs,
} = {}) {
  assertLinuxPlatform(platform);
  const before = await readState(root);
  assertExactCleanCommit({ expected: expectedCommit, before, after: before });
  try {
    definition ??= JSON.parse(await readFileAsync(path.join(root, "tooling/phase-4-exit-evidence.json"), "utf8"));
    acceptanceDefinition ??= JSON.parse(await readFileAsync(path.join(root, definition.proofCatalog.path), "utf8"));
    acceptanceEvidence ??= JSON.parse(await readFileAsync(path.join(root, definition.proofCatalog.evidence), "utf8"));
    validatePhase4ExitDefinition(definition);
    await validatePhase4AcceptanceDefinition(root, acceptanceDefinition, acceptanceEvidence);
    if (acceptanceDefinition.scenarios.length !== definition.proofCatalog.expectedScenarioCount ||
        acceptanceEvidence.quarantined.length !== 0) fail("PHASE4_EXIT_DEFINITION");
  } catch (error) {
    if (error instanceof Phase4ExitError) throw error;
    fail("PHASE4_EXIT_DEFINITION");
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
    phase: 4,
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
      scenarioDigest: phase4ScenarioDigest(acceptanceDefinition),
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
    check: "phase-4-exit",
    sourceCommit: evidence.sourceCommit,
    defaultBranchRef: evidence.defaultBranchRef,
    evidenceDigest: evidence.evidenceDigest,
    status: evidence.status,
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const evidence = await runPhase4Exit(ROOT, parsePhase4ExitArgs(process.argv.slice(2)));
    process.stdout.write(`${JSON.stringify(summary(evidence))}\n`);
  } catch (error) {
    const stage = error instanceof Phase4ExitError ? error.message : "PHASE4_EXIT_VERIFICATION";
    process.stderr.write(`phase-4-exit: ${stage}\n`);
    process.exitCode = 1;
  }
}
