import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const EVIDENCE_PATH = path.join("tooling", "testdata", "phase-0-5", "evidence-index.json");
const SCHEMA = "vegastack-labs.dev/phase-0.5-evidence-index";
const SCHEMA_VERSION = "1.0.0";

const EXPECTED_DEPENDENCIES = new Map([
  [3, {
    developmentId: "0.1",
    pullRequest: 4,
    head: "chore/0.1-development-route",
    mergeCommit: "36ffcbae7bbb0cc28a5f63ec4d07055c066cf373",
    evidenceKind: "legacy-implementation-summary",
    reviewKind: "legacy-summary-clean-review",
  }],
  [5, {
    developmentId: "0.2",
    pullRequest: 6,
    head: "chore/0.2-public-development-scaffold",
    mergeCommit: "a20d0f526018bab27d72738a94d637d3d7d4036f",
    evidenceKind: "legacy-implementation-summary",
    reviewKind: "legacy-summary-clean-review",
  }],
  [16, {
    developmentId: "0.3",
    pullRequest: 19,
    head: "chore/0.3-bootstrap-profile-human-proof",
    mergeCommit: "fff6d34400f299f9b3b220c8ae5a61efdca47457",
    evidenceKind: "vsk-evidence",
    reviewKind: "vsk-review",
  }],
  [17, {
    developmentId: "0.4",
    pullRequest: 20,
    head: "chore/0.4-host-security-admission",
    mergeCommit: "4412c30c49c8ea6b5e6a8929f05178db235c7b42",
    evidenceKind: "vsk-evidence",
    reviewKind: "vsk-review",
  }],
]);

const EXPECTED_PARENT_ISSUES = new Set([7, 8, 9, 10, 11, 12, 13, 14, 15]);
const EXPECTED_MODULE_PARENTS = new Map([
  [7, { sharedSpine: "platform-core-api-sqlite", deliveryPhases: [1, 2, 4, 5, 11], phaseOneRole: "metadata-graph-and-portable-contracts" }],
  [8, { sharedSpine: "hardware-inventory-hosts", deliveryPhases: [2, 5, 6, 10], phaseOneRole: null }],
  [9, { sharedSpine: "network-identity-edge", deliveryPhases: [3, 6, 7, 10], phaseOneRole: null }],
  [10, { sharedSpine: "source-ci-releases", deliveryPhases: [1, 9, 11], phaseOneRole: "offline-release-verification" }],
  [11, { sharedSpine: "registry-hosting", deliveryPhases: [8, 9, 11], phaseOneRole: null }],
  [12, { sharedSpine: "secrets-redaction", deliveryPhases: [1, 5, 7], phaseOneRole: "redaction-foundation" }],
  [13, { sharedSpine: "backup-restore-audit", deliveryPhases: [2, 5, 11], phaseOneRole: null }],
  [14, { sharedSpine: "observability-notifications", deliveryPhases: [3, 10], phaseOneRole: null }],
  [15, { sharedSpine: "operator-console-agents", deliveryPhases: [1, 3, 4, 10, 11], phaseOneRole: "generated-cli-help-presentation" }],
]);
const EXPECTED_PHASE_ONE_SEQUENCE = new Map([
  ["metadata-graph", { ownerIssue: 7, after: [] }],
  ["portable-contracts", { ownerIssue: 7, after: ["metadata-graph"] }],
  ["redaction-foundation", { ownerIssue: 12, after: ["portable-contracts"] }],
  ["offline-release-verification", { ownerIssue: 10, after: ["portable-contracts"] }],
  ["generated-cli-help-presentation", {
    ownerIssue: 15,
    after: ["redaction-foundation", "offline-release-verification"],
  }],
]);
const EXPECTED_LIMITATIONS = new Map([
  ["github-actions-billing-lock", {
    classification: "external-unavailable",
    claim: "hosted-ci-not-passed",
  }],
  ["pr-20-non-squash-merge", {
    classification: "workflow-divergence",
    claim: "squash-route-not-conformant",
  }],
]);

function assertPlainObject(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
}

function assertExactKeys(value, keys, label) {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${label} fields are incomplete or unknown`);
  }
}

function assertNonemptyString(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${label} must be a nonempty string`);
  }
}

function assertInteger(value, label) {
  if (!Number.isInteger(value) || value < 0) {
    throw new Error(`${label} must be a nonnegative integer`);
  }
}

function assertSha(value, label) {
  if (typeof value !== "string" || !/^[0-9a-f]{40}$/.test(value)) {
    throw new Error(`${label} must be a full lowercase Git commit SHA`);
  }
}

function assertTimestamp(value, label) {
  if (typeof value !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value) ||
      Number.isNaN(Date.parse(value))) {
    throw new Error(`${label} must be a valid RFC 3339 UTC timestamp`);
  }
}

function assertPublicGitHubUrl(value, label, pathPattern) {
  assertNonemptyString(value, label);
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${label} must be a public GitHub URL`);
  }
  if (url.protocol !== "https:" || url.hostname !== "github.com" ||
      !pathPattern.test(url.pathname)) {
    throw new Error(`${label} must be a public GitHub URL for the expected repository object`);
  }
}

function assertSanitized(value) {
  const forbiddenKey = /(?:password|private.?key|secret.?value|credential.?value|raw.?response|authorization.?header|private.?host|operational.?state)/i;
  const forbiddenValue = /(?:\bgh[pousr]_[A-Za-z0-9_]{20,}|\bx(?:app|ox[abprs])-[A-Za-z0-9-]+|-----BEGIN [A-Z ]*PRIVATE KEY-----|\bpassword\s*[=:]\s*\S+)/i;

  function visit(current) {
    if (typeof current === "string") {
      if (forbiddenValue.test(current)) {
        throw new Error("Phase 0.5 evidence contains a prohibited secret-shaped value");
      }
      return;
    }
    if (Array.isArray(current)) {
      current.forEach(visit);
      return;
    }
    if (current === null || typeof current !== "object") return;
    for (const [key, child] of Object.entries(current)) {
      if (forbiddenKey.test(key) || (/token/i.test(key) && !/(?:Ref|Refs)$/.test(key))) {
        throw new Error("Phase 0.5 evidence contains a prohibited private-value field");
      }
      visit(child);
    }
  }

  visit(value);
}

function validateEvidenceReference(reference, label, expectedKind, issueNumber) {
  assertPlainObject(reference, label);
  assertExactKeys(reference, ["kind", "marker", "url"], label);
  if (reference.kind !== expectedKind) throw new Error(`${label}.kind does not match the audited evidence`);
  assertPublicGitHubUrl(
    reference.url,
    `${label}.url`,
    new RegExp(`^/vegastack/vegastack-labs/issues/${issueNumber}$`),
  );
  if (expectedKind === "vsk-evidence") {
    if (reference.marker !== "type=evidence") {
      throw new Error(`#${issueNumber} requires marker-based implementation evidence`);
    }
  } else if (reference.marker !== null) {
    throw new Error(`#${issueNumber} legacy evidence must not invent a workflow marker`);
  }
}

function validateReviewReference(review, expectedKind, issueNumber) {
  assertPlainObject(review, `dependency #${issueNumber}.review`);
  assertExactKeys(review, ["kind", "marker", "verdict", "url"], `dependency #${issueNumber}.review`);
  if (review.kind !== expectedKind || review.verdict !== "clean") {
    throw new Error(`#${issueNumber} requires clean review evidence`);
  }
  assertPublicGitHubUrl(
    review.url,
    `dependency #${issueNumber}.review.url`,
    new RegExp(`^/vegastack/vegastack-labs/issues/${issueNumber}$`),
  );
  if (expectedKind === "vsk-review") {
    if (review.marker !== "type=review verdict=clean") {
      throw new Error(`#${issueNumber} requires clean review evidence`);
    }
  } else if (review.marker !== null) {
    throw new Error(`#${issueNumber} legacy review must not invent a workflow marker`);
  }
}

function validateDependency(dependency, seen) {
  assertPlainObject(dependency, "dependency");
  assertExactKeys(
    dependency,
    ["developmentId", "issueNumber", "issueUrl", "issueState", "pullRequest", "evidence", "review"],
    "dependency",
  );
  assertInteger(dependency.issueNumber, "dependency.issueNumber");
  const expected = EXPECTED_DEPENDENCIES.get(dependency.issueNumber);
  if (!expected || seen.has(dependency.issueNumber)) {
    throw new Error("Phase 0.5 dependencies contain an unknown or duplicate issue");
  }
  seen.add(dependency.issueNumber);
  if (dependency.developmentId !== expected.developmentId) {
    throw new Error(`#${dependency.issueNumber} has the wrong development ID`);
  }
  if (dependency.issueState !== "closed") {
    throw new Error(`#${dependency.issueNumber} must remain recorded as closed`);
  }
  assertPublicGitHubUrl(
    dependency.issueUrl,
    `dependency #${dependency.issueNumber}.issueUrl`,
    new RegExp(`^/vegastack/vegastack-labs/issues/${dependency.issueNumber}$`),
  );

  const pull = dependency.pullRequest;
  assertPlainObject(pull, `dependency #${dependency.issueNumber}.pullRequest`);
  assertExactKeys(
    pull,
    ["number", "url", "state", "base", "head", "mergeCommit", "parentCount"],
    `dependency #${dependency.issueNumber}.pullRequest`,
  );
  if (pull.number !== expected.pullRequest || pull.state !== "merged" || pull.base !== "main" ||
      pull.head !== expected.head || pull.mergeCommit !== expected.mergeCommit) {
    throw new Error(`#${dependency.issueNumber} pull-request binding does not match the audited merge`);
  }
  assertSha(pull.mergeCommit, `dependency #${dependency.issueNumber}.pullRequest.mergeCommit`);
  assertInteger(pull.parentCount, `dependency #${dependency.issueNumber}.pullRequest.parentCount`);
  if (pull.parentCount < 1) throw new Error(`#${dependency.issueNumber} merge commit must have a parent`);
  assertPublicGitHubUrl(
    pull.url,
    `dependency #${dependency.issueNumber}.pullRequest.url`,
    new RegExp(`^/vegastack/vegastack-labs/pull/${pull.number}$`),
  );

  validateEvidenceReference(
    dependency.evidence,
    `dependency #${dependency.issueNumber}.evidence`,
    expected.evidenceKind,
    dependency.issueNumber,
  );
  validateReviewReference(dependency.review, expected.reviewKind, dependency.issueNumber);
}

function validateModuleParentShape(parent, seen, spines) {
  assertPlainObject(parent, "module parent");
  assertExactKeys(
    parent,
    ["issueNumber", "url", "sharedSpine", "deliveryPhases", "phaseOneRole"],
    "module parent",
  );
  assertInteger(parent.issueNumber, "module parent issueNumber");
  if (!EXPECTED_PARENT_ISSUES.has(parent.issueNumber) || seen.has(parent.issueNumber)) {
    throw new Error("module parents contain an unknown or duplicate issue");
  }
  seen.add(parent.issueNumber);
  const expected = EXPECTED_MODULE_PARENTS.get(parent.issueNumber);
  assertPublicGitHubUrl(
    parent.url,
    `module parent #${parent.issueNumber}.url`,
    new RegExp(`^/vegastack/vegastack-labs/issues/${parent.issueNumber}$`),
  );
  assertNonemptyString(parent.sharedSpine, `module parent #${parent.issueNumber}.sharedSpine`);
  if (spines.has(parent.sharedSpine)) {
    throw new Error("shared spine owner must be unique");
  }
  spines.add(parent.sharedSpine);
  if (!Array.isArray(parent.deliveryPhases) || parent.deliveryPhases.length === 0) {
    throw new Error(`module parent #${parent.issueNumber} must list delivery phases`);
  }
  parent.deliveryPhases.forEach((phase) => assertInteger(phase, `module parent #${parent.issueNumber} phase`));
  if (parent.phaseOneRole !== null) {
    assertNonemptyString(parent.phaseOneRole, `module parent #${parent.issueNumber}.phaseOneRole`);
  }
  if (parent.sharedSpine !== expected.sharedSpine ||
      JSON.stringify(parent.deliveryPhases) !== JSON.stringify(expected.deliveryPhases) ||
      parent.phaseOneRole !== expected.phaseOneRole) {
    throw new Error(`module parent #${parent.issueNumber} does not match its audited ownership`);
  }
}

function visitCapability(capability, byCapability, visiting, visited) {
  if (visited.has(capability)) return;
  if (visiting.has(capability)) throw new Error("Phase 1 handoff contains an order cycle");
  const step = byCapability.get(capability);
  if (!step) throw new Error("Phase 1 handoff references an unknown prerequisite");
  visiting.add(capability);
  step.after.forEach((dependency) => visitCapability(dependency, byCapability, visiting, visited));
  visiting.delete(capability);
  visited.add(capability);
}

function validateHandoffShape(handoff) {
  assertPlainObject(handoff, "phaseOneHandoff");
  assertExactKeys(handoff, ["authority", "firstCapability", "sequence"], "phaseOneHandoff");
  if (handoff.authority !== "planning-only") {
    throw new Error("Phase 1 handoff authority must be planning-only");
  }
  if (handoff.firstCapability !== "metadata-graph") {
    throw new Error("Phase 1 handoff must start with the metadata graph");
  }
  if (!Array.isArray(handoff.sequence) || handoff.sequence.length === 0) {
    throw new Error("phaseOneHandoff.sequence must be nonempty");
  }
  const byCapability = new Map();
  for (const [index, step] of handoff.sequence.entries()) {
    assertPlainObject(step, `phaseOneHandoff.sequence[${index}]`);
    assertExactKeys(step, ["capability", "ownerIssue", "after"], `phaseOneHandoff.sequence[${index}]`);
    assertNonemptyString(step.capability, `phaseOneHandoff.sequence[${index}].capability`);
    assertInteger(step.ownerIssue, `phaseOneHandoff.sequence[${index}].ownerIssue`);
    if (!Array.isArray(step.after)) throw new Error(`phaseOneHandoff.sequence[${index}].after must be an array`);
    step.after.forEach((entry) => assertNonemptyString(entry, "phaseOneHandoff dependency"));
    if (byCapability.has(step.capability)) throw new Error("Phase 1 handoff contains a duplicate capability");
    byCapability.set(step.capability, step);
  }
  if (byCapability.size !== EXPECTED_PHASE_ONE_SEQUENCE.size) {
    throw new Error("Phase 1 handoff has incomplete capability coverage");
  }
  const visited = new Set();
  for (const capability of byCapability.keys()) {
    visitCapability(capability, byCapability, new Set(), visited);
  }
  for (const [capability, expected] of EXPECTED_PHASE_ONE_SEQUENCE) {
    const step = byCapability.get(capability);
    if (!step || step.ownerIssue !== expected.ownerIssue ||
        JSON.stringify(step.after) !== JSON.stringify(expected.after)) {
      throw new Error(`Phase 1 capability ${capability} does not match the approved order`);
    }
  }
}

export function validateModuleOwnership(entries) {
  if (!Array.isArray(entries) || entries.length !== EXPECTED_PARENT_ISSUES.size) {
    throw new Error("Phase 0.5 must record all nine module parents");
  }
  const moduleParents = new Set();
  const sharedSpines = new Set();
  entries.forEach((parent) => validateModuleParentShape(parent, moduleParents, sharedSpines));
  const phaseOneOwners = new Set(
    entries.filter(({ phaseOneRole }) => phaseOneRole !== null).map(({ issueNumber }) => issueNumber),
  );
  return {
    moduleParents: moduleParents.size,
    sharedSpines: sharedSpines.size,
    phaseOneOwners: phaseOneOwners.size,
  };
}

function validateLimitations(limitations) {
  if (!Array.isArray(limitations) || limitations.length !== EXPECTED_LIMITATIONS.size) {
    throw new Error("Phase 0.5 must record exactly two known limitations");
  }
  const seen = new Set();
  for (const limitation of limitations) {
    assertPlainObject(limitation, "limitation");
    assertExactKeys(limitation, ["id", "classification", "owner", "claim", "evidenceUrl"], "limitation");
    const expected = EXPECTED_LIMITATIONS.get(limitation.id);
    if (!expected || seen.has(limitation.id)) {
      throw new Error("Phase 0.5 limitations contain an unknown or duplicate ID");
    }
    seen.add(limitation.id);
    if (limitation.classification !== expected.classification || limitation.claim !== expected.claim) {
      if (limitation.id === "github-actions-billing-lock") {
        throw new Error("hosted CI must remain unavailable rather than being recorded as passed");
      }
      throw new Error("PR #20 must remain recorded as nonconformant with the squash route");
    }
    assertNonemptyString(limitation.owner, `${limitation.id}.owner`);
    assertPublicGitHubUrl(
      limitation.evidenceUrl,
      `${limitation.id}.evidenceUrl`,
      /^\/vegastack\/vegastack-labs\/issues\/17$/,
    );
  }
}

export async function loadPhaseZeroFiveEvidence(root = ROOT) {
  return JSON.parse(await readFile(path.join(root, EVIDENCE_PATH), "utf8"));
}

export function validatePhaseZeroFiveEvidence(document) {
  assertSanitized(document);
  assertPlainObject(document, "Phase 0.5 evidence");
  assertExactKeys(
    document,
    [
      "schema", "schemaVersion", "repository", "reviewedAt", "baselineCommit",
      "dependencies", "moduleParents", "phaseOneHandoff", "limitations",
    ],
    "Phase 0.5 evidence",
  );
  if (document.schema !== SCHEMA || document.schemaVersion !== SCHEMA_VERSION) {
    throw new Error("Phase 0.5 evidence schema is unsupported");
  }
  if (document.repository !== "vegastack/vegastack-labs") {
    throw new Error("Phase 0.5 evidence names the wrong repository");
  }
  assertTimestamp(document.reviewedAt, "reviewedAt");
  if (document.baselineCommit !== EXPECTED_DEPENDENCIES.get(17).mergeCommit) {
    throw new Error("Phase 0.5 baseline must be the integrated Phase 0.4 commit");
  }
  assertSha(document.baselineCommit, "baselineCommit");

  if (!Array.isArray(document.dependencies) || document.dependencies.length !== EXPECTED_DEPENDENCIES.size) {
    throw new Error("Phase 0.5 must record all four dependency issues");
  }
  const dependencyIssues = new Set();
  document.dependencies.forEach((dependency) => validateDependency(dependency, dependencyIssues));

  const ownership = validateModuleOwnership(document.moduleParents);
  validateHandoffShape(document.phaseOneHandoff);
  validateLimitations(document.limitations);

  return {
    dependencyIssues: dependencyIssues.size,
    mergedPullRequests: document.dependencies.length,
    moduleParents: ownership.moduleParents,
    sharedSpines: ownership.sharedSpines,
    limitations: document.limitations.length,
  };
}

export async function verifyPhaseZeroFive(root = ROOT) {
  return validatePhaseZeroFiveEvidence(await loadPhaseZeroFiveEvidence(root));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const result = await verifyPhaseZeroFive();
    process.stdout.write(
      `${JSON.stringify({ schemaVersion: 1, check: "phase-0-5", status: "pass", ...result })}\n`,
    );
  } catch (error) {
    process.stderr.write(`Phase 0.5 verification failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
