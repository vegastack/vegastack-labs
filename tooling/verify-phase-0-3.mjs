import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURE_DIRECTORY = path.join("tooling", "testdata", "phase-0-3");
const FIXTURE_SCHEMA = "vegastack-labs.dev/phase-0.3-contract-fixture";
const INDEX_SCHEMA = "vegastack-labs.dev/phase-0.3-contract-index";
const SCHEMA_VERSION = "1.0.0";

const CONTRACT_NAMES = new Set([
  "installation-manifest",
  "setup-state",
  "slack-acknowledgement",
  "approver-import",
  "constrained-ssh",
  "profile-gates",
]);

const ERROR_CODES = new Set([
  "INPUT_INVALID",
  "SCHEMA_UNSUPPORTED",
  "AUTHENTICATION_REQUIRED",
  "AUTHORIZATION_DENIED",
  "APPROVAL_REQUIRED",
  "STATE_CONFLICT",
  "PLAN_STALE",
  "RECOVERY_EPOCH_MISMATCH",
  "PREREQUISITE_BLOCKED",
  "DEPENDENCY_UNAVAILABLE",
  "INTERRUPTED",
]);

function assertPlainObject(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
}

function assertExactKeys(value, expected, label) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    throw new Error(`${label} fields must be ${wanted.join(", ")}; found ${actual.join(", ")}`);
  }
}

function assertNonemptyString(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${label} must be a nonempty string`);
  }
}

export function validatePhaseZeroThreeFixture(document, source) {
  assertPlainObject(document, source);
  assertExactKeys(document, ["schema", "schemaVersion", "contract", "cases"], source);

  if (document.schema !== FIXTURE_SCHEMA) {
    throw new Error(`${source} has unsupported fixture schema ${JSON.stringify(document.schema)}`);
  }
  if (document.schemaVersion !== SCHEMA_VERSION) {
    throw new Error(`${source} has unsupported schema version ${JSON.stringify(document.schemaVersion)}`);
  }
  if (!CONTRACT_NAMES.has(document.contract)) {
    throw new Error(`${source} has unknown contract ${JSON.stringify(document.contract)}`);
  }
  if (!Array.isArray(document.cases) || document.cases.length === 0) {
    throw new Error(`${source} cases must be a nonempty array`);
  }

  const caseIds = new Set();
  for (const [index, contractCase] of document.cases.entries()) {
    const label = `${source} cases[${index}]`;
    assertPlainObject(contractCase, label);
    assertExactKeys(contractCase, ["id", "input", "expected"], label);
    assertNonemptyString(contractCase.id, `${label}.id`);
    if (caseIds.has(contractCase.id)) {
      throw new Error(`${source} has duplicate case id ${JSON.stringify(contractCase.id)}`);
    }
    caseIds.add(contractCase.id);
    assertPlainObject(contractCase.input, `${label}.input`);
    assertPlainObject(contractCase.expected, `${label}.expected`);
    assertExactKeys(
      contractCase.expected,
      ["status", "errorCode", "reason"],
      `${label}.expected`,
    );

    if (!["accepted", "blocked", "failed"].includes(contractCase.expected.status)) {
      throw new Error(`${label} has unknown expected status ${JSON.stringify(contractCase.expected.status)}`);
    }
    if (contractCase.expected.status === "accepted") {
      if (contractCase.expected.errorCode !== null) {
        throw new Error(`${label} accepted result must have a null error code`);
      }
    } else if (!ERROR_CODES.has(contractCase.expected.errorCode)) {
      throw new Error(`${label} has unknown error code ${JSON.stringify(contractCase.expected.errorCode)}`);
    }
    assertNonemptyString(contractCase.expected.reason, `${label}.expected.reason`);
  }

  return { contract: document.contract, cases: document.cases.length };
}

function validateIndex(document, source) {
  assertPlainObject(document, source);
  assertExactKeys(document, ["schema", "schemaVersion", "contracts"], source);
  if (document.schema !== INDEX_SCHEMA || document.schemaVersion !== SCHEMA_VERSION) {
    throw new Error(`${source} has an unsupported index schema or version`);
  }
  if (!Array.isArray(document.contracts)) {
    throw new Error(`${source}.contracts must be an array`);
  }

  const contracts = new Set();
  const files = new Set();
  for (const [index, entry] of document.contracts.entries()) {
    const label = `${source} contracts[${index}]`;
    assertPlainObject(entry, label);
    assertExactKeys(entry, ["contract", "file", "requiredCaseIds"], label);
    if (!CONTRACT_NAMES.has(entry.contract)) {
      throw new Error(`${label} has unknown contract ${JSON.stringify(entry.contract)}`);
    }
    if (contracts.has(entry.contract)) {
      throw new Error(`${source} has duplicate contract ${JSON.stringify(entry.contract)}`);
    }
    contracts.add(entry.contract);
    assertNonemptyString(entry.file, `${label}.file`);
    if (entry.file !== path.basename(entry.file) || !entry.file.endsWith(".json")) {
      throw new Error(`${label}.file must be a JSON basename`);
    }
    if (entry.file === "contract-index.json" || files.has(entry.file)) {
      throw new Error(`${source} has duplicate or reserved fixture file ${JSON.stringify(entry.file)}`);
    }
    files.add(entry.file);
    if (!Array.isArray(entry.requiredCaseIds) || entry.requiredCaseIds.length === 0) {
      throw new Error(`${label}.requiredCaseIds must be a nonempty array`);
    }
    const required = new Set();
    for (const caseId of entry.requiredCaseIds) {
      assertNonemptyString(caseId, `${label}.requiredCaseIds entry`);
      if (required.has(caseId)) {
        throw new Error(`${label} has duplicate required case id ${JSON.stringify(caseId)}`);
      }
      required.add(caseId);
    }
  }
  return document.contracts;
}

async function loadJson(file) {
  return JSON.parse(await readFile(file, "utf8"));
}

export async function loadPhaseZeroThreeFixtures(root = ROOT) {
  const directory = path.join(root, FIXTURE_DIRECTORY);
  const indexPath = path.join(directory, "contract-index.json");
  const entries = validateIndex(await loadJson(indexPath), "contract-index.json");
  const expectedFiles = new Set(["contract-index.json", ...entries.map(({ file }) => file)]);
  const actualFiles = (await readdir(directory)).filter((file) => file.endsWith(".json"));
  for (const file of actualFiles) {
    if (!expectedFiles.has(file)) {
      throw new Error(`unindexed Phase 0.3 fixture file ${JSON.stringify(file)}`);
    }
  }
  for (const file of expectedFiles) {
    if (!actualFiles.includes(file)) {
      throw new Error(`indexed Phase 0.3 fixture file is missing: ${file}`);
    }
  }

  const fixtures = new Map();
  for (const entry of entries) {
    const document = await loadJson(path.join(directory, entry.file));
    validatePhaseZeroThreeFixture(document, entry.file);
    if (document.contract !== entry.contract) {
      throw new Error(`${entry.file} contract does not match its index entry`);
    }
    const caseIds = new Set(document.cases.map(({ id }) => id));
    for (const requiredCaseId of entry.requiredCaseIds) {
      if (!caseIds.has(requiredCaseId)) {
        throw new Error(`${entry.file} is missing required case ${JSON.stringify(requiredCaseId)}`);
      }
    }
    fixtures.set(entry.contract, document);
  }
  return fixtures;
}

export async function verifyPhaseZeroThree(root = ROOT) {
  const fixtures = await loadPhaseZeroThreeFixtures(root);
  const contracts = [...fixtures.keys()].sort();
  const cases = [...fixtures.values()].reduce((total, fixture) => total + fixture.cases.length, 0);
  return { fixtureFiles: fixtures.size, cases, contracts };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const result = await verifyPhaseZeroThree();
    process.stdout.write(
      `${JSON.stringify({ schemaVersion: 1, check: "phase-0-3-contracts", status: "pass", ...result })}\n`,
    );
  } catch (error) {
    process.stderr.write(`Phase 0.3 contract verification failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
