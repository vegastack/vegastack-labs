import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { runCommand } from "./lib/process.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const MANIFEST_PATH = "tooling/phase-2-evidence.json";
const CODE_ORDER = [
  "PHASE2_CHILD_INCOMPLETE",
  "PHASE2_TRACEABILITY_GAP",
  "PHASE2_CONTRACT_DRIFT",
  "PHASE2_MUTATION_AVAILABLE",
  "PHASE2_PRODUCTION_BYPASS",
  "PHASE2_PRIVATE_FIXTURE",
  "PHASE2_EVIDENCE_STALE",
];
const REQUIREMENT_IDS = [
  "module-1.server-lifecycle-local-api",
  "module-1.sqlite-durability-migrations",
  "module-1.versioned-read-api-events",
  "module-2.labs-sheet-adapter",
  "module-2.read-api-cli",
  "module-2.typed-inventory",
  "module-7.audit-outbox",
  "module-7.online-backup-signed-export",
  "roadmap.phase-2",
];
const EXPECTED_CHILDREN = [
  [29, 40, "61dd286cc414dcbe9fd0919b31acb0216d8e183a"],
  [30, 41, "478c1d71b32f90fe546a8c0c1b08165bccaa9446"],
  [31, 43, "81b0d8ed48836a84636a44566ee337d37f369d42"],
  [32, 44, "2bc14ca99b10333a94803e3f3d51c150cc77950b"],
  [33, 45, "04f555fb15985e82bba09ce562fa0a4abfcc537e"],
  [34, 42, "1dc2e9ffecf1d8b4a148f676bb28826b329e88fe"],
  [35, 46, "4118272e027385affd56b38e65a7ebb320d025ef"],
  [36, 48, "8d4a07bedc8d2aaadb479dab73210435c907f24a"],
  [37, 47, "34e9e9d01f6c0bbb14c8e54d4a2ab4a1b1e77fc3"],
];
const EXPECTED_AVAILABLE_COMMANDS = [
  "database status", "help", "inventory diff", "inventory export", "inventory import",
  "release inspect", "release verify", "server run", "server status", "status", "version",
];
const EXPECTED_ENDPOINT_IDS = [
  "api.v1.database-status.get", "api.v1.events.stream", "api.v1.health.get",
  "api.v1.inventory-diffs.create", "api.v1.inventory-draft-aliases.get",
  "api.v1.inventory-draft-aliases.list", "api.v1.inventory-draft-assets.get",
  "api.v1.inventory-draft-assets.list", "api.v1.inventory-draft-nodes.get",
  "api.v1.inventory-draft-nodes.list", "api.v1.inventory-draft-observations.get",
  "api.v1.inventory-draft-observations.list", "api.v1.inventory-drafts.get",
  "api.v1.inventory-drafts.import", "api.v1.inventory-drafts.list",
  "api.v1.inventory-exports.create", "api.v1.summary.get",
];

function exactKeys(value, keys) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
}

function same(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

async function sha256(filename) {
  return createHash("sha256").update(await readFile(filename)).digest("hex");
}

async function filesBelow(root) {
  const found = [];
  async function walk(directory) {
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch (error) {
      if (error.code === "ENOENT") return;
      throw error;
    }
    for (const entry of entries) {
      const filename = path.join(directory, entry.name);
      if (entry.isDirectory()) await walk(filename);
      else if (entry.isFile()) found.push(filename);
    }
  }
  await walk(root);
  return found.sort();
}

async function commandOutput(root, command, args) {
  return (await runCommand(command, args, { cwd: root, capture: true, timeoutMs: 120_000 })).stdout.trim();
}

async function proofExists(root, proof) {
  const [kind, location, testName] = proof.split(":");
  if (kind === "node-test" && location && !testName) {
    try {
      await readFile(path.join(root, location));
      return true;
    } catch {
      return false;
    }
  }
  if (kind !== "go-test" || !location || !testName || !/^Test[A-Za-z0-9_]+$/.test(testName)) return false;
  const relative = location.replace(/^\.\//, "");
  const files = await filesBelow(path.join(root, relative));
  for (const filename of files.filter((candidate) => candidate.endsWith("_test.go"))) {
    if ((await readFile(filename, "utf8")).includes(`func ${testName}(`)) return true;
  }
  return false;
}

export async function collectIntegratedFacts(root = ROOT) {
  const commands = JSON.parse(await readFile(path.join(root, "schemas/v1/command-registry.json"), "utf8"));
  const endpoints = JSON.parse(await readFile(path.join(root, "schemas/v1/endpoint-registry.json"), "utf8"));
  const migrationFiles = (await readdir(path.join(root, "internal/store/migrations")))
    .filter((name) => /^\d{4}_[a-z0-9_]+\.sql$/.test(name)).sort();
  const migrations = await Promise.all(migrationFiles.map(async (file) => ({
    file,
    sha256: await sha256(path.join(root, "internal/store/migrations", file)),
  })));
  const head = await commandOutput(root, "git", ["rev-parse", "HEAD"]);
  const children = [];
  for (const [issue, pr, mergeCommit] of EXPECTED_CHILDREN) {
    let state = "OPEN";
    try {
      await runCommand("git", ["merge-base", "--is-ancestor", mergeCommit, head], {
        cwd: root, capture: true, timeoutMs: 30_000,
      });
      state = "CLOSED";
    } catch {
      state = "OPEN";
    }
    children.push({ issue, pr, mergeCommit, state });
  }
  const productionImports = (await commandOutput(root, "go", [
    "list", "-deps", "-f", "{{.ImportPath}}", "./cmd/vsk-labs",
  ])).split("\n").filter(Boolean).sort();
  const serviceSource = await readFile(path.join(root, "internal/server/service.go"), "utf8");
  const fixtureFiles = await filesBelow(path.join(root, "tooling/testdata/phase-2"));
  let privateFixture = false;
  for (const filename of fixtureFiles) {
    const content = await readFile(filename, "utf8");
    if (/BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|ghp_[A-Za-z0-9]|sk-[A-Za-z0-9]|\/Users\/|@vegastack\.(?:com|in)/i.test(content)) {
      privateFixture = true;
    }
  }
  return {
    testedCommit: head,
    schemaVersion: commands.schemaVersion,
    endpointSchemaVersion: endpoints.schemaVersion,
    availableCommands: commands.commands.filter(({ availability }) => availability === "available")
      .map(({ path: segments }) => segments.join(" ")).sort(),
    endpointIds: endpoints.endpoints.map(({ id }) => id).sort(),
    migrations,
    productionExecutable: "cmd/vsk-labs",
    mutationAvailable: /MutationAvailable:\s*true/.test(serviceSource) ||
      !/MutationAvailable:\s*false/.test(serviceSource),
    productionImports,
    privateFixture,
    children,
  };
}

export function validateEvidence(manifest, facts) {
  const codes = new Set();
  const scenarioIDs = [];
  if (!exactKeys(manifest, ["schemaVersion", "phase", "status", "contract", "children", "scenarios", "requirements"]) ||
      manifest.schemaVersion !== 1 || manifest.phase !== "2" ||
      manifest.status !== "implemented-awaiting-operator-acceptance" ||
      !exactKeys(manifest.contract, ["schemaVersion", "productionExecutable", "mutationAvailable", "availableCommands", "endpointIds", "migrations"]) ||
      !Array.isArray(manifest.children) || !Array.isArray(manifest.scenarios) || !Array.isArray(manifest.requirements)) {
    codes.add("PHASE2_TRACEABILITY_GAP");
  } else {
    const scenarioSet = new Set();
    for (const scenario of manifest.scenarios) {
      if (!exactKeys(scenario, ["id", "category", "ownerIssue", "proof"]) ||
          !/^[a-z0-9]+(?:[.-][a-z0-9]+)*$/.test(scenario.id) || scenarioSet.has(scenario.id) ||
          !["happy", "denial", "privacy", "recovery", "parity"].includes(scenario.category) ||
          !Number.isInteger(scenario.ownerIssue) || typeof scenario.proof !== "string") {
        codes.add("PHASE2_TRACEABILITY_GAP");
      }
      scenarioSet.add(scenario.id);
      scenarioIDs.push(scenario.id);
    }
    const requirementIDs = [];
    for (const requirement of manifest.requirements) {
      if (!exactKeys(requirement, ["requirementId", "module", "ownerIssue", "status", "scenarioIds"]) ||
          !["covered", "absent", "deferred"].includes(requirement.status) ||
          !Number.isInteger(requirement.ownerIssue) || !Array.isArray(requirement.scenarioIds) ||
          requirement.status === "covered" && requirement.scenarioIds.length === 0 ||
          requirement.scenarioIds.some((id) => !scenarioSet.has(id)) ||
          new Set(requirement.scenarioIds).size !== requirement.scenarioIds.length) {
        codes.add("PHASE2_TRACEABILITY_GAP");
      }
      requirementIDs.push(requirement.requirementId);
    }
    if (!same([...requirementIDs].sort(), REQUIREMENT_IDS) || new Set(requirementIDs).size !== requirementIDs.length) {
      codes.add("PHASE2_TRACEABILITY_GAP");
    }
    const expectedChildren = EXPECTED_CHILDREN.map(([issue, pr, mergeCommit]) => ({ issue, pr, mergeCommit }));
    const actualChildren = manifest.children.map(({ issue, pr, mergeCommit }) => ({ issue, pr, mergeCommit }));
    if (!same(actualChildren, expectedChildren) || manifest.children.some((child) =>
      !exactKeys(child, ["issue", "pr", "mergeCommit", "evidence", "review"]) ||
      !/^https:\/\/github\.com\/vegastack\/vegastack-labs\/issues\/\d+#issuecomment-\d+$/.test(child.evidence) ||
      !/^https:\/\/github\.com\/vegastack\/vegastack-labs\/issues\/\d+#issuecomment-\d+$/.test(child.review))) {
      codes.add("PHASE2_EVIDENCE_STALE");
    }
  }
  if (facts.children.some(({ state }) => state !== "CLOSED")) codes.add("PHASE2_CHILD_INCOMPLETE");
  if (manifest.contract && (!same(manifest.contract.endpointIds, EXPECTED_ENDPOINT_IDS) ||
      !same(facts.endpointIds, EXPECTED_ENDPOINT_IDS) ||
      !same(manifest.contract.migrations, facts.migrations) ||
      manifest.contract.schemaVersion !== facts.schemaVersion || facts.schemaVersion !== facts.endpointSchemaVersion ||
      manifest.contract.productionExecutable !== facts.productionExecutable)) {
    codes.add("PHASE2_CONTRACT_DRIFT");
  }
  if (manifest.contract && (manifest.contract.mutationAvailable !== false || facts.mutationAvailable ||
      !same(manifest.contract.availableCommands, EXPECTED_AVAILABLE_COMMANDS) ||
      !same(facts.availableCommands, EXPECTED_AVAILABLE_COMMANDS))) {
    codes.add("PHASE2_MUTATION_AVAILABLE");
  }
  if (facts.productionImports.some((name) => /phase2(?:fixture|harness)/i.test(name))) {
    codes.add("PHASE2_PRODUCTION_BYPASS");
  }
  if (facts.privateFixture) codes.add("PHASE2_PRIVATE_FIXTURE");
  const ordered = CODE_ORDER.filter((code) => codes.has(code));
  return { status: ordered.length === 0 ? "pass" : "fail", codes: ordered, scenarios: scenarioIDs };
}

async function main() {
  const manifest = JSON.parse(await readFile(path.join(ROOT, MANIFEST_PATH), "utf8"));
  const facts = await collectIntegratedFacts(ROOT);
  for (const scenario of manifest.scenarios) {
    if (!await proofExists(ROOT, scenario.proof)) {
      const result = { status: "fail", codes: ["PHASE2_TRACEABILITY_GAP"], scenarios: [] };
      process.stdout.write(`${JSON.stringify({ schemaVersion: 1, check: "phase-2", testedCommit: facts.testedCommit, ...result })}\n`);
      process.exitCode = 1;
      return;
    }
  }
  const result = validateEvidence(manifest, facts);
  process.stdout.write(`${JSON.stringify({ schemaVersion: 1, check: "phase-2", testedCommit: facts.testedCommit, ...result })}\n`);
  if (result.status !== "pass") process.exitCode = 1;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`phase 2 verification failed: ${error.message}\n`);
    process.exitCode = 1;
  });
}
