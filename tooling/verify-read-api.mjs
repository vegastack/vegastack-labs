import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CODE_ORDER = [
  "READ_API_ENDPOINT_DRIFT",
  "READ_API_AUTH_ORDER",
  "READ_API_UNSCOPED_STORE",
  "READ_API_OFFSET_PAGINATION",
  "READ_API_CURSOR_SECRET",
  "READ_API_EVENT_PAYLOAD",
  "READ_API_SSE_LIMITS",
  "READ_API_BROWSER_REMOTE",
  "READ_API_SQLITE_SCOPE",
];
const EXPECTED_ENDPOINTS = [
  "api.v1.database-status.get", "api.v1.declarations.get", "api.v1.declarations.plan-preparation.get", "api.v1.declarations.revise",
  "api.v1.events.stream",
  "api.v1.execution-receipts.create",
  "api.v1.executor-leases.claim", "api.v1.executor-leases.renew",
  "api.v1.health.get",
  "api.v1.inventory-diffs.create",
  "api.v1.inventory-draft-aliases.get", "api.v1.inventory-draft-aliases.list",
  "api.v1.inventory-draft-assets.get", "api.v1.inventory-draft-assets.list",
  "api.v1.inventory-draft-nodes.get", "api.v1.inventory-draft-nodes.list",
  "api.v1.inventory-draft-observations.get", "api.v1.inventory-draft-observations.list",
  "api.v1.inventory-drafts.get", "api.v1.inventory-drafts.import", "api.v1.inventory-drafts.list",
  "api.v1.inventory-exports.create",
  "api.v1.plans.acknowledgements.create", "api.v1.plans.acknowledgements.get",
  "api.v1.plans.approval-request.create", "api.v1.plans.approval-status.get",
  "api.v1.plans.create", "api.v1.plans.execute", "api.v1.plans.get", "api.v1.plans.run-resolution.get",
  "api.v1.runs.cancel", "api.v1.runs.get", "api.v1.runs.resume",
  "api.v1.session.create", "api.v1.session.logout", "api.v1.session.renew",
  "api.v1.sources.list", "api.v1.summary.get",
];
// Preserve the original reviewed read/API registry. #104's five gate routes
// are an additional exact wave, not permission for an arbitrary new route.
const REVIEWED_GATE_ENDPOINTS = [
  "api.v1.gate-evidence.create", "api.v1.gate-profile-drafts.create",
  "api.v1.gates.check", "api.v1.gates.get", "api.v1.gates.list",
];
// #124 adds one local binary write route. Keep it separate from both the
// historical read/API surface and #104's gate wave so neither allowance can
// absorb an unrelated credential read, activation, browser or SSH route.
const REVIEWED_CREDENTIAL_IMPORT_ENDPOINTS = [
  "api.v1.credential-references.import-stream",
];
const REVIEWED_AUDIT_ENDPOINTS = [
  "api.v1.audit-checkpoints.create", "api.v1.audit-checkpoints.list",
  "api.v1.audit-history.verification",
];
// #106 adds one inert operator-only backup-policy-draft write route. Keep it as a
// separate reviewed wave so no other allowance can absorb an unrelated backup
// status/run/verify route (those remain planned for #117).
const REVIEWED_BACKUP_ENDPOINTS = [
  "api.v1.backup-policy-drafts.create",
];

async function filesBelow(root, relative) {
  const start = path.join(root, relative); const files = [];
  async function walk(directory) {
    let entries; try { entries = await readdir(directory, { withFileTypes: true }); } catch (error) { if (error.code === "ENOENT") return; throw error; }
    for (const entry of entries) {
      const target = path.join(directory, entry.name);
      if (entry.isDirectory()) await walk(target);
      else if (entry.isFile() && entry.name.endsWith(".go") && !entry.name.endsWith("_test.go")) files.push(target);
    }
  }
  await walk(start); return files.sort();
}

async function optionalRead(filename) { try { return await readFile(filename, "utf8"); } catch (error) { if (error.code === "ENOENT") return ""; throw error; } }

export async function verifyReadAPI(root = ROOT) {
  const codes = new Set();
  const apiFiles = await filesBelow(root, "internal/api");
  const storeFiles = await filesBelow(root, "internal/store");
  const moduleFiles = await filesBelow(root, "internal");
  const api = (await Promise.all(apiFiles.map(optionalRead))).join("\n");
  const store = (await Promise.all(storeFiles.map(optionalRead))).join("\n");

  const registrySource = await optionalRead(path.join(root, "schemas/v1/endpoint-registry.json"));
  if (registrySource) {
    try {
      const registry = JSON.parse(registrySource);
      const ids = registry.endpoints
        .filter((endpoint) => endpoint.availability === "available")
        .map((endpoint) => endpoint.id)
        .sort();
      const gateIDs = ids.filter((id) => id.startsWith("api.v1.gate-") || id.startsWith("api.v1.gates."));
      const credentialImportIDs = ids.filter((id) => id.startsWith("api.v1.credential-references."));
      const auditIDs = ids.filter((id) => id.startsWith("api.v1.audit-"));
      const backupIDs = ids.filter((id) => id.startsWith("api.v1.backup"));
      const historicalIDs = ids.filter((id) => !gateIDs.includes(id) && !credentialImportIDs.includes(id) && !auditIDs.includes(id) && !backupIDs.includes(id));
      if (JSON.stringify(historicalIDs) !== JSON.stringify(EXPECTED_ENDPOINTS) ||
          JSON.stringify(gateIDs) !== JSON.stringify(REVIEWED_GATE_ENDPOINTS) ||
          JSON.stringify(credentialImportIDs) !== JSON.stringify(REVIEWED_CREDENTIAL_IMPORT_ENDPOINTS) ||
          JSON.stringify(auditIDs) !== JSON.stringify(REVIEWED_AUDIT_ENDPOINTS) ||
          JSON.stringify(backupIDs) !== JSON.stringify(REVIEWED_BACKUP_ENDPOINTS)) codes.add("READ_API_ENDPOINT_DRIFT");
    } catch { codes.add("READ_API_ENDPOINT_DRIFT"); }
  }

  const firstQuery = api.search(/\.URL\.Query\s*\(|\.Decode\s*\([^\n]*URL\.Query/);
  const firstAuthorization = api.search(/\.AuthorizeRead\s*\(/);
  if (firstQuery >= 0 && (firstAuthorization < 0 || firstQuery < firstAuthorization)) codes.add("READ_API_AUTH_ORDER");

  const repository = await optionalRead(path.join(root, "internal/store/read_repository.go"));
  for (const name of ["CurrentRevision", "DatabaseStatus", "Summary", "ListDrafts", "GetDraft", "ListRecords", "GetRecord", "ReadEvents", "EventHighWater", "EventExists"]) {
    const declaration = repository.match(new RegExp(`func \\(repository \\*ReadRepository\\) ${name}\\(([^)]*)\\)`));
    if (repository.includes("type ReadRepository") && (!declaration || !declaration[1].includes("authorization.ReadScope"))) codes.add("READ_API_UNSCOPED_STORE");
  }
  if (/\bOFFSET\b/i.test(repository) || /SELECT\s+\*/i.test(repository)) codes.add("READ_API_OFFSET_PAGINATION");
  const cursor = await optionalRead(path.join(root, "internal/api/cursor.go"));
  if (/const\s+\w*(?:key|secret)\w*\s*=|var\s+\w*(?:key|secret)\w*\s*=\s*\[\]byte/i.test(cursor)) codes.add("READ_API_CURSOR_SECRET");
  const sse = await optionalRead(path.join(root, "internal/api/sse.go"));
  if (sse && (!sse.includes("generated.ApiAuditEventData") || /payload_bytes|canonical_payload|OutboxRecordData/.test(sse))) codes.add("READ_API_EVENT_PAYLOAD");
  if (sse && !/BatchSize:\s*200,\s*SignalQueue:\s*64,\s*Heartbeat:\s*15\s*\*\s*time\.Second,\s*WriteDeadline:\s*5\s*\*\s*time\.Second,\s*MaxTotal:\s*16,\s*MaxPerPrincipal:\s*4/.test(sse)) codes.add("READ_API_SSE_LIMITS");
  const serverFiles = await filesBelow(root, "internal/server");
  const server = (await Promise.all(serverFiles.map(optionalRead))).join("\n");
  if (/ListenAndServe|ListenTLS|ListenTCP|websocket|Upgrade\s*\(/i.test(api + "\n" + server)) codes.add("READ_API_BROWSER_REMOTE");
  for (const file of moduleFiles) {
    const relative = path.relative(root, file).split(path.sep).join("/");
    if (relative.startsWith("internal/store/")) continue;
    const source = await optionalRead(file);
    if (/"database\/sql"|"github\.com\/ncruces\/go-sqlite3/.test(source)) codes.add("READ_API_SQLITE_SCOPE");
  }
  const ordered = CODE_ORDER.filter((code) => codes.has(code));
  return { status: ordered.length === 0 ? "pass" : "fail", codes: ordered };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const result = await verifyReadAPI();
    process.stdout.write(`${JSON.stringify({ schemaVersion: 1, check: "read-api", ...result })}\n`);
    if (result.status !== "pass") process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`read API verification failed: ${error.message}\n`); process.exitCode = 1;
  }
}
