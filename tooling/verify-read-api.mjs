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
const REVIEWED_CREDENTIAL_LIFECYCLE_ENDPOINTS = ["api.v1.credential-lifecycle-drafts.create"];
const REVIEWED_AUDIT_ENDPOINTS = [
  "api.v1.audit-checkpoints.create", "api.v1.audit-checkpoints.list",
  "api.v1.audit-history.verification",
];
// #106 adds the inert policy-draft route; #115 adds inert retention-lock and
// local-retirement draft routes; #117 adds exact status/run/verify routes.
// Keep the reviewed set closed against direct delete or status edits.
const REVIEWED_BACKUP_ENDPOINTS = [
  "api.v1.backup-jobs.create", "api.v1.backup-offsite-retirements.dry-run", "api.v1.backup-offsite-retirements.stage",
  "api.v1.backup-policy-drafts.create", "api.v1.backup-retention-lock-drafts.create", "api.v1.backup-retirement-drafts.create",
  "api.v1.backup-verifications.create", "api.v1.backups.status",
];
// #222 adds one inert draft and one unadmitted-host read, never admission.
const REVIEWED_ADOPTION_ENDPOINTS = [{"id":"api.v1.host-adoptions.draft","method":"POST","path":"/api/v1/host-adoptions/draft","availability":"available","ownerPhase":"6","requestSchema":"vegastack-labs.dev/host-adoption-request","dataSchema":"vegastack-labs.dev/host-adoption-submission","stream":"finite","audiences":["browser","operator"]},{"id":"api.v1.hosts.get","method":"GET","path":"/api/v1/hosts/{hostID}","availability":"available","ownerPhase":"6","dataSchema":"vegastack-labs.dev/managed-host","stream":"finite","audiences":["browser","operator"]},{"id":"api.v1.hosts.list","method":"GET","path":"/api/v1/hosts","availability":"available","ownerPhase":"6","dataSchema":"vegastack-labs.dev/managed-host-list","stream":"finite","audiences":["browser","operator"]}];
// #223 adds only an inert exact-action draft. Execution stays on the existing
// acknowledged plan route; this wave cannot admit a direct host mutation API.
const REVIEWED_HOST_ACTION_ENDPOINTS = [{"id":"api.v1.host-actions.draft","method":"POST","path":"/api/v1/host-actions/draft","availability":"available","ownerPhase":"6","requestSchema":"vegastack-labs.dev/host-action-request","dataSchema":"vegastack-labs.dev/host-action-submission","stream":"finite","audiences":["browser","operator"]}];
// #225 adds only the finite Debian access-sequence draft; it cannot apply directly.
const REVIEWED_HOST_ACCESS_ENDPOINTS = [{"id":"api.v1.host-access.draft","method":"POST","path":"/api/v1/host-access/draft","availability":"available","ownerPhase":"6","requestSchema":"vegastack-labs.dev/host-access-draft-request","dataSchema":"vegastack-labs.dev/host-action-submission","stream":"finite","audiences":["browser","operator"]}];
// #233 adds only inert replacement drafts and scoped state reads.
// Alias claim reuses declarations; execution remains on acknowledged plans.
const REVIEWED_HOST_REPLACEMENT_ENDPOINTS = [{"id":"api.v1.host-replacements.create","method":"POST","path":"/api/v1/host-replacements","availability":"available","ownerPhase":"6","requestSchema":"vegastack-labs.dev/host-replacement-request","dataSchema":"vegastack-labs.dev/host-replacement-submission","stream":"finite","audiences":["browser","operator"]},{"id":"api.v1.host-replacements.get","method":"GET","path":"/api/v1/host-replacements/{replacementId}","availability":"available","ownerPhase":"6","dataSchema":"vegastack-labs.dev/host-replacement-state","stream":"finite","audiences":["browser","operator"]}];
// #247 adds one inert operator grant-batch draft; apply retains the existing plan route.
const REVIEWED_GRANT_ENDPOINTS = [{"id":"api.v1.authorization.grant-batches.create","method":"POST","path":"/api/v1/authorization/grant-batches","availability":"available","ownerPhase":"6","requestSchema":"vegastack-labs.dev/authorization-grant-batch-request","dataSchema":"vegastack-labs.dev/declaration-revision","stream":"finite","audiences":["operator"]}];
// #228 adds only these exact operator qualification routes; producer lookup stays local and bounded.
const REVIEWED_QUALIFICATION_ENDPOINTS = [{"id":"api.v1.qualification.collect","method":"POST","path":"/api/v1/qualification/collect","availability":"available","ownerPhase":"6","requestSchema":"vegastack-labs.dev/native-collect-request","dataSchema":"vegastack-labs.dev/native-collect-data","stream":"finite","audiences":["operator"]},{"id":"api.v1.qualification.inspect","method":"POST","path":"/api/v1/qualification/inspect","availability":"available","ownerPhase":"6","requestSchema":"vegastack-labs.dev/qualification-inspect-request","dataSchema":"vegastack-labs.dev/qualification-inspect-data","stream":"finite","audiences":["operator"]},{"id":"api.v1.qualification.producer","method":"POST","path":"/api/v1/qualification/native/producer","availability":"available","ownerPhase":"6","requestSchema":"vegastack-labs.dev/native-producer-lookup-request","dataSchema":"vegastack-labs.dev/native-producer-lookup-data","stream":"finite","audiences":["operator"],"transportScope":"local","maxRequestBytes":8192}];
// #276 adds only four scoped finite GETs; lifecycle changes retain exact approved plans.
const REVIEWED_OPERATOR_ACCESS_ENDPOINTS = [{"id":"api.v1.devices.list","method":"GET","path":"/api/v1/devices","availability":"available","ownerPhase":"7","querySchema":"vegastack-labs.dev/operator-read-query","dataSchema":"vegastack-labs.dev/operator-device-list","stream":"finite","audiences":["browser","operator"]},{"id":"api.v1.grants.list","method":"GET","path":"/api/v1/grants","availability":"available","ownerPhase":"7","querySchema":"vegastack-labs.dev/operator-read-query","dataSchema":"vegastack-labs.dev/operator-grant-list","stream":"finite","audiences":["browser","operator"]},{"id":"api.v1.people.list","method":"GET","path":"/api/v1/people","availability":"available","ownerPhase":"7","querySchema":"vegastack-labs.dev/operator-read-query","dataSchema":"vegastack-labs.dev/operator-people-page","stream":"finite","audiences":["browser","operator"]},{"id":"api.v1.providers.list","method":"GET","path":"/api/v1/providers","availability":"available","ownerPhase":"7","dataSchema":"vegastack-labs.dev/operator-provider-list","stream":"finite","audiences":["browser","operator"]}];
// Operator-approved #277 adds only an inert endpoint draft and operator-only fresh descriptor.
const APPROVED_NETWORK_CONNECT_ENDPOINTS = [{"id":"api.v1.hosts.connection-descriptor.get","method":"GET","path":"/api/v1/hosts/{hostID}/connection-descriptor","availability":"available","ownerPhase":"7","dataSchema":"vegastack-labs.dev/network-connect-descriptor","stream":"finite","audiences":["operator"]},{"id":"api.v1.network.endpoint-drafts.create","method":"POST","path":"/api/v1/network/endpoint-drafts","availability":"available","ownerPhase":"7","requestSchema":"vegastack-labs.dev/network-endpoint-request","dataSchema":"vegastack-labs.dev/declaration-revision","stream":"finite","audiences":["operator"]}];
// Approved aggregate Mesh and ingress routes remain separate exact contracts.
const APPROVED_MESH_ENDPOINTS = [{"id":"api.v1.network.mesh.draft","method":"POST","path":"/api/v1/network/mesh/draft","availability":"available","ownerPhase":"7","requestSchema":"vegastack-labs.dev/mesh-draft-request","dataSchema":"vegastack-labs.dev/mesh-draft-submission","stream":"finite","audiences":["browser","operator"]},{"id":"api.v1.network.mesh.observe","method":"POST","path":"/api/v1/network/mesh/observe","availability":"available","ownerPhase":"7","requestSchema":"vegastack-labs.dev/mesh-draft-request","dataSchema":"vegastack-labs.dev/mesh-status-data","stream":"finite","audiences":["browser","operator"]},{"id":"api.v1.network.mesh.status","method":"GET","path":"/api/v1/network/mesh/{profileID}","availability":"available","ownerPhase":"7","dataSchema":"vegastack-labs.dev/mesh-status-data","stream":"finite","audiences":["browser","operator"]}];
const APPROVED_INGRESS_ENDPOINTS = [{"id":"api.v1.network.ingress.draft","method":"POST","path":"/api/v1/network/ingress/draft","availability":"available","ownerPhase":"7","requestSchema":"vegastack-labs.dev/ingress-draft-request","dataSchema":"vegastack-labs.dev/ingress-draft-submission","stream":"finite","audiences":["browser","operator"]},{"id":"api.v1.network.ingress.observe","method":"POST","path":"/api/v1/network/ingress/observe","availability":"available","ownerPhase":"7","requestSchema":"vegastack-labs.dev/ingress-draft-request","dataSchema":"vegastack-labs.dev/ingress-status-data","stream":"finite","audiences":["browser","operator"]},{"id":"api.v1.network.ingress.rollout-evidence","method":"POST","path":"/api/v1/network/ingress/rollout-evidence","availability":"available","ownerPhase":"7","requestSchema":"vegastack-labs.dev/ingress-rollout-evidence-request","dataSchema":"vegastack-labs.dev/ingress-status-data","stream":"finite","audiences":["browser","operator"]},{"id":"api.v1.network.ingress.status","method":"GET","path":"/api/v1/network/ingress/{profileID}","availability":"available","ownerPhase":"7","dataSchema":"vegastack-labs.dev/ingress-status-data","stream":"finite","audiences":["browser","operator"]}];
// #322 adds one inert server-collected pilot evidence draft; no direct activation.
const APPROVED_INGRESS_PILOT_ENDPOINTS = [{"id":"api.v1.network.ingress.pilot-evidence","method":"POST","path":"/api/v1/network/ingress/pilot-evidence","availability":"available","ownerPhase":"7","requestSchema":"vegastack-labs.dev/ingress-pilot-evidence-request","dataSchema":"vegastack-labs.dev/gate-evidence-submission","stream":"finite","audiences":["browser","operator"]}];

// Approved #286 service imports remain inert; provider observations are scoped GETs.
const APPROVED_CI_ENROLLMENT_ENDPOINTS = [{"id":"api.v1.ci.enrollments.drafts.create","method":"POST","path":"/api/v1/ci/enrollments/drafts","availability":"available","ownerPhase":"9","requestSchema":"vegastack-labs.dev/ci-enrollment-draft-request","dataSchema":"vegastack-labs.dev/declaration-revision","stream":"finite","audiences":["operator"]},{"id":"api.v1.ci.enrollments.get","method":"GET","path":"/api/v1/ci/enrollments/{enrollmentID}","availability":"available","ownerPhase":"9","dataSchema":"vegastack-labs.dev/ci-enrollment-record","stream":"finite","audiences":["browser","operator"]},{"id":"api.v1.ci.enrollments.list","method":"GET","path":"/api/v1/ci/enrollments","availability":"available","ownerPhase":"9","querySchema":"vegastack-labs.dev/service-read-query","dataSchema":"vegastack-labs.dev/ci-enrollment-list","stream":"finite","audiences":["browser","operator"]}];
// Approved #313 adds only an operator-only inert job draft; execution uses acknowledged plans.
const APPROVED_CI_JOB_ENDPOINTS = [{"id":"api.v1.ci.jobs.drafts.create","method":"POST","path":"/api/v1/ci/jobs/drafts","availability":"available","ownerPhase":"9","requestSchema":"vegastack-labs.dev/ci-job-draft-request","dataSchema":"vegastack-labs.dev/declaration-revision","stream":"finite","audiences":["operator"]}];
// #319 adds one inert operator publication draft; execution uses the existing approved plan.
const APPROVED_CI_PUBLICATION_ENDPOINTS = [{"id":"api.v1.ci.publications.drafts.create","method":"POST","path":"/api/v1/ci/publications/drafts","availability":"available","ownerPhase":"9","requestSchema":"vegastack-labs.dev/ci-publication-draft-request","dataSchema":"vegastack-labs.dev/declaration-revision","stream":"finite","audiences":["operator"]}];
const APPROVED_SERVICE_ENDPOINTS = [{"id":"api.v1.services.get","method":"GET","path":"/api/v1/services/{serviceID}","availability":"available","ownerPhase":"8","dataSchema":"vegastack-labs.dev/service-record","stream":"finite","audiences":["browser","operator"]},{"id":"api.v1.services.import-drafts.create","method":"POST","path":"/api/v1/services/import-drafts","availability":"available","ownerPhase":"8","requestSchema":"vegastack-labs.dev/service-import-draft-request","dataSchema":"vegastack-labs.dev/declaration-revision","stream":"finite","audiences":["operator"]},{"id":"api.v1.services.list","method":"GET","path":"/api/v1/services","availability":"available","ownerPhase":"8","querySchema":"vegastack-labs.dev/service-read-query","dataSchema":"vegastack-labs.dev/service-list","stream":"finite","audiences":["browser","operator"]},{"id":"api.v1.services.observation.get","method":"GET","path":"/api/v1/services/{serviceID}/observation","availability":"available","ownerPhase":"8","dataSchema":"vegastack-labs.dev/service-observation","stream":"finite","audiences":["browser","operator"]}];
// Approved #288 adds one operator-only inert draft and one exact deployment-result GET.
// Execution remains on the existing acknowledged plan path. #286 stays unchanged.
const APPROVED_SERVICE_DEPLOYMENT_ENDPOINTS = [{"id":"api.v1.services.deployment-drafts.create","method":"POST","path":"/api/v1/services/deployment-drafts","availability":"available","ownerPhase":"8","requestSchema":"vegastack-labs.dev/service-deployment-draft-request","dataSchema":"vegastack-labs.dev/declaration-revision","stream":"finite","audiences":["operator"]},{"id":"api.v1.services.deployment.get","method":"GET","path":"/api/v1/services/{serviceID}/deployment","availability":"available","ownerPhase":"8","dataSchema":"vegastack-labs.dev/service-deployment-record","stream":"finite","audiences":["browser","operator"]}];
// #290–#293 add only exact scoped reads and inert operator drafts.
const APPROVED_PHASE8_FINISH_ENDPOINTS = [{"id":"api.v1.hosting.lifecycle-drafts.create","method":"POST","path":"/api/v1/hosting/lifecycle-drafts","availability":"available","ownerPhase":"8","requestSchema":"vegastack-labs.dev/hosting-lifecycle-draft-request","dataSchema":"vegastack-labs.dev/declaration-revision","stream":"finite","audiences":["operator"]},{"id":"api.v1.hosting.lifecycle.get","method":"GET","path":"/api/v1/hosting/{targetID}/lifecycle","availability":"available","ownerPhase":"8","dataSchema":"vegastack-labs.dev/hosting-lifecycle-record","stream":"finite","audiences":["browser","operator"]},{"id":"api.v1.services.configuration.get","method":"GET","path":"/api/v1/services/{serviceID}/configuration","availability":"available","ownerPhase":"8","dataSchema":"vegastack-labs.dev/service-configuration-status","stream":"finite","audiences":["browser","operator"]},{"id":"api.v1.services.recovery-drafts.create","method":"POST","path":"/api/v1/services/recovery-drafts","availability":"available","ownerPhase":"8","requestSchema":"vegastack-labs.dev/service-recovery-draft-request","dataSchema":"vegastack-labs.dev/declaration-revision","stream":"finite","audiences":["operator"]},{"id":"api.v1.services.recovery.get","method":"GET","path":"/api/v1/services/{serviceID}/recovery","availability":"available","ownerPhase":"8","dataSchema":"vegastack-labs.dev/service-recovery-record","stream":"finite","audiences":["browser","operator"]}];
// Combined Phase 10 exact reads and inert drafts; execution retains acknowledged plans.
const APPROVED_PHASE10_ENDPOINTS = [{"id":"api.v1.maintenance.diagnose","method":"GET","path":"/api/v1/maintenance/hosts/{hostID}","availability":"available","ownerPhase":"10","dataSchema":"vegastack-labs.dev/maintenance-diagnosis","stream":"finite","audiences":["operator"]},{"id":"api.v1.maintenance.drafts.create","method":"POST","path":"/api/v1/maintenance/drafts","availability":"available","ownerPhase":"10","requestSchema":"vegastack-labs.dev/maintenance-draft-request","dataSchema":"vegastack-labs.dev/declaration-revision","stream":"finite","audiences":["operator"]},{"id":"api.v1.operations.notification-readiness","method":"POST","path":"/api/v1/operations/notification-readiness","availability":"available","ownerPhase":"10","requestSchema":"vegastack-labs.dev/notification-readiness-request","dataSchema":"vegastack-labs.dev/declaration-revision","stream":"finite","audiences":["operator"]},{"id":"api.v1.operations.observe","method":"POST","path":"/api/v1/operations/observe","availability":"available","ownerPhase":"10","requestSchema":"vegastack-labs.dev/operations-observe-request","dataSchema":"vegastack-labs.dev/operations-status-data","stream":"finite","audiences":["operator"]},{"id":"api.v1.operations.status","method":"GET","path":"/api/v1/operations","availability":"available","ownerPhase":"10","dataSchema":"vegastack-labs.dev/operations-status-data","stream":"finite","audiences":["browser","operator"]}];
const REVIEWED_DISCOVERY_ENDPOINTS = ["api.v1.host-discovery-targets.draft", "api.v1.host-observations.create", "api.v1.host-observations.get"];
const REVIEWED_OPERATOR_ENDPOINTS = [
  "api.v1.database-backups.create", "api.v1.database-exports.create", "api.v1.database-restores.create", "api.v1.database-verifications.create",
  "api.v1.recovery-points.list", "api.v1.restore-drafts.create", "api.v1.restores.list", "api.v1.restores.plan",
  "api.v1.restores.run", "api.v1.restores.verify", "api.v1.scheduled-job-policies.drafts.create",
  "api.v1.scheduled-job-policies.get", "api.v1.scheduled-job-policies.list", "api.v1.scheduled-jobs.cancel",
  "api.v1.scheduled-jobs.list", "api.v1.scheduled-occurrences.create",
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
      const operatorIDs = ids.filter((id) => REVIEWED_OPERATOR_ENDPOINTS.includes(id));
      const lifecycleIDs = ids.filter((id) => id.startsWith("api.v1.credential-lifecycle-"));
      const discoveryIDs = ids.filter((id) => id.startsWith("api.v1.host-discovery-") || id.startsWith("api.v1.host-observations."));
      // The operator-only descriptor has its own exact #277 contract below.
      const adoptionIDs = ids.filter((id) => id.startsWith("api.v1.host-adoptions.") || (id.startsWith("api.v1.hosts.") && !id.startsWith("api.v1.hosts.connection-descriptor.")));
      const adoptionExact = JSON.stringify(adoptionIDs) === JSON.stringify(REVIEWED_ADOPTION_ENDPOINTS.map(({id}) => id)) && REVIEWED_ADOPTION_ENDPOINTS.every((expected) => {
        const actual = registry.endpoints.find(({id}) => id === expected.id);
        return actual && Object.keys(actual).length === Object.keys(expected).length && Object.entries(expected).every(([key, value]) => JSON.stringify(actual[key]) === JSON.stringify(value));
      });
      const hostActionEndpoints = registry.endpoints.filter(({id}) => id.startsWith("api.v1.host-actions."));
      const hostActionExact = hostActionEndpoints.length === REVIEWED_HOST_ACTION_ENDPOINTS.length && REVIEWED_HOST_ACTION_ENDPOINTS.every((expected) => {
        const actual = hostActionEndpoints.find(({id}) => id === expected.id);
        return actual && Object.keys(actual).length === Object.keys(expected).length && Object.entries(expected).every(([key, value]) => JSON.stringify(actual[key]) === JSON.stringify(value));
      });
      const hostActionIDs = hostActionEndpoints.map(({id}) => id);
      const hostAccessEndpoints = registry.endpoints.filter(({id}) => id.startsWith("api.v1.host-access."));
      const hostAccessExact = hostAccessEndpoints.length === REVIEWED_HOST_ACCESS_ENDPOINTS.length && REVIEWED_HOST_ACCESS_ENDPOINTS.every((expected) => {
        const actual = hostAccessEndpoints.find(({id}) => id === expected.id);
        return actual && Object.keys(actual).length === Object.keys(expected).length && Object.entries(expected).every(([key, value]) => JSON.stringify(actual[key]) === JSON.stringify(value));
      });
      const hostAccessIDs = hostAccessEndpoints.map(({id}) => id);
      const replacementEndpoints = registry.endpoints.filter(({id}) => id.startsWith("api.v1.host-replacements."));
      const replacementExact = replacementEndpoints.length === REVIEWED_HOST_REPLACEMENT_ENDPOINTS.length && REVIEWED_HOST_REPLACEMENT_ENDPOINTS.every((expected) => {
        const actual = replacementEndpoints.find(({id}) => id === expected.id);
        return actual && Object.keys(actual).length === Object.keys(expected).length && Object.entries(expected).every(([key, value]) => JSON.stringify(actual[key]) === JSON.stringify(value));
      });
      const replacementIDs = replacementEndpoints.map(({id}) => id);
      const grantEndpoints = registry.endpoints.filter(({id}) => id.startsWith("api.v1.authorization."));
      const grantExact = grantEndpoints.length === REVIEWED_GRANT_ENDPOINTS.length && REVIEWED_GRANT_ENDPOINTS.every((expected) => {
        const actual = grantEndpoints.find(({id}) => id === expected.id);
        return actual && Object.keys(actual).length === Object.keys(expected).length && Object.entries(expected).every(([key, value]) => JSON.stringify(actual[key]) === JSON.stringify(value));
      });
      const grantIDs = grantEndpoints.map(({id}) => id);
      const qualificationEndpoints = registry.endpoints.filter(({id}) => id.startsWith("api.v1.qualification."));
      const qualificationExact = qualificationEndpoints.length === REVIEWED_QUALIFICATION_ENDPOINTS.length && REVIEWED_QUALIFICATION_ENDPOINTS.every((expected) => {
        const actual = qualificationEndpoints.find(({id}) => id === expected.id);
        return actual && Object.keys(actual).length === Object.keys(expected).length && Object.entries(expected).every(([key, value]) => JSON.stringify(actual[key]) === JSON.stringify(value));
      });
      const qualificationIDs = qualificationEndpoints.map(({id}) => id);
      const operatorAccessEndpoints = registry.endpoints.filter(({id}) => /^api\.v1\.(?:people|devices|grants|providers)\./.test(id));
      const operatorAccessExact = operatorAccessEndpoints.length === REVIEWED_OPERATOR_ACCESS_ENDPOINTS.length && REVIEWED_OPERATOR_ACCESS_ENDPOINTS.every((expected) => {
        const actual = operatorAccessEndpoints.find(({id}) => id === expected.id);
        return actual && Object.keys(actual).length === Object.keys(expected).length && Object.entries(expected).every(([key, value]) => JSON.stringify(actual[key]) === JSON.stringify(value));
      });
      const operatorAccessIDs = operatorAccessEndpoints.map(({id}) => id);
      const networkConnectEndpoints = registry.endpoints.filter(({id}) => (id.startsWith("api.v1.network.") && !id.startsWith("api.v1.network.mesh.") && !id.startsWith("api.v1.network.ingress.")) || id.startsWith("api.v1.hosts.connection-descriptor."));
      const networkConnectExact = networkConnectEndpoints.length === APPROVED_NETWORK_CONNECT_ENDPOINTS.length && APPROVED_NETWORK_CONNECT_ENDPOINTS.every((expected) => {
        const actual = networkConnectEndpoints.find(({id}) => id === expected.id);
        return actual && Object.keys(actual).length === Object.keys(expected).length && Object.entries(expected).every(([key, value]) => JSON.stringify(actual[key]) === JSON.stringify(value));
      });
      const networkConnectIDs = networkConnectEndpoints.map(({id}) => id);
      const meshEndpoints = registry.endpoints.filter(({id}) => id.startsWith("api.v1.network.mesh."));
      const meshExact = meshEndpoints.length === APPROVED_MESH_ENDPOINTS.length && APPROVED_MESH_ENDPOINTS.every((expected) => {
        const actual = meshEndpoints.find(({id}) => id === expected.id);
        return actual && Object.keys(actual).length === Object.keys(expected).length && Object.entries(expected).every(([key, value]) => JSON.stringify(actual[key]) === JSON.stringify(value));
      });
      const meshIDs = meshEndpoints.map(({id}) => id);
      const ingressEndpoints = registry.endpoints.filter(({id}) => id.startsWith("api.v1.network.ingress."));
      const approvedIngressEndpoints = [...APPROVED_INGRESS_ENDPOINTS, ...APPROVED_INGRESS_PILOT_ENDPOINTS];
      const ingressExact = ingressEndpoints.length === approvedIngressEndpoints.length && approvedIngressEndpoints.every((expected) => {
        const actual = ingressEndpoints.find(({id}) => id === expected.id);
        return actual && Object.keys(actual).length === Object.keys(expected).length && Object.entries(expected).every(([key, value]) => JSON.stringify(actual[key]) === JSON.stringify(value));
      });
      const ingressIDs = ingressEndpoints.map(({id}) => id);
      const serviceEndpoints = registry.endpoints.filter(({id}) => id.startsWith("api.v1.services.") || id.startsWith("api.v1.hosting."));
      const approvedServiceEndpoints = [...APPROVED_SERVICE_ENDPOINTS, ...APPROVED_SERVICE_DEPLOYMENT_ENDPOINTS, ...APPROVED_PHASE8_FINISH_ENDPOINTS];
      const serviceExact = serviceEndpoints.length === approvedServiceEndpoints.length && approvedServiceEndpoints.every((expected) => {
        const actual = serviceEndpoints.find(({id}) => id === expected.id);
        return actual && Object.keys(actual).length === Object.keys(expected).length && Object.entries(expected).every(([key,value]) => JSON.stringify(actual[key]) === JSON.stringify(value));
      });
      const serviceIDs = serviceEndpoints.map(({id}) => id);
      const ciEndpoints = registry.endpoints.filter(({id}) => id.startsWith("api.v1.ci."));
      const approvedCIEndpoints = [...APPROVED_CI_ENROLLMENT_ENDPOINTS, ...APPROVED_CI_JOB_ENDPOINTS, ...APPROVED_CI_PUBLICATION_ENDPOINTS];
      const ciIDs = ciEndpoints.map(({id}) => id);
      const ciExact = ciEndpoints.length === approvedCIEndpoints.length && approvedCIEndpoints.every((expected) => {
        const actual = ciEndpoints.find(({id}) => id === expected.id);
        return actual && Object.keys(actual).length === Object.keys(expected).length && Object.entries(expected).every(([key, value]) => JSON.stringify(actual[key]) === JSON.stringify(value));
      });
      const phase10Endpoints = registry.endpoints.filter(({id}) => id.startsWith("api.v1.operations.") || id.startsWith("api.v1.maintenance."));
      const phase10IDs = phase10Endpoints.map(({id}) => id);
      const phase10Exact = phase10Endpoints.length === APPROVED_PHASE10_ENDPOINTS.length && APPROVED_PHASE10_ENDPOINTS.every((expected) => {
        const actual = phase10Endpoints.find(({id}) => id === expected.id);
        return actual && Object.keys(actual).length === Object.keys(expected).length && Object.entries(expected).every(([key, value]) => JSON.stringify(actual[key]) === JSON.stringify(value));
      });
 const historicalIDs = ids.filter((id) => !gateIDs.includes(id) && !credentialImportIDs.includes(id) && !auditIDs.includes(id) && !lifecycleIDs.includes(id) && !backupIDs.includes(id) && !operatorIDs.includes(id) && !discoveryIDs.includes(id) && !adoptionIDs.includes(id) && !hostActionIDs.includes(id) && !hostAccessIDs.includes(id) && !replacementIDs.includes(id) && !grantIDs.includes(id) && !qualificationIDs.includes(id) && !operatorAccessIDs.includes(id) && !networkConnectIDs.includes(id) && !meshIDs.includes(id) && !ingressIDs.includes(id) && !serviceIDs.includes(id) && !ciIDs.includes(id) && !phase10IDs.includes(id));
      if (!phase10Exact || !ciExact || !serviceExact || !meshExact || !ingressExact || !networkConnectExact || !operatorAccessExact || !qualificationExact || !grantExact || !replacementExact || !hostAccessExact || !hostActionExact || !adoptionExact || JSON.stringify(discoveryIDs) !== JSON.stringify(REVIEWED_DISCOVERY_ENDPOINTS) || JSON.stringify(historicalIDs) !== JSON.stringify(EXPECTED_ENDPOINTS) ||
          JSON.stringify(gateIDs) !== JSON.stringify(REVIEWED_GATE_ENDPOINTS) ||
          JSON.stringify(credentialImportIDs) !== JSON.stringify(REVIEWED_CREDENTIAL_IMPORT_ENDPOINTS) ||
          JSON.stringify(auditIDs) !== JSON.stringify(REVIEWED_AUDIT_ENDPOINTS) || JSON.stringify(lifecycleIDs) !== JSON.stringify(REVIEWED_CREDENTIAL_LIFECYCLE_ENDPOINTS) || JSON.stringify(operatorIDs) !== JSON.stringify(REVIEWED_OPERATOR_ENDPOINTS) ||
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
    if (relative.startsWith("internal/store/") || relative === "internal/adapter/localbackup/recovery_restore_linux.go") continue;
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
