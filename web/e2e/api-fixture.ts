import type { Page, Route } from "@playwright/test";

export type FixtureMode = "healthy" | "recovery-required" | "dependency" | "dependency-summary" | "dependency-node-page" | "unavailable" | "denied" | "deny-node-page" | "empty" | "missing" | "mismatched-source" | "malformed";
type DomainFixtureState = "healthy" | "stale" | "unknown" | "unavailable" | "failed";
export const fixtureState: { mode: FixtureMode; delay: number; domainState: DomainFixtureState } = { mode: "healthy", delay: 0, domainState: "unavailable" };
export const fixtureAudit: { requests: string[]; responses: string[]; domainProjections: Array<{ source: string; candidates: number; excluded: number }> } = { requests: [], responses: [], domainProjections: [] };
export const phase5ProtectedEffectPaths = [
  "/api/v1/backup-policies/policy-a/jobs",
  "/api/v1/backup-policies/policy-a/retirements",
  "/api/v1/recovery-points/point-a/verifications",
  "/api/v1/audit-checkpoints",
  "/api/v1/restore-plans/plan-a/runs",
  "/api/v1/restore-plans/plan-a/verifications",
  "/api/v1/database/recovery",
  "/api/v1/database/exports",
  "/api/v1/scheduled-job-policies/policy-a/occurrences",
] as const;
const digest = `sha256:${"a".repeat(64)}`;
const gateFixtures = [
  { gateId: "G-008", applicability: "profile", outcome: "blocked", reasonCode: "proof-unavailable", applicabilityReasonCode: "applicable" },
  { gateId: "G-023", applicability: "deferred", outcome: "not-applicable", reasonCode: "deferred", applicabilityReasonCode: "deferred" },
] as const;
function gateViewFixture(source: typeof gateFixtures[number]) {
  return {
    schema: "vegastack-labs.dev/gate-view", schemaVersion: "1.1.0", applicabilityReasonCode: source.applicabilityReasonCode,
    definition: { schema: "vegastack-labs.dev/gate-definition", schemaVersion: "1.1.0", gateId: source.gateId, definitionVersion: "1.0.0", layer: "deployment-profile", profileId: "vegastack-labs", capabilityId: null, subjectKinds: ["site"], applicability: source.applicability, prerequisiteGateIds: [], evidenceSchemaId: "vegastack-labs.dev/gate-evidence", evaluatorVersion: "1.0.0", freshnessSeconds: 86400, recoveryEpochBound: true },
    evaluation: { schema: "vegastack-labs.dev/gate-evaluation", schemaVersion: "1.1.0", evaluationId: `eval-${source.gateId.toLowerCase()}`, gateId: source.gateId, subjectId: "scope", definitionVersion: "1.0.0", evaluatorVersion: "1.0.0", evidenceIds: [], evaluatedAt: "2026-09-15T08:00:00Z", recoveryEpoch: 2, outcome: source.outcome, reasonCode: source.reasonCode, evidenceSource: "none", readyForInput: source.outcome === "blocked" },
  };
}
const nodeBackingRecords = [
  { scope: "draft-one", page: 1, authority: "draft", validationStatus: "valid", id: "node-one", assetId: "asset-one", parentId: "site-one" },
  { scope: "draft-one", page: 2, authority: "draft", validationStatus: "valid", id: "node-two", assetId: "asset-two", parentId: "site-one" },
  { scope: "another-draft", page: 1, authority: "draft", validationStatus: "valid", id: "private-canary", assetId: "op://secret-canary", parentId: "cross-scope-canary" },
] as const;
export const privateFixtureRecords = [nodeBackingRecords[2].id, nodeBackingRecords[2].assetId, nodeBackingRecords[2].parentId] as const;
export const privateDomainBackingRecords = [
  { scope: "another-project", source: "people", kind: "person", value: "private-person-canary" },
  { scope: "another-project", source: "services", kind: "service", value: "private-service-canary" },
  { scope: "another-project", source: "backups", kind: "backup-evidence", value: "private-backup-canary" },
  { scope: "another-project", source: "providers", kind: "provider-error", value: "private-provider-canary" },
] as const;
export const privateDomainCanaries = privateDomainBackingRecords.map(record => record.value);
const domainSourceBackingRecords = [
  { scope: "current-project", source: "people", capability: "identity.person.read" },
  { scope: "current-project", source: "services", capability: "service.read" },
  { scope: "current-project", source: "backups", capability: "backup.status.read" },
  { scope: "current-project", source: "providers", capability: "adapter.status.read" },
  ...privateDomainBackingRecords,
] as const;

function projectDomainSource(source: string, state: DomainFixtureState) {
  const candidates = domainSourceBackingRecords.filter(record => record.source === source);
  const authorized = candidates.filter(record => record.scope === "current-project");
  fixtureAudit.domainProjections.push({ source, candidates: candidates.length, excluded: candidates.length - authorized.length });
  const record = authorized[0];
  if (!record || !("capability" in record)) return undefined;
  const reason = state === "healthy" ? "source observation is current" : state === "stale" ? "source observation is stale" : state === "unknown" ? "source has no observation timestamp" : state === "failed" ? "source reported a collection failure" : "source capability is unavailable";
  return { id: record.source, capability: record.capability, state, collectedAt: state === "healthy" ? "2026-09-11T08:00:00Z" : null, lastSuccessAt: state === "healthy" ? "2026-09-11T08:00:00Z" : "2026-09-10T07:00:00Z", lastErrorAt: state === "failed" || state === "unavailable" ? "2026-09-11T08:00:00Z" : null, reason };
}

function envelope(command: string, data: unknown, status = "succeeded", errors: unknown[] = []) {
  return { schema: "vegastack-labs.dev/browser-run-result", schemaVersion: "1.0.0", toolVersion: "test", command, runId: null, status, changed: false, recoveryEpoch: 2, stateRevision: 8, snapshotDigest: null, releaseBuildId: "test", sourceRevision: null, planId: null, errors, data };
}

async function fulfill(route: Route, status: number, body: string) {
  fixtureAudit.responses.push(body);
  await route.fulfill({ status, contentType: "application/json", body });
}

async function respond(route: Route) {
  const requestUrl = route.request().url();
  fixtureAudit.requests.push(requestUrl);
  if (fixtureState.delay) await new Promise(resolve => setTimeout(resolve, fixtureState.delay));
  const url = new URL(requestUrl);
  const path = url.pathname;
  const method = route.request().method();
  const isSecondNodePage = path.endsWith("/nodes") && Boolean(url.searchParams.get("cursor"));
  if (fixtureState.mode === "malformed") return fulfill(route, 200, "{not-json");
  if (fixtureState.mode === "denied" || (fixtureState.mode === "deny-node-page" && isSecondNodePage)) return fulfill(route, 403, JSON.stringify(envelope("read", {}, "failed", [{ code: "AUTHORIZATION_DENIED", target: "read", retryable: false }])));
  if (fixtureState.mode === "dependency-node-page" && isSecondNodePage) return fulfill(route, 503, JSON.stringify(envelope("read", {}, "failed", [{ code: "DEPENDENCY_UNAVAILABLE", target: "source", retryable: true }])));
  if (fixtureState.mode === "dependency-summary" && path === "/api/v1/summary") return fulfill(route, 503, JSON.stringify(envelope("read", {}, "failed", [{ code: "DEPENDENCY_UNAVAILABLE", target: "summary", retryable: true }])));
  if (fixtureState.mode === "dependency" || fixtureState.mode === "unavailable") return fulfill(route, 503, JSON.stringify(envelope("read", {}, "failed", [{ code: "DEPENDENCY_UNAVAILABLE", target: "source", retryable: fixtureState.mode === "dependency" }])));
  if (method === "POST" && phase5ProtectedEffectPaths.includes(path as typeof phase5ProtectedEffectPaths[number])) {
    return fulfill(route, 403, JSON.stringify(envelope("phase5.protected-effect.denied", {}, "failed", [
      { code: "AUTHORIZATION_DENIED", target: "protected-effect", retryable: false },
    ])));
  }
  if (method === "POST" && /^\/api\/v1\/recovery-points\/[^/]+\/restore-drafts$/.test(path)) return fulfill(route, 200, JSON.stringify(envelope("api.v1.restore-drafts.create", { schema: "vegastack-labs.dev/browser-restore-draft-submission", schemaVersion: "1.0.0", draftId: "draft-restore-a", changeId: "change-restore-a", pointId: "point-a", status: "draft", stateRevision: 9, recoveryEpoch: 2 })));
  if (method === "POST" && /^\/api\/v1\/gates\/[^/]+\/check$/.test(path)) return fulfill(route, 200, JSON.stringify(envelope("api.v1.gates.check", gateViewFixture(gateFixtures[0]).evaluation)));
  if (method === "POST" && /^\/api\/v1\/gates\/[^/]+\/evidence$/.test(path)) return fulfill(route, 200, JSON.stringify(envelope("api.v1.gate-evidence.create", { schema: "vegastack-labs.dev/gate-evidence-submission", schemaVersion: "1.1.0", draftId: "draft-gate-a", changeId: "change-gate-a", evidenceId: "evidence-a", status: "draft", stateRevision: 9, recoveryEpoch: 2 })));
  let command = "api.v1.summary.get";
  let data: unknown;
  if (path === "/api/v1/summary") data = { databaseMode: "ready", readAvailable: true, mutationAvailable: false, draftCount: fixtureState.mode === "empty" ? 0 : 1, validDraftCount: fixtureState.mode === "empty" ? 0 : 1, blockedDraftCount: 0, lastEventId: 4, recoveryEpoch: 2, stateRevision: 8, sourceCounts: { total: fixtureState.mode === "empty" ? 0 : 7, healthy: fixtureState.mode === "empty" ? 0 : 2, stale: 0, unknown: 0, unavailable: fixtureState.mode === "empty" ? 0 : 5, failed: 0 }, worstSourceState: fixtureState.mode === "empty" ? "unknown" : "unavailable" };
  else if (path === "/api/v1/backups/status") {
    command = "api.v1.backups.status";
    const recoveryRequired = fixtureState.mode === "recovery-required";
    data = { schema: "vegastack-labs.dev/browser-backup-status-data", schemaVersion: "1.0.0", status: recoveryRequired ? "recovery-required" : "healthy", reasonCode: recoveryRequired ? "audit-continuity-required" : "last-good-current", sourceKind: "local", proofClass: "live", lastGoodPointId: "point-a", recoveryRequired, stateRevision: 8, recoveryEpoch: 2, safeNextAction: recoveryRequired ? "follow the recovery continuity runbook" : "inspect the last-good point" };
  } else if (path === "/api/v1/recovery-points") {
    command = "api.v1.recovery-points.list";
    const item = { schema: "vegastack-labs.dev/browser-recovery-point", schemaVersion: "1.0.0", pointId: "point-a", sourceKind: "local", proofClass: "live", contentDigest: digest, manifestDigest: digest, createdAt: "2026-09-24T03:00:00Z", verifiedAt: "2026-09-24T03:05:00Z", verificationStatus: "verified", reasonCode: "integrity-verified", recoveryEpoch: 2 };
    data = { schema: "vegastack-labs.dev/browser-recovery-point-list-data", schemaVersion: "1.0.0", items: fixtureState.mode === "empty" ? [] : [item], nextCursor: null, stateRevision: 8, recoveryEpoch: 2 };
  } else if (path === "/api/v1/audit-checkpoints") {
    command = "api.v1.audit-checkpoints.list";
    const item = { schema: "vegastack-labs.dev/browser-audit-checkpoint", schemaVersion: "1.0.0", checkpointId: "checkpoint-a", firstEventId: 1, lastEventId: 4, chainDigest: digest, status: "anchored", reasonCode: "independent-match", sourceKind: "independent", proofClass: "live", verifiedAt: "2026-09-24T03:05:00Z", verificationStatus: "verified", recoveryEpoch: 2 };
    data = { schema: "vegastack-labs.dev/browser-audit-checkpoint-list-data", schemaVersion: "1.0.0", items: fixtureState.mode === "empty" ? [] : [item], nextCursor: null, stateRevision: 8, recoveryEpoch: 2 };
  } else if (path === "/api/v1/audit-history/verification") {
    command = "api.v1.audit-history.verification";
    const incident = fixtureState.mode === "recovery-required";
    data = { schema: "vegastack-labs.dev/browser-audit-verification-data", schemaVersion: "1.0.0", status: incident ? "incident" : "anchored", reasonCode: incident ? "independent-mismatch" : "independent-match", sourceKind: "independent", proofClass: "live", independentMatch: !incident, lastAnchoredSequence: 4, preAnchor: false, stateRevision: 8, recoveryEpoch: 2, safeNextAction: incident ? "follow the audit continuity runbook" : "continue independent verification" };
  } else if (path === "/api/v1/restore-plans") {
    command = "api.v1.restores.list";
    const item = { schema: "vegastack-labs.dev/browser-restore-status", schemaVersion: "1.0.0", pointId: "point-a", planId: "plan-a", planDigest: digest, targetDigest: digest, status: "planned", reasonCode: "awaiting-approval", recoveryEpoch: 2, verificationStatus: "pending", safeNextAction: "inspect exact plan" };
    data = { schema: "vegastack-labs.dev/browser-restore-status-list-data", schemaVersion: "1.0.0", items: fixtureState.mode === "empty" ? [] : [item], nextCursor: null, stateRevision: 8, recoveryEpoch: 2 };
  } else if (path === "/api/v1/plans/plan-a") {
    command = "api.v1.plans.get";
    const operation = { sequence: 1, operationId: "operation-a", operationType: "restore.fixture", adapterId: "adapter.fixture", executorId: "executor-central", targetId: "target-a", inputDigest: digest, artifactDigest: digest, idempotent: true };
    const plan = { schema: "vegastack-labs.dev/plan", schemaVersion: "1.0.0", planId: "plan-a", planDigest: digest, declarationId: "declaration-a", binding: { recoveryEpoch: 2, priorStateRevision: 7, stateRevision: 8, declarationRevision: 1, observationFingerprint: digest, targetDigest: digest, reasonDigest: digest, policyVersion: "1.0.0", toolVersion: "1.0.0", contractVersion: "1.0.0" }, operations: [operation], status: "planned", risk: "destructive", authorizationBranch: "human", executorMode: "central", executorId: null, createdAt: "2026-09-24T03:00:00Z", expiresAt: "2099-09-24T03:00:00Z", readableDigest: digest, extensions: [] };
    data = { plan, readablePlan: "Exact fixture restore plan", canonicalPlan: JSON.stringify(plan) };
  } else if (path === "/api/v1/scheduled-job-policies") {
    command = "api.v1.scheduled-job-policies.list";
    const item = { schema: "vegastack-labs.dev/browser-scheduled-job-policy", schemaVersion: "1.0.0", policyId: "policy-a", revision: 1, actionKind: "backup-create", enabled: true, status: "active", reasonCode: "policy-current", targetDigest: digest, stateRevision: 8, recoveryEpoch: 2 };
    data = { schema: "vegastack-labs.dev/browser-scheduled-job-policy-list-data", schemaVersion: "1.0.0", items: fixtureState.mode === "empty" ? [] : [item], nextCursor: null, stateRevision: 8, recoveryEpoch: 2 };
  } else if (path === "/api/v1/scheduled-jobs") {
    command = "api.v1.scheduled-jobs.list";
    const item = { schema: "vegastack-labs.dev/browser-scheduled-job", schemaVersion: "1.0.0", jobId: "scheduled-a", policyId: "policy-a", policyRevision: 1, status: "succeeded", reasonCode: "completed", scheduledAt: "2026-09-24T03:00:00Z", windowClosesAt: "2026-09-24T03:15:00Z", stateRevision: 8, recoveryEpoch: 2 };
    data = { schema: "vegastack-labs.dev/browser-scheduled-job-list-data", schemaVersion: "1.0.0", items: fixtureState.mode === "empty" ? [] : [item], nextCursor: null, stateRevision: 8, recoveryEpoch: 2 };
  } else if (path === "/api/v1/sources") {
    command = "api.v1.sources.list";
    const requested = url.searchParams.get("source");
    const ids = fixtureState.mode === "empty" || (fixtureState.mode === "missing" && requested) ? [] : fixtureState.mode === "mismatched-source" && requested ? [requested === "people" ? "services" : "people"] : requested ? [requested] : fixtureState.mode === "missing" ? ["database"] : ["database", "nodes", "gates", "people", "services", "backups", "providers"];
    data = { items: ids.map(id => {
      const isDomain = ["people", "services", "backups", "providers"].includes(id);
      const state = id === "database" || id === "nodes" ? "healthy" : isDomain ? fixtureState.domainState : "unavailable";
      if (isDomain) return projectDomainSource(id, state);
      const reason = state === "healthy" ? "source observation is current" : state === "stale" ? "source observation is stale" : state === "unknown" ? "source has no observation timestamp" : state === "failed" ? "source reported a collection failure" : "source capability is unavailable";
      return { id, capability: id === "database" ? "database.status.read" : id === "nodes" ? "inventory.node.read" : id === "gates" ? "gate.read" : id === "people" ? "identity.person.read" : id === "services" ? "service.read" : id === "backups" ? "backup.status.read" : "adapter.status.read", state, collectedAt: state === "healthy" ? "2026-09-11T08:00:00Z" : null, lastSuccessAt: state === "healthy" ? "2026-09-11T08:00:00Z" : "2026-09-10T07:00:00Z", lastErrorAt: state === "failed" || state === "unavailable" ? "2026-09-11T08:00:00Z" : null, reason };
    }).filter(Boolean), nextCursor: null, stateRevision: 8, recoveryEpoch: 2 };
  } else if (path === "/api/v1/gates") {
    command = "api.v1.gates.list";
    data = { schema: "vegastack-labs.dev/gate-list-data", schemaVersion: "1.1.0", gates: fixtureState.mode === "empty" || fixtureState.mode === "missing" ? [] : gateFixtures.map(gateViewFixture), recoveryEpoch: 2 };
  } else if (path === "/api/v1/inventory-drafts") {
    command = "api.v1.inventory-drafts.list";
    data = { items: fixtureState.mode === "empty" ? [] : [{ authority: "draft", draftId: "draft-one", revision: 1, validationStatus: "valid", contentDigest: digest, createdAt: "2026-09-11T08:00:00Z", counts: { assets: 1, nodes: 2, aliases: 2, addresses: 0, observations: 2, hardwareFacts: 0, provenance: 1, findings: 0 } }], nextCursor: null, stateRevision: 8, recoveryEpoch: 2 };
  } else if (path.endsWith("/nodes")) {
    command = "api.v1.inventory-draft-nodes.list";
    const second = Boolean(url.searchParams.get("cursor"));
    const items = nodeBackingRecords.filter(record => record.scope === "draft-one" && record.page === (second ? 2 : 1)).map(record => ({ authority: record.authority, validationStatus: record.validationStatus, id: record.id, assetId: record.assetId, parentId: record.parentId }));
    data = { items, nextCursor: second ? null : "opaque/nodes/two", stateRevision: 8, recoveryEpoch: 2 };
  } else if (path.endsWith("/aliases")) {
    command = "api.v1.inventory-draft-aliases.list";
    const second = Boolean(url.searchParams.get("cursor"));
    data = { items: [{ authority: "draft", validationStatus: "valid", id: second ? "alias-two" : "alias-one", targetId: second ? "node-two" : "node-one", value: second ? "vsk-node-02" : "vsk-node-01" }], nextCursor: second ? null : "opaque/aliases/two", stateRevision: 8, recoveryEpoch: 2 };
  } else if (path.endsWith("/observations")) {
    command = "api.v1.inventory-draft-observations.list";
    const second = Boolean(url.searchParams.get("cursor"));
    data = { items: [{ authority: "draft", validationStatus: "valid", id: second ? "observation-two" : "observation-one", subjectId: second ? "node-two" : "node-one", kind: "reachability", state: "observed", observedAt: "2026-09-11T08:00:00Z", source: "fixture" }], nextCursor: second ? null : "opaque/observations/two", stateRevision: 8, recoveryEpoch: 2 };
  } else if (path.includes("/nodes/")) { command = "api.v1.inventory-draft-nodes.get"; data = { authority: "draft", validationStatus: "valid", id: path.endsWith("node-two") ? "node-two" : "node-one", assetId: "asset-one", parentId: "site-one" }; }
  else if (path.includes("/aliases/")) { command = "api.v1.inventory-draft-aliases.get"; data = { authority: "draft", validationStatus: "valid", id: "alias-one", targetId: "node-one", value: "vsk-node-01" }; }
  else { command = "api.v1.inventory-draft-observations.get"; data = { authority: "draft", validationStatus: "valid", id: "observation-one", subjectId: "node-one", kind: "reachability", state: "observed", observedAt: "2026-09-11T08:00:00Z", source: "fixture" }; }
  return fulfill(route, 200, JSON.stringify(envelope(command, data)));
}

export async function installReadFixture(page: Page) {
  fixtureState.mode = "healthy";
  fixtureState.delay = 0;
  fixtureState.domainState = "unavailable";
  fixtureAudit.requests.length = 0;
  fixtureAudit.responses.length = 0;
  fixtureAudit.domainProjections.length = 0;
  await page.route("**/api/v1/**", respond);
}
