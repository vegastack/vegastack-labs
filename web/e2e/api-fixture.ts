import type { Page, Route } from "@playwright/test";

export type FixtureMode = "healthy" | "dependency" | "dependency-node-page" | "unavailable" | "denied" | "deny-node-page" | "empty" | "missing" | "malformed";
export const fixtureState: { mode: FixtureMode; delay: number } = { mode: "healthy", delay: 0 };
export const fixtureAudit: { requests: string[]; responses: string[] } = { requests: [], responses: [] };
const digest = `sha256:${"a".repeat(64)}`;
const nodeBackingRecords = [
  { scope: "draft-one", page: 1, authority: "draft", validationStatus: "valid", id: "node-one", assetId: "asset-one", parentId: "site-one" },
  { scope: "draft-one", page: 2, authority: "draft", validationStatus: "valid", id: "node-two", assetId: "asset-two", parentId: "site-one" },
  { scope: "another-draft", page: 1, authority: "draft", validationStatus: "valid", id: "private-canary", assetId: "op://secret-canary", parentId: "cross-scope-canary" },
] as const;
export const privateFixtureRecords = [nodeBackingRecords[2].id, nodeBackingRecords[2].assetId, nodeBackingRecords[2].parentId] as const;

function envelope(command: string, data: unknown, status = "succeeded", errors: unknown[] = []) {
  return { schema: "vegastack-labs.dev/run-result", schemaVersion: "1.0.0", toolVersion: "test", command, requestId: "request-browser", runId: null, status, changed: false, recoveryEpoch: 2, stateRevision: 8, snapshotDigest: null, releaseBuildId: "test", sourceRevision: null, planId: null, errors, data };
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
  const isSecondNodePage = path.endsWith("/nodes") && Boolean(url.searchParams.get("cursor"));
  if (fixtureState.mode === "malformed") return fulfill(route, 200, "{not-json");
  if (fixtureState.mode === "denied" || (fixtureState.mode === "deny-node-page" && isSecondNodePage)) return fulfill(route, 403, JSON.stringify(envelope("read", {}, "failed", [{ code: "AUTHORIZATION_DENIED", target: "read", retryable: false }])));
  if (fixtureState.mode === "dependency-node-page" && isSecondNodePage) return fulfill(route, 503, JSON.stringify(envelope("read", {}, "failed", [{ code: "DEPENDENCY_UNAVAILABLE", target: "source", retryable: true }])));
  if (fixtureState.mode === "dependency" || fixtureState.mode === "unavailable") return fulfill(route, 503, JSON.stringify(envelope("read", {}, "failed", [{ code: "DEPENDENCY_UNAVAILABLE", target: "source", retryable: fixtureState.mode === "dependency" }])));
  let command = "api.v1.summary.get";
  let data: unknown;
  if (path === "/api/v1/summary") data = { databaseMode: "ready", readAvailable: true, mutationAvailable: false, draftCount: fixtureState.mode === "empty" ? 0 : 1, validDraftCount: fixtureState.mode === "empty" ? 0 : 1, blockedDraftCount: 0, lastEventId: 4, recoveryEpoch: 2, stateRevision: 8, sourceCounts: { total: fixtureState.mode === "empty" ? 0 : 7, healthy: fixtureState.mode === "empty" ? 0 : 2, stale: 0, unknown: 0, unavailable: fixtureState.mode === "empty" ? 0 : 5, failed: 0 }, worstSourceState: fixtureState.mode === "empty" ? "unknown" : "unavailable" };
  else if (path === "/api/v1/sources") {
    command = "api.v1.sources.list";
    const requested = url.searchParams.get("source");
    const ids = fixtureState.mode === "empty" || (fixtureState.mode === "missing" && requested) ? [] : requested ? [requested] : fixtureState.mode === "missing" ? ["database"] : ["database", "nodes", "gates", "people", "services", "backups", "providers"];
    data = { items: ids.map(id => ({ id, capability: id === "database" ? "database.status.read" : id === "nodes" ? "inventory.node.read" : id === "gates" ? "gate.read" : id === "people" ? "identity.person.read" : id === "services" ? "service.read" : id === "backups" ? "backup.status.read" : "adapter.status.read", state: id === "database" || id === "nodes" ? "healthy" : "unavailable", collectedAt: id === "database" || id === "nodes" ? "2026-09-11T08:00:00Z" : null, lastSuccessAt: id === "database" || id === "nodes" ? "2026-09-11T08:00:00Z" : "2026-09-10T07:00:00Z", lastErrorAt: id === "database" || id === "nodes" ? null : "2026-09-11T08:00:00Z", reason: id === "database" || id === "nodes" ? "source observation is current" : "source capability is unavailable" })), nextCursor: null, stateRevision: 8, recoveryEpoch: 2 };
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
  fixtureAudit.requests.length = 0;
  fixtureAudit.responses.length = 0;
  await page.route("**/api/v1/**", respond);
}
