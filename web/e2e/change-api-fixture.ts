import type { Page, Route } from "@playwright/test";

type ApprovalState = "pending" | "approved" | "rejected" | "expired";
type RunState = "queued" | "running" | "partial" | "failed" | "cancelled" | "interrupted" | "succeeded";
const digest = (character: string) => `sha256:${character.repeat(64)}`;

export const privateChangeCanaries = ["private-human-canary", "private-proof-canary", "private-nonce-canary"] as const;
export const changeFixture: {
  approval: ApprovalState;
  run: RunState;
  executeRequests: number;
  requestBodies: string[];
  requestPaths: string[];
  reasonDigest: string;
  planDigest: string;
} = { approval: "pending", run: "running", executeRequests: 0, requestBodies: [], requestPaths: [], reasonDigest: digest("b"), planDigest: digest("c") };

const operation = { sequence: 1, operationId: "operation-one", operationType: "fixture.reconcile", adapterId: "adapter.fake", targetId: "target-one", inputDigest: digest("d"), artifactDigest: digest("e"), idempotent: true } as const;

function declaration(revision: number, operations = [operation]) {
  return { schema: "vegastack-labs.dev/declaration-revision", schemaVersion: "1.0.0", declarationId: "declaration-one", declarationType: "fixture.change", revision, stateRevision: 8 + revision, recoveryEpoch: 2, contentDigest: digest(revision === 1 ? "a" : "f"), status: "draft", operations, createdAt: "2026-09-13T12:30:00Z", createdBy: "redacted-browser-principal", agentSessionId: "redacted-browser-session", extensions: [] };
}

const plan = {
  schema: "vegastack-labs.dev/plan", schemaVersion: "1.0.0", planId: "plan-one", planDigest: changeFixture.planDigest, declarationId: "declaration-one",
  binding: { recoveryEpoch: 2, priorStateRevision: 9, stateRevision: 10, declarationRevision: 2, observationFingerprint: digest("1"), targetDigest: digest("2"), reasonDigest: changeFixture.reasonDigest, policyVersion: "1.0.0", toolVersion: "1.0.0", contractVersion: "1.0.0" },
  operations: [{ ...operation, executorId: "executor-central" }], status: "awaiting-acknowledgement", risk: "infrastructure", authorizationBranch: "human", executorMode: "central", executorId: null, createdAt: "2026-09-13T12:31:00Z", expiresAt: "2026-09-13T13:01:00Z", readableDigest: digest("3"), extensions: [],
} as const;

function approval() {
  const current = changeFixture.approval === "approved";
  return { schema: "vegastack-labs.dev/approval-status", schemaVersion: "1.0.0", planId: plan.planId, planDigest: plan.planDigest, status: changeFixture.approval, authorizationCurrent: current, canApply: current, channel: "slack", owner: "assigned-maintainer", stateRevision: 10, recoveryEpoch: 2, expiresAt: plan.expiresAt, observedAt: "2026-09-13T12:32:00Z" };
}

function runPresentation() {
  const terminal = ["partial", "failed", "cancelled", "interrupted", "succeeded"].includes(changeFixture.run);
  const effectState = changeFixture.run === "succeeded" ? "verified" : changeFixture.run === "partial" ? "effect-unknown" : changeFixture.run === "running" ? "intent-recorded" : "not-started";
  const step = { ...operation, executorId: "executor-central", stepId: "step-one", status: changeFixture.run, effectState };
  const nextSafeAction = changeFixture.run === "succeeded" ? "none; execution completed" : changeFixture.run === "partial" ? "recovery required; inspect the durable run" : changeFixture.run === "interrupted" ? "inspect, then resume or cancel through the server" : changeFixture.run === "queued" || changeFixture.run === "running" ? "inspect or cancel through the server" : "inspect the durable run";
  return { run: { schema: "vegastack-labs.dev/run", schemaVersion: "1.0.0", runId: "run-one", planId: plan.planId, planDigest: plan.planDigest, authorizationDecisionId: "decision-one", acknowledgementId: null, policyVersion: "1.0.0", executorMode: "central", executorId: "executor-central", executorBindingDigest: digest("4"), status: changeFixture.run, steps: [step], cancellationRequested: false, rollbackStatus: changeFixture.run === "partial" ? "required" : "not-requested", verificationStatus: changeFixture.run === "succeeded" ? "verified" : terminal ? "incomplete" : "pending", verificationDigest: changeFixture.run === "succeeded" ? digest("5") : null, changed: changeFixture.run !== "queued", stateRevision: 11, recoveryEpoch: 2, createdAt: "2026-09-13T12:33:00Z", updatedAt: "2026-09-13T12:34:00Z", extensions: [] }, completedWork: changeFixture.run === "succeeded" ? [step] : [], incompleteWork: changeFixture.run === "succeeded" ? [] : [step], nextSafeAction };
}

function envelope(command: string, data: unknown, status = "succeeded", errors: unknown[] = []) {
  return { schema: "vegastack-labs.dev/run-result", schemaVersion: "1.0.0", toolVersion: "test", command, requestId: "request-change-browser", runId: null, status, changed: false, recoveryEpoch: 2, stateRevision: 11, snapshotDigest: null, releaseBuildId: "test", sourceRevision: null, planId: null, errors, data };
}

async function reply(route: Route, command: string, data: unknown) {
  await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope(command, data)) });
}

async function respond(route: Route) {
  const request = route.request();
  const path = new URL(request.url()).pathname;
  changeFixture.requestPaths.push(path);
  if (request.method() === "POST") changeFixture.requestBodies.push(request.postData() ?? "");
  if (/^\/api\/v1\/declarations\/declaration-one\/revisions\/\d+$/.test(path)) return reply(route, "api.v1.declarations.get", declaration(Number(path.split("/").at(-1))));
  if (path.endsWith("/plan-preparation")) return reply(route, "api.v1.declarations.plan-preparation.get", { schema: "vegastack-labs.dev/plan-preparation", schemaVersion: "1.0.0", declarationId: "declaration-one", declarationRevision: Number(path.split("/").at(-2)), expectedStateRevision: 10, recoveryEpoch: 2, observationFingerprint: digest("1") });
  if (path === "/api/v1/declarations/declaration-one/revisions" && request.method() === "POST") {
    const body = request.postDataJSON() as { operations: typeof operation[] };
    return reply(route, "api.v1.declarations.revise", declaration(2, body.operations));
  }
  if (path === "/api/v1/declarations/declaration-one/plans" && request.method() === "POST") return reply(route, "api.v1.plans.create", plan);
  if (path === "/api/v1/plans/plan-one/approval-request" && request.method() === "POST") return reply(route, "api.v1.plans.approval-request.create", approval());
  if (path === "/api/v1/plans/plan-one/approval-status") return reply(route, "api.v1.plans.approval-status.get", approval());
  if (path === "/api/v1/plans/plan-one/execute" && request.method() === "POST") { changeFixture.executeRequests += 1; return reply(route, "api.v1.plans.execute", runPresentation()); }
  if (path === "/api/v1/runs/run-one" && request.method() === "GET") return reply(route, "api.v1.runs.get", runPresentation());
  if (path === "/api/v1/runs/run-one/cancel" && request.method() === "POST") { changeFixture.run = "cancelled"; return reply(route, "api.v1.runs.cancel", runPresentation()); }
  if (path === "/api/v1/runs/run-one/resume" && request.method() === "POST") { changeFixture.run = "running"; return reply(route, "api.v1.runs.resume", runPresentation()); }
  await route.fulfill({ status: 404, contentType: "application/json", body: JSON.stringify(envelope("unknown", {}, "failed", [{ code: "RESOURCE_NOT_FOUND", target: path, retryable: false }])) });
}

export async function installChangeFixture(page: Page) {
  changeFixture.approval = "pending";
  changeFixture.run = "running";
  changeFixture.executeRequests = 0;
  changeFixture.requestBodies.length = 0;
  changeFixture.requestPaths.length = 0;
  await page.route("**/api/v1/**", respond);
}
