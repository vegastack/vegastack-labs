import { chromium } from "@playwright/test";

const baseURL = process.env.VSK_PHASE3_BASE_URL;
const controllerURL = process.env.VSK_PHASE3_CONTROLLER_URL;
const assertion = process.env.VSK_PHASE3_ASSERTION;
const fullLoop = process.env.VSK_PHASE4_FULL_LOOP === "1";

if (!baseURL || !controllerURL || !assertion) throw new Error("phase 4 fixture inputs are required");

const browser = await chromium.launch({ headless: true });
let stage = "session";
try {
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  await context.route("**/*", async route => {
    const target = new URL(route.request().url());
    if ((target.protocol === "http:" || target.protocol === "https:") && target.origin !== baseURL) {
      await route.abort("blockedbyclient");
      return;
    }
    await route.continue({ headers: { ...route.request().headers(), "Cf-Access-Jwt-Assertion": assertion } });
  });
  const headers = { Origin: baseURL, "Content-Type": "application/json", "Cf-Access-Jwt-Assertion": assertion };
  let session;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      session = await context.request.post(`${baseURL}/api/v1/session`, { headers, data: { requestVersion: "1.0.0" }, timeout: 1_000 });
      if (session.status() === 200) break;
    } catch {}
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  if (!session || session.status() !== 200) throw new Error("session bootstrap failed");

  async function request(method, path, data) {
    const response = await context.request.fetch(`${baseURL}${path}`, { method, headers, data });
    const text = await response.text();
    if (/humanId|authorityId|nonce(?:Digest)?|proofDigest|acknowledgementId/.test(text)) {
      stage = `${stage}-disclosure`;
      throw new Error("protected approval material was disclosed");
    }
    let body;
    try { body = JSON.parse(text); } catch { throw new Error("server response was not JSON"); }
    return { status: response.status(), body };
  }

  stage = "save-declaration";
  const digest = value => `sha256:${value.repeat(64)}`;
  const revised = await request("POST", "/api/v1/declarations/declaration-console/revisions", {
    schema: "vegastack-labs.dev/declaration-revision-request",
    schemaVersion: "1.0.0",
    declarationId: "declaration-console",
    declarationType: "node.configuration",
    expectedRevision: 1,
    expectedStateRevision: 0,
    recoveryEpoch: 0,
    operations: [{
      sequence: 1,
      operationId: "operation-console",
      operationType: "health.check",
      adapterId: "adapter-console",
      targetId: "target-console",
      inputDigest: digest("b"),
      artifactDigest: digest("c"),
      idempotent: true,
    }],
    reasonDigest: digest("d"),
    extensions: [],
  });
  if (revised.status !== 200 || revised.body?.data?.status !== "draft" || revised.body?.data?.stateRevision !== 1) throw new Error("declaration save failed");

  stage = "prepare-plan";
  const prepared = await request("GET", "/api/v1/declarations/declaration-console/revisions/1/plan-preparation");
  if (prepared.status !== 200 || prepared.body?.data?.declarationRevision !== 1 || prepared.body?.data?.expectedStateRevision !== 1) throw new Error("server plan preparation failed");

  stage = "create-plan";
  const planResult = await request("POST", "/api/v1/declarations/declaration-console/plans", {
    schema: "vegastack-labs.dev/plan-create-request",
    schemaVersion: "1.0.0",
    declarationId: prepared.body.data.declarationId,
    declarationRevision: prepared.body.data.declarationRevision,
    expectedStateRevision: prepared.body.data.expectedStateRevision,
    recoveryEpoch: prepared.body.data.recoveryEpoch,
    observationFingerprint: prepared.body.data.observationFingerprint,
    idempotencyKey: "console-plan-request",
    extensions: [],
  });
  const plan = planResult.body?.data;
  if (planResult.status !== 200) {
    const code = planResult.body?.errors?.[0]?.code;
    if (code === "AUTHORIZATION_DENIED") stage = "create-plan-authorization";
    else if (code === "STATE_CONFLICT") stage = "create-plan-conflict";
    else if (code === "INPUT_INVALID") {
      const target = planResult.body?.errors?.[0]?.target;
      if (target === "plan") stage = "create-plan-input-plan";
      else if (target === "desired-declaration") stage = "create-plan-input-declaration";
      else if (typeof target === "string" && /^[a-z-]{1,32}$/.test(target)) stage = `create-plan-input-${target}`;
      else stage = "create-plan-input";
    }
    else if (code === "INTEGRITY_FAILURE") stage = "create-plan-integrity";
    else stage = "create-plan-response";
    throw new Error("exact plan creation failed");
  }
  if (!/^plan-[a-f0-9]{32}$/.test(plan?.planId ?? "")) { stage = "create-plan-identity"; throw new Error("exact plan creation failed"); }
  if (plan?.binding?.stateRevision !== 2) { stage = "create-plan-state"; throw new Error("exact plan creation failed"); }
  if (plan?.status !== "planned") { stage = "create-plan-status"; throw new Error("exact plan creation failed"); }

  stage = "plan-grant";
  const granted = await fetch(`${controllerURL}/grant-plan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ planId: plan.planId }),
  });
  if (!granted.ok) throw new Error("plan fixture grant failed");

  stage = "read-plan";
  const storedPlan = await request("GET", `/api/v1/plans/${plan.planId}`);
  if (storedPlan.status !== 200 || JSON.stringify(storedPlan.body?.data) !== JSON.stringify(plan)) throw new Error("stored exact plan changed");

  stage = "protected-approval-route";
  const rawApproval = await context.request.post(`${baseURL}/api/v1/plans/${plan.planId}/acknowledgements`, { headers, data: {} });
  const rawApprovalText = await rawApproval.text();
  if (/humanId|authorityId|nonce(?:Digest)?|proofDigest|acknowledgementId/.test(rawApprovalText)) {
    stage = "protected-approval-disclosure";
    throw new Error("protected approval material was disclosed");
  }
  if (rawApproval.status() !== 404) {
    if (rawApproval.status() === 403) stage = "protected-approval-forbidden";
    else if (rawApproval.status() === 401) stage = "protected-approval-unauthorized";
    else if (rawApproval.status() === 400) stage = "protected-approval-input";
    else if (rawApproval.status() === 405) stage = "protected-approval-method";
    else if (rawApproval.status() === 200) stage = "protected-approval-reached";
    else if (rawApproval.status() >= 500) stage = "protected-approval-server";
    throw new Error("browser reached protected acknowledgement route");
  }

  stage = "approval-status-empty";
  const emptyStatus = await request("GET", `/api/v1/plans/${plan.planId}/approval-status`);
  if (emptyStatus.status !== 404) throw new Error("missing approval did not remain empty");

  stage = "safe-approval-request";
  const approval = await request("POST", `/api/v1/plans/${plan.planId}/approval-request`, {
    schema: "vegastack-labs.dev/plan-reference-request",
    schemaVersion: "1.0.0",
    planId: plan.planId,
    planDigest: plan.planDigest,
    recoveryEpoch: plan.binding.recoveryEpoch,
    idempotencyKey: "console-approval-request",
    extensions: [],
  });
  if (!fullLoop) {
    if (approval.status !== 412 || approval.body?.errors?.[0]?.code !== "PREREQUISITE_BLOCKED") throw new Error("unconfigured Slack approval did not fail closed");
  } else {
    if (approval.status !== 200 || approval.body?.data?.status !== "pending" || approval.body?.data?.canApply !== false) throw new Error("safe approval request failed");
    const approve = await fetch(`${controllerURL}/approve`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ planId: plan.planId }) });
    if (!approve.ok) throw new Error("server-owned approval callback failed");
    const approved = await request("GET", `/api/v1/plans/${plan.planId}/approval-status`);
    if (approved.status !== 200 || approved.body?.data?.status !== "approved" || approved.body?.data?.canApply !== true || approved.body?.data?.authorizationCurrent !== true) throw new Error("approved status projection failed");

    stage = "execute-interrupted";
    const executed = await request("POST", `/api/v1/plans/${plan.planId}/execute`, {
      schema: "vegastack-labs.dev/plan-reference-request",
      schemaVersion: "1.0.0",
      planId: plan.planId,
      planDigest: plan.planDigest,
      recoveryEpoch: plan.binding.recoveryEpoch,
      idempotencyKey: "console-run-resume",
      extensions: [],
    });
    const interrupted = executed.body?.data?.run;
    if (executed.status !== 408 || interrupted?.status !== "interrupted" || executed.body?.errors?.[0]?.code !== "INTERRUPTED") throw new Error("interrupted run projection failed");
    const runGrant = await fetch(`${controllerURL}/grant-run`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ runId: interrupted.runId }) });
    if (!runGrant.ok) throw new Error("run fixture grant failed");
    const observed = await request("GET", `/api/v1/runs/${interrupted.runId}`);
    if (observed.status !== 200 || observed.body?.data?.run?.status !== "interrupted") throw new Error("durable interrupted run read failed");

    stage = "resume-run";
    const resumed = await request("POST", `/api/v1/runs/${interrupted.runId}/resume`, {
      schema: "vegastack-labs.dev/run-reference-request",
      schemaVersion: "1.0.0",
      runId: interrupted.runId,
      idempotencyKey: "console-resume-request",
      recoveryEpoch: interrupted.recoveryEpoch,
      extensions: [],
    });
    if (resumed.status !== 200 || resumed.body?.data?.run?.status !== "succeeded") throw new Error("safe run resume failed");

    stage = "second-declaration";
    const revisedAgain = await request("POST", "/api/v1/declarations/declaration-console/revisions", {
      schema: "vegastack-labs.dev/declaration-revision-request",
      schemaVersion: "1.0.0",
      declarationId: "declaration-console",
      declarationType: "node.configuration",
      expectedRevision: 3,
      expectedStateRevision: 2,
      recoveryEpoch: 0,
      operations: [{ sequence: 1, operationId: "operation-console-cancel", operationType: "health.check", adapterId: "adapter-console", targetId: "target-console", inputDigest: digest("b"), artifactDigest: digest("c"), idempotent: true }],
      reasonDigest: digest("d"),
      extensions: [],
    });
    if (revisedAgain.status !== 200 || revisedAgain.body?.data?.stateRevision !== 3) throw new Error("second declaration save failed");
    const preparedAgain = await request("GET", "/api/v1/declarations/declaration-console/revisions/3/plan-preparation");
    const planAgainResult = await request("POST", "/api/v1/declarations/declaration-console/plans", {
      schema: "vegastack-labs.dev/plan-create-request", schemaVersion: "1.0.0",
      declarationId: preparedAgain.body.data.declarationId, declarationRevision: preparedAgain.body.data.declarationRevision,
      expectedStateRevision: preparedAgain.body.data.expectedStateRevision, recoveryEpoch: preparedAgain.body.data.recoveryEpoch,
      observationFingerprint: preparedAgain.body.data.observationFingerprint, idempotencyKey: "console-plan-cancel", extensions: [],
    });
    const planAgain = planAgainResult.body?.data;
    if (planAgainResult.status !== 200 || planAgain?.binding?.stateRevision !== 4) throw new Error("second plan creation failed");
    for (const path of ["/grant-plan", "/approve"]) {
      if (path === "/approve") {
        const requested = await request("POST", `/api/v1/plans/${planAgain.planId}/approval-request`, { schema: "vegastack-labs.dev/plan-reference-request", schemaVersion: "1.0.0", planId: planAgain.planId, planDigest: planAgain.planDigest, recoveryEpoch: 0, idempotencyKey: "console-approval-cancel", extensions: [] });
        if (requested.status !== 200) throw new Error("second approval request failed");
      }
      const controlled = await fetch(`${controllerURL}${path}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ planId: planAgain.planId }) });
      if (!controlled.ok) throw new Error("second plan controller failed");
    }
    const executedAgain = await request("POST", `/api/v1/plans/${planAgain.planId}/execute`, { schema: "vegastack-labs.dev/plan-reference-request", schemaVersion: "1.0.0", planId: planAgain.planId, planDigest: planAgain.planDigest, recoveryEpoch: 0, idempotencyKey: "console-run-cancel", extensions: [] });
    const interruptedAgain = executedAgain.body?.data?.run;
    if (executedAgain.status !== 408 || interruptedAgain?.status !== "interrupted") throw new Error("second interrupted run failed");
    const cancelled = await request("POST", `/api/v1/runs/${interruptedAgain.runId}/cancel`, { schema: "vegastack-labs.dev/run-reference-request", schemaVersion: "1.0.0", runId: interruptedAgain.runId, idempotencyKey: "console-cancel-request", recoveryEpoch: 0, extensions: [] });
    if (cancelled.status !== 200 || cancelled.body?.data?.run?.status !== "cancelled") throw new Error("safe run cancellation failed");
  }

  stage = "console-route";
  const page = await context.newPage();
  const navigation = await page.goto(`${baseURL}/changes`, { waitUntil: "networkidle" });
  if (!navigation || navigation.status() !== 200) throw new Error("embedded changes route failed");

  process.stdout.write(`${JSON.stringify({ schemaVersion: 1, check: "phase-4-real-change-server", status: "pass" })}\n`);
} catch {
  process.stderr.write(`PROBE_FAILED:${stage}\n`);
  process.exitCode = 1;
} finally {
  await browser.close();
}
