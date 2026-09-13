import { chromium } from "@playwright/test";
import axe from "axe-core";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer as createSecureServer, request as secureRequest } from "node:https";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { assertPrivacyEvidence, assertSettledPrivacyChecks, assertShippedVisualAssetsSafe, captureVisibleBrowserEvidence, finalizeProbeResources, inspectTraceArchive, installCanvasTextCapture, settlePrivacyCheck } from "./browser-privacy-proof.mjs";

const upstreamBaseURL = process.env.VSK_PHASE3_BASE_URL;
const controllerURL = process.env.VSK_PHASE3_CONTROLLER_URL;
const assertion = process.env.VSK_PHASE3_ASSERTION;
const proxyCertificatePath = process.env.VSK_PHASE4_PROXY_CERTIFICATE;
const proxyPrivateKeyPath = process.env.VSK_PHASE4_PROXY_PRIVATE_KEY;
const fullLoop = process.env.VSK_PHASE4_FULL_LOOP === "1";
const privateCanaries = ["subject-real-browser", "human.console", "authority.console", "server-owned-console-nonce"];
const protectedBrowserFields = ["humanId", "authorityId", "nonceDigest", "proofDigest", "acknowledgementId", "createdBy", "agentSessionId", "authorizationDecisionId", "executorBindingDigest", "effectState", "requestId", "correlationId"];
const credentialHeaderEvidence = ["Authorization", "Cookie", "Set-Cookie", "Cf-Access-Jwt-Assertion"];
const forbiddenBrowserEvidence = [...privateCanaries, ...protectedBrowserFields, assertion];
let browserConsole = [];
let droppedBrowserExecuteResponse = false;

function digestText(value) {
	return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function durableRunId(planId, idempotencyKey) {
	return `run-${createHash("sha256").update(["run", planId, idempotencyKey].join("\0")).digest("hex").slice(0, 32)}`;
}

function assertCanaryFree(value, surface) {
	const text = typeof value === "string" ? value : JSON.stringify(value);
	for (const canary of privateCanaries) {
		if (text.includes(canary)) throw new Error(`private canary reached ${surface}`);
	}
}

function assertBrowserSafe(value, surface) {
	const text = typeof value === "string" ? value : JSON.stringify(value);
	for (const field of protectedBrowserFields) {
		if (text.includes(field)) throw new Error(`protected field reached ${surface}`);
	}
	assertCanaryFree(text, surface);
}

function privacyCheckWithDeadline(check, surface) {
	let timeout;
	return Promise.race([
		check,
		new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error(`privacy check timed out for ${surface}`)), 2_000); }),
	]).finally(() => clearTimeout(timeout));
}

async function assertSafeBrowserResponse(response, surface) {
	let body;
	try {
		body = await response.body();
	} catch (error) {
		const failure = response.request().failure()?.errorText ?? "";
		if (/ERR_ABORTED|ERR_CONNECTION_CLOSED/.test(failure)) return;
		throw error;
	}
	assertBrowserSafe(body.toString(), surface);
}

function withoutCredentialHeaders(headers) {
	const safe = { ...headers };
	for (const name of Object.keys(safe)) {
		if (["authorization", "cookie", "set-cookie", "cf-access-jwt-assertion"].includes(name.toLowerCase())) delete safe[name];
	}
	return safe;
}

async function startCredentialProxy() {
	let sessionCookie = "";
	const server = createSecureServer({ cert: await readFile(proxyCertificatePath), key: await readFile(proxyPrivateKeyPath) }, (incoming, outgoing) => {
		const target = new URL(incoming.url ?? "/", upstreamBaseURL);
		const headers = withoutCredentialHeaders(incoming.headers);
		headers.host = target.host;
		if (headers.origin) headers.origin = upstreamBaseURL;
		headers["cf-access-jwt-assertion"] = assertion;
		if (sessionCookie && target.pathname !== "/api/v1/session") headers.cookie = sessionCookie;
		const upstream = secureRequest(target, { method: incoming.method, headers, rejectUnauthorized: false }, response => {
			const issued = response.headers["set-cookie"]?.[0]?.split(";", 1)[0];
			if (issued) sessionCookie = issued;
			outgoing.writeHead(response.statusCode ?? 502, withoutCredentialHeaders(response.headers));
			response.pipe(outgoing);
		});
		upstream.on("error", () => {
			if (!outgoing.headersSent) outgoing.writeHead(502, { "Content-Type": "text/plain" });
			outgoing.end("test proxy upstream unavailable");
		});
		incoming.pipe(upstream);
	});
	await new Promise((resolve, reject) => {
		server.once("error", reject);
		server.listen(0, "127.0.0.1", () => { server.off("error", reject); resolve(); });
	});
	const address = server.address();
	if (!address || typeof address === "string") throw new Error("test credential proxy did not bind");
	return {
		url: `https://127.0.0.1:${address.port}`,
		sessionCookie: () => sessionCookie,
		close: () => new Promise(resolve => server.close(resolve)),
	};
}

let stage = "fixture-inputs";
let credentialProxy;
let baseURL;
let browser;
let context;
let traceStarted = false;
let tracePath;
let screenshotPath;
let failureStage;
try {
  if (!upstreamBaseURL || !controllerURL || !assertion || !proxyCertificatePath || !proxyPrivateKeyPath) throw new Error("phase 4 fixture inputs are required");
  stage = "credential-proxy";
  credentialProxy = await startCredentialProxy();
  baseURL = credentialProxy.url;
  stage = "chromium-launch";
  browser = await chromium.launch({ headless: true, args: ["--ignore-certificate-errors"], timeout: 30_000 });
  stage = "artifact-root";
  const configuredArtifactRoot = process.env.VSK_PHASE3_PLAYWRIGHT_OUTPUT ?? process.env.VSK_PHASE3_RUNTIME_ROOT;
  const artifactRoot = configuredArtifactRoot ? path.join(configuredArtifactRoot, "phase4-browser-proof") : await mkdtemp(path.join(tmpdir(), "vsk-phase4-browser-proof-"));
  await mkdir(artifactRoot, { recursive: true, mode: 0o700 });
  tracePath = path.join(artifactRoot, "changes-trace.zip");
  screenshotPath = path.join(artifactRoot, "changes-screenshot.png");
  stage = "session";
  context = await browser.newContext({ ignoreHTTPSErrors: true });
  await context.route("**/*", async route => {
    const target = new URL(route.request().url());
    if ((target.protocol === "http:" || target.protocol === "https:") && target.origin !== baseURL) {
      await route.abort("blockedbyclient");
      return;
    }
		const execution = target.pathname.match(/^\/api\/v1\/plans\/(plan-[a-f0-9]{32})\/execute$/);
		if (execution && route.request().method() === "POST") {
			const requestBody = route.request().postDataJSON();
			const runGrant = await fetch(`${controllerURL}/grant-run`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ runId: durableRunId(execution[1], requestBody.idempotencyKey) }),
			});
			if (!runGrant.ok) throw new Error("browser run fixture grant failed");
			const response = await route.fetch();
			const body = await response.body();
			assertBrowserSafe(body.toString(), "browser execute response");
			if (fullLoop && !droppedBrowserExecuteResponse) {
				droppedBrowserExecuteResponse = true;
				await route.abort("connectionclosed");
				return;
			}
			await route.fulfill({ status: response.status(), headers: response.headers(), body });
			return;
		}
		if (/^\/api\/v1\/declarations\/declaration-browser(?:-cancel)?\/plans$/.test(target.pathname) && route.request().method() === "POST") {
			const response = await route.fetch();
			const body = await response.body();
			assertBrowserSafe(body.toString(), "browser plan response");
			const payload = JSON.parse(body.toString());
			const planId = payload?.data?.plan?.planId;
			const planGrant = await fetch(`${controllerURL}/grant-plan`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ planId }) });
			if (!planGrant.ok) throw new Error("browser plan fixture grant failed");
			await route.fulfill({ status: response.status(), headers: response.headers(), body });
			return;
		}
    await route.continue();
  });
  const headers = { Origin: baseURL, "Content-Type": "application/json" };
  let session;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      session = await context.request.post(`${baseURL}/api/v1/session`, { headers, data: { requestVersion: "1.0.0" }, timeout: 1_000 });
      if (session.status() === 200) break;
    } catch {}
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  if (!session || session.status() !== 200) throw new Error("session bootstrap failed");
	const sessionCookie = credentialProxy.sessionCookie();
	if (!sessionCookie.includes("=")) throw new Error("test credential proxy did not retain the server session");
	forbiddenBrowserEvidence.push(sessionCookie, sessionCookie.slice(sessionCookie.indexOf("=") + 1));

	async function request(method, path, data) {
    const response = await context.request.fetch(`${baseURL}${path}`, { method, headers, data });
    const text = await response.text();
		try {
			assertBrowserSafe(text, `network response ${path}`);
		} catch (error) {
      stage = `${stage}-disclosure`;
			throw error;
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
	const planView = planResult.body?.data;
	const plan = planView?.plan;
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
	if (storedPlan.status !== 200 || JSON.stringify(storedPlan.body?.data) !== JSON.stringify(planView) || storedPlan.body?.data?.canonicalPlan !== JSON.stringify(plan) || digestText(storedPlan.body?.data?.readablePlan ?? "") !== plan.readableDigest) throw new Error("stored exact plan changed");

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
	const resolved = await request("GET", `/api/v1/plans/${plan.planId}/runs/console-run-resume`);
	if (resolved.status !== 200 || resolved.body?.data?.run?.runId !== interrupted.runId || resolved.body?.data?.run?.status !== "interrupted") throw new Error("exact submit-key run resolution failed");
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
		const planAgain = planAgainResult.body?.data?.plan;
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

	if (fullLoop) {
		stage = "browser-declaration-seed";
		const browserDeclaration = await request("POST", "/api/v1/declarations/declaration-browser/revisions", {
			schema: "vegastack-labs.dev/declaration-revision-request",
			schemaVersion: "1.0.0",
			declarationId: "declaration-browser",
			declarationType: "node.configuration",
			expectedRevision: 1,
			expectedStateRevision: 4,
			recoveryEpoch: 0,
			operations: [{ sequence: 1, operationId: "operation-browser", operationType: "health.check", adapterId: "adapter-console", targetId: "target-browser", inputDigest: digest("b"), artifactDigest: digest("c"), idempotent: true }],
			reasonDigest: digest("d"),
			extensions: [],
		});
		if (browserDeclaration.status !== 200 || browserDeclaration.body?.data?.stateRevision !== 5) throw new Error("browser declaration seed failed");
	}

	stage = "console-route";
	await installCanvasTextCapture(context);
	await context.tracing.start({ screenshots: true, snapshots: true, sources: true, title: "phase-4-real-change-server" });
	traceStarted = true;
	const page = await context.newPage();
	page.setDefaultTimeout(5_000);
	browserConsole = [];
	const browserResponseChecks = [];
	const browserAPIPaths = [];
	page.on("request", request => {
		const target = new URL(request.url());
		if (target.pathname.startsWith("/api/v1/")) browserAPIPaths.push(target.pathname);
	});
	page.on("console", message => browserConsole.push(message.text()));
	page.on("pageerror", error => browserConsole.push(error.message));
	page.on("response", response => {
		const target = new URL(response.url());
		if (target.origin === baseURL && target.pathname !== "/api/v1/events") {
			const surface = `browser response ${target.pathname}`;
			browserResponseChecks.push(settlePrivacyCheck(privacyCheckWithDeadline(assertSafeBrowserResponse(response, surface), surface)));
		}
		if (target.pathname.startsWith("/api/v1/") && response.status() >= 400) {
			const resource = target.pathname.includes("/runs/") ? "run" : target.pathname.includes("/plans/") ? "plan" : target.pathname.includes("/declarations/") ? "declaration" : target.pathname.endsWith("/session") ? "session" : "other";
			const method = response.request().method().toLowerCase();
			stage = response.status() === 401 ? `browser-${resource}-${method}-unauthenticated` : response.status() === 403 ? `browser-${resource}-${method}-denied` : response.status() === 404 ? `browser-${resource}-${method}-missing` : response.status() === 409 ? `browser-${resource}-${method}-conflict` : response.status() >= 500 ? `browser-${resource}-${method}-server-error` : `browser-${resource}-${method}-failed`;
		}
		if (target.pathname === "/api/v1/declarations/declaration-browser/revisions" && response.request().method() === "POST") {
			stage = response.status() === 200 ? "browser-save-response-ok" : response.status() === 409 ? "browser-save-response-conflict" : response.status() === 403 ? "browser-save-response-denied" : "browser-save-response-failed";
		}
		if (target.pathname === "/api/v1/declarations/declaration-browser/revisions/2" && response.request().method() === "GET") {
			stage = response.status() === 200 ? "browser-saved-read-ok" : response.status() === 403 ? "browser-saved-read-denied" : "browser-saved-read-failed";
		}
		if (target.pathname.endsWith("/plan-preparation")) stage = response.status() === 200 ? "browser-plan-preparation-ok" : "browser-plan-preparation-failed";
		if (/^\/api\/v1\/declarations\/declaration-browser(?:-cancel)?\/plans$/.test(target.pathname) && response.request().method() === "POST") stage = response.status() === 200 ? "browser-plan-response-ok" : response.status() === 403 ? "browser-plan-response-denied" : response.status() === 409 ? "browser-plan-response-conflict" : "browser-plan-response-failed";
		if (/^\/api\/v1\/plans\/plan-[a-f0-9]{32}$/.test(target.pathname) && response.request().method() === "GET") stage = response.status() === 200 ? "browser-plan-read-ok" : response.status() === 403 ? "browser-plan-read-denied" : "browser-plan-read-failed";
		if (target.pathname.endsWith("/approval-request") && response.request().method() === "POST") stage = response.status() === 200 ? "browser-approval-request-ok" : "browser-approval-request-failed";
		if (target.pathname.endsWith("/approval-status") && response.request().method() === "GET") stage = response.status() === 200 ? "browser-approval-status-ok" : response.status() === 404 ? "browser-approval-status-missing" : "browser-approval-status-failed";
		if (target.pathname.endsWith("/execute") && response.request().method() === "POST") stage = response.status() === 408 ? "browser-execute-interrupted" : response.status() === 200 ? "browser-execute-complete" : "browser-execute-failed";
		if (/^\/api\/v1\/runs\/run-[a-f0-9]{32}$/.test(target.pathname) && response.request().method() === "GET") stage = response.status() === 200 ? "browser-run-read-ok" : response.status() === 403 ? "browser-run-read-denied" : "browser-run-read-failed";
		if (target.pathname.endsWith("/resume") && response.request().method() === "POST") stage = response.status() === 200 ? "browser-resume-ok" : "browser-resume-failed";
		if (target.pathname === "/api/v1/events" && response.request().method() === "GET") stage = response.status() === 404 ? "browser-events-unavailable" : response.status() === 200 ? "browser-events-open" : "browser-events-failed";
	});
	const navigation = await page.goto(`${baseURL}/changes`, { waitUntil: "networkidle" });
	if (!navigation || navigation.status() !== 200) throw new Error("embedded changes route failed");

	if (fullLoop) {
		stage = "browser-open-declaration";
		await page.getByLabel("Declaration ID").fill("declaration-browser");
		await page.getByLabel("Revision").fill("1");
		await page.getByRole("button", { name: "Open declaration" }).click();
		await page.getByText("Draft revision 1", { exact: true }).waitFor();

		stage = "browser-save-declaration";
		await page.getByLabel("Reason digest").fill(digest("d"));
		await page.getByRole("button", { name: "Save declaration" }).click();
		try {
			await page.getByText("Draft revision 2", { exact: true }).waitFor();
		} catch (error) {
			if (await page.getByText(/Save failed/).count()) stage = "browser-save-ui-failed";
			else if (await page.getByText("Draft revision 1", { exact: true }).count()) stage = "browser-save-ui-stale";
			else stage = "browser-save-ui-cleared";
			throw error;
		}

		stage = "browser-create-plan";
		const generatePlan = page.getByRole("button", { name: "Generate plan" });
		if (await generatePlan.isDisabled()) { stage = "browser-plan-disabled"; throw new Error("browser plan action remained disabled after save"); }
		await generatePlan.click();
		try {
			await page.getByText("Exact plan review", { exact: true }).waitFor();
		} catch (error) {
			const failedHandles = await page.evaluate(() => history.state?.vskChangeHandles);
			if (failedHandles?.planId && !stage.startsWith("browser-plan-read")) stage = "browser-plan-created-not-rendered";
			else if (!stage.startsWith("browser-plan-response") && !stage.startsWith("browser-plan-preparation") && !stage.startsWith("browser-plan-read")) {
				if (await page.getByText(/Plan generation failed/).count()) stage = "browser-plan-ui-failed";
				else if (await page.getByText("Change details cleared", { exact: true }).count()) stage = "browser-plan-ui-cleared";
				else if (await page.getByText("Draft revision 2", { exact: true }).count()) stage = "browser-plan-action-no-request";
				else stage = "browser-plan-ui-missing";
			}
			throw error;
		}
		const browserHandles = await page.evaluate(() => history.state?.vskChangeHandles);
		if (!/^plan-[a-f0-9]{32}$/.test(browserHandles?.planId ?? "")) throw new Error("browser did not retain a safe plan handle");
		const browserPlanResult = await request("GET", `/api/v1/plans/${browserHandles.planId}`);
		if (browserPlanResult.status !== 200) throw new Error("browser-created plan was not durable");
		const browserPlanView = browserPlanResult.body.data;
		const browserPlan = browserPlanView.plan;
		if (await page.getByText(browserPlan.planDigest, { exact: true }).count() < 1) throw new Error("browser did not render the exact plan digest");
		if (!(await page.getByText(browserPlanView.readablePlan, { exact: true }).isVisible())) throw new Error("browser did not render the server-owned readable plan");

		stage = "browser-request-approval";
		await page.getByRole("button", { name: "Request Slack approval" }).click();
		await page.getByText("Pending", { exact: true }).waitFor();
		const browserApprove = await fetch(`${controllerURL}/approve`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ planId: browserPlan.planId }) });
		if (!browserApprove.ok) throw new Error("browser approval callback failed");
		await page.getByRole("button", { name: "Refresh approval status" }).click();
		await page.getByText("Approved", { exact: true }).waitFor();

		stage = "browser-execute-interrupted";
		await page.getByRole("button", { name: "Start run" }).click();
		await page.getByRole("button", { name: "Start exact run" }).click();
		await page.locator('[data-run-status="interrupted"]').waitFor();
		const firstExecuteRequests = browserAPIPaths.filter(path => path.endsWith("/execute")).length;
		const firstResolutionRequests = browserAPIPaths.filter(path => /^\/api\/v1\/plans\/plan-[a-f0-9]{32}\/runs\/console-run-[a-f0-9-]+$/.test(path)).length;
		if (!droppedBrowserExecuteResponse || firstExecuteRequests !== 1 || firstResolutionRequests !== 1) throw new Error("browser did not resolve the dropped execute response exactly once");
		const interruptedHandles = await page.evaluate(() => history.state?.vskChangeHandles);
		if (!/^run-[a-f0-9]{32}$/.test(interruptedHandles?.runId ?? "")) throw new Error("browser did not retain the durable run handle");

		stage = "browser-resume-run";
		await page.getByRole("button", { name: "Resume run" }).click();
		await page.getByRole("button", { name: "Resume exact run" }).click();
		await page.locator('[data-run-status="succeeded"]').waitFor();
		const executeCount = await page.locator('[data-run-status="succeeded"]').count();
		await page.reload({ waitUntil: "networkidle" });
		await page.locator('[data-run-status="succeeded"]').waitFor();
		if (executeCount !== 1) throw new Error("browser rendered an unexpected durable run count");
		if (browserAPIPaths.filter(path => path.endsWith("/execute")).length !== firstExecuteRequests || browserAPIPaths.filter(path => /^\/api\/v1\/plans\/plan-[a-f0-9]{32}\/runs\/console-run-[a-f0-9-]+$/.test(path)).length !== firstResolutionRequests) throw new Error("reload resubmitted or re-resolved a known durable run");

		stage = "browser-cancel-declaration-seed";
		const cancelDeclaration = await request("POST", "/api/v1/declarations/declaration-browser-cancel/revisions", {
			schema: "vegastack-labs.dev/declaration-revision-request",
			schemaVersion: "1.0.0",
			declarationId: "declaration-browser-cancel",
			declarationType: "node.configuration",
			expectedRevision: 1,
			expectedStateRevision: 7,
			recoveryEpoch: 0,
			operations: [{ sequence: 1, operationId: "operation-browser-cancel", operationType: "health.check", adapterId: "adapter-console", targetId: "target-browser-cancel", inputDigest: digest("b"), artifactDigest: digest("c"), idempotent: true }],
			reasonDigest: digest("d"),
			extensions: [],
		});
		if (cancelDeclaration.status !== 200 || cancelDeclaration.body?.data?.stateRevision !== 8) throw new Error("browser cancel declaration seed failed");
		await page.getByLabel("Declaration ID").fill("declaration-browser-cancel");
		await page.getByLabel("Revision").fill("1");
		await page.getByRole("button", { name: "Open declaration" }).click();
		await page.getByText("Draft revision 1", { exact: true }).waitFor();
		await page.getByLabel("Reason digest").fill(digest("d"));
		await page.getByRole("button", { name: "Save declaration" }).click();
		await page.getByText("Draft revision 2", { exact: true }).waitFor();

		stage = "browser-cancel-create-plan";
		await page.getByRole("button", { name: "Generate plan" }).click();
		await page.getByText("Exact plan review", { exact: true }).waitFor();
		const cancelHandles = await page.evaluate(() => history.state?.vskChangeHandles);
		const cancelPlanResult = await request("GET", `/api/v1/plans/${cancelHandles.planId}`);
		if (cancelPlanResult.status !== 200) throw new Error("browser cancel plan was not durable");
		const cancelPlan = cancelPlanResult.body.data.plan;
		await page.getByRole("button", { name: "Request Slack approval" }).click();
		await page.getByText("Pending", { exact: true }).waitFor();
		const cancelApprove = await fetch(`${controllerURL}/approve`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ planId: cancelPlan.planId }) });
		if (!cancelApprove.ok) throw new Error("browser cancel approval callback failed");
		await page.getByRole("button", { name: "Refresh approval status" }).click();
		await page.getByText("Approved", { exact: true }).waitFor();
		await page.getByRole("button", { name: "Start run" }).click();
		await page.getByRole("button", { name: "Start exact run" }).click();
		await page.locator('[data-run-status="interrupted"]').waitFor();

		stage = "browser-cancel-run";
		await page.getByRole("button", { name: "Cancel run" }).click();
		await page.getByRole("button", { name: "Request cancel" }).click();
		await page.locator('[data-run-status="cancelled"]').waitFor();
		await page.reload({ waitUntil: "networkidle" });
		await page.locator('[data-run-status="cancelled"]').waitFor();

		stage = "browser-privacy-accessibility";
		for (const colorScheme of ["light", "dark"]) {
			stage = `browser-theme-${colorScheme}`;
			await page.emulateMedia({ colorScheme });
			await page.waitForFunction(expected => (document.documentElement.classList.contains("dark") ? "dark" : "light") === expected, colorScheme);
		}
		stage = "browser-accessibility";
		await page.evaluate(axe.source);
		const accessibility = await page.evaluate(async () => (await globalThis.axe.run(document)).violations.filter(({ impact }) => impact === "serious" || impact === "critical").map(({ id }) => id));
		if (accessibility.length > 0) throw new Error("real changes route has serious accessibility violations");
		stage = "browser-reflow";
		await page.setViewportSize({ width: 390, height: 844 });
		await page.evaluate(() => { document.documentElement.style.zoom = "2"; });
		const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
		if (overflow) throw new Error("real changes route overflows at 200 percent zoom");
		stage = "browser-visible-privacy";
		const browserSurfaces = await captureVisibleBrowserEvidence(page, browserConsole);
		assertPrivacyEvidence(browserSurfaces, forbiddenBrowserEvidence, "browser DOM, inputs, ARIA, accessibility tree, pseudo-content, SVG, canvas, URL, history, storage, cache, IndexedDB, and console");
		assertBrowserSafe(await page.content(), "browser DOM snapshot");
		stage = "browser-screenshot";
		await page.screenshot({ path: screenshotPath, fullPage: true });
		const screenshot = await readFile(screenshotPath);
		if (screenshot.length < 1_024 || screenshot[0] !== 0x89 || screenshot.subarray(1, 4).toString() !== "PNG") throw new Error("browser screenshot proof is invalid");
		// Screenshot pixels are not UTF-8. Runtime text/ARIA/pseudo/SVG/canvas extraction covers
		// dynamic visible content; same-origin static image/background inputs are source-scanned below.
		stage = "browser-static-privacy";
		await assertShippedVisualAssetsSafe(fileURLToPath(new URL("../out/", import.meta.url)), forbiddenBrowserEvidence);
		assertBrowserSafe(await readFile(new URL("../generated/read-api.ts", import.meta.url), "utf8"), "generated browser source");
		stage = "browser-response-privacy";
		await assertSettledPrivacyChecks(browserResponseChecks);
		stage = "browser-authority-path";
		if (browserAPIPaths.some(path => /provider|sqlite|acknowledgements/i.test(path))) throw new Error("browser used a forbidden alternate authority path");
		stage = "browser-history-privacy";
		if (browserSurfaces.url.includes("declaration-browser") || Object.keys(browserSurfaces.localStorage).length !== 0 || Object.keys(browserSurfaces.sessionStorage).length !== 0) throw new Error("change handles escaped safe history state");

		stage = "browser-trace-privacy";
		await context.tracing.stop({ path: tracePath });
		traceStarted = false;
		await inspectTraceArchive(tracePath, forbiddenBrowserEvidence, credentialHeaderEvidence);
		await Promise.all([rm(tracePath, { force: true }), rm(screenshotPath, { force: true })]);
	}
} catch {
  failureStage = stage;
} finally {
	const cleanupFailure = await finalizeProbeResources({ browser, context, credentialProxy, remove: rm, screenshotPath, tracePath, traceStarted });
	failureStage ??= cleanupFailure;
}
if (failureStage) {
	process.stderr.write(`PROBE_FAILED:${failureStage}\n`);
	process.exitCode = 1;
} else {
	process.stdout.write(`${JSON.stringify({ schemaVersion: 1, check: "phase-4-real-change-server", status: "pass" })}\n`);
}
