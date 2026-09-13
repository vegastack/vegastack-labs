import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { phase3LinkerFlags } from "./verify-phase-3.mjs";
import { packageManagerInvocation, runCommand } from "./lib/process.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function safeFailureStage(error, fallback) {
  const captured = `${error?.stdout ?? ""}\n${error?.stderr ?? ""}`;
  const probe = captured.match(/PROBE_FAILED:([a-z]+(?:-[a-z]+)*)/);
  return probe?.[1] ?? fallback;
}

export async function verifyPhase4Sources(root = ROOT) {
  const [fixture, probe, client] = await Promise.all([
    readFile(path.join(root, "internal/server/phase4_console_acceptance_linux_test.go"), "utf8"),
    readFile(path.join(root, "web/e2e/real-change-server-probe.mjs"), "utf8"),
    readFile(path.join(root, "web/generated/read-api.ts"), "utf8"),
  ]);
  for (const pattern of [/CompleteApprovedResumeAndCancelLoopsOverRealTLS/, /phase4ApprovalBridge/, /phase4ResumableAdapter/]) {
    if (!pattern.test(fixture)) throw new Error("PHASE4_FAILED:fixture-definition");
  }
  for (const pattern of [/protected approval material was disclosed/, /approval-status/, /execute-interrupted/, /resume-run/, /cancelled/]) {
    if (!pattern.test(probe)) throw new Error("PHASE4_FAILED:browser-proof");
  }
  for (const pattern of [/requestApproval/, /getApprovalStatus/, /preparePlan/, /reviseDeclaration/]) {
    if (!pattern.test(client)) throw new Error("PHASE4_FAILED:generated-client");
  }
  return true;
}

export async function runPhase4(root = ROOT, { prepared = false } = {}) {
  await verifyPhase4Sources(root);
  if (!prepared) {
    const build = packageManagerInvocation(["--filter", "@vegastack/labs-web", "build"]);
    await runCommand(build.command, build.args, { cwd: root, timeoutMs: 180_000 });
  }
  if (process.platform === "linux") {
    const runtimeRoot = await mkdtemp(path.join(tmpdir(), "vsk-phase4-runtime-"));
    const binary = path.join(runtimeRoot, "vsk-labs");
    const database = path.join(runtimeRoot, "control.db");
    const osRelease = path.join(runtimeRoot, "os-release");
    try {
      await writeFile(osRelease, "ID=debian\nVERSION_ID=13\n", { mode: 0o600 });
      await runCommand("go", ["build", "-race", "-ldflags", phase3LinkerFlags({ database, osRelease }), "-o", binary, "./cmd/vsk-labs"], { cwd: root, capture: true, timeoutMs: 180_000 });
      await runCommand("go", ["test", "-race", "-count=1", "./internal/server", "-run", "Phase4ConsoleChanges"], {
        cwd: root,
        capture: true,
        env: { ...process.env, VSK_PHASE3_BINARY: binary, VSK_PHASE3_RUNTIME_ROOT: runtimeRoot },
        timeoutMs: 180_000,
      });
    } catch (error) {
      throw new Error(`PHASE4_FAILED:${safeFailureStage(error, "real-server")}`);
    } finally {
      await rm(runtimeRoot, { recursive: true, force: true });
    }
  }
  return { schemaVersion: 1, check: "phase-4-change-workflow", status: "pass" };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    if (args.some(value => value !== "--prepared") || args.filter(value => value === "--prepared").length > 1) throw new Error("PHASE4_FAILED:arguments");
    process.stdout.write(`${JSON.stringify(await runPhase4(ROOT, { prepared: args.includes("--prepared") }))}\n`);
  } catch (error) {
    const stage = /^PHASE4_FAILED:([a-z]+(?:-[a-z]+)*)$/.exec(error?.message ?? "")?.[1] ?? "verification";
    process.stderr.write(`Phase 4 verification failed at ${stage}\n`);
    process.exitCode = 1;
  }
}
