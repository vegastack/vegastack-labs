import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runCommand } from "./lib/process.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const ANALYZER = path.join(ROOT, "tooling/analyze-server");
const CODE_ORDER = [
  "SERVER_EXECUTABLE_COUNT",
  "SERVER_ENTRYPOINT_COUNT",
  "SERVER_TCP_LISTENER",
  "SERVER_IDENTITY_HEADER_TRUST",
  "SERVER_CONTEXT_SETTER",
  "SERVER_SQLITE_ACCESS",
  "SERVER_XSYS_SCOPE",
  "SERVER_PLATFORM_SCOPE",
];

export async function verifyServer(root = ROOT) {
  const codes = new Set();
  let analysis;
  try {
    const output = await runCommand("go", ["run", ANALYZER, "--root", root], {
      cwd: ROOT,
      capture: true,
      timeoutMs: 120_000,
    });
    analysis = JSON.parse(output.stdout);
  } catch {
    return { status: "fail", codes: [...CODE_ORDER] };
  }
  if (
    !Array.isArray(analysis.executableDirectories) ||
    analysis.executableDirectories.length !== 1 ||
    analysis.executableDirectories[0] !== "cmd/vsk-labs"
  ) {
    codes.add("SERVER_EXECUTABLE_COUNT");
  }
  try {
    const registry = JSON.parse(await readFile(path.join(root, "schemas/v1/command-registry.json"), "utf8"));
    const entries = registry.commands?.filter(
      (command) => command.availability === "available" && JSON.stringify(command.path) === JSON.stringify(["server", "run"]),
    );
    if (!Array.isArray(entries) || entries.length !== 1) codes.add("SERVER_ENTRYPOINT_COUNT");
  } catch {
    codes.add("SERVER_ENTRYPOINT_COUNT");
  }
  if (analysis.tcpListener) codes.add("SERVER_TCP_LISTENER");
  if (analysis.identityHeaderTrust) codes.add("SERVER_IDENTITY_HEADER_TRUST");
  if (analysis.contextSetterOutside) codes.add("SERVER_CONTEXT_SETTER");
  if (analysis.sqliteAccess) codes.add("SERVER_SQLITE_ACCESS");
  if (analysis.xSysOutsideScope) codes.add("SERVER_XSYS_SCOPE");
  if (analysis.platformScopeInvalid) codes.add("SERVER_PLATFORM_SCOPE");
  const ordered = CODE_ORDER.filter((code) => codes.has(code));
  return { status: ordered.length === 0 ? "pass" : "fail", codes: ordered };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const result = await verifyServer();
    process.stdout.write(`${JSON.stringify({ schemaVersion: 1, check: "server", ...result })}\n`);
    if (result.status !== "pass") process.exitCode = 1;
  } catch {
    process.stderr.write("server verification failed\n");
    process.exitCode = 1;
  }
}
