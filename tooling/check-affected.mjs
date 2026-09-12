import path from "node:path";
import { fileURLToPath } from "node:url";
import { CommandError, runCommand } from "./lib/process.mjs";
import {
  classifyChangedPaths,
  fullCheckPlan,
  runCheckPlan,
  validCommit,
  validateCheckPlan,
} from "./lib/check-plan.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function argumentValue(args, flag) {
  const index = args.indexOf(flag);
  if (index === -1) return undefined;
  return args[index + 1];
}

export function parseNameStatus(raw) {
  if (typeof raw !== "string" || !raw.endsWith("\0")) throw new Error("invalid git diff framing");
  const fields = raw.split("\0");
  fields.pop();
  const changes = [];
  for (let index = 0; index < fields.length;) {
    const status = fields[index++];
    if (!status) throw new Error("missing git status");
    if (/^[RC][0-9]{1,3}$/.test(status)) {
      const previousPath = fields[index++];
      const path = fields[index++];
      if (!previousPath || !path) throw new Error("incomplete rename or copy");
      changes.push({ status, path, previousPath });
    } else {
      const path = fields[index++];
      if (!path) throw new Error("missing git path");
      changes.push({ status, path });
    }
  }
  return changes;
}

async function commitExists(commit) {
  try {
    await runCommand("git", ["cat-file", "-e", `${commit}^{commit}`], { cwd: ROOT, capture: true });
    return true;
  } catch {
    return false;
  }
}

export async function planForCommits(base, head) {
  if (!base || !head) return fullCheckPlan("missing-base-or-head");
  if (!validCommit(base) || !validCommit(head)) return fullCheckPlan("invalid-base-or-head");
  if (!(await commitExists(base)) || !(await commitExists(head))) return fullCheckPlan("commit-unavailable");
  try {
    await runCommand("git", ["merge-base", "--is-ancestor", base, head], { cwd: ROOT, capture: true });
  } catch {
    return fullCheckPlan("unverified-ancestry");
  }
  try {
    const diff = await runCommand("git", ["diff", "--name-status", "-z", "--find-renames", `${base}...${head}`], { cwd: ROOT, capture: true });
    return classifyChangedPaths(parseNameStatus(diff.stdout));
  } catch {
    return fullCheckPlan("unreadable-diff");
  }
}

export function encodeExecutionPlan(plan, base, head) {
  const envelope = {
    schemaVersion: 1,
    baseSha: validCommit(base) ? base : "",
    headSha: validCommit(head) ? head : "",
    plan: validateCheckPlan(plan),
  };
  return Buffer.from(JSON.stringify(envelope), "utf8").toString("base64url");
}

export function decodeExecutionPlan(encoded) {
  if (typeof encoded !== "string" || encoded.length === 0 || encoded.length > 1_000_000 ||
      !/^[A-Za-z0-9_-]+$/.test(encoded)) {
    throw new Error("invalid encoded check plan");
  }
  let parsed;
  try {
    const decoded = Buffer.from(encoded, "base64url");
    if (decoded.toString("base64url") !== encoded) throw new Error("non-canonical encoding");
    parsed = JSON.parse(decoded.toString("utf8"));
  } catch {
    throw new Error("invalid encoded check plan");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) ||
      Object.keys(parsed).sort().join(",") !== "baseSha,headSha,plan,schemaVersion" ||
      parsed.schemaVersion !== 1 ||
      (parsed.baseSha !== "" && !validCommit(parsed.baseSha)) ||
      (parsed.headSha !== "" && !validCommit(parsed.headSha))) {
    throw new Error("invalid encoded check plan envelope");
  }
  return Object.freeze({
    schemaVersion: 1,
    baseSha: parsed.baseSha,
    headSha: parsed.headSha,
    plan: validateCheckPlan(parsed.plan),
  });
}

function githubOutput(plan, base, head) {
  const baseSha = validCommit(base) ? base : "";
  const headSha = validCommit(head) ? head : "";
  const checkPlan = encodeExecutionPlan(plan, base, head);
  return `browser=${plan.browser}\nmode=${plan.mode}\nfail_closed=${plan.failClosed}\nbase_sha=${baseSha}\nhead_sha=${headSha}\ncheck_plan=${checkPlan}\n`;
}

async function main() {
  const args = process.argv.slice(2);
  const allowed = new Set(["--base", "--head", "--format", "--dry-run", "--execute-plan"]);
  const switches = new Set(["--dry-run", "--execute-plan"]);
  for (let index = 0; index < args.length; index++) {
    const value = args[index];
    if (!allowed.has(value)) throw new Error(`unknown argument: ${value}`);
    if (!switches.has(value)) {
      index++;
      if (args[index] === undefined) throw new Error(`missing value for ${value}`);
    }
  }
  if (args.includes("--execute-plan")) {
    if (args.length !== 1) throw new Error("execute-plan cannot be combined with other arguments");
    const execution = decodeExecutionPlan(process.env.VSK_CHECK_PLAN_B64);
    await runCheckPlan(execution.plan, { root: ROOT });
    process.stdout.write(`${JSON.stringify({
      ...execution.plan,
      baseSha: execution.baseSha,
      headSha: execution.headSha,
      status: "pass",
    })}\n`);
    return;
  }
  const format = argumentValue(args, "--format") || "json";
  if (format !== "json" && format !== "github") throw new Error("format must be json or github");
  const base = argumentValue(args, "--base");
  const head = argumentValue(args, "--head");
  const plan = await planForCommits(base, head);
  if (format === "github") {
    if (!args.includes("--dry-run")) throw new Error("github format requires --dry-run");
    process.stdout.write(githubOutput(plan, base, head));
    return;
  }
  if (!args.includes("--dry-run")) await runCheckPlan(plan, { root: ROOT });
  process.stdout.write(`${JSON.stringify({ ...plan, status: args.includes("--dry-run") ? "planned" : "pass" })}\n`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    const detail = error instanceof CommandError ? `${error.message}` : error.message;
    process.stderr.write(`affected checks failed: ${detail}\n`);
    process.exitCode = 1;
  });
}
