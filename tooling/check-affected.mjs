import path from "node:path";
import { fileURLToPath } from "node:url";
import { CommandError, runCommand } from "./lib/process.mjs";
import { classifyChangedPaths, fullCheckPlan, runCheckPlan, validCommit } from "./lib/check-plan.mjs";

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

function githubOutput(plan) {
  return `browser=${plan.browser}\nmode=${plan.mode}\nfail_closed=${plan.failClosed}\n`;
}

async function main() {
  const args = process.argv.slice(2);
  const allowed = new Set(["--base", "--head", "--format", "--dry-run"]);
  for (let index = 0; index < args.length; index++) {
    const value = args[index];
    if (!allowed.has(value)) throw new Error(`unknown argument: ${value}`);
    if (value !== "--dry-run") {
      index++;
      if (args[index] === undefined) throw new Error(`missing value for ${value}`);
    }
  }
  const format = argumentValue(args, "--format") || "json";
  if (format !== "json" && format !== "github") throw new Error("format must be json or github");
  const plan = await planForCommits(argumentValue(args, "--base"), argumentValue(args, "--head"));
  if (format === "github") {
    if (!args.includes("--dry-run")) throw new Error("github format requires --dry-run");
    process.stdout.write(githubOutput(plan));
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
