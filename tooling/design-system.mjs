import { createHash } from "node:crypto";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseEnv } from "node:util";
import { runCommand } from "./lib/process.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const LOCK = "tooling/design-system-lock.json";
const ORIGIN = "https://design.vegastack.com";
const VERSION = "0.6.0";
const ROOTS = new Map([
  ["provider", "sha256-j7RJm9M0bbnthF2SXN8AfSKfoZqUnnPm169og/MPM8E="],
  ["dashboard-01", "sha256-H3abUSAP+yCnOjs0Qy0Y1R9PhqJQJ3wR7w7/ZX2dI58="],
]);

function assertObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
}

function assertSafeRelative(relative, label) {
  if (typeof relative !== "string" || !relative || path.isAbsolute(relative) || relative.includes("\\")) {
    throw new Error(`${label} must be a portable relative path`);
  }
  const normalized = path.posix.normalize(relative);
  if (normalized !== relative || normalized === ".." || normalized.startsWith("../")) {
    throw new Error(`${label} escapes the repository`);
  }
  return normalized;
}

function digest(bytes) {
  return `sha256-${createHash("sha256").update(bytes).digest("base64")}`;
}

function installedPath(target) {
  if (target.startsWith("@ui/")) return `web/components/ui/${target.slice(4)}`;
  return `web/${assertSafeRelative(target, "registry target")}`;
}

function assertNoSecrets(value) {
  const text = JSON.stringify(value);
  if (/CF-Access-Client-(?:Id|Secret)|CF_ACCESS_CLIENT_(?:ID|SECRET)|\.access\b|cfast_[A-Za-z0-9]+/i.test(text)) {
    throw new Error("design-system lock contains credential material");
  }
}

export async function verifyPinnedDesignSystem({ root = ROOT, lockPath = LOCK } = {}) {
  const absoluteLock = path.resolve(root, lockPath);
  const lock = JSON.parse(await readFile(absoluteLock, "utf8"));
  assertObject(lock, "design-system lock");
  assertNoSecrets(lock);
  if (lock.schemaVersion !== 1 || lock.registryOrigin !== ORIGIN || lock.registryVersion !== VERSION) {
    throw new Error("design-system lock has an unapproved schema, origin, or version");
  }
  const roots = new Map((lock.roots ?? []).map(entry => [entry.name, entry.integrity]));
  for (const [name, integrity] of ROOTS) {
    if (roots.get(name) !== integrity) throw new Error(`design-system root ${name} integrity is not approved`);
  }
  if (roots.size !== ROOTS.size || !Array.isArray(lock.items) || lock.items.length === 0) {
    throw new Error("design-system lock has an invalid root or item set");
  }
  const names = new Set();
  const targets = new Set();
  let fileCount = 0;
  for (const item of lock.items) {
    assertObject(item, "design-system item");
    if (!/^[a-z0-9-]+$/.test(item.name) || names.has(item.name)) throw new Error(`invalid or duplicate design-system item ${item.name}`);
    names.add(item.name);
    if (item.version !== VERSION || !/^sha256-[A-Za-z0-9+/]+=*$/.test(item.integrity)) throw new Error(`${item.name} has invalid version or integrity`);
    if (!Array.isArray(item.files) || item.files.length === 0) throw new Error(`${item.name} has no locked files`);
    for (const file of item.files) {
      const relative = assertSafeRelative(file.path, `${item.name} file`);
      if (targets.has(relative)) throw new Error(`duplicate design-system target ${relative}`);
      targets.add(relative);
      const bytes = await readFile(path.resolve(root, relative));
      if (digest(bytes) !== file.sha256) throw new Error(`${relative} digest does not match the approved design-system lock`);
      fileCount += 1;
    }
  }
  return { itemCount: lock.items.length, fileCount };
}

async function loadMaintainerEnv(root) {
  const dotenv = path.join(root, ".env.local");
  let values = {};
  try { values = parseEnv(await readFile(dotenv, "utf8")); } catch (error) { if (error.code !== "ENOENT") throw error; }
  const env = { ...process.env, ...values, VEGASTACK_TRUSTED_REGISTRY_ORIGIN: ORIGIN };
  if (!env.CF_ACCESS_CLIENT_ID || !env.CF_ACCESS_CLIENT_SECRET) throw new Error("maintainer refresh requires CF_ACCESS_CLIENT_ID and CF_ACCESS_CLIENT_SECRET");
  return env;
}

async function readVerifiedItem(file, expectedName) {
  const item = JSON.parse(await readFile(file, "utf8"));
  if (item.name !== expectedName || item.meta?.version !== VERSION || !Array.isArray(item.files)) {
    throw new Error(`verified registry item ${expectedName} has an unexpected identity, version, or files contract`);
  }
  return item;
}

export async function refreshPinnedDesignSystem({ root = ROOT, registryOrigin = ORIGIN, expectedVersion = VERSION } = {}) {
  if (registryOrigin !== ORIGIN || expectedVersion !== VERSION) throw new Error("refresh origin or version is not operator-approved");
  const env = await loadMaintainerEnv(root);
  const indexResponse = await fetch(`${ORIGIN}/r/registry.json`, {
    redirect: "error",
    headers: { "CF-Access-Client-Id": env.CF_ACCESS_CLIENT_ID, "CF-Access-Client-Secret": env.CF_ACCESS_CLIENT_SECRET },
  });
  if (!indexResponse.ok) throw new Error(`registry index returned HTTP ${indexResponse.status}`);
  const index = await indexResponse.json();
  const indexItems = new Map((index.items ?? []).map(item => [item.name, item]));
  const queue = [...ROOTS.keys()];
  const names = [];
  const seen = new Set();
  while (queue.length) {
    const name = queue.shift();
    if (seen.has(name)) continue;
    seen.add(name);
    const indexed = indexItems.get(name);
    if (!indexed || indexed.meta?.version !== VERSION) throw new Error(`registry index does not contain approved ${name}@${VERSION}`);
    names.push(name);
    for (const dependency of indexed.registryDependencies ?? []) queue.push(dependency.replace(/^@vegastack\//, ""));
  }
  names.sort();
  const verifyDir = await mkdtemp(path.join(tmpdir(), "vsk-design-verify-"));
  const items = [];
  for (const name of names) {
    const savePath = path.join(verifyDir, `${name}.json`);
    await runCommand("pnpm", ["--dir", "web", "exec", "vegastack-design", "verify", "--save", savePath, name], { cwd: root, env, timeoutMs: 120_000 });
    const item = await readVerifiedItem(savePath, name);
    if (item.meta.integrity !== indexItems.get(name).meta.integrity) throw new Error(`${name} differs from the signed index`);
    items.push({ item, savePath });
  }
  await runCommand("pnpm", ["dlx", "shadcn@latest", "add", "-c", "web", "-y", "@vegastack/provider", "@vegastack/dashboard-01"], { cwd: root, env, timeoutMs: 180_000 });
  const lockedItems = [];
  for (const { item, savePath } of items) {
    await runCommand("pnpm", ["--dir", "web", "exec", "vegastack-design", "verify", "--post-write", "--item", savePath, "--expected-integrity", item.meta.integrity, "--target-dir", "."], { cwd: root, env, timeoutMs: 120_000 });
    const files = [];
    for (const file of item.files) {
      const relative = installedPath(file.target ?? file.path);
      files.push({ path: relative, sha256: digest(await readFile(path.join(root, relative))) });
    }
    lockedItems.push({ name: item.name, type: item.type, version: item.meta.version, integrity: item.meta.integrity, files });
  }
  const lock = {
    schemaVersion: 1,
    registryOrigin: ORIGIN,
    registryVersion: VERSION,
    acceptedAt: "10-09-2026",
    roots: [...ROOTS].map(([name, integrity]) => ({ name, integrity })),
    items: lockedItems.sort((a, b) => a.name.localeCompare(b.name)),
  };
  assertNoSecrets(lock);
  await writeFile(path.join(root, LOCK), `${JSON.stringify(lock, null, 2)}\n`, { mode: 0o644 });
  return verifyPinnedDesignSystem({ root });
}

async function main() {
  const [mode, ...args] = process.argv.slice(2);
  let result;
  if (mode === "--check" && args.length === 0) result = await verifyPinnedDesignSystem();
  else if (mode === "--refresh" && args.join(" ") === "--approve-version 0.6.0") result = await refreshPinnedDesignSystem();
  else throw new Error("usage: node tooling/design-system.mjs --check | --refresh --approve-version 0.6.0");
  process.stdout.write(`${JSON.stringify({ schemaVersion: 1, check: "design-system", status: "pass", ...result })}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => { process.stderr.write(`design-system verification failed: ${error.message}\n`); process.exitCode = 1; });
}
