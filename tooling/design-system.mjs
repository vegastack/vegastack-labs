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
export const VERSION = "0.9.1";
const ACCESS_ID_ENV = ["CF", "ACCESS", "CLIENT", "ID"].join("_");
const ACCESS_SECRET_ENV = ["CF", "ACCESS", "CLIENT", "SECRET"].join("_");
const ACCESS_ID_HEADER = ["CF", "Access", "Client", "Id"].join("-");
const ACCESS_SECRET_HEADER = ["CF", "Access", "Client", "Secret"].join("-");
const REVIEWED_SOURCE_CLOSURE_SHA256 = "756725140cc4e9e9f33330c06497676cbf9405e431f6090b256ea44e73489f25";
const SHADCN_VERSION = "4.21.0";
const SHADCN_INTEGRITY = "sha512-UU2mFNusW8C5rvadKdH69vERYZqUlOOlXBcf0MYhYLdTGP6DPti7X4qovCu+RTfCqsAgq/T+YfE0Vnttxh9aiw==";
export const ROOTS = new Map([
  ["provider", "sha256-PTk0QbeCkLBWvgfFCz6caP2bkxYSXNqTe50NOBBburg="],
  ["button", "sha256-Ood+nbd5djqlMamanG14IdSyvS+psDEc/WAfcqMKuTQ="],
  ["badge", "sha256-yjFgCl418g5sVLav33JA6tsBkTaJxpZkyzkfF9vB9HM="],
  ["card", "sha256-U8K5KtHspmfQOimkAO/8TpQ9uq7eYYmLxbQiSaklaZ0="],
  ["empty", "sha256-5t3dzeajxtdosB6RktNM/RUyZBbHH/f1f0D8V6AMYeM="],
  ["alert", "sha256-Az8K2MwE9cmvEGVFaQR/K1W5wiAGwtUzq7jrXxmx9Rs="],
  ["chip", "sha256-iEVyViVOSa8k3gk8f6NoAjO+9WyDjFkc3elS0B3brhg="],
  ["page-header", "sha256-IDvxvY9nPczNeLmuvnfaBvBnUZeFw90+Urgh/CP6SDI="],
  ["property-list", "sha256-zrNLmcNbniOmeRX1o6oIZCl5I2U5FXUuKqwRalso2Mc="],
  ["table", "sha256-bcGnmXGVfKnFEi8v7O5yIe0i/NckNk/SSSg+LBRO/RM="],
  ["data-list", "sha256-VvVeDmjzqOniqERzym9BV455T0Vb29MK8/fhN8mhZso="],
  ["status-icon", "sha256-16U1Eq6MVoHPyO8m/EQ0D9Vwei7fg1y6U/krx4hx0ho="],
  ["stat", "sha256-FJMYLHN2OiammVnkOyIgIY4dmgK4F8k38Nap87jh+EY="],
  ["sidebar", "sha256-F13vRu6isX1c0BA1NFX6wExSQrQUDT4whu0iSkluVsA="],
  ["app-shell", "sha256-uanFu9u2xy5BPOcHiJGWz3Ht8CDxl7KPEVQercn4IWk="],
  ["breadcrumb", "sha256-tKp+EKVOCwG88ELIP/zB09TMmpCtOML/9NzuFZ8euSQ="],
  ["separator", "sha256-0EODyTqr2HJWZfY24AhFWddoEjk0cQiuxs5AL0H5wQo="],
  ["sheet", "sha256-V+yegcfH4CYnmeTHtEqclMWR9V4C6oh7LYXg0j/7XKE="],
  ["skeleton", "sha256-nPr0DYXiEY9p9zCuw5Anw7lJRnkOCXO1fCZOSltsW5k="],
  ["avatar", "sha256-Kw/orhYVtjD59QCwWS7uMzAuVXaCcQGBrvz+PO9Fvc0="],
  ["dropdown-menu", "sha256-NqmrleFyI1JaCpx84cWzR5GbJcywBKn7LGZ3+7AMi7Y="],
  ["relative-time", "sha256-GnHlW/uNrUsK1gxXIppDi/5mUctLeHA0DwtCGWudOSE="],
  ["tabs", "sha256-ytXteWT4ZI3GKEPufRZbV/gxQZuYyqBVGkZGLRoM3yk="],
  ["segmented", "sha256-Iv+/dk7VK+6od4+jriV+8ZlT1rn7wlyE2nf1B+5EpEU="],
  ["item", "sha256-2WU+gKnHHeBh5aMPecC+FEIH1vh76BWx5LrnIeupcF0="],
  ["progress", "sha256-KNN8LtQdQzblHpEgHk6qThEmKbrP9ojKhYpbMn9qC4w="],
  ["chart", "sha256-V5u94RFZYwLTPROUTw1aZYUpMjvjtH/JgEYmHMb2bF4="],
  ["animated-number", "sha256-KxvDjVZ54wgu29zyQA8z0bH7kHQqak8wvuEuQpQxht8="],
  ["timeline", "sha256-765Yodf1rCmCCrBMVmx7uo3zVBabogLdhx0Tz/qbfVU="],
  ["field", "sha256-o/a0uNPd5e/CBX6yxZFZrdFlXJ97BE+7Sp4HFszKwMI="],
  ["input", "sha256-D/2LzEH/T5SGZD3nDBxK607aBF7sSR31I5xW53bJAmg="],
  ["label", "sha256-yhCF/XXGR2IyYa1m9xyq6UOL45TDYOyyLzgFoixSgmE="],
  ["number-field", "sha256-gNwEG6AkZQTi6uktdg9y/4G5pmgpDPo1B+Lq3JI3qJA="],
  ["code-block", "sha256-qTVDsNJWbg1Wq3iogZXr0S01qix/yBKotpOXhZ/3KJQ="],
  ["accordion", "sha256-OazYh0N/yW3tErBVNoixEk95zDnyjKsjOlfkag/gYyE="],
  ["collapsible", "sha256-gpIh/LhTg2zK44IjAj8bBJ63Qf6VLSr00J6p04XF3co="],
  ["dialog", "sha256-Fqe7GVUAXfmpa3Yzy912L1gcrwcUfQX6QxZu6FuVekk="],
  ["alert-dialog", "sha256-fxVFfGmJHVeQ0P9LqDa24t76Rdjf5PehWyPtrgRaGSQ="],
  ["stepper", "sha256-p14iB0IedPGi91Ll9LO0zwaddKS6kIPSWUaEe6bYPCw="],
  ["checkbox", "sha256-A6k4NJ4Z396UIrj4efZKMZCfKG+8Ycx9NgYTSn3mW8Q="],
  ["tooltip", "sha256-JC0fGGed7SGqZJLrOjT4N2z+GxX+l5dASQvydG7ugmw="],
  ["truncated-text", "sha256-L9T6gXKxsdpbn/HIEBZMhThh4IUD+jvqRiei6R4Zol0="],
  ["icon-button", "sha256-2pqvb4v/mv1M63c0kF/Lu4ylQP7mVJKzqdmAmn1m6NA="],
  ["spinner", "sha256-TI8+t0J4cYzkLYT0ySPB3JaOXr+/t2oZ3pqiTn0FFZc="],
  ["copy-button", "sha256-BhrRxaV78w/vW1oWH3KzvCncx7JVayshBv6mYNsHRPo="],
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

export function sourceClosureDigest(lock) {
  const closure = (lock.items ?? []).map(item => ({
    name: item.name,
    type: item.type,
    version: item.version,
    integrity: item.integrity,
    files: (item.files ?? []).map(file => ({ path: file.path, sha256: file.upstreamSha256 ?? file.sha256 })).sort((a, b) => a.path.localeCompare(b.path)),
  })).sort((a, b) => a.name.localeCompare(b.name));
  return createHash("sha256").update(JSON.stringify(closure)).digest("hex");
}

export function installedPath(target) {
  if (target.startsWith("@ui/")) return assertSafeRelative(`web/components/ui/${assertSafeRelative(target.slice(4), "registry UI target")}`, "installed UI target");
  return assertSafeRelative(`web/${assertSafeRelative(target, "registry target")}`, "installed target");
}

function assertNoSecrets(value) {
  const text = JSON.stringify(value);
  if (/CF-Access-Client-(?:Id|Secret)|CF_ACCESS_CLIENT_(?:ID|SECRET)|\.access\b|cfast_[A-Za-z0-9]+/i.test(text)) {
    throw new Error("design-system lock contains credential material");
  }
}

export async function verifyPinnedDesignSystem({ root = ROOT, lockPath = LOCK, expectedClosureSha256 = REVIEWED_SOURCE_CLOSURE_SHA256 } = {}) {
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
  if (lock.sourceClosureSha256 !== expectedClosureSha256 || sourceClosureDigest(lock) !== expectedClosureSha256) {
    throw new Error("design-system source closure does not match the reviewed item, integrity, and target set");
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
      const ownedBlock = item.name === "dashboard-01" && item.type === "registry:block";
      if (file.upstreamSha256 !== undefined && !ownedBlock) throw new Error(`${relative} cannot declare an owned-block upstream digest`);
      if (file.upstreamSha256 !== undefined && !/^sha256-[A-Za-z0-9+/]+=*$/.test(file.upstreamSha256)) throw new Error(`${relative} has an invalid upstream digest`);
      if (targets.has(relative)) throw new Error(`duplicate design-system target ${relative}`);
      targets.add(relative);
      const bytes = await readFile(path.resolve(root, relative));
      if (digest(bytes) !== file.sha256) throw new Error(`${relative} digest does not match the approved design-system lock`);
      fileCount += 1;
    }
  }
  for (const [name, integrity] of ROOTS) {
    const item = lock.items.find(candidate => candidate.name === name);
    if (!item || item.integrity !== integrity) throw new Error(`design-system root item ${name} does not match its approved integrity`);
  }
  return { itemCount: lock.items.length, fileCount };
}

async function loadMaintainerEnv(root) {
  const dotenv = path.join(root, ".env.local");
  let values = {};
  try { values = parseEnv(await readFile(dotenv, "utf8")); } catch (error) { if (error.code !== "ENOENT") throw error; }
  const env = {};
  for (const name of ["HOME", "PATH", "TMPDIR", "TEMP", "TMP", "SystemRoot", "COMSPEC", "NO_COLOR", "CI"]) {
    if (process.env[name]) env[name] = process.env[name];
  }
  env[ACCESS_ID_ENV] = values[ACCESS_ID_ENV] ?? process.env[ACCESS_ID_ENV];
  env[ACCESS_SECRET_ENV] = values[ACCESS_SECRET_ENV] ?? process.env[ACCESS_SECRET_ENV];
  env.VEGASTACK_TRUSTED_REGISTRY_ORIGIN = ORIGIN;
  if (!env[ACCESS_ID_ENV] || !env[ACCESS_SECRET_ENV]) throw new Error("maintainer refresh requires the documented Cloudflare Access environment variables");
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
  const initialStatus = await runCommand("git", ["status", "--porcelain=v1", "-z"], { cwd: root, capture: true, timeoutMs: 30_000 });
  if (initialStatus.stdout) throw new Error("maintainer refresh requires a clean Git worktree");
  const indexResponse = await fetch(`${ORIGIN}/r/registry.json`, {
    redirect: "error",
    signal: AbortSignal.timeout(30_000),
    headers: { [ACCESS_ID_HEADER]: env[ACCESS_ID_ENV], [ACCESS_SECRET_HEADER]: env[ACCESS_SECRET_ENV] },
  });
  if (!indexResponse.ok) throw new Error(`registry index returned HTTP ${indexResponse.status}`);
  const index = await indexResponse.json();
  const indexItems = new Map((index.items ?? []).map(item => [item.name, item]));
  const queue = [...ROOTS.keys()];
  const seen = new Set();
  const items = [];
  const verifyDir = await mkdtemp(path.join(tmpdir(), "vsk-design-verify-"));
  while (queue.length) {
    const name = queue.shift();
    if (seen.has(name)) continue;
    seen.add(name);
    const indexed = indexItems.get(name);
    if (!indexed || indexed.meta?.version !== VERSION) throw new Error(`registry index does not contain approved ${name}@${VERSION}`);
    const savePath = path.join(verifyDir, `${name}.json`);
    await runCommand("pnpm", ["--dir", "web", "exec", "vegastack-design", "verify", "--save", savePath, name], { cwd: root, env, timeoutMs: 120_000 });
    const item = await readVerifiedItem(savePath, name);
    if (item.meta.integrity !== indexItems.get(name).meta.integrity) throw new Error(`${name} differs from the signed index`);
    if (ROOTS.has(name) && item.meta.integrity !== ROOTS.get(name)) throw new Error(`${name} differs from the operator-approved root integrity`);
    const verifiedDependencies = (item.registryDependencies ?? []).map(dependency => dependency.replace(/^@vegastack\//, "")).sort();
    const indexedDependencies = (indexed.registryDependencies ?? []).map(dependency => dependency.replace(/^@vegastack\//, "")).sort();
    if (JSON.stringify(verifiedDependencies) !== JSON.stringify(indexedDependencies)) throw new Error(`${name} dependency summary differs from its verified item`);
    for (const dependency of verifiedDependencies) queue.push(dependency);
    items.push({ item, savePath });
  }
  items.sort((a, b) => a.item.name.localeCompare(b.item.name));
  const expectedTargets = new Set(items.flatMap(({ item }) => item.files.map(file => installedPath(file.target ?? file.path))));
  const packageEnv = { ...env };
  delete packageEnv[ACCESS_ID_ENV];
  delete packageEnv[ACCESS_SECRET_ENV];
  const published = await runCommand("pnpm", ["view", `shadcn@${SHADCN_VERSION}`, "dist.integrity", "--json"], { cwd: root, env: packageEnv, capture: true, timeoutMs: 30_000 });
  if (JSON.parse(published.stdout) !== SHADCN_INTEGRITY) throw new Error("shadcn installer integrity differs from the reviewed release");
  await runCommand("pnpm", ["dlx", `shadcn@${SHADCN_VERSION}`, "add", "-c", "web", "-y", ...[...ROOTS.keys()].map(name => `@vegastack/${name}`)], { cwd: root, env, timeoutMs: 180_000 });
  const changedStatus = await runCommand("git", ["status", "--porcelain=v1", "-z"], { cwd: root, capture: true, timeoutMs: 30_000 });
  const changedPaths = changedStatus.stdout.split("\0").filter(Boolean).map(entry => entry.slice(3));
  const unexpected = changedPaths.filter(file => !expectedTargets.has(file));
  if (unexpected.length) throw new Error(`shadcn wrote outside the verified source target set: ${unexpected.join(", ")}`);
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
    acceptedAt: "16-09-2026",
    roots: [...ROOTS].map(([name, integrity]) => ({ name, integrity })),
    items: lockedItems.sort((a, b) => a.name.localeCompare(b.name)),
  };
  lock.sourceClosureSha256 = sourceClosureDigest(lock);
  if (lock.sourceClosureSha256 !== REVIEWED_SOURCE_CLOSURE_SHA256) throw new Error("refreshed source closure differs from the reviewed baseline");
  assertNoSecrets(lock);
  await writeFile(path.join(root, LOCK), `${JSON.stringify(lock, null, 2)}\n`, { mode: 0o644 });
  return verifyPinnedDesignSystem({ root });
}

export async function acceptOwnedBlock({ root = ROOT, lockPath = LOCK } = {}) {
  const absoluteLock = path.resolve(root, lockPath);
  const lock = JSON.parse(await readFile(absoluteLock, "utf8"));
  const owned = lock.items.filter(item => item.type === "registry:block");
  if (owned.length !== 1 || owned[0].name !== "dashboard-01") {
    throw new Error("the approved dashboard block is not the sole repository-owned block");
  }
  for (const file of owned[0].files) {
    file.upstreamSha256 ??= file.sha256;
    file.sha256 = digest(await readFile(path.resolve(root, assertSafeRelative(file.path, "owned block file"))));
  }
  lock.ownedBlockAcceptedAt = "10-09-2026";
  assertNoSecrets(lock);
  await writeFile(absoluteLock, `${JSON.stringify(lock, null, 2)}\n`, { mode: 0o644 });
  return verifyPinnedDesignSystem({ root, lockPath });
}

async function main() {
  const [mode, ...args] = process.argv.slice(2);
  let result;
  if (mode === "--check" && args.length === 0) result = await verifyPinnedDesignSystem();
  else if (mode === "--refresh" && args.join(" ") === "--approve-version 0.9.1") result = await refreshPinnedDesignSystem();
  else if (mode === "--accept-owned-block" && args.join(" ") === "--approve-version 0.9.1") result = await acceptOwnedBlock();
  else throw new Error("usage: node tooling/design-system.mjs --check | --refresh --approve-version 0.9.1 | --accept-owned-block --approve-version 0.9.1");
  process.stdout.write(`${JSON.stringify({ schemaVersion: 1, check: "design-system", status: "pass", ...result })}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => { process.stderr.write(`design-system verification failed: ${error.message}\n`); process.exitCode = 1; });
}
