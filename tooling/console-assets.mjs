import { createHash } from "node:crypto";
import { copyFile, mkdir, mkdtemp, readFile, readdir, rename, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DEFAULT_SOURCE = path.join(ROOT, "web", "out");
const DEFAULT_DESTINATION = path.join(ROOT, "internal", "consoleassets", "dist");
const DEFAULT_MANIFEST = path.join(ROOT, "internal", "consoleassets", "manifest.json");

const CONTENT_TYPES = new Map([
  [".css", "text/css; charset=utf-8"],
  [".html", "text/html; charset=utf-8"],
  [".ico", "image/x-icon"],
  [".jpeg", "image/jpeg"],
  [".jpg", "image/jpeg"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".map", "application/json; charset=utf-8"],
  [".png", "image/png"],
  [".svg", "image/svg+xml"],
  [".txt", "text/plain; charset=utf-8"],
  [".webp", "image/webp"],
  [".woff", "font/woff"],
  [".woff2", "font/woff2"],
]);

function sha256(content) {
  return createHash("sha256").update(content).digest("hex");
}

function contentSecurityPolicy(htmlDocuments) {
  const hashes = new Set();
  for (const document of htmlDocuments) {
    for (const match of document.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi)) {
      hashes.add(`'sha256-${createHash("sha256").update(match[1]).digest("base64")}'`);
    }
  }
  return [
    "default-src 'self'",
    "base-uri 'none'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "form-action 'none'",
    `script-src 'self' ${[...hashes].sort().join(" ")}`.trim(),
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
  ].join("; ");
}

function immutableAsset(name) {
  return name.startsWith("_next/static/chunks/");
}

function canonicalFiles(files) {
  return Object.fromEntries(Object.entries(files).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0));
}

function assertSafeTargets({ source, destination, manifestPath }) {
  const resolved = [source, destination, manifestPath].map(value => path.resolve(value));
  if (new Set(resolved).size !== resolved.length || resolved.some(value => value === path.parse(value).root)) {
    throw new Error("unsafe Console asset paths");
  }
  if (resolved[1].startsWith(`${resolved[0]}${path.sep}`) || resolved[0].startsWith(`${resolved[1]}${path.sep}`)) {
    throw new Error("Console source and destination overlap");
  }
}

async function collect(directory, prefix = "") {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries.sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0)) {
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
    const absolute = path.join(directory, entry.name);
    if (entry.isSymbolicLink()) throw new Error(`Console assets must be regular files: ${relative}`);
    if (entry.isDirectory()) files.push(...await collect(absolute, relative));
    else if (entry.isFile()) files.push({ absolute, relative });
    else throw new Error(`Console assets must be regular files: ${relative}`);
  }
  return files;
}

async function describeAssetTree(root, { requireIndex = false } = {}) {
  const rootStatus = await stat(root).catch(() => undefined);
  if (!rootStatus?.isDirectory()) throw new Error("Console output directory is missing");
  const files = await collect(root);
  const described = {};
  const htmlDocuments = [];
  for (const file of files) {
    const extension = path.extname(file.relative).toLowerCase();
    const contentType = CONTENT_TYPES.get(extension);
    if (!contentType) throw new Error(`unsupported Console asset: ${file.relative}`);
    const content = await readFile(file.absolute);
    if (extension === ".html") htmlDocuments.push(content.toString("utf8"));
    described[file.relative] = {
      sha256: sha256(content),
      size: content.byteLength,
      contentType,
      immutable: immutableAsset(file.relative),
    };
  }
  if (requireIndex && (!described["index.html"] || described["index.html"].size === 0)) {
    throw new Error("Console output requires a non-empty index.html");
  }
  const csp = contentSecurityPolicy(htmlDocuments);
  const ordered = canonicalFiles(described);
  const buildDigest = sha256(JSON.stringify({ files: ordered, contentSecurityPolicy: csp }));
  return { files, manifest: { schemaVersion: 1, buildDigest, contentSecurityPolicy: csp, files: ordered } };
}

async function exists(candidate, statPath) {
  try {
    await statPath(candidate);
    return true;
  } catch {
    return false;
  }
}

async function recoverReplacement({ destination, manifestPath, backupDestination, backupManifest, renamePath, removePath, statPath }) {
  if (await exists(backupDestination, statPath)) {
    await removePath(destination, { recursive: true, force: true });
    await renamePath(backupDestination, destination);
  }
  if (await exists(backupManifest, statPath)) {
    await removePath(manifestPath, { force: true });
    await renamePath(backupManifest, manifestPath);
  }
}

export async function writeConsoleAssets({
  source = DEFAULT_SOURCE,
  destination = DEFAULT_DESTINATION,
  manifestPath = DEFAULT_MANIFEST,
  renamePath = rename,
  removePath = rm,
  statPath = stat,
} = {}) {
  assertSafeTargets({ source, destination, manifestPath });
  const { files, manifest } = await describeAssetTree(source, { requireIndex: true });
  const parent = path.dirname(destination);
  await mkdir(parent, { recursive: true });
  const stagingRoot = await mkdtemp(path.join(parent, ".console-assets-"));
  const temporary = path.join(stagingRoot, "dist");
  const temporaryManifest = path.join(stagingRoot, "manifest.json");
  const backupDestination = `${destination}.previous`;
  const backupManifest = `${manifestPath}.previous`;
  await mkdir(temporary);
  try {
    await recoverReplacement({ destination, manifestPath, backupDestination, backupManifest, renamePath, removePath, statPath });
    for (const file of files) {
      const target = path.join(temporary, ...file.relative.split("/"));
      await mkdir(path.dirname(target), { recursive: true });
      await copyFile(file.absolute, target);
    }
    await writeFile(temporaryManifest, `${JSON.stringify(manifest, null, 2)}\n`, { flag: "wx" });
    await removePath(backupDestination, { recursive: true, force: true });
    await removePath(backupManifest, { force: true });
    if (await exists(destination, statPath)) await renamePath(destination, backupDestination);
    if (await exists(manifestPath, statPath)) await renamePath(manifestPath, backupManifest);
    await renamePath(temporary, destination);
    await renamePath(temporaryManifest, manifestPath);
    await removePath(backupDestination, { recursive: true, force: true });
    await removePath(backupManifest, { force: true });
  } catch (error) {
    try {
      await recoverReplacement({ destination, manifestPath, backupDestination, backupManifest, renamePath, removePath, statPath });
    } catch {
      throw new Error("Console asset replacement recovery failed", { cause: error });
    }
    throw error;
  } finally {
    await removePath(stagingRoot, { recursive: true, force: true });
  }
  return { files: files.length, digest: manifest.buildDigest };
}

export async function verifyConsoleAssets({ source = DEFAULT_SOURCE, destination = DEFAULT_DESTINATION, manifestPath = DEFAULT_MANIFEST } = {}) {
  assertSafeTargets({ source, destination, manifestPath });
  const expected = (await describeAssetTree(source, { requireIndex: true })).manifest;
  const actualBytes = await readFile(manifestPath).catch(() => undefined);
  if (!actualBytes) throw new Error("Console asset manifest is missing");
  let recorded;
  try { recorded = JSON.parse(actualBytes); } catch { throw new Error("Console asset manifest is invalid"); }
  const actual = await describeAssetTree(destination).then((description) => description.manifest).catch(() => undefined);
  if (!actual || JSON.stringify(recorded) !== JSON.stringify(expected) || JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error("Console asset manifest does not match the built output");
  }
  return { files: Object.keys(expected.files).length, digest: expected.buildDigest };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const mode = process.argv[2];
    const result = mode === "--write" ? await writeConsoleAssets() : mode === "--check" ? await verifyConsoleAssets() : undefined;
    if (!result) throw new Error("usage: node tooling/console-assets.mjs --write|--check");
    process.stdout.write(`${JSON.stringify({ schemaVersion: 1, check: "console-assets", status: "pass", ...result })}\n`);
  } catch (error) {
    process.stderr.write(`Console asset operation failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
