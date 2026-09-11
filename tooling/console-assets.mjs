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

function immutableAsset(name) {
  return name.startsWith("_next/static/") && /[0-9a-f]{8,}/i.test(path.basename(name));
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
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
    const absolute = path.join(directory, entry.name);
    if (entry.isSymbolicLink()) throw new Error(`Console assets must be regular files: ${relative}`);
    if (entry.isDirectory()) files.push(...await collect(absolute, relative));
    else if (entry.isFile()) files.push({ absolute, relative });
    else throw new Error(`Console assets must be regular files: ${relative}`);
  }
  return files;
}

async function describeSource(source) {
  const root = await stat(source).catch(() => undefined);
  if (!root?.isDirectory()) throw new Error("Console output directory is missing");
  const files = await collect(source);
  const described = {};
  for (const file of files) {
    const extension = path.extname(file.relative).toLowerCase();
    const contentType = CONTENT_TYPES.get(extension);
    if (!contentType) throw new Error(`unsupported Console asset: ${file.relative}`);
    const content = await readFile(file.absolute);
    described[file.relative] = {
      sha256: sha256(content),
      size: content.byteLength,
      contentType,
      immutable: immutableAsset(file.relative),
    };
  }
  if (!described["index.html"] || described["index.html"].size === 0) {
    throw new Error("Console output requires a non-empty index.html");
  }
  const buildDigest = sha256(JSON.stringify(described));
  return { files, manifest: { schemaVersion: 1, buildDigest, files: described } };
}

async function describeDestination(destination) {
  const files = await collect(destination);
  const described = {};
  for (const file of files) {
    const content = await readFile(file.absolute);
    const extension = path.extname(file.relative).toLowerCase();
    const contentType = CONTENT_TYPES.get(extension);
    if (!contentType) throw new Error(`unsupported Console asset: ${file.relative}`);
    described[file.relative] = {
      sha256: sha256(content),
      size: content.byteLength,
      contentType,
      immutable: immutableAsset(file.relative),
    };
  }
  return { schemaVersion: 1, buildDigest: sha256(JSON.stringify(described)), files: described };
}

export async function writeConsoleAssets({ source = DEFAULT_SOURCE, destination = DEFAULT_DESTINATION, manifestPath = DEFAULT_MANIFEST } = {}) {
  assertSafeTargets({ source, destination, manifestPath });
  const { files, manifest } = await describeSource(source);
  const parent = path.dirname(destination);
  await mkdir(parent, { recursive: true });
  const temporary = await mkdtemp(path.join(parent, ".console-dist-"));
  const temporaryManifest = `${manifestPath}.new`;
  try {
    for (const file of files) {
      const target = path.join(temporary, ...file.relative.split("/"));
      await mkdir(path.dirname(target), { recursive: true });
      await copyFile(file.absolute, target);
    }
    await writeFile(temporaryManifest, `${JSON.stringify(manifest, null, 2)}\n`, { flag: "wx" });
    await rm(destination, { recursive: true, force: true });
    await rename(temporary, destination);
    await rm(manifestPath, { force: true });
    await rename(temporaryManifest, manifestPath);
  } finally {
    await rm(temporary, { recursive: true, force: true });
    await rm(temporaryManifest, { force: true });
  }
  return { files: files.length, digest: manifest.buildDigest };
}

export async function verifyConsoleAssets({ source = DEFAULT_SOURCE, destination = DEFAULT_DESTINATION, manifestPath = DEFAULT_MANIFEST } = {}) {
  assertSafeTargets({ source, destination, manifestPath });
  const expected = (await describeSource(source)).manifest;
  const actualBytes = await readFile(manifestPath).catch(() => undefined);
  if (!actualBytes) throw new Error("Console asset manifest is missing");
  let recorded;
  try { recorded = JSON.parse(actualBytes); } catch { throw new Error("Console asset manifest is invalid"); }
  const actual = await describeDestination(destination).catch(() => undefined);
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
