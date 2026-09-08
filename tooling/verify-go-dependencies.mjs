import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runCommand } from "./lib/process.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const MANIFEST_NAME = "tooling/go-dependency-provenance.json";
const NOTICES_NAME = "THIRD_PARTY_NOTICES.md";
const GO_NOTICE_MARKER = "<!-- go-dependency-notices:start -->";
const AUTHORITY = "manual-review:go-dependency-provenance";
const SIGSTORE_MODULE = "github.com/sigstore/sigstore-go";
const SIGSTORE_VERSION = "v1.3.0";
const ALLOWED_LICENSES = new Set([
  "Apache-2.0",
  "Apache-2.0 AND BSD-3-Clause",
  "Apache-2.0 AND BSD-3-Clause AND MIT",
  "Apache-2.0 AND ISC AND MIT",
  "Apache-2.0 AND MIT",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "CC0-1.0",
  "ISC",
  "MIT",
  "MIT-0",
  "MPL-2.0",
]);
const ALLOWED_SOURCE_HOSTS = new Set([
  "bitbucket.org",
  "github.com",
  "go.googlesource.com",
  "gitlab.com",
  "gopkg.in",
  "software.sslmate.com",
]);

// Updated only after every module's exact version, checksum, source, license,
// role, decision, and reason have been reviewed. Resolution checks cannot
// approve changed metadata by themselves.
const REVIEWED_METADATA_SHA256 =
  "da7c2142f176425c64c2aeea1bad26ff2f47c3048a23364b6e11a7c1831d19b7";

export class GoDependencyError extends Error {
  constructor(code, target) {
    super(`${code}: ${target}`);
    this.name = "GoDependencyError";
    this.code = code;
    this.target = target;
  }
}

function fail(code, target) {
  throw new GoDependencyError(code, target);
}

function digest(value) {
  return createHash("sha256").update(value).digest("hex");
}

function reviewedMetadata(manifest) {
  return {
    reviewedOn: manifest.reviewedOn,
    modules: manifest.modules.map((record) => ({
      path: record.path,
      version: record.version,
      license: record.license,
      source: record.source,
      role: record.role,
      reviewDecision: record.reviewDecision,
      reviewReason: record.reviewReason,
    })),
  };
}

export function reviewMetadataDigest(manifest) {
  return digest(JSON.stringify(reviewedMetadata(manifest)));
}

function parseJSONStream(text) {
  const values = [];
  let cursor = 0;
  while (cursor < text.length) {
    while (/\s/.test(text[cursor] ?? "")) cursor += 1;
    if (cursor >= text.length) break;
    let depth = 0;
    let quoted = false;
    let escaped = false;
    const start = cursor;
    for (; cursor < text.length; cursor += 1) {
      const character = text[cursor];
      if (quoted) {
        if (escaped) escaped = false;
        else if (character === "\\") escaped = true;
        else if (character === '"') quoted = false;
        continue;
      }
      if (character === '"') quoted = true;
      else if (character === "{") depth += 1;
      else if (character === "}") {
        depth -= 1;
        if (depth === 0) {
          cursor += 1;
          values.push(JSON.parse(text.slice(start, cursor)));
          break;
        }
      }
    }
    if (depth !== 0 || quoted) fail("GO_MODULE_GRAPH", "go-list-json");
  }
  return values;
}

function checksumMap(goSum) {
  const checksums = new Map();
  for (const line of goSum.split("\n")) {
    if (!line) continue;
    const [modulePath, version, checksum, extra] = line.split(" ");
    if (!modulePath || !version || !checksum || extra !== undefined) {
      fail("GO_MODULE_CHECKSUM", "go.sum");
    }
    if (!version.endsWith("/go.mod")) checksums.set(`${modulePath}@${version}`, checksum);
  }
  return checksums;
}

function inferredSource(modulePath) {
  if (modulePath.startsWith("github.com/")) {
    return `https://${modulePath.split("/").slice(0, 3).join("/")}`;
  }
  switch (modulePath) {
    case "gopkg.in/check.v1":
      return "https://github.com/go-check/check";
    case "gopkg.in/tomb.v1":
      return "https://gopkg.in/tomb.v1";
    case "gopkg.in/yaml.v2":
    case "gopkg.in/yaml.v3":
      return "https://github.com/go-yaml/yaml";
    default:
      return "";
  }
}

async function downloadedModules(root, run, selected) {
  const requested = new Set(selected.map((record) => `${record.path}@${record.version}`));
  let output;
  try {
    output = await run(
      "go",
      [
        "mod",
        "download",
        "-json",
        ...selected.map((record) => `${record.path}@${record.version}`),
      ],
      {
        cwd: root,
        capture: true,
        timeoutMs: 120_000,
      },
    );
  } catch {
    fail("GO_SOURCE", "go-mod-download");
  }
  const downloaded = new Map();
  for (const record of parseJSONStream(output.stdout)) {
    const identity = `${record.Path}@${record.Version}`;
    if (!requested.has(identity)) continue;
    if (record.Error) fail("GO_SOURCE", identity);
    let source = record.Origin?.URL;
    if (!source && record.Info) {
      try {
        const info = JSON.parse(await readFile(record.Info, "utf8"));
        source = info.Origin?.URL;
      } catch {
        fail("GO_SOURCE", `${record.Path}@${record.Version}`);
      }
    }
    source ||= inferredSource(record.Path);
    if (!source) fail("GO_SOURCE", identity);
    if (!record.Sum) fail("GO_MODULE_CHECKSUM", identity);
    downloaded.set(identity, { checksum: record.Sum, source });
  }
  for (const identity of requested) {
    if (!downloaded.has(identity)) fail("GO_SOURCE", identity);
  }
  return downloaded;
}

function validateRecord(record, index) {
  const identity = `${record?.path ?? "module"}@${record?.version ?? index}`;
  const keys = [
    "checksum",
    "license",
    "path",
    "reviewDecision",
    "reviewReason",
    "role",
    "source",
    "version",
  ];
  if (
    !record ||
    typeof record !== "object" ||
    Array.isArray(record) ||
    JSON.stringify(Object.keys(record).sort()) !== JSON.stringify(keys)
  ) {
    fail("GO_MANIFEST_SCHEMA", identity);
  }
  for (const key of keys) {
    if (typeof record[key] !== "string" || !record[key]) fail("GO_MANIFEST_SCHEMA", identity);
  }
  if (!/^[A-Za-z0-9._~+/-]+$/.test(record.path)) fail("GO_MANIFEST_SCHEMA", identity);
  if (!/^v[^\s]+$/.test(record.version) || !/^h1:[A-Za-z0-9+/=]+$/.test(record.checksum)) {
    fail("GO_MANIFEST_SCHEMA", identity);
  }
  if (!ALLOWED_LICENSES.has(record.license)) fail("GO_LICENSE", identity);
  if (record.role !== "runtime" && record.role !== "build") fail("GO_ROLE", identity);
  if (record.license === "MPL-2.0" && record.role !== "build") fail("GO_LICENSE", identity);
  if (record.reviewDecision !== "approved") fail("GO_REVIEW_DECISION", identity);
  let source;
  try {
    source = new URL(record.source);
  } catch {
    fail("GO_SOURCE", identity);
  }
  if (
    source.protocol !== "https:" ||
    source.username ||
    source.password ||
    !ALLOWED_SOURCE_HOSTS.has(source.hostname)
  ) {
    fail("GO_SOURCE", identity);
  }
  return identity;
}

export function renderGoNotices(manifest) {
  const runtime = manifest.modules.filter((record) => record.role === "runtime");
  const lines = [
    GO_NOTICE_MARKER,
    "",
    "## Go runtime dependencies",
    "",
    "This section is reviewed from `tooling/go-dependency-provenance.json` by `node tooling/verify-go-dependencies.mjs --check`. Modules marked `build` in that inventory are selected by the test or transitive Go module graph and are not compiled into `vsk-labs` for the approved verifier import set.",
    "",
    "The compiled Apache-2.0 modules with upstream NOTICE files are `github.com/go-openapi/jsonpointer`, `github.com/go-openapi/jsonreference`, `github.com/go-openapi/runtime`, `github.com/theupdateframework/go-tuf/v2`, `go.yaml.in/yaml/v3`, and `google.golang.org/grpc`; their attribution is retained through the linked exact source release. MIT and BSD copyright/license notices remain with those exact sources.",
    "",
    "| Module | Version | License | Upstream |",
    "|---|---|---|---|",
  ];
  for (const record of runtime) {
    lines.push(
      `| \`${record.path}\` | \`${record.version}\` | \`${record.license}\` | [source](${record.source}) |`,
    );
  }
  lines.push("");
  return lines.join("\n");
}

function validateManifest(manifest, expectedReviewDigest) {
  const expectedKeys = [
    "authority",
    "modules",
    "reviewMetadataSha256",
    "reviewedOn",
    "schemaVersion",
  ];
  if (
    !manifest ||
    typeof manifest !== "object" ||
    Array.isArray(manifest) ||
    JSON.stringify(Object.keys(manifest).sort()) !== JSON.stringify(expectedKeys) ||
    manifest.schemaVersion !== 1 ||
    manifest.authority !== AUTHORITY ||
    !/^\d{2}-\d{2}-\d{4}$/.test(manifest.reviewedOn) ||
    !Array.isArray(manifest.modules)
  ) {
    fail("GO_MANIFEST_SCHEMA", "manifest");
  }
  const actualDigest = reviewMetadataDigest(manifest);
  if (
    manifest.reviewMetadataSha256 !== actualDigest ||
    expectedReviewDigest !== actualDigest
  ) {
    fail("GO_REVIEW_SEAL", "review-metadata");
  }
  const identities = new Set();
  let prior;
  for (const [index, record] of manifest.modules.entries()) {
    const identity = validateRecord(record, index);
    if (identities.has(identity)) fail("GO_MODULE_DUPLICATE", identity);
    if (
      prior &&
      (prior.path.localeCompare(record.path) > 0 ||
        (prior.path === record.path && prior.version.localeCompare(record.version) >= 0))
    ) {
      fail("GO_MODULE_ORDER", identity);
    }
    identities.add(identity);
    prior = record;
  }
  return actualDigest;
}

async function selectedModules(root, run) {
  let output;
  try {
    output = await run("go", ["list", "-m", "-json", "all"], {
      cwd: root,
      capture: true,
      timeoutMs: 120_000,
    });
  } catch {
    fail("GO_MODULE_GRAPH", "go-list");
  }
  return parseJSONStream(output.stdout)
    .filter((record) => !record.Main)
    .map((record) => {
      if (!record.Path || !record.Version || record.Replace) fail("GO_MODULE_GRAPH", "replacement");
      return { path: record.Path, version: record.Version, checksum: record.Sum };
    })
    .sort((left, right) =>
      left.path.localeCompare(right.path) || left.version.localeCompare(right.version),
    );
}

async function dependencyModules(root, run, args, target) {
  let output;
  try {
    output = await run("go", args, {
      cwd: root,
      capture: true,
      timeoutMs: 120_000,
    });
  } catch {
    fail("GO_MODULE_GRAPH", target);
  }
  const modules = new Set();
  for (const record of parseJSONStream(output.stdout)) {
    if (record.Module?.Main || !record.Module) continue;
    if (!record.Module.Path || !record.Module.Version || record.Module.Replace) {
      fail("GO_MODULE_GRAPH", target);
    }
    modules.add(`${record.Module.Path}@${record.Module.Version}`);
  }
  return modules;
}

export async function verifyGoDependencies(root = ROOT, options = {}) {
  const run = options.run ?? runCommand;
  const checkOrigins = options.checkOrigins ?? true;
  const expectedReviewDigest = options.expectedReviewDigest ?? REVIEWED_METADATA_SHA256;
  let manifest;
  let goSum;
  let notices;
  let goMod;
  try {
    [manifest, goSum, notices, goMod] = await Promise.all([
      readFile(path.join(root, MANIFEST_NAME), "utf8").then(JSON.parse),
      readFile(path.join(root, "go.sum"), "utf8"),
      readFile(path.join(root, NOTICES_NAME), "utf8"),
      readFile(path.join(root, "go.mod"), "utf8"),
    ]);
  } catch {
    fail("GO_MANIFEST_SCHEMA", "files");
  }
  const reviewDigest = validateManifest(manifest, expectedReviewDigest);

  try {
    await run("go", ["mod", "verify"], { cwd: root, capture: true, timeoutMs: 120_000 });
  } catch {
    fail("GO_MODULE_VERIFY", "module-cache");
  }

  const selected = await selectedModules(root, run);
  const [runtime, tests] = await Promise.all([
    dependencyModules(
      root,
      run,
      ["list", "-deps", "-json", "./cmd/vsk-labs", "./internal/store"],
      "runtime-dependencies",
    ),
    dependencyModules(
      root,
      run,
      ["list", "-deps", "-test", "-json", "./..."],
      "test-dependencies",
    ),
  ]);
  const downloaded = checkOrigins ? await downloadedModules(root, run, selected) : new Map();
  const checksums = checksumMap(goSum);
  const reviewed = new Map(manifest.modules.map((record) => [`${record.path}@${record.version}`, record]));
  const selectedIdentities = new Set(selected.map((module) => `${module.path}@${module.version}`));
  for (const identity of [...runtime, ...tests]) {
    if (!selectedIdentities.has(identity)) fail("GO_MODULE_GRAPH", identity);
  }
  if (reviewed.size !== selected.length) fail("GO_MODULE_GRAPH", "module-count");
  for (const module of selected) {
    const identity = `${module.path}@${module.version}`;
    const record = reviewed.get(identity);
    if (!record) fail("GO_MODULE_GRAPH", identity);
    const checksum = module.checksum || checksums.get(identity) || downloaded.get(identity)?.checksum;
    if (
      !checksum ||
      record.checksum !== checksum ||
      (checksums.has(identity) && checksums.get(identity) !== checksum) ||
      (checkOrigins && downloaded.get(identity)?.checksum !== checksum)
    ) {
      fail("GO_MODULE_CHECKSUM", identity);
    }
    if (checkOrigins && downloaded.get(identity)?.source !== record.source) {
      fail("GO_SOURCE", identity);
    }
    const expectedRole = runtime.has(identity) ? "runtime" : "build";
    if (record.role !== expectedRole) fail("GO_ROLE", identity);
  }
  if (!reviewed.has(`${SIGSTORE_MODULE}@${SIGSTORE_VERSION}`)) {
    fail("GO_SIGSTORE_PIN", SIGSTORE_MODULE);
  }
  for (const identity of reviewed.keys()) {
    if (!selectedIdentities.has(identity)) {
      fail("GO_MODULE_GRAPH", identity);
    }
  }
  const marker = notices.indexOf(GO_NOTICE_MARKER);
  if (marker < 0 || notices.slice(marker) !== renderGoNotices(manifest)) {
    fail("GO_NOTICES", "THIRD_PARTY_NOTICES.md");
  }
  const [finalGoMod, finalGoSum] = await Promise.all([
    readFile(path.join(root, "go.mod"), "utf8"),
    readFile(path.join(root, "go.sum"), "utf8"),
  ]);
  if (finalGoMod !== goMod || finalGoSum !== goSum) fail("GO_REPOSITORY_WRITE", "module-files");

  return { status: "pass", modules: selected.length, reviewDigest };
}

async function propose(root = ROOT) {
  const goSum = await readFile(path.join(root, "go.sum"), "utf8");
  const checksums = checksumMap(goSum);
  const selected = await selectedModules(root, runCommand);
  return selected.map((record) => ({
    path: record.path,
    version: record.version,
    checksum: record.checksum || checksums.get(`${record.path}@${record.version}`) || "missing",
    reviewDecision: "pending",
  }));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const mode = process.argv[2] ?? "--check";
  try {
    if (mode === "--check") {
      const result = await verifyGoDependencies();
      process.stdout.write(
        `${JSON.stringify({ schemaVersion: 1, check: "go-dependencies", ...result })}\n`,
      );
    } else if (mode === "--propose") {
      process.stdout.write(`${JSON.stringify({ schemaVersion: 1, modules: await propose() }, null, 2)}\n`);
    } else {
      fail("GO_MODE", "argument");
    }
  } catch (error) {
    const code = error?.code ?? "GO_DEPENDENCY_CHECK";
    const target = error?.target ?? "verification";
    process.stderr.write(`Go dependency verification failed: ${code}: ${target}\n`);
    process.exitCode = 1;
  }
}
