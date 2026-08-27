import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import parseSpdx from "spdx-expression-parse";
import { parse as parseYaml } from "yaml";
import { packageManagerInvocation, runCommand } from "./lib/process.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const LOCK_PATH = path.join(ROOT, "pnpm-lock.yaml");
const MANIFEST_PATH = path.join(ROOT, "tooling/dependency-provenance.json");
const NOTICES_PATH = path.join(ROOT, "THIRD_PARTY_NOTICES.md");
const PUBLIC_REGISTRY = "https://registry.npmjs.org";
const REVIEWED_LICENSES = new Set([
  "0BSD",
  "Apache-2.0",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "BlueOak-1.0.0",
  "CC-BY-3.0",
  "CC-BY-4.0",
  "CC0-1.0",
  "ISC",
  "MIT",
  "Python-2.0",
]);

function digest(buffer) {
  return createHash("sha256").update(buffer).digest("hex");
}

function splitLockKey(lockKey) {
  const withoutPeers = lockKey.replace(/\(.*/, "");
  const separator = withoutPeers.lastIndexOf("@");
  if (separator <= 0 || separator === withoutPeers.length - 1) {
    throw new Error(`unsupported lockfile package key ${lockKey}`);
  }
  return {
    name: withoutPeers.slice(0, separator),
    version: withoutPeers.slice(separator + 1),
  };
}

function sourceForResolution(resolution, lockKey) {
  if (!resolution?.integrity) {
    throw new Error(`${lockKey} has no registry integrity`);
  }
  if (!resolution.tarball) {
    return PUBLIC_REGISTRY;
  }

  const url = new URL(resolution.tarball);
  if (url.origin !== PUBLIC_REGISTRY) {
    throw new Error(`${lockKey} uses unexpected dependency origin ${url.origin}`);
  }
  if (url.username || url.password) {
    throw new Error(`${lockKey} embeds dependency credentials`);
  }
  return url.origin;
}

export function inspectLockPackages(lock) {
  if (!lock?.packages || typeof lock.packages !== "object") {
    throw new Error("pnpm lockfile has no packages map");
  }

  const byPackage = new Map();
  for (const [lockKey, metadata] of Object.entries(lock.packages)) {
    const { name, version } = splitLockKey(lockKey);
    const source = sourceForResolution(metadata.resolution, lockKey);
    const identity = `${name}@${version}`;
    const existing = byPackage.get(identity);

    if (existing && existing.integrity !== metadata.resolution.integrity) {
      throw new Error(`${identity} resolves to more than one integrity value`);
    }

    const record = existing ?? {
      name,
      version,
      source,
      integrity: metadata.resolution.integrity,
      lockKeys: [],
    };
    record.lockKeys.push(lockKey);
    byPackage.set(identity, record);
  }

  return [...byPackage.values()].sort(
    (left, right) => left.name.localeCompare(right.name) || left.version.localeCompare(right.version),
  );
}

function isApprovedMpl(record) {
  return (
    record.license === "MPL-2.0" &&
    ((record.name === "axe-core" && record.version === "4.13.0") ||
      (record.version === "1.32.0" &&
        (record.name === "lightningcss" || record.name.startsWith("lightningcss-"))))
  );
}

export function validateLicenseDecision(record) {
  try {
    parseSpdx(record.license);
  } catch {
    throw new Error(`${record.name}@${record.version} has invalid SPDX license ${record.license}`);
  }

  if (record.license === "MPL-2.0") {
    if (!isApprovedMpl(record) || record.role !== "build") {
      throw new Error(`${record.name}@${record.version} is outside the approved MPL development set`);
    }
    return "Approved exact development-only MPL dependency; retain notices and exclude from output.";
  }

  if (!REVIEWED_LICENSES.has(record.license)) {
    throw new Error(
      `${record.name}@${record.version} has unreviewed license ${record.license}`,
    );
  }

  if (record.license.startsWith("CC-BY-")) {
    return "Reviewed attribution license for exact locked data/package; retain notice and source link.";
  }
  return "Reviewed permissive license for this exact locked package.";
}

async function licenseInventory(prod = false) {
  const args = ["licenses", "list"];
  if (prod) {
    args.push("--prod");
  }
  args.push("--json");
  const invocation = packageManagerInvocation(args);
  const result = await runCommand(invocation.command, invocation.args, {
    cwd: ROOT,
    capture: true,
  });
  return JSON.parse(result.stdout);
}

function flattenLicenses(inventory) {
  const packages = new Map();
  for (const [groupLicense, records] of Object.entries(inventory)) {
    for (const record of records) {
      for (const version of record.versions) {
        const identity = `${record.name}@${version}`;
        packages.set(identity, {
          name: record.name,
          version,
          license: record.license || groupLicense,
          homepage:
            typeof record.homepage === "string" && record.homepage
              ? record.homepage
              : `https://www.npmjs.com/package/${encodeURIComponent(record.name)}/v/${version}`,
        });
      }
    }
  }
  return packages;
}

function roleFor(name, identity, production) {
  if (production.has(identity) || name.startsWith("@next/swc-")) {
    return "runtime";
  }
  return "build";
}

async function registryMetadata(name, version) {
  const packagePath = name.startsWith("@") ? name.replace("/", "%2F") : name;
  const url = `${PUBLIC_REGISTRY}/${packagePath}/${version}`;
  let lastError;

  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(15_000) });
      if (!response.ok) {
        throw new Error(`registry returned ${response.status}`);
      }
      const metadata = await response.json();
      const license =
        typeof metadata.license === "string" ? metadata.license : metadata.license?.type;
      if (!license) {
        throw new Error("registry metadata has no license");
      }
      return {
        name,
        version,
        license,
        homepage:
          typeof metadata.homepage === "string" && metadata.homepage
            ? metadata.homepage
            : `https://www.npmjs.com/package/${encodeURIComponent(name)}/v/${version}`,
      };
    } catch (error) {
      lastError = error;
    }
  }
  throw new Error(`unable to read public registry metadata for ${name}@${version}: ${lastError.message}`);
}

async function mapWithConcurrency(values, limit, mapper) {
  const output = new Array(values.length);
  let cursor = 0;

  async function worker() {
    while (cursor < values.length) {
      const index = cursor;
      cursor += 1;
      output[index] = await mapper(values[index]);
    }
  }

  await Promise.all(Array.from({ length: Math.min(limit, values.length) }, () => worker()));
  return output;
}

function reviewedDate() {
  const parts = new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    timeZone: "Asia/Kolkata",
  }).formatToParts(new Date());
  const values = Object.fromEntries(parts.map((part) => [part.type, part.value]));
  return `${values.day}-${values.month}-${values.year}`;
}

async function buildManifest() {
  const lockBytes = await readFile(LOCK_PATH);
  const lock = parseYaml(lockBytes.toString("utf8"));
  const locked = inspectLockPackages(lock);
  const [allInventory, productionInventory] = await Promise.all([
    licenseInventory(false),
    licenseInventory(true),
  ]);
  const installed = flattenLicenses(allInventory);
  const production = flattenLicenses(productionInventory);
  const missing = locked.filter((record) => !installed.has(`${record.name}@${record.version}`));
  const fetched = await mapWithConcurrency(missing, 8, (record) =>
    registryMetadata(record.name, record.version),
  );
  for (const record of fetched) {
    installed.set(`${record.name}@${record.version}`, record);
  }

  const packages = locked.map((record) => {
    const identity = `${record.name}@${record.version}`;
    const licenseRecord = installed.get(identity);
    if (!licenseRecord) {
      throw new Error(`${identity} has no license metadata`);
    }
    const resolved = {
      ...record,
      license: licenseRecord.license,
      homepage: licenseRecord.homepage,
      role: roleFor(record.name, identity, production),
      reviewDecision: "approved",
    };
    resolved.reviewReason = validateLicenseDecision(resolved);
    return resolved;
  });

  return {
    schemaVersion: 1,
    authority: "node tooling/provenance.mjs --write --approve-current-lock",
    reviewedOn: reviewedDate(),
    lockfileSha256: digest(lockBytes),
    registry: PUBLIC_REGISTRY,
    packages,
  };
}

function renderManifest(manifest) {
  return `${JSON.stringify(manifest, null, 2)}\n`;
}

function renderNotices(manifest) {
  const lines = [
    "# Third-party notices",
    "",
    "This file is generated from `tooling/dependency-provenance.json` by `node tooling/provenance.mjs --write --approve-current-lock`. The VegaStack Labs source remains MIT-licensed; third-party packages retain their own licenses.",
    "",
    "The exact development-only MPL-2.0 dependencies listed below are unmodified and are not shipped in `web/out`. MPL source and obligations are available from the linked upstream project and the [Mozilla Public License 2.0](https://www.mozilla.org/MPL/2.0/). Attribution datasets retain their source links.",
    "",
    "| Package | Version | License | Role | Upstream |",
    "|---|---|---|---|---|",
  ];

  for (const record of manifest.packages) {
    const upstream = record.homepage || `https://www.npmjs.com/package/${record.name}/v/${record.version}`;
    lines.push(
      `| \`${record.name}\` | \`${record.version}\` | \`${record.license}\` | ${record.role} | [source](${upstream}) |`,
    );
  }
  lines.push("");
  return lines.join("\n");
}

export async function verifyProvenance() {
  const [lockBytes, manifestText, notices] = await Promise.all([
    readFile(LOCK_PATH),
    readFile(MANIFEST_PATH, "utf8"),
    readFile(NOTICES_PATH, "utf8"),
  ]);
  const lock = parseYaml(lockBytes.toString("utf8"));
  const locked = inspectLockPackages(lock);
  const manifest = JSON.parse(manifestText);

  if (manifest.schemaVersion !== 1 || manifest.registry !== PUBLIC_REGISTRY) {
    throw new Error("dependency provenance schema or registry is invalid");
  }
  if (manifest.lockfileSha256 !== digest(lockBytes)) {
    throw new Error("dependency provenance is stale for pnpm-lock.yaml");
  }

  const manifestPackages = new Map();
  for (const record of manifest.packages) {
    if (record.reviewDecision !== "approved") {
      throw new Error(`${record.name}@${record.version} lacks an approved review decision`);
    }
    const reason = validateLicenseDecision(record);
    if (record.reviewReason !== reason) {
      throw new Error(`${record.name}@${record.version} has a stale review reason`);
    }
    manifestPackages.set(`${record.name}@${record.version}`, record);
  }

  for (const record of locked) {
    const reviewed = manifestPackages.get(`${record.name}@${record.version}`);
    if (!reviewed) {
      throw new Error(`${record.name}@${record.version} is absent from dependency provenance`);
    }
    if (
      reviewed.integrity !== record.integrity ||
      reviewed.source !== record.source ||
      JSON.stringify(reviewed.lockKeys) !== JSON.stringify(record.lockKeys)
    ) {
      throw new Error(`${record.name}@${record.version} does not match the lockfile resolution`);
    }
  }
  if (manifestPackages.size !== locked.length) {
    throw new Error("dependency provenance contains packages absent from the lockfile");
  }

  const [allInventory, productionInventory] = await Promise.all([
    licenseInventory(false),
    licenseInventory(true),
  ]);
  const installed = flattenLicenses(allInventory);
  const production = flattenLicenses(productionInventory);
  for (const [identity, record] of installed) {
    const reviewed = manifestPackages.get(identity);
    if (!reviewed || reviewed.license !== record.license) {
      throw new Error(`${identity} installed license does not match reviewed provenance`);
    }
    const expectedRole = roleFor(record.name, identity, production);
    if (reviewed.role !== expectedRole) {
      throw new Error(`${identity} installed role does not match reviewed provenance`);
    }
  }

  if (notices !== renderNotices(manifest)) {
    throw new Error("THIRD_PARTY_NOTICES.md is stale");
  }

  return { packages: locked.length, installedPackages: installed.size };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const mode = process.argv[2] ?? "--check";
  try {
    if (mode === "--write") {
      if (!process.argv.includes("--approve-current-lock")) {
        throw new Error("writing requires --approve-current-lock after dependency and license review");
      }
      const manifest = await buildManifest();
      await Promise.all([
        writeFile(MANIFEST_PATH, renderManifest(manifest), "utf8"),
        writeFile(NOTICES_PATH, renderNotices(manifest), "utf8"),
      ]);
      process.stdout.write(
        `${JSON.stringify({ schemaVersion: 1, check: "provenance", status: "written", packages: manifest.packages.length })}\n`,
      );
    } else if (mode === "--check") {
      const result = await verifyProvenance();
      process.stdout.write(
        `${JSON.stringify({ schemaVersion: 1, check: "provenance", status: "pass", ...result })}\n`,
      );
    } else {
      throw new Error(`unknown mode ${mode}`);
    }
  } catch (error) {
    process.stderr.write(`dependency provenance failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
