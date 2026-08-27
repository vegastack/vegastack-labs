import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runCommand } from "./lib/process.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const EXPECTED_NODE = "24.20.0";
const EXPECTED_PNPM = "11.24.0";

export function assertExactDependencySpec(name, specifier) {
  if (typeof specifier !== "string" || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(specifier)) {
    throw new Error(`${name} must use an exact semantic version, found ${JSON.stringify(specifier)}`);
  }
}

export function findSecretMarkers(text) {
  const markers = [];

  if (/-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----/.test(text)) {
    markers.push("private-key material");
  }
  if (/\b(?:gh[pousr]_|npm_)[A-Za-z0-9]{20,}\b/.test(text)) {
    markers.push("token-shaped value");
  }
  if (/^[\t ]*CF_ACCESS_CLIENT_SECRET[\t ]*=[\t ]*(?!#|$)\S+/m.test(text)) {
    markers.push("Cloudflare Access secret value");
  }
  for (const match of text.matchAll(
    /(?:^|[,{])[\t ]*["']?CF-Access-Client-Secret["']?[\t ]*:[\t ]*(?:"([^"]*)"|'([^']*)'|([^\s,}]+))/gim,
  )) {
    const value = match[1] ?? match[2] ?? match[3] ?? "";
    if (value && value !== "${CF_ACCESS_CLIENT_SECRET}") {
      if (!markers.includes("Cloudflare Access secret value")) {
        markers.push("Cloudflare Access secret value");
      }
      break;
    }
  }

  return markers;
}

export function isSecretEnvironmentFile(relative) {
  const basename = path.basename(relative);
  return (
    /^\.env(?:\..+)?$/.test(basename) && !/^\.env(?:\..+)?\.example$/.test(basename)
  );
}

export async function listTrackedFiles(root = ROOT) {
  const result = await runCommand("git", ["ls-files", "-z"], {
    capture: true,
    cwd: root,
    timeoutMs: 30_000,
  });
  return result.stdout.split("\0").filter(Boolean);
}

async function loadJson(file) {
  return JSON.parse(await readFile(file, "utf8"));
}

function verifyPackage(packageJson, label) {
  if (packageJson.private !== true) {
    throw new Error(`${label} must remain private`);
  }
  if (packageJson.engines?.node !== EXPECTED_NODE) {
    throw new Error(`${label} must pin Node ${EXPECTED_NODE}`);
  }
  if (packageJson.engines?.pnpm !== EXPECTED_PNPM) {
    throw new Error(`${label} must pin pnpm ${EXPECTED_PNPM}`);
  }

  for (const section of ["dependencies", "devDependencies", "optionalDependencies"]) {
    for (const [name, specifier] of Object.entries(packageJson[section] ?? {})) {
      assertExactDependencySpec(`${label} ${section}.${name}`, specifier);
    }
  }
}

export async function verifyRepository(root = ROOT, runtimeVersion = process.versions.node) {
  if (runtimeVersion !== EXPECTED_NODE) {
    throw new Error(`Node ${EXPECTED_NODE} is required, found ${runtimeVersion}`);
  }

  const [rootPackage, webPackage, nodeVersion, goModule, components] = await Promise.all([
    loadJson(path.join(root, "package.json")),
    loadJson(path.join(root, "web/package.json")),
    readFile(path.join(root, ".node-version"), "utf8"),
    readFile(path.join(root, "go.mod"), "utf8"),
    loadJson(path.join(root, "web/components.json")),
  ]);

  verifyPackage(rootPackage, "root package");
  verifyPackage(webPackage, "web package");

  if (rootPackage.packageManager !== `pnpm@${EXPECTED_PNPM}`) {
    throw new Error(`root packageManager must be pnpm@${EXPECTED_PNPM}`);
  }
  if (nodeVersion.trim() !== EXPECTED_NODE) {
    throw new Error(`.node-version must contain ${EXPECTED_NODE}`);
  }
  if (!/^go 1\.27\.0$/m.test(goModule)) {
    throw new Error("go.mod must pin Go 1.27.0");
  }

  const headers = components.registries?.["@vegastack"]?.headers;
  if (headers?.["CF-Access-Client-Id"] !== "${CF_ACCESS_CLIENT_ID}") {
    throw new Error("components.json must use the client ID environment placeholder");
  }
  if (headers?.["CF-Access-Client-Secret"] !== "${CF_ACCESS_CLIENT_SECRET}") {
    throw new Error("components.json must use the client secret environment placeholder");
  }

  const files = await listTrackedFiles(root);
  for (const relative of files) {
    const basename = path.basename(relative);
    if (isSecretEnvironmentFile(relative)) {
      throw new Error(`secret-bearing environment file must not be tracked: ${relative}`);
    }

    const fullPath = path.join(root, relative);
    const buffer = await readFile(fullPath);
    if (buffer.includes(0)) {
      continue;
    }
    const text = buffer.toString("utf8");
    const markers = findSecretMarkers(text);
    if (markers.length > 0) {
      throw new Error(`${relative} contains prohibited ${markers.join(" and ")}`);
    }

    if (basename === ".npmrc" && /(?:_authToken|:\s*_auth)\s*=/.test(text)) {
      throw new Error(`${relative} contains package-manager authentication`);
    }
  }

  for (const relative of ["package.json", "web/package.json", "pnpm-lock.yaml"]) {
    const text = await readFile(path.join(root, relative), "utf8");
    for (const match of text.matchAll(/https?:\/\/[^\s'"}]+/g)) {
      const url = new URL(match[0]);
      if (url.hostname !== "registry.npmjs.org") {
        throw new Error(`${relative} contains unexpected dependency origin ${url.origin}`);
      }
    }
  }

  return { filesChecked: files.length };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const result = await verifyRepository();
    process.stdout.write(
      `${JSON.stringify({ schemaVersion: 1, check: "repository", status: "pass", ...result })}\n`,
    );
  } catch (error) {
    process.stderr.write(`repository verification failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
