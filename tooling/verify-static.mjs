import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { verifyConsoleAssets } from "./console-assets.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUTPUT = path.join(ROOT, "web/out");
const FORBIDDEN_NAMES = new Set([
  "middleware-manifest.json",
  "required-server-files.json",
  "server.js",
  "server-artifact.json",
]);
const FORBIDDEN_BUILD_MARKERS = ["axe-core", "MPL-2.0", "Mozilla Public License"];
const EXPECTED_BUILD_ID = "vegastack-console-v1";

async function walk(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const child = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await walk(child)));
    } else if (entry.isFile()) {
      files.push(child);
    }
  }
  return files;
}

export async function verifyStaticExport(output = OUTPUT, embedded = output === OUTPUT ? {} : false, requireDeterministicBuildID = output === OUTPUT) {
  const index = await readFile(path.join(output, "index.html"), "utf8");
  if (!index.includes("Loading Overview")) {
    throw new Error("static index does not contain the truthful Console markers");
  }

  const files = await walk(output);
  for (const file of files) {
    const basename = path.basename(file);
    const relative = path.relative(output, file);
    if (/axe-core|lightningcss/i.test(relative)) {
      throw new Error(`static output contains a development-only package path: ${relative}`);
    }
    if (FORBIDDEN_NAMES.has(basename) || basename.endsWith(".node")) {
      throw new Error(`static output contains server runtime artifact ${relative}`);
    }
    if (relative.split(path.sep).includes("api")) {
      throw new Error(`static output contains an API artifact ${relative}`);
    }
    const buffer = await readFile(file);
    if (!buffer.includes(0)) {
      const text = buffer.toString("utf8");
      if (/CF[_-]ACCESS[_-]CLIENT[_-](?:ID|SECRET)|CF-Access-Client-(?:Id|Secret)|cfast_[A-Za-z0-9]+/i.test(text)) {
        throw new Error(`static output contains a registry credential name: ${relative}`);
      }
      if ([".html", ".css"].includes(path.extname(file)) && (/(?:src|href)=["']https?:\/\//i.test(text) || /url\(["']?https?:\/\//i.test(text))) {
        throw new Error(`static output contains an unexpected remote asset origin: ${relative}`);
      }
      const marker = FORBIDDEN_BUILD_MARKERS.find((value) => text.includes(value));
      if (marker) {
        throw new Error(
          `static output contains development-only dependency marker ${marker}: ${relative}`,
        );
      }
    }
  }
  if (requireDeterministicBuildID && !files.some((file) => path.relative(output, file).split(path.sep).includes(EXPECTED_BUILD_ID))) {
    throw new Error("static output does not use the deterministic Console build ID");
  }
  if (requireDeterministicBuildID) {
    const routeMarkers = new Map([
      ["nodes.html", "Loading Nodes"],
      ["gates.html", "Loading gate capability"],
    ]);
    for (const [route, marker] of routeMarkers) {
      const html = await readFile(path.join(output, route), "utf8");
      if (!html.includes(marker)) throw new Error(`static ${route} does not contain its truthful Console marker`);
    }
  }

  const embeddedResult = embedded === false ? undefined : await verifyConsoleAssets({ source: output, ...embedded });
  return { files: files.length, ...(embeddedResult ? { embeddedDigest: embeddedResult.digest } : {}) };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const result = await verifyStaticExport();
    process.stdout.write(
      `${JSON.stringify({ schemaVersion: 1, check: "static-export", status: "pass", ...result })}\n`,
    );
  } catch (error) {
    process.stderr.write(`static export verification failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
