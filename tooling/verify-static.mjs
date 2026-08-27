import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUTPUT = path.join(ROOT, "web/out");
const FORBIDDEN_NAMES = new Set([
  "middleware-manifest.json",
  "required-server-files.json",
  "server.js",
]);
const FORBIDDEN_BUILD_MARKERS = ["axe-core", "MPL-2.0", "Mozilla Public License"];

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

export async function verifyStaticExport(output = OUTPUT) {
  const index = await readFile(path.join(output, "index.html"), "utf8");
  if (!index.includes("Development scaffold") || !index.includes("does not expose")) {
    throw new Error("static index does not contain the truthful scaffold markers");
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
    const buffer = await readFile(file);
    if (!buffer.includes(0)) {
      const text = buffer.toString("utf8");
      if (/CF_ACCESS_CLIENT_(?:ID|SECRET)/.test(text)) {
        throw new Error(`static output contains a registry credential name: ${relative}`);
      }
      const marker = FORBIDDEN_BUILD_MARKERS.find((value) => text.includes(value));
      if (marker) {
        throw new Error(
          `static output contains development-only dependency marker ${marker}: ${relative}`,
        );
      }
    }
  }

  return { files: files.length };
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
