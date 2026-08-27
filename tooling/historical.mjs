import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const MANIFEST_PATH = path.join(ROOT, "tooling/historical-artifacts.json");
const HISTORICAL_FILES = [
  "audit-reports/audit-completion.md",
  "audit-reports/gap-closure-report.md",
  "docs/audit-register.json",
];

async function digest(root, relative) {
  return createHash("sha256").update(await readFile(path.join(root, relative))).digest("hex");
}

export async function currentManifest(root = ROOT, historicalFiles = HISTORICAL_FILES) {
  const artifacts = [];
  for (const relative of historicalFiles) {
    artifacts.push({ path: relative, sha256: await digest(root, relative) });
  }
  return {
    schemaVersion: 1,
    authority: "node tooling/historical.mjs --write --approve-current",
    purpose: "Detect changes to preserved historical evidence without claiming current generation.",
    artifacts,
  };
}

function render(manifest) {
  return `${JSON.stringify(manifest, null, 2)}\n`;
}

export async function verifyHistorical(
  root = ROOT,
  manifestPath = MANIFEST_PATH,
  historicalFiles = HISTORICAL_FILES,
) {
  const expected = render(await currentManifest(root, historicalFiles));
  const actual = await readFile(manifestPath, "utf8");
  if (actual !== expected) {
    throw new Error("historical artifact manifest does not match the preserved files");
  }
  return { artifacts: historicalFiles.length };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const mode = process.argv[2] ?? "--check";
  try {
    if (mode === "--write") {
      if (!process.argv.includes("--approve-current")) {
        throw new Error("writing requires --approve-current after inspecting the historical files");
      }
      await writeFile(MANIFEST_PATH, render(await currentManifest()), "utf8");
      process.stdout.write(
        `${JSON.stringify({ schemaVersion: 1, check: "historical", status: "written", artifacts: HISTORICAL_FILES.length })}\n`,
      );
    } else if (mode === "--check") {
      const result = await verifyHistorical();
      process.stdout.write(
        `${JSON.stringify({ schemaVersion: 1, check: "historical", status: "pass", ...result })}\n`,
      );
    } else {
      throw new Error(`unknown mode ${mode}`);
    }
  } catch (error) {
    process.stderr.write(`historical verification failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
