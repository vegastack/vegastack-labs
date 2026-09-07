import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runCommand } from "./lib/process.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const EXPECTED_EXECUTABLE = "cmd/vsk-labs";
const ANALYZER_DIRECTORY = path.join(ROOT, "tooling/analyze-cli");
const TARGETS = [
  ["linux", "amd64"],
  ["linux", "arm64"],
  ["darwin", "amd64"],
  ["darwin", "arm64"],
  ["windows", "amd64"],
];
const CODE_ORDER = [
  "CLI_EXECUTABLE_COUNT",
  "CLI_GENERATED_OWNERSHIP",
  "CLI_HANDWRITTEN_REGISTRY",
  "CLI_SQLITE_ACCESS",
  "CLI_SHELL_DISPATCH",
  "CLI_CROSS_BUILD",
];

async function goFiles(root, relative) {
  const start = path.join(root, relative);
  const files = [];
  async function walk(directory) {
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch (error) {
      if (error.code === "ENOENT") return;
      throw error;
    }
    for (const entry of entries) {
      const fullPath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        await walk(fullPath);
      } else if (entry.isFile() && entry.name.endsWith(".go") && !entry.name.endsWith("_test.go")) {
        files.push(fullPath);
      }
    }
  }
  await walk(start);
  return files;
}

function relativeDirectory(root, file) {
  return path.relative(root, path.dirname(file)).split(path.sep).join("/");
}

async function inspectSources(root, execute) {
  const codes = new Set();
  const commandFiles = await goFiles(root, "cmd");
  const mainDirectories = new Set();
  for (const file of commandFiles) {
    const source = await readFile(file, "utf8");
    if (/^\s*package\s+main\s*$/m.test(source)) {
      mainDirectories.add(relativeDirectory(root, file));
    }
  }
  if (mainDirectories.size !== 1 || !mainDirectories.has(EXPECTED_EXECUTABLE)) {
    codes.add("CLI_EXECUTABLE_COUNT");
  }

  let analysis;
  try {
    const result = await execute("go", ["run", ANALYZER_DIRECTORY, "--root", root], {
      cwd: ROOT,
      capture: true,
      timeoutMs: 120_000,
    });
    analysis = JSON.parse(result.stdout);
  } catch {
    codes.add("CLI_GENERATED_OWNERSHIP");
    return codes;
  }
  if (!analysis.generatedCommandsReference) {
    codes.add("CLI_GENERATED_OWNERSHIP");
  }
  if (analysis.handwrittenRegistry) codes.add("CLI_HANDWRITTEN_REGISTRY");
  if (analysis.sqliteAccess) codes.add("CLI_SQLITE_ACCESS");
  if (analysis.shellDispatch) codes.add("CLI_SHELL_DISPATCH");
  return codes;
}

async function crossBuild(root, operations) {
  const { createDirectory, execute, removeDirectory } = operations;
  const outputDirectory = await createDirectory(path.join(tmpdir(), "vegastack-cli-build-"));
  const targetsBuilt = [];
  try {
    for (const [goos, goarch] of TARGETS) {
      const suffix = goos === "windows" ? ".exe" : "";
      const output = path.join(outputDirectory, `vsk-labs-${goos}-${goarch}${suffix}`);
      await execute("go", ["build", "-o", output, "./cmd/vsk-labs"], {
        cwd: root,
        env: { ...process.env, CGO_ENABLED: "0", GOOS: goos, GOARCH: goarch },
        timeoutMs: 120_000,
      });
      targetsBuilt.push(`${goos}/${goarch}`);
    }
    return targetsBuilt;
  } finally {
    await removeDirectory(outputDirectory, { recursive: true, force: true });
  }
}

export async function verifyCLI(root = ROOT, options = {}) {
  const {
    crossBuild: shouldCrossBuild = true,
    runAnalyzer = runCommand,
    runBuild = runCommand,
    createBuildDirectory = mkdtemp,
    removeBuildDirectory = rm,
  } = options;
  const codes = await inspectSources(root, runAnalyzer);
  let targetsBuilt = [];
  if (codes.size === 0 && shouldCrossBuild) {
    try {
      targetsBuilt = await crossBuild(root, {
        createDirectory: createBuildDirectory,
        execute: runBuild,
        removeDirectory: removeBuildDirectory,
      });
    } catch {
      codes.add("CLI_CROSS_BUILD");
    }
  }
  const orderedCodes = CODE_ORDER.filter((code) => codes.has(code));
  return {
    status: orderedCodes.length === 0 ? "pass" : "fail",
    codes: orderedCodes,
    targetsBuilt,
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const result = await verifyCLI();
    process.stdout.write(`${JSON.stringify({ schemaVersion: 1, check: "cli", ...result })}\n`);
    if (result.status !== "pass") process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`CLI verification failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
