import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runCommand } from "./lib/process.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const EXPECTED_EXECUTABLE = "cmd/vsk-labs";
const GENERATED_PACKAGE_SUFFIX = "/internal/generated";
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

function parseJSONStream(source) {
  const values = [];
  let start = -1;
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];
    if (start === -1) {
      if (/\s/.test(character)) continue;
      if (character !== "{") throw new Error("go list returned a non-JSON value");
      start = index;
      depth = 1;
      continue;
    }
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (character === "\\") {
        escaped = true;
      } else if (character === '"') {
        inString = false;
      }
      continue;
    }
    if (character === '"') {
      inString = true;
    } else if (character === "{") {
      depth += 1;
    } else if (character === "}") {
      depth -= 1;
      if (depth === 0) {
        values.push(JSON.parse(source.slice(start, index + 1)));
        start = -1;
      }
    }
  }
  if (start !== -1 || inString || depth !== 0) throw new Error("go list returned incomplete JSON");
  return values;
}

async function dependencyClosure(root, execute) {
  const result = await execute("go", ["list", "-deps", "-json", "./cmd/vsk-labs"], {
    cwd: root,
    capture: true,
    timeoutMs: 120_000,
  });
  const packages = parseJSONStream(result.stdout);
  return packages.filter((entry) => entry.Module?.Main === true);
}

function sourceFilesForPackage(entry) {
  return [...(entry.GoFiles ?? []), ...(entry.CgoFiles ?? [])].map((file) =>
    path.join(entry.Dir, file),
  );
}

// Remove comments and literal contents before looking for executable Go structure.
// Newlines and delimiters are retained so declarations cannot be joined accidentally.
function structuralSource(source) {
  let output = "";
  let state = "code";
  let escaped = false;
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];
    const next = source[index + 1];
    if (state === "line-comment") {
      if (character === "\n") {
        output += "\n";
        state = "code";
      } else {
        output += " ";
      }
      continue;
    }
    if (state === "block-comment") {
      if (character === "*" && next === "/") {
        output += "  ";
        index += 1;
        state = "code";
      } else {
        output += character === "\n" ? "\n" : " ";
      }
      continue;
    }
    if (state === "string" || state === "rune") {
      output += character === "\n" ? "\n" : " ";
      if (escaped) {
        escaped = false;
      } else if (character === "\\") {
        escaped = true;
      } else if ((state === "string" && character === '"') || (state === "rune" && character === "'")) {
        state = "code";
      }
      continue;
    }
    if (state === "raw-string") {
      output += character === "\n" ? "\n" : " ";
      if (character === "`") state = "code";
      continue;
    }
    if (character === "/" && next === "/") {
      output += "  ";
      index += 1;
      state = "line-comment";
    } else if (character === "/" && next === "*") {
      output += "  ";
      index += 1;
      state = "block-comment";
    } else if (character === '"') {
      output += " ";
      state = "string";
    } else if (character === "'") {
      output += " ";
      state = "rune";
    } else if (character === "`") {
      output += " ";
      state = "raw-string";
    } else {
      output += character;
    }
  }
  return output;
}

function declaresCommandRegistry(source) {
  const structural = structuralSource(source);
  const commandType = String.raw`(?:[A-Za-z_]\w*\.)?(?:Command|CommandDefinition)`;
  const collectionType = String.raw`(?:\[\]\s*${commandType}|map\s*\[[^\]]+\]\s*${commandType})`;
  const typedVariable = new RegExp(String.raw`\bvar\s+[A-Za-z_]\w*\s+${collectionType}(?:\s*=|\s*(?:\n|$))`);
  const collectionValue = new RegExp(
    String.raw`(?:\bvar\s+[A-Za-z_]\w*(?:\s+${collectionType})?\s*=\s*|:=\s*)(?:${collectionType}\s*\{|make\s*\(\s*${collectionType}\b)`,
  );
  return typedVariable.test(structural) || collectionValue.test(structural);
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

  let packages;
  try {
    packages = await dependencyClosure(root, execute);
  } catch {
    codes.add("CLI_GENERATED_OWNERSHIP");
    return codes;
  }
  const mainPackage = packages.find((entry) => entry.ImportPath?.endsWith(`/${EXPECTED_EXECUTABLE}`));
  const modulePath = mainPackage?.Module?.Path;
  const generatedImport = modulePath ? `${modulePath}${GENERATED_PACKAGE_SUFFIX}` : "";
  if (!mainPackage || !generatedImport || !packages.some((entry) => entry.ImportPath === generatedImport)) {
    codes.add("CLI_GENERATED_OWNERSHIP");
  }

  for (const entry of packages) {
    for (const file of sourceFilesForPackage(entry)) {
      const source = await readFile(file, "utf8");
      if (entry.ImportPath !== generatedImport && declaresCommandRegistry(source)) {
        codes.add("CLI_HANDWRITTEN_REGISTRY");
      }
      if ((entry.Imports ?? []).includes("database/sql")) {
        codes.add("CLI_SQLITE_ACCESS");
      }
      if (
        (entry.Imports ?? []).includes("os/exec") ||
        /\b(?:exec\.Command(?:Context)?|syscall\.Exec)\s*\(/.test(structuralSource(source))
      ) {
        codes.add("CLI_SHELL_DISPATCH");
      }
    }
  }
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
    runGoList = runCommand,
    runBuild = runCommand,
    createBuildDirectory = mkdtemp,
    removeBuildDirectory = rm,
  } = options;
  const codes = await inspectSources(root, runGoList);
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
