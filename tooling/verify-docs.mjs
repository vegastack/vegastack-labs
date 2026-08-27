import { readFile, readdir, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const EXCLUDED_DIRECTORIES = new Set([".git", ".next", "node_modules", "out", "coverage"]);

async function walk(root, relative = "") {
  const entries = await readdir(path.join(root, relative), { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const child = path.join(relative, entry.name);
    if (entry.isDirectory() && !EXCLUDED_DIRECTORIES.has(entry.name)) {
      files.push(...(await walk(root, child)));
    } else if (entry.isFile()) {
      files.push(child);
    }
  }
  return files;
}

export function githubSlug(value) {
  return value
    .normalize("NFKD")
    .toLowerCase()
    .replace(/<[^>]+>/g, "")
    .replace(/!\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/\[([^\]]+)\]\([^)]*\)/g, "$1")
    .replace(/[`*_~]/g, "")
    .replace(/[^\p{Letter}\p{Number}\s_-]/gu, "")
    .trim()
    .replace(/\s/g, "-");
}

function markdownAnchors(text) {
  const anchors = new Set();
  const seen = new Map();
  let fenced = false;

  for (const line of text.split(/\r?\n/)) {
    if (/^\s*(```|~~~)/.test(line)) {
      fenced = !fenced;
      continue;
    }
    if (fenced) {
      continue;
    }

    const heading = line.match(/^#{1,6}\s+(.+?)\s*#*\s*$/);
    if (heading) {
      const base = githubSlug(heading[1]);
      const count = seen.get(base) ?? 0;
      anchors.add(count === 0 ? base : `${base}-${count}`);
      seen.set(base, count + 1);
    }

    for (const match of line.matchAll(/<(?:a|[^>]+)\s+(?:id|name)=["']([^"']+)["'][^>]*>/gi)) {
      anchors.add(match[1]);
    }
  }

  return anchors;
}

function markdownTargets(text) {
  const targets = [];
  for (const match of text.matchAll(/\[[^\]]*\]\((<[^>]+>|[^)\s]+)(?:\s+["'][^"']*["'])?\)/g)) {
    targets.push(match[1].replace(/^<|>$/g, ""));
  }
  for (const match of text.matchAll(/^\s*\[[^\]]+\]:\s*(<[^>]+>|\S+)/gm)) {
    targets.push(match[1].replace(/^<|>$/g, ""));
  }
  return targets;
}

export async function verifyDocumentation(root = ROOT) {
  const files = await walk(root);
  const markdownFiles = files.filter((file) => file.endsWith(".md"));
  const jsonFiles = files.filter((file) => file.endsWith(".json"));
  const anchorCache = new Map();

  for (const relative of jsonFiles) {
    try {
      JSON.parse(await readFile(path.join(root, relative), "utf8"));
    } catch (error) {
      throw new Error(`${relative} is not valid JSON: ${error.message}`);
    }
  }

  for (const relative of markdownFiles) {
    const sourcePath = path.join(root, relative);
    const text = await readFile(sourcePath, "utf8");
    for (const rawTarget of markdownTargets(text)) {
      if (/^(?:https?:|mailto:|data:)/i.test(rawTarget)) {
        continue;
      }

      const [rawFile, rawFragment] = rawTarget.split("#", 2);
      const targetPath = rawFile
        ? path.resolve(path.dirname(sourcePath), decodeURIComponent(rawFile))
        : sourcePath;

      let targetStat;
      try {
        targetStat = await stat(targetPath);
      } catch {
        throw new Error(`${relative} links to missing target ${rawTarget}`);
      }

      const resolvedPath = targetStat.isDirectory() ? path.join(targetPath, "README.md") : targetPath;
      try {
        await stat(resolvedPath);
      } catch {
        throw new Error(`${relative} links to directory without README.md: ${rawTarget}`);
      }

      if (!rawFragment || !resolvedPath.endsWith(".md")) {
        continue;
      }

      if (!anchorCache.has(resolvedPath)) {
        anchorCache.set(resolvedPath, markdownAnchors(await readFile(resolvedPath, "utf8")));
      }
      const fragment = decodeURIComponent(rawFragment).toLowerCase();
      if (!anchorCache.get(resolvedPath).has(fragment)) {
        throw new Error(`${relative} links to missing fragment ${rawTarget}`);
      }
    }
  }

  return { markdownFiles: markdownFiles.length, jsonFiles: jsonFiles.length };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const result = await verifyDocumentation();
    process.stdout.write(
      `${JSON.stringify({ schemaVersion: 1, check: "documentation", status: "pass", ...result })}\n`,
    );
  } catch (error) {
    process.stderr.write(`documentation verification failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
