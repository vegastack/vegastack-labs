import { inflateRawSync } from "node:zlib";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";

const visualAssetExtensions = new Set([".avif", ".css", ".gif", ".ico", ".jpeg", ".jpg", ".png", ".svg", ".webp"]);
const maximumTraceEntries = 20_000;
const maximumTraceEntryBytes = 64 * 1024 * 1024;
const maximumTraceBytes = 512 * 1024 * 1024;

export function assertPrivacyEvidence(value, needles, surface) {
  const text = Buffer.isBuffer(value) ? value.toString("utf8") : typeof value === "string" ? value : JSON.stringify(value);
  for (const needle of needles) {
    if (text.includes(needle)) throw new Error(`${needle} reached ${surface}`);
  }
}

function assertCredentialHeadersAbsent(value, forbiddenHeaders, surface) {
  const forbidden = new Set(forbiddenHeaders.map(name => name.toLowerCase()));
  if (forbidden.size === 0) return;
  const visit = candidate => {
    if (Array.isArray(candidate)) {
      for (const item of candidate) visit(item);
      return;
    }
    if (!candidate || typeof candidate !== "object") return;
    if (typeof candidate.name === "string" && forbidden.has(candidate.name.toLowerCase())) throw new Error(`credential header reached ${surface}`);
    for (const [name, item] of Object.entries(candidate)) {
      if (forbidden.has(name.toLowerCase())) throw new Error(`credential header reached ${surface}`);
      visit(item);
    }
  };
  for (const line of value.toString("utf8").split("\n")) {
    if (!line.trim().startsWith("{")) continue;
    try { visit(JSON.parse(line)); } catch (error) {
      if (error instanceof SyntaxError) continue;
      throw error;
    }
  }
}

export async function installCanvasTextCapture(context) {
  await context.addInitScript(() => {
    const evidence = [];
    Object.defineProperty(globalThis, "__vskCanvasTextEvidence", { value: evidence, configurable: false, writable: false });
    for (const constructorName of ["CanvasRenderingContext2D", "OffscreenCanvasRenderingContext2D"]) {
      const prototype = globalThis[constructorName]?.prototype;
      if (!prototype) continue;
      for (const methodName of ["fillText", "strokeText"]) {
        const original = prototype[methodName];
        if (typeof original !== "function") continue;
        Object.defineProperty(prototype, methodName, {
          configurable: true,
          writable: true,
          value(text, ...args) {
            evidence.push(String(text));
            return Reflect.apply(original, this, [text, ...args]);
          },
        });
      }
    }
  });
}

export async function captureVisibleBrowserEvidence(page, consoleMessages) {
  const runtime = await page.evaluate(async () => {
    const elements = [...document.querySelectorAll("*")];
    const attributes = ["alt", "aria-description", "aria-label", "aria-placeholder", "aria-valuetext", "placeholder", "title", "value"];
    const attributeEvidence = elements.flatMap(element => attributes.flatMap(name => {
      const value = element.getAttribute(name);
      return value === null ? [] : [`${name}=${value}`];
    }));
    const controlValues = elements.flatMap(element => element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement || element instanceof HTMLSelectElement ? [element.value] : []);
    const pseudoContent = elements.flatMap(element => ["::before", "::after"].flatMap(pseudo => {
      const content = getComputedStyle(element, pseudo).content;
      return content && content !== "none" && content !== "normal" ? [`${pseudo}=${content}`] : [];
    }));
    const svg = [...document.querySelectorAll("svg")].map(element => ({
      text: element.textContent,
      attributes: [...element.querySelectorAll("*")].flatMap(child => [...child.attributes].map(attribute => `${attribute.name}=${attribute.value}`)),
    }));
    return {
      text: document.body.innerText,
      attributeEvidence,
      controlValues,
      pseudoContent,
      svg,
      canvasText: globalThis.__vskCanvasTextEvidence ?? [],
      url: location.href,
      history: history.state,
      localStorage: { ...localStorage },
      sessionStorage: { ...sessionStorage },
      indexedDB: typeof indexedDB.databases === "function" ? (await indexedDB.databases()).map(database => database.name) : [],
      caches: typeof caches === "undefined" ? [] : await caches.keys(),
    };
  });
  return { ...runtime, accessibilityTree: await page.locator("html").ariaSnapshot(), consoleMessages };
}

async function walk(directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const target = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await walk(target));
    else if (entry.isFile()) files.push(target);
  }
  return files;
}

export async function assertShippedVisualAssetsSafe(directory, needles) {
  const files = (await walk(directory)).filter(file => visualAssetExtensions.has(path.extname(file).toLowerCase()));
  if (files.length === 0) throw new Error("no shipped visual assets were available for privacy inspection");
  for (const file of files) assertPrivacyEvidence(await readFile(file), needles, `shipped visual asset ${path.relative(directory, file)}`);
  return files.length;
}

function traceEntries(archive) {
  let end = -1;
  for (let offset = archive.length - 22; offset >= Math.max(0, archive.length - 65_557); offset -= 1) {
    if (archive.readUInt32LE(offset) === 0x06054b50) { end = offset; break; }
  }
  if (end < 0) throw new Error("trace archive has no end record");
  const count = archive.readUInt16LE(end + 10);
  const centralOffset = archive.readUInt32LE(end + 16);
  if (count < 1 || count > maximumTraceEntries) throw new Error("trace archive entry count is invalid");
  const entries = [];
  let offset = centralOffset;
  let totalBytes = 0;
  for (let index = 0; index < count; index += 1) {
    if (offset + 46 > archive.length || archive.readUInt32LE(offset) !== 0x02014b50) throw new Error("trace archive central directory is invalid");
    const method = archive.readUInt16LE(offset + 10);
    const compressedBytes = archive.readUInt32LE(offset + 20);
    const uncompressedBytes = archive.readUInt32LE(offset + 24);
    const nameBytes = archive.readUInt16LE(offset + 28);
    const extraBytes = archive.readUInt16LE(offset + 30);
    const commentBytes = archive.readUInt16LE(offset + 32);
    const localOffset = archive.readUInt32LE(offset + 42);
    if (uncompressedBytes > maximumTraceEntryBytes || totalBytes + uncompressedBytes > maximumTraceBytes) throw new Error("trace archive exceeds privacy inspection bounds");
    if (localOffset + 30 > archive.length || archive.readUInt32LE(localOffset) !== 0x04034b50) throw new Error("trace archive local entry is invalid");
    const localNameBytes = archive.readUInt16LE(localOffset + 26);
    const localExtraBytes = archive.readUInt16LE(localOffset + 28);
    const dataOffset = localOffset + 30 + localNameBytes + localExtraBytes;
    if (dataOffset + compressedBytes > archive.length) throw new Error("trace archive entry is truncated");
    const compressed = archive.subarray(dataOffset, dataOffset + compressedBytes);
    const body = method === 0 ? Buffer.from(compressed) : method === 8 ? inflateRawSync(compressed, { maxOutputLength: maximumTraceEntryBytes }) : undefined;
    if (!body || body.length !== uncompressedBytes) throw new Error("trace archive entry compression is unsupported or inconsistent");
    const name = archive.subarray(offset + 46, offset + 46 + nameBytes).toString("utf8");
    entries.push({ name, body });
    totalBytes += body.length;
    offset += 46 + nameBytes + extraBytes + commentBytes;
  }
  return entries;
}

export async function inspectTraceArchive(tracePath, needles, forbiddenHeaders = []) {
  const entries = traceEntries(await readFile(tracePath));
  const names = entries.map(entry => entry.name);
  if (!names.some(name => name.endsWith("trace.trace")) || !names.some(name => name.endsWith("trace.network")) || !names.some(name => name.startsWith("resources/"))) {
    throw new Error("trace archive lacks timeline, network, or resource evidence");
  }
  // Playwright embeds the probe source itself under src/. That source contains
  // the denylist and deliberate canaries used by this test, so it is not a
  // browser-observable surface. Timeline, network, and resource payloads are.
  for (const entry of entries) {
    if (entry.name.startsWith("src/")) continue;
    assertPrivacyEvidence(entry.body, needles, `trace entry ${entry.name}`);
    assertCredentialHeadersAbsent(entry.body, forbiddenHeaders, `trace entry ${entry.name}`);
  }
  return { entries: entries.length, names };
}
