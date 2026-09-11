import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { createServer } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MIME = new Map([[".css", "text/css; charset=utf-8"], [".html", "text/html; charset=utf-8"], [".js", "text/javascript; charset=utf-8"], [".json", "application/json; charset=utf-8"], [".svg", "image/svg+xml"], [".txt", "text/plain; charset=utf-8"], [".woff2", "font/woff2"]]);

async function existingFile(candidates) {
  for (const candidate of candidates) {
    try { if ((await stat(candidate)).isFile()) return candidate; } catch (error) { if (error.code !== "ENOENT") throw error; }
  }
  return undefined;
}

export async function startStaticPreview({ root, port }) {
  const absoluteRoot = path.resolve(root);
  const server = createServer(async (request, response) => {
    try {
      const rawPath = (request.url ?? "/").split("?", 1)[0];
      const decoded = decodeURIComponent(rawPath);
      if (decoded.split("/").includes("..") || decoded.includes("\\") || decoded.includes("\0")) {
        response.writeHead(400).end("Bad request");
        return;
      }
      const relative = decoded.replace(/^\/+/, "");
      const base = path.resolve(absoluteRoot, relative);
      if (base !== absoluteRoot && !base.startsWith(`${absoluteRoot}${path.sep}`)) {
        response.writeHead(400).end("Bad request");
        return;
      }
      const file = await existingFile(relative === "" ? [path.join(absoluteRoot, "index.html")] : [base, `${base}.html`, path.join(base, "index.html")]);
      if (!file) { response.writeHead(404).end("Not found"); return; }
      response.writeHead(200, { "Content-Type": MIME.get(path.extname(file)) ?? "application/octet-stream", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" });
      createReadStream(file).pipe(response);
    } catch { response.writeHead(400).end("Bad request"); }
  });
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(port, "127.0.0.1", resolve); });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("preview did not bind a TCP port");
  return { origin: `http://127.0.0.1:${address.port}`, close: () => new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())) };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../out");
  const preview = await startStaticPreview({ root, port: Number(process.env.PORT ?? 4173) });
  process.stderr.write(`Static preview listening on ${preview.origin}\n`);
  const close = async () => { await preview.close(); process.exit(0); };
  process.on("SIGINT", close);
  process.on("SIGTERM", close);
}
