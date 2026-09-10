import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { request } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { startStaticPreview } from "../scripts/preview.mjs";

test("static preview binds to loopback and maps exported routes", async (context) => {
  const root = await mkdtemp(path.join(tmpdir(), "vsk-preview-"));
  await mkdir(path.join(root, "dashboard"));
  await writeFile(path.join(root, "index.html"), "home");
  await writeFile(path.join(root, "dashboard", "index.html"), "dashboard");
  const server = await startStaticPreview({ root, port: 0 });
  context.after(() => server.close());

  assert.match(server.origin, /^http:\/\/127\.0\.0\.1:/);
  assert.equal(await (await fetch(`${server.origin}/dashboard`)).text(), "dashboard");
  assert.equal((await fetch(`${server.origin}/missing`)).status, 404);
});

test("static preview rejects encoded traversal", async (context) => {
  const root = await mkdtemp(path.join(tmpdir(), "vsk-preview-"));
  await writeFile(path.join(root, "index.html"), "home");
  const server = await startStaticPreview({ root, port: 0 });
  context.after(() => server.close());
  const status = await new Promise((resolve, reject) => {
    const probe = request(`${server.origin}/`, { path: "/%2e%2e/secret" }, response => {
      response.resume();
      response.on("end", () => resolve(response.statusCode));
    });
    probe.on("error", reject);
    probe.end();
  });
  assert.equal(status, 400);
});
