import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (name) => readFile(new URL(`../${name}`, import.meta.url), "utf8");

test("hard denials clear cached operational data and requests consume AbortSignal", async () => {
  const boundary = await read("components/query-provider.tsx");
  const queries = await read("lib/read-queries.ts");
  assert.match(boundary, /removeQueries/);
  assert.match(queries, /signal/);
  assert.doesNotMatch(boundary + queries, /persistQueryClient|localStorage|sessionStorage/);
  assert.match(boundary, /retry: false/);
  assert.match(boundary, /gcTime: 0/);
});

test("the browser client is generated and same-origin only", async () => {
  const client = await read("lib/read-client.ts");
  assert.match(client, /createReadClient/);
  assert.match(client, /fetch\(input, init\)/);
  assert.doesNotMatch(client, /https?:\/\//);
});
