import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (name) => readFile(new URL(`../${name}`, import.meta.url), "utf8");
test("Nodes keeps three server-paginated generated collections in memory", async () => {
  const queries = await read("lib/node-queries.ts");
  for (const operation of ["listInventoryDraftNodes", "listInventoryDraftAliases", "listInventoryDraftObservations"]) assert.match(queries, new RegExp(operation));
  assert.match(queries, /current.*back/s);
  assert.doesNotMatch(queries, /localStorage|sessionStorage|URLSearchParams/);
});
test("Nodes has generated details, qualification truth, and focus restoration", async () => {
  const view = await read("components/nodes-view.tsx");
  assert.match(view, /getInventoryDraftNode/);
  assert.match(view, /Qualification is unavailable/);
  assert.match(view, /returnFocusRef/);
});
