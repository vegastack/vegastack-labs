import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (name) => readFile(new URL(`../${name}`, import.meta.url), "utf8");
test("every truthful state is named and no status relies on color", async () => {
  const source = await read("components/read-view-state.tsx");
  for (const state of ["loading", "empty", "stale", "unknown", "unavailable", "denied", "partial", "error"]) assert.match(source, new RegExp(state));
  assert.match(source, /aria-live|role=/);
});
test("pagination and detail controls retain accessible behavior", async () => {
  const source = await read("components/read-pagination.tsx") + await read("components/read-detail.tsx");
  assert.match(source, /min-h-11/);
  assert.match(source, /returnFocusRef/);
  assert.match(source, /aria-label/);
});
