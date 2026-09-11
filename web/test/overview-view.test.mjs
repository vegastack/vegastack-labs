import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (name) => readFile(new URL(`../${name}`, import.meta.url), "utf8");
test("Overview uses generated summary and source reads with cancellation", async () => {
  const query = await read("lib/overview-queries.ts");
  assert.match(query, /readQueries\.summary/);
  assert.match(query, /readQueries\.sources/);
  assert.match(query, /cancelQueries/);
  assert.doesNotMatch(query, /\bfetch\(/);
});
test("Overview names stale partial denied and revision truth", async () => {
  const view = await read("components/overview-view.tsx");
  for (const text of ["Showing last known Overview", "Overview is partial", "Overview access denied", "State revision"]) assert.match(view, new RegExp(text));
});
