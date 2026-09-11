import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("domain status uses one exact generated source read and defines no record loader", async () => {
  const query = await readFile(new URL("../lib/domain-status-queries.ts", import.meta.url), "utf8");
  const view = await readFile(new URL("../components/domain-status-view.tsx", import.meta.url), "utf8");
  assert.match(query, /readClient\.listSources/);
  assert.match(query, /source: definition\.source/);
  assert.match(query, /source\.id !== definition\.source/);
  assert.match(query, /source\.capability !== definition\.capability/);
  assert.doesNotMatch(`${query}\n${view}`, /listPeople|listServices|listBackups|listProviders|\bfetch\(/);
});

test("current status copy still says that domain records arrive later", async () => {
  const view = await readFile(new URL("../components/domain-status-view.tsx", import.meta.url), "utf8");
  assert.match(view, /status observation is current/i);
  assert.match(view, /records arrive in their owning later phase/i);
  assert.doesNotMatch(view, /create|restore now|configure provider|suspend/i);
});
