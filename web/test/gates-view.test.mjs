import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("Gates renders capability status without invented gate records or controls", async () => {
  const source = await readFile(new URL("../components/gates-view.tsx", import.meta.url), "utf8");
  assert.match(source, /source: "gates"/);
  assert.match(source, /Gate evaluation is not implemented/);
  assert.doesNotMatch(source, /<Button|approveGate|passGate|applyGate/);
});
