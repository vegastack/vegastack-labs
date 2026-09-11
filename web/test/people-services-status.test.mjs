import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("People and Services use only their safe status definitions", async () => {
  const people = await readFile(new URL("../app/people/page.tsx", import.meta.url), "utf8");
  const services = await readFile(new URL("../app/services/page.tsx", import.meta.url), "utf8");
  assert.match(people, /source: "people"/);
  assert.match(people, /capability: "identity\.person\.read"/);
  assert.match(services, /source: "services"/);
  assert.match(services, /capability: "service\.read"/);
  assert.doesNotMatch(`${people}\n${services}`, /email|credential|deploy|recordId/i);
});
