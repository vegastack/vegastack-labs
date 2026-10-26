import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("People uses authorized records while Services retains safe status", async () => {
  const people = await readFile(new URL("../app/people/page.tsx", import.meta.url), "utf8");
  const services = await readFile(new URL("../app/services/page.tsx", import.meta.url), "utf8");
  assert.match(people, /PeopleView/);
  assert.match(services, /source: "services"/);
  assert.match(services, /capability: "service\.read"/);
  assert.doesNotMatch(`${people}\n${services}`, /email|credential|deploy|recordId/i);
});
