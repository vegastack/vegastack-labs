import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("People and Services use authorized record views", async () => {
  const people = await readFile(new URL("../app/people/page.tsx", import.meta.url), "utf8");
  const services = await readFile(new URL("../app/services/page.tsx", import.meta.url), "utf8");
  assert.match(people, /PeopleView/);
  assert.match(services, /ServicesView/);
  assert.doesNotMatch(`${people}\n${services}`, /email|credential|deploy|recordId/i);
});
