import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (path) => readFile(new URL(`../${path}`, import.meta.url), "utf8");

test("declaration changes persist only after Save through the generated client", async () => {
  const source = await read("components/declaration-editor.tsx");
  assert.match(source, /Save declaration/);
  assert.match(source, /useSaveDeclaration/);
  assert.match(source, /Generate plan/);
  assert.doesNotMatch(source, /setInterval|onBlur=.*save|fetch\(/);
});

test("the Changes route uses typed queries and keeps plan generation separate", async () => {
  const [page, queries, sidebar] = await Promise.all([
    read("app/changes/page.tsx"),
    read("lib/change-queries.ts"),
    read("app/dashboard/components/app-sidebar.tsx"),
  ]);
  assert.match(page, /ChangesWorkspace/);
  assert.match(sidebar, /href: "\/changes"/);
  assert.match(queries, /changeClient/);
  assert.match(await read("lib/read-client.ts"), /createChangeClient/);
  assert.match(queries, /useDeclaration|useSaveDeclaration|useCreatePlan/);
  assert.doesNotMatch(queries, /fetch\(|axios|sqlite|provider/i);
});

test("generated client owns safe browser plan preparation", async () => {
  const generated = await read("generated/read-api.ts");
  assert.match(generated, /preparePlan/);
  assert.match(generated, /PlanPreparation/);
});
