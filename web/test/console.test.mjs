import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (relativePath) => readFile(new URL(`../${relativePath}`, import.meta.url), "utf8");

test("every foundation state is named and the Console makes no healthy claim", async () => {
  const [shell, state, home, dashboard] = await Promise.all([
    read("components/console-shell.tsx"),
    read("components/console-state.tsx"),
    read("app/page.tsx"),
    read("app/dashboard/page.tsx"),
  ]);

  assert.match(shell, /Skip to main content/);
  for (const kind of ["loading", "empty", "error", "unavailable"]) {
    assert.match(state, new RegExp(kind));
  }
  assert.match(`${home}\n${dashboard}`, /data integration is not implemented/i);
  assert.doesNotMatch(`${home}\n${dashboard}`, /all systems operational/i);
});

test("foundation routes use the shared shell and expose unique titles", async () => {
  const [home, dashboard, unavailable] = await Promise.all([
    read("app/page.tsx"),
    read("app/dashboard/page.tsx"),
    read("app/unavailable/page.tsx"),
  ]);

  for (const source of [home, dashboard, unavailable]) assert.match(source, /ConsoleShell/);
  assert.match(home, /title="Overview"/);
  assert.match(dashboard, /title="Console foundation"/);
  assert.match(unavailable, /title="Service unavailable"/);
});
