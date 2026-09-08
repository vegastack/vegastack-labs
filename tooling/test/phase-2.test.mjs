import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

const ROOT = path.resolve(import.meta.dirname, "../..");

test("Phase 2 starts with one protected service and frozen dependent ports", async () => {
  const phase = await readFile(
    path.join(ROOT, "docs/development/phases/02-authoritative-control-service-and-inventory.md"),
    "utf8",
  );
  assert.match(phase, /Issue 2\.1 \(#29\).*Issue 2\.10 \(#38\)/s);
  assert.match(phase, /StateAuthority.*Application.*#30.*#35/s);
  assert.match(phase, /UID.*principal.*permissions.*SQLite/is);
  assert.match(phase, /#38.*combined.*acceptance/is);
  assert.match(phase, /synthetic fixtures/i);
  assert.doesNotMatch(phase, /Phase 2 (?:is )?accepted/i);
});

test("current development pointers advance only to active Phase 2", async () => {
  const [index, roadmap, phaseOne, readme, contributing] = await Promise.all([
    readFile(path.join(ROOT, "docs/development/README.md"), "utf8"),
    readFile(path.join(ROOT, "docs/development/roadmap.md"), "utf8"),
    readFile(
      path.join(ROOT, "docs/development/phases/01-portable-executable-and-generated-contracts.md"),
      "utf8",
    ),
    readFile(path.join(ROOT, "README.md"), "utf8"),
    readFile(path.join(ROOT, "CONTRIBUTING.md"), "utf8"),
  ]);
  assert.match(index, /Phase 1.*accepted.*Phase 2.*active/is);
  assert.match(roadmap, /Phase 1.*accepted.*Phase 2.*active/is);
  assert.match(phaseOne, /^Status: accepted\./m);
  assert.match(readme, /protected Unix-domain.*kernel peer credentials/is);
  assert.match(readme, /does not.*SQLite.*inventory.*permissions/is);
  assert.match(contributing, /server run --config .*fixture\/server-profile\.json/);
  assert.match(contributing, /server status --config .*fixture\/server-profile\.json --output json/);
  assert.match(contributing, /synthetic.*no real operational data/is);
});
