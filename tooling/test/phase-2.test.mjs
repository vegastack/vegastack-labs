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
  assert.doesNotMatch(phase, /^Status: accepted\./m);
});

test("Phase 2 documents draft-only CLI/API parity without a second authority", async () => {
  const phase = await readFile(
    path.join(ROOT, "docs/development/phases/02-authoritative-control-service-and-inventory.md"),
    "utf8",
  );
  assert.match(
    phase,
    /Issue 2\.8 \(#36\).*status.*database status.*inventory import.*inventory diff.*inventory export/is,
  );
  assert.match(phase, /authorize.*before.*body/is);
  assert.match(phase, /baseline.*draft.*PREREQUISITE_BLOCKED/is);
  assert.match(phase, /Issue #37.*publish.*signed/is);
  assert.match(phase, /human.*JSON.*exact.*envelope/is);
  assert.match(phase, /never edit SQLite.*source Sheet.*export root.*infrastructure/is);
  assert.doesNotMatch(phase, /^Status: accepted\./m);
});

test("current development pointers preserve Phase 2 acceptance and record Phase 3 awaiting acceptance", async () => {
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
  assert.match(index, /Phase 2.*accepted.*Phase 3.*implemented.*exact-commit.*operator-acceptance/is);
  assert.match(roadmap, /Phase 2.*10-09-2026.*Phase 3.*implemented.*exact-commit.*operator-acceptance/is);
  assert.match(phaseOne, /^Status: accepted\./m);
  assert.match(readme, /protected Unix-domain.*kernel peer credentials/is);
  assert.match(readme, /does not.*SQLite.*inventory.*permissions/is);
  assert.match(contributing, /server run --config .*fixture\/server-profile\.json/);
  assert.match(contributing, /server status --config .*fixture\/server-profile\.json --output json/);
  assert.match(contributing, /synthetic.*no real operational data/is);
});

test("the Phase 2 record links every child and keeps fixture proof separate from live evidence", async () => {
  const [phase, manifest] = await Promise.all([
    readFile(path.join(ROOT, "docs/development/phases/02-authoritative-control-service-and-inventory.md"), "utf8"),
    readFile(path.join(ROOT, "tooling/phase-2-evidence.json"), "utf8").then(JSON.parse),
  ]);
  assert.match(phase, /^Status: implemented; awaiting operator acceptance\./m);
  assert.doesNotMatch(phase, /^Status: accepted\./m);
  assert.match(phase, /fixture proof.*not live evidence/is);
  assert.match(phase, /Phase 3 handoff/i);
  for (const child of manifest.children) {
    assert.match(phase, new RegExp(`Issue 2\\.${child.issue - 28} \\(#${child.issue}\\).*PR #${child.pr}`, "s"));
    assert.ok(phase.includes(child.evidence));
    assert.ok(phase.includes(child.review));
  }
});
