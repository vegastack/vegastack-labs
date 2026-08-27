import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { parse as parseYaml } from "yaml";
import { inspectLockPackages, validateLicenseDecision } from "../provenance.mjs";

const fixture = (name) => readFile(new URL(`../testdata/${name}`, import.meta.url), "utf8");

test("private dependency origins fail closed", async () => {
  const lock = parseYaml(await fixture("private-origin-lock.yaml"));
  assert.throws(() => inspectLockPackages(lock), /unexpected dependency origin/);
});

test("missing dependency integrity fails closed", async () => {
  const lock = parseYaml(await fixture("missing-integrity-lock.yaml"));
  assert.throws(() => inspectLockPackages(lock), /no registry integrity/);
});

test("invalid SPDX licenses fail closed", async () => {
  const record = JSON.parse(await fixture("invalid-license.json"));
  assert.throws(() => validateLicenseDecision({ ...record, role: "build" }), /invalid SPDX/);
});

test("only the exact approved MPL development set passes", () => {
  assert.match(
    validateLicenseDecision({
      name: "axe-core",
      version: "4.13.0",
      license: "MPL-2.0",
      role: "build",
    }),
    /development-only MPL/,
  );
  assert.throws(
    () =>
      validateLicenseDecision({
        name: "another-package",
        version: "1.0.0",
        license: "MPL-2.0",
        role: "build",
      }),
    /outside the approved MPL/,
  );
});
