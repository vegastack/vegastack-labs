import assert from "node:assert/strict";
import test from "node:test";
import {
  assertExactDependencySpec,
  findSecretMarkers,
  isSecretEnvironmentFile,
} from "../verify-repository.mjs";

test("exact dependency specifications pass", () => {
  assert.doesNotThrow(() => assertExactDependencySpec("example", "1.2.3"));
});

test("unpinned dependency specifications fail", () => {
  assert.throws(() => assertExactDependencySpec("example", "^1.2.3"), /exact semantic version/);
  assert.throws(() => assertExactDependencySpec("example", "latest"), /exact semantic version/);
});

test("secret markers detect a nonempty registry secret without echoing it", () => {
  const markers = findSecretMarkers(["CF_ACCESS_CLIENT_SECRET", "fixture-secret-value"].join("="));
  assert.deepEqual(markers, ["Cloudflare Access secret value"]);
});

test("empty registry placeholders are accepted", () => {
  assert.deepEqual(findSecretMarkers("CF_ACCESS_CLIENT_SECRET=\n"), []);
  assert.deepEqual(findSecretMarkers("CF_ACCESS_CLIENT_SECRET=\nNEXT_VALUE=safe\n"), []);
  assert.deepEqual(findSecretMarkers('"CF-Access-Client-Secret": "${CF_ACCESS_CLIENT_SECRET}"'), []);
});

test("tracked environment secrets fail while redacted examples pass", () => {
  assert.equal(isSecretEnvironmentFile("web/.env.local"), true);
  assert.equal(isSecretEnvironmentFile("web/.env"), true);
  assert.equal(isSecretEnvironmentFile("web/.env.example"), false);
});
