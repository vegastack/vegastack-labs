import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import {
  reviewMetadataDigest,
  renderGoNotices,
  verifyGoDependencies,
} from "../verify-go-dependencies.mjs";

const MODULE = {
  path: "github.com/sigstore/sigstore-go",
  version: "v1.3.0",
  checksum: "h1:YWJjZA==",
  license: "Apache-2.0",
  source: "https://github.com/sigstore/sigstore-go",
  role: "runtime",
  reviewDecision: "approved",
  reviewReason: "Reviewed permissive runtime dependency for offline Sigstore verification.",
};

function manifest(overrides = {}) {
  const value = {
    schemaVersion: 1,
    authority: "manual-review:go-dependency-provenance",
    reviewedOn: "08-09-2026",
    modules: [structuredClone(MODULE)],
    ...overrides,
  };
  value.reviewMetadataSha256 = reviewMetadataDigest(value);
  return value;
}

async function fixtureRepo(t, value = manifest()) {
  const root = await mkdtemp(path.join(tmpdir(), "vegastack-go-provenance-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, "tooling"), { recursive: true });
  await Promise.all([
    writeFile(path.join(root, "go.mod"), "module example.test\n\ngo 1.27.0\n", "utf8"),
    writeFile(
      path.join(root, "go.sum"),
      `${MODULE.path} ${MODULE.version} ${MODULE.checksum}\n`,
      "utf8",
    ),
    writeFile(
      path.join(root, "tooling/go-dependency-provenance.json"),
      `${JSON.stringify(value, null, 2)}\n`,
      "utf8",
    ),
    writeFile(
      path.join(root, "THIRD_PARTY_NOTICES.md"),
      `# Fixture notices\n\n${renderGoNotices(value)}`,
      "utf8",
    ),
  ]);
  return root;
}

function successfulRunner(value = MODULE) {
  return async (_command, args) => {
    if (args[0] === "mod" && args[1] === "verify") return { stdout: "all modules verified\n" };
    if (args[0] === "list" && args.includes("-deps")) {
      return {
        stdout: [
          JSON.stringify({
            ImportPath: "example.test/cmd/vsk-labs",
            Module: { Path: "example.test", Main: true },
          }),
          JSON.stringify({
            ImportPath: `${value.path}/pkg/verify`,
            Module: { Path: value.path, Version: value.version },
          }),
          "",
        ].join("\n"),
      };
    }
    if (args[0] === "list") {
      return {
        stdout: [
          JSON.stringify({ Path: "example.test", Main: true }),
          JSON.stringify({ Path: value.path, Version: value.version }),
          "",
        ].join("\n"),
      };
    }
    throw new Error("unexpected command");
  };
}

async function expectFailure(t, value, code, options = {}) {
  const root = await fixtureRepo(t, value);
  await assert.rejects(
    verifyGoDependencies(root, {
      run: options.run ?? successfulRunner(),
      checkOrigins: false,
      expectedReviewDigest: options.expectedReviewDigest ?? value.reviewMetadataSha256,
    }),
    (error) => error?.code === code,
  );
}

test("the exact reviewed Go graph verifies without writing", async (t) => {
  const value = manifest();
  const root = await fixtureRepo(t, value);
  const result = await verifyGoDependencies(root, {
    run: successfulRunner(),
    checkOrigins: false,
    expectedReviewDigest: value.reviewMetadataSha256,
  });
  assert.deepEqual(result, {
    status: "pass",
    modules: 1,
    reviewDigest: value.reviewMetadataSha256,
  });
});

test("source verification downloads exact selected versions instead of the mutable all target", async (t) => {
  const value = manifest();
  const root = await fixtureRepo(t, value);
  const baseRunner = successfulRunner();
  const run = async (command, args) => {
    if (args[0] === "mod" && args[1] === "download") {
      assert.deepEqual(args, ["mod", "download", "-json", `${MODULE.path}@${MODULE.version}`]);
      return {
        stdout: `${JSON.stringify({
          Path: MODULE.path,
          Version: MODULE.version,
          Sum: MODULE.checksum,
          Origin: { URL: MODULE.source },
        })}\n`,
      };
    }
    return baseRunner(command, args);
  };
  const result = await verifyGoDependencies(root, {
    run,
    expectedReviewDigest: value.reviewMetadataSha256,
  });
  assert.equal(result.status, "pass");
});

test("version, checksum, omitted, added, and duplicate modules fail closed", async (t) => {
  for (const [name, mutate, code] of [
    ["version", (value) => { value.modules[0].version = "v1.3.1"; }, "GO_MODULE_GRAPH"],
    ["checksum", (value) => { value.modules[0].checksum = "h1:Y2hhbmdlZA=="; }, "GO_MODULE_CHECKSUM"],
    ["omitted", (value) => { value.modules = []; }, "GO_MODULE_GRAPH"],
    ["added", (value) => { value.modules.push({ ...MODULE, path: "zzz.test/extra" }); }, "GO_MODULE_GRAPH"],
    ["duplicate", (value) => { value.modules.push(structuredClone(value.modules[0])); }, "GO_MODULE_DUPLICATE"],
  ]) {
    await t.test(name, async (t) => {
      const value = manifest();
      mutate(value);
      value.reviewMetadataSha256 = reviewMetadataDigest(value);
      await expectFailure(t, value, code);
    });
  }
});

test("license, source, role, reason, seal, and disallowed licenses fail closed", async (t) => {
  for (const [name, mutate, code, preserveSeal] of [
    ["license", (value) => { value.modules[0].license = "MIT"; }, "GO_REVIEW_SEAL", true],
    ["source", (value) => { value.modules[0].source = "https://example.invalid"; }, "GO_REVIEW_SEAL", true],
    ["role", (value) => { value.modules[0].role = "build"; }, "GO_REVIEW_SEAL", true],
    ["reason", (value) => { value.modules[0].reviewReason = "changed"; }, "GO_REVIEW_SEAL", true],
    ["seal", (value) => { value.reviewMetadataSha256 = "0".repeat(64); }, "GO_REVIEW_SEAL", false],
    ["disallowed", (value) => { value.modules[0].license = "GPL-3.0-only"; }, "GO_LICENSE", false],
  ]) {
    await t.test(name, async (t) => {
      const value = manifest();
      const approved = value.reviewMetadataSha256;
      mutate(value);
      if (!preserveSeal && name === "disallowed") {
        value.reviewMetadataSha256 = reviewMetadataDigest(value);
      }
      await expectFailure(t, value, code, {
        expectedReviewDigest: name === "disallowed" ? value.reviewMetadataSha256 : approved,
      });
    });
  }
});

test("go mod verify failure has a stable code", async (t) => {
  const value = manifest();
  await expectFailure(t, value, "GO_MODULE_VERIFY", {
    run: async (_command, args) => {
      if (args[0] === "mod") throw new Error("hostile module cache detail");
      return successfulRunner()(_command, args);
    },
  });
});

test("stale Go notices fail closed", async (t) => {
  const value = manifest();
  const root = await fixtureRepo(t, value);
  await writeFile(path.join(root, "THIRD_PARTY_NOTICES.md"), "# stale\n", "utf8");
  await assert.rejects(
    verifyGoDependencies(root, {
      run: successfulRunner(),
      checkOrigins: false,
      expectedReviewDigest: value.reviewMetadataSha256,
    }),
    (error) => error?.code === "GO_NOTICES",
  );
});

test("runtime roles must match the actual executable dependency closure", async (t) => {
  const value = manifest();
  value.modules[0].role = "build";
  value.reviewMetadataSha256 = reviewMetadataDigest(value);
  const root = await fixtureRepo(t, value);
  await assert.rejects(
    verifyGoDependencies(root, {
      run: successfulRunner(),
      checkOrigins: false,
      expectedReviewDigest: value.reviewMetadataSha256,
    }),
    (error) => error?.code === "GO_ROLE",
  );
});
