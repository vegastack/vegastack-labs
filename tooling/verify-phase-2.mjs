import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { access, lstat, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { runCommand } from "./lib/process.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const MANIFEST_PATH = "tooling/phase-2-evidence.json";
const MODULE_PREFIX = "github.com/vegastack/vegastack-labs/";
const REVIEWED_POST_PHASE2_IMPORTS = new Set([
  `${MODULE_PREFIX}internal/acknowledgement`,
  // Issue #74 adds the provider-neutral execution boundary and durable run
  // engine to the existing server composition. They are reviewed product
  // dependencies, not test-only escape hatches around Phase 2 acceptance.
  `${MODULE_PREFIX}internal/adapter`,
  `${MODULE_PREFIX}internal/adapters/slack`,
  // Issue #78's constrained-SSH path is a generated, length-bounded frame
  // transported through a protected profile. These packages are covered by
  // the exact mutation-safety boundary digest below.
  `${MODULE_PREFIX}internal/apissh`,
  `${MODULE_PREFIX}internal/change`,
  `${MODULE_PREFIX}internal/clientprofile`,
  `${MODULE_PREFIX}internal/consoleassets`,
  `${MODULE_PREFIX}internal/credentialref`,
  `${MODULE_PREFIX}internal/plan`,
  `${MODULE_PREFIX}internal/run`,
  // Issue #78 confines the protected local client's reviewed HTTP-over-Unix
  // implementation to a sealed value-only transport package. The package adds
  // no alternate production route or Phase 2 authority bypass.
  `${MODULE_PREFIX}internal/localtransport`,
  // Issue #78 moves the local socket's passive principal and peer contract
  // out of the remote-capable identity package. This network-free package is
  // an intentional boundary hardening, not a Phase 2 production bypass.
  `${MODULE_PREFIX}internal/principal`,
  // Issue #78 shares this pure provider-neutral ID protocol between the
  // reviewed run engine and its thin local client. It adds no bypass path.
  `${MODULE_PREFIX}internal/runprotocol`,
  `${MODULE_PREFIX}internal/sshtransport`,
]);
const REVIEWED_POST_PHASE2_COMMANDS = new Set([
  "apply", "plan", "run cancel", "run inspect", "run resume", "server api-ssh",
]);
// Preserve the original Phase 2/Phase 4 command and digest goldens. Each
// later reviewed wave has a separate exact name/import/source closure; adding
// another gate command or import cannot inherit #104's allowance.
const PHASE2_BASELINE_DEPENDENCY_DIGEST = "sha256:a9e8788558fa5c3347b5b8464d8d5e4a67dcc9357e5ae07478b606a806f78133";
const PHASE2_BASELINE_MUTATION_DIGEST = "sha256:e530e3139c9f06995389c39c28dc2c9758f96030c073c40e1b5000d44d32994c";
const REVIEWED_GATE_WAVE = Object.freeze({
  id: "phase5-issue104-v1", issue: 104,
  commands: Object.freeze(["gate check", "gate evidence", "gate inspect", "gate list", "gate profile draft"]),
  imports: Object.freeze([`${MODULE_PREFIX}internal/gate`]),
  mutationBoundaryDigest: "sha256:e93cbd898ee0ddd237bd90e83f7b7db153451883fbf590fbd5f42146a5b0a4a9",
});
const REVIEWED_CREDENTIAL_FOUNDATION_WAVE = Object.freeze({
  id: "phase5-issue123-v1", issue: 123,
  commands: Object.freeze([]),
  imports: Object.freeze([
    `${MODULE_PREFIX}internal/adapter/nativecredential`,
    `${MODULE_PREFIX}internal/adapter/onepassword`,
  ]),
  mutationBoundaryDigest: "sha256:1e72e5133f8446b73494065096dec7f91d6bbc771b6ca137c0b7b4a3d1b1d4ed",
});
// Issue #128 re-sealed the production source closure after refreshing the embedded
// Console assets to design-system registry 0.9.1. It adds NO production command and NO
// Go import — the only closure delta is the inert embedded `internal/consoleassets`
// bytes (verified: zero .go/schemas/go.mod/internal-metadata changes) — so its wave
// carries empty commands/imports and only the new boundary digest.
const REVIEWED_DESIGN_SYSTEM_WAVE = Object.freeze({
  id: "designsystem-issue128-v1", issue: 128,
  commands: Object.freeze([]),
  imports: Object.freeze([]),
  mutationBoundaryDigest: "sha256:0b2d4b56d0d5ca1e3ba7c8e796cf0a22a171faad87213cedafcd8ecedf714680",
});
// Issue #124 adds the inert local encrypted-credential import wave. Because it lands
// after the #128 design-system reseal, its boundary digest is the combined closure of
// the credential-import production sources over the resealed Console assets.
const REVIEWED_CREDENTIAL_IMPORT_WAVE = Object.freeze({
  id: "phase5-issue124-v1", issue: 124,
  commands: Object.freeze(["credential import"]),
  imports: Object.freeze([]),
  mutationBoundaryDigest: "sha256:c18f9df9999784b2c319741cb65172dd802f61bca61abb29a4ecd0a96ce53ba1",
});
// Issue #107 adds the two typed audit read commands (checkpoint listing and history
// verification) with no new Go import. Its historical landing digest remains
// immutable when the subsequent #125 execution-core wave seals the combined closure.
const REVIEWED_AUDIT_WAVE = Object.freeze({
  id: "phase5-issue107-v1", issue: 107,
  commands: Object.freeze(["audit checkpoints", "audit verify"]),
  imports: Object.freeze([]),
  mutationBoundaryDigest: "sha256:f7f91580362c31d0d9f66cc9ebb427df1080b8bef771c1a0ab620138da0ecd39",
});
// Issue #125 lands the credential lifecycle EXECUTION CORE only (contracts,
// migration 0015, append-only store layer, and the in-process `core.credential`
// run dispatch). The five `credential stage|activate|rotate|revoke|recover`
// commands and the `credential-lifecycle-drafts` endpoint are DEFERRED to a
// Task-5 follow-up, so this wave carries NO available command and NO new Go
// import — the only closure delta is the added lifecycle production source under
// `internal/**` and `schemas/v1/**`. As the new final Phase 5 wave it supersedes
// #107 as the current head closure that `postPhase2MutationBoundaryDigest`
// reproduces and must equal.
const REVIEWED_CREDENTIAL_EXECUTION_CORE_WAVE = Object.freeze({
  id: "phase5-issue125-v1", issue: 125,
  commands: Object.freeze([]),
  imports: Object.freeze([]),
  mutationBoundaryDigest: "sha256:89dd556b7afa3ebc646dc1c5cba24add52888317883cedf082b701128e46b6f2",
});
// Issue #132's reviewed surface wave includes the five metadata-only lifecycle
// commands. Recompute its boundary digest live when production code changes.
const REVIEWED_CREDENTIAL_LIFECYCLE_SURFACE_WAVE = Object.freeze({
  id: "phase5-issue132-v1", issue: 132,
  commands: Object.freeze(["credential activate", "credential recover", "credential revoke", "credential rotate", "credential stage"]), imports: Object.freeze([]),
  mutationBoundaryDigest: "sha256:e6d31940c5e8ce3f14720592b374e397c66eef11e477fcb2afe68a6b1b2a87c4",
});
// Issue #133 hardens verifier panic/evidence boundaries and adds exact registry
// enumeration. It registers no production consumer verifier, command, or import.
// This digest is recomputed from the live production source closure at its head.
const REVIEWED_CREDENTIAL_VERIFIER_HARDENING_WAVE = Object.freeze({
  id: "phase5-issue133-v1", issue: 133,
  commands: Object.freeze([]), imports: Object.freeze([]),
  mutationBoundaryDigest: "sha256:1b31eaa862d23433611a5638d9876dc2d5f8aedbccfd76d80106a579d1b0e76b",
});
// Issue #134 binds clean-host recovery evidence to an exact inert draft and
// epoch, but registers no production recovery source, command, or import.
const REVIEWED_CREDENTIAL_RECOVERY_CUSTODY_WAVE = Object.freeze({
  id: "phase5-issue134-v1", issue: 134,
  commands: Object.freeze([]), imports: Object.freeze([]),
  mutationBoundaryDigest: "sha256:5d0d831196eb25b842999dc70d19c97b4f503ad827ba64148b3c283a70b0855a",
});
// Issue #106 adds the inert local backup-policy-draft command and the local
// recovery-point creation source closure (the guarded REST object boundary, the
// sealed-FD restic child and the exact bound adapter). Its reviewed imports
// cover the backup package, fixed identity registry and local adapter. The
// later #146 wave owns the merged final boundary digest.
const REVIEWED_BACKUP_WAVE = Object.freeze({
  id: "phase5-issue106-v1", issue: 106,
  commands: Object.freeze(["backup policy draft"]),
  imports: Object.freeze([`${MODULE_PREFIX}internal/adapter/localbackup`, `${MODULE_PREFIX}internal/backup`, `${MODULE_PREFIX}internal/backupidentity`]),
  mutationBoundaryDigest: "sha256:adb10fa89d1ded9b316adf689b3e1ae35dcdb3a17fbf6a6a08f506e0e55d9a6b",
});

// Issue #146 adds the public recovery-verification contract and exactly one
// production import, with no available command or registered source.
const REVIEWED_WITNESS_RECOVERY_CONTRACT_WAVE = Object.freeze({
  id: "phase5-issue146-v1", issue: 146,
  commands: Object.freeze([]), imports: Object.freeze(["github.com/vegastack/vegastack-labs/internal/recovery"]),
  mutationBoundaryDigest: "sha256:4c1e231743f35fd482d3b8541bc99ee9d2c4cb20276f13bafba297cf4c231125",
});
// Issue #140 seals local native credential consumer and denied-reader identities
// into inert lifecycle plans. It registers no runtime verifier or new command.
// Recheck this measured production-source closure after final main integration.
const REVIEWED_NATIVE_READER_MAP_WAVE = Object.freeze({
  id: "phase5-issue140-v1", issue: 140,
  commands: Object.freeze([]), imports: Object.freeze([]),
  mutationBoundaryDigest: "sha256:1e0ddd40124fbd35a86ab13b26525e0765c7b0c13e2d108b72ae6f44d010f347",
});
// Issue #141 composes #140's consumer map with #143's qualified local OS
// authority and an exact native lifecycle verifier. Production G-007 remains
// unavailable. Recompute this digest from the final integrated source closure.
const REVIEWED_NATIVE_LIFECYCLE_WAVE = Object.freeze({
  id: "phase5-issue141-v1", issue: 141,
  commands: Object.freeze([]), imports: Object.freeze([]),
  mutationBoundaryDigest: "sha256:1c1c655f661db1efe1586da0e731dfb2d7471d76d742c4e0ba774a90c114f0a1",
});


// Issue #143 adds only the exact local delegated native authority and private
// probe. It registers no additional public command or external adapter.
const REVIEWED_NATIVE_AUTHORITY_WAVE = Object.freeze({
  id: "phase5-issue143-v1", issue: 143,
  commands: Object.freeze([]), imports: Object.freeze([]),
  mutationBoundaryDigest: "sha256:8f475ee6b254aef31714c2990053fe43964775d6521caf3f90acf0a41550f81a",
});

// #153 exposes a finite, default-blocked custodian collection command and
// typed direct-denial interface. No qualified production adapter is wired.
const REVIEWED_WITNESS_COLLECTION_WAVE = Object.freeze({
  id: "phase5-issue153-v1", issue: 153,
  commands: Object.freeze(["recovery witness collect"]),
  imports: Object.freeze(["github.com/vegastack/vegastack-labs/internal/adapter/recoverydenial"]),
  mutationBoundaryDigest: "sha256:d14608fe7b00ce92fe57cc4bed03beb44c8ac43d9e49bb5c18343da29a61da97",
});

// Issue #156 changes the browser's same-run SSE cursor lifecycle. The
// generated Console asset refresh is the sole production closure delta; no
// command, Go import, or server mutation authority is added by this wave.
const REVIEWED_BROWSER_RECONNECT_WAVE = Object.freeze({
  id: "phase5-issue156-v1", issue: 156,
  commands: Object.freeze([]), imports: Object.freeze([]),
  mutationBoundaryDigest: "sha256:378485d4c81e751b0e9b72ab53083c5834c09f104166ef04af29035abb6af64a",
});

// Issue #117 activates the exact backup status/run/verify commands and seals
// their point-bound read role, full-read/restore, policy cadence and proof CAS.
// It adds no new production import: #106 already introduced the backup package
// and local adapter. The digest is recomputed from the current source closure.
const REVIEWED_BACKUP_VERIFY_WAVE = Object.freeze({
  id: "phase5-issue117-v1", issue: 117,
  commands: Object.freeze(["backup run", "backup status", "backup verify"]),
  imports: Object.freeze([]),
  mutationBoundaryDigest: "sha256:89ff1628146fb0d7da81011c57793664f953faf4b482a07de34e66c2e241646a",
});

// #159 admits only an exact administrator-installed public package through a
// closed verifier registry. Production remains unavailable with no factories.
const REVIEWED_RECOVERY_SOURCE_ADMISSION_WAVE = Object.freeze({
  id: "phase5-issue159-v1", issue: 159,
  commands: Object.freeze([]), imports: Object.freeze([]),
  mutationBoundaryDigest: "sha256:a87f15826c58af20b2fd5fe7048c49311c68cf279f4486d68e0a54f37365e31d",
});

// #144 composes the protected handoff with the existing-draft native
// comparator behind a future current-authority source. Production selection
// remains unavailable.
const REVIEWED_CLEAN_HOST_RECOVERY_WAVE = Object.freeze({
  id: "phase5-issue144-v1", issue: 144,
  commands: Object.freeze([]), imports: Object.freeze([]),
  mutationBoundaryDigest: "sha256:9c0314e30319a02d3acafa546c37af5d38c8dab05537a49eec64e1a355d020f4",
});

// #163 replaces direct controller repository access with one finite mode of the
// existing executable behind an exact systemd/polkit custody boundary. It adds
// no command or import; this wave seals the integrated production closure.
const REVIEWED_REPOSITORY_CUSTODY_WAVE = Object.freeze({
  id: "phase5-issue163-v1", issue: 163,
  commands: Object.freeze([]), imports: Object.freeze([]),
  mutationBoundaryDigest: "sha256:592096b123cc8cc0701cd66381bc4a6bce3ade7d6f87562f48e4650d59e6c92c",
});

// #154 adds the current signed dependency resolver used by the existing local
// backup verification path. It adds no command; production source/root reading
// remains unavailable until a separately approved site adapter is registered.
const REVIEWED_BACKUP_DEPENDENCY_TRUST_WAVE = Object.freeze({
  id: "phase5-issue154-v1", issue: 154,
  commands: Object.freeze([]), imports: Object.freeze([`${MODULE_PREFIX}internal/adapter/backuptrust`]),
  mutationBoundaryDigest: "sha256:2d212fc6e280422b5086b1914831ae0d3e4aa8380fff7d8a509035bf8910cd71",
});

// #135 removes the weaker store transition API after all serial credential
// lifecycle prerequisites have landed. It adds no command or import.
const REVIEWED_CREDENTIAL_LIFECYCLE_ACCEPTANCE_WAVE = Object.freeze({
  id: "phase5-issue135-v1", issue: 135,
  commands: Object.freeze([]), imports: Object.freeze([]),
  mutationBoundaryDigest: "sha256:0baef2613b97b94b88439b2098f508d24dbe34777dd818e117fa0d1ccd8b8a8a",
});

// #115 adds the human-only local retention lock and retirement draft surfaces
// plus the exact bound local-retention adapter. It has no provider dependency.
const REVIEWED_LOCAL_RETIREMENT_WAVE = Object.freeze({
  id: "phase5-issue115-v1", issue: 115,
  commands: Object.freeze(["backup retention-locks draft", "backup retirement draft"]),
  imports: Object.freeze(["github.com/vegastack/vegastack-labs/internal/adapter/localretention"]),
  mutationBoundaryDigest: "sha256:f012f10bb2cb917423afac31aea31a2021ce1de488f3fbc1cdb47ef1f0c3d38d",
});

// #114 adds no direct CLI command. It extends the existing backup status and
// exact run executor with an optional credential-bound off-site effect.
const REVIEWED_OFFSITE_GENERATION_WAVE = Object.freeze({
  id: "phase5-issue114-v1", issue: 114,
  commands: Object.freeze([]), imports: Object.freeze(["github.com/vegastack/vegastack-labs/internal/adapters/r2"]),
  mutationBoundaryDigest: "sha256:6c6a3ab5f366603d73c1bd07d91097d0062f49a48231aca42a4c1f500af0455d",
});

// #118 adds the closed destructive off-site retirement contract. It exposes no
// direct CLI command and production registration remains unavailable until
// actual G-008 one-owner, credential, and recovery evidence qualifies the site.
const REVIEWED_OFFSITE_RETIREMENT_WAVE = Object.freeze({
  id: "phase5-issue118-v1", issue: 118,
  commands: Object.freeze([]), imports: Object.freeze(["github.com/vegastack/vegastack-labs/internal/adapter/r2retention"]),
  mutationBoundaryDigest: "sha256:dfd65a0ae1e191be887fe8038402f5334603ac854cb8b1877d3e8adde3b8a45f",
});

const REVIEWED_PHASE5_WAVES = Object.freeze([REVIEWED_GATE_WAVE, REVIEWED_CREDENTIAL_FOUNDATION_WAVE, REVIEWED_DESIGN_SYSTEM_WAVE, REVIEWED_CREDENTIAL_IMPORT_WAVE, REVIEWED_AUDIT_WAVE, REVIEWED_CREDENTIAL_EXECUTION_CORE_WAVE, REVIEWED_CREDENTIAL_LIFECYCLE_SURFACE_WAVE, REVIEWED_CREDENTIAL_VERIFIER_HARDENING_WAVE, REVIEWED_CREDENTIAL_RECOVERY_CUSTODY_WAVE, REVIEWED_BACKUP_WAVE, REVIEWED_WITNESS_RECOVERY_CONTRACT_WAVE, REVIEWED_NATIVE_READER_MAP_WAVE, REVIEWED_NATIVE_AUTHORITY_WAVE, REVIEWED_NATIVE_LIFECYCLE_WAVE, REVIEWED_WITNESS_COLLECTION_WAVE, REVIEWED_BROWSER_RECONNECT_WAVE, REVIEWED_BACKUP_VERIFY_WAVE, REVIEWED_RECOVERY_SOURCE_ADMISSION_WAVE, REVIEWED_CLEAN_HOST_RECOVERY_WAVE, REVIEWED_REPOSITORY_CUSTODY_WAVE, REVIEWED_BACKUP_DEPENDENCY_TRUST_WAVE, REVIEWED_CREDENTIAL_LIFECYCLE_ACCEPTANCE_WAVE, REVIEWED_LOCAL_RETIREMENT_WAVE, REVIEWED_OFFSITE_GENERATION_WAVE, REVIEWED_OFFSITE_RETIREMENT_WAVE]);
const ONEPASSWORD_SDK_VERSION = "v0.4.1";
const CREDENTIAL_FOUNDATION_MIGRATION = Object.freeze({ file: "0012_credential_refs.sql", sha256: "302b2bedb4eee771436e3772c49b3c0c6cdaefbd5a1a17d11370e10a44c8e0c7" });
const CREDENTIAL_IMPORT_MIGRATION = Object.freeze({ file: "0013_credential_import_drafts.sql", sha256: "2dd9895e6a06a6789635cbe787fc89c6c56597f2192b39395ffa5186388e5204" });
const CREDENTIAL_IMPORT_FLAGS = Object.freeze([
  "--config", "--consumer-id", "--expected-state-revision", "--idempotency-key", "--input-fd", "--material-version",
  "--output", "--purpose-id", "--recovery-epoch", "--reference-id", "--resolver-id", "--schema-version", "--target-id",
]);
const CREDENTIAL_IMPORT_ENDPOINTS = Object.freeze(["api.v1.credential-references.import-stream"]);
// Phase 2's no-mutation proof predates Phase 4. Later commands are accepted
// only while the complete local production source closure of cmd/vsk-labs
// remains byte-for-byte reviewed. This avoids a brittle hand-maintained file
// allowlist: every production package, target-specific implementation, and
// embedded production asset is sealed automatically. Tests and testdata do
// not affect the production digest. Any production edit fails the old
// acceptance gate until it receives a fresh review and this digest is
// deliberately updated.
const POST_PHASE2_MUTATION_BOUNDARY_ROOTS = ["go.mod", "go.sum"];
const POST_PHASE2_MUTATION_BOUNDARY_DIRECTORIES = ["internal/metadata", "schemas/v1"];
const CODE_ORDER = [
  "PHASE2_CHILD_INCOMPLETE",
  "PHASE2_TRACEABILITY_GAP",
  "PHASE2_CONTRACT_DRIFT",
  "PHASE2_MUTATION_AVAILABLE",
  "PHASE2_PRODUCTION_BYPASS",
  "PHASE2_PRIVATE_FIXTURE",
  "PHASE2_EVIDENCE_STALE",
];
const REQUIREMENT_IDS = [
  "module-1.server-lifecycle-local-api",
  "module-1.sqlite-durability-migrations",
  "module-1.versioned-read-api-events",
  "module-2.labs-sheet-adapter",
  "module-2.read-api-cli",
  "module-2.typed-inventory",
  "module-7.audit-outbox",
  "module-7.online-backup-signed-export",
  "roadmap.phase-2",
];
const EXPECTED_CHILDREN = [
  [29, 40, "61dd286cc414dcbe9fd0919b31acb0216d8e183a"],
  [30, 41, "478c1d71b32f90fe546a8c0c1b08165bccaa9446"],
  [31, 43, "81b0d8ed48836a84636a44566ee337d37f369d42"],
  [32, 44, "2bc14ca99b10333a94803e3f3d51c150cc77950b"],
  [33, 45, "04f555fb15985e82bba09ce562fa0a4abfcc537e"],
  [34, 42, "1dc2e9ffecf1d8b4a148f676bb28826b329e88fe"],
  [35, 46, "4118272e027385affd56b38e65a7ebb320d025ef"],
  [36, 48, "8d4a07bedc8d2aaadb479dab73210435c907f24a"],
  [37, 47, "34e9e9d01f6c0bbb14c8e54d4a2ab4a1b1e77fc3"],
];
const EXPECTED_AVAILABLE_COMMANDS = [
  "backup policy draft", "database status", "help", "inventory diff", "inventory export", "inventory import",
  "release inspect", "release verify", "server run", "server status", "status", "version",
];
const EXPECTED_ENDPOINT_IDS = [
  "api.v1.backup-policy-drafts.create",
  "api.v1.database-status.get", "api.v1.events.stream", "api.v1.health.get",
  "api.v1.inventory-diffs.create", "api.v1.inventory-draft-aliases.get",
  "api.v1.inventory-draft-aliases.list", "api.v1.inventory-draft-assets.get",
  "api.v1.inventory-draft-assets.list", "api.v1.inventory-draft-nodes.get",
  "api.v1.inventory-draft-nodes.list", "api.v1.inventory-draft-observations.get",
  "api.v1.inventory-draft-observations.list", "api.v1.inventory-drafts.get",
  "api.v1.inventory-drafts.import", "api.v1.inventory-drafts.list",
  "api.v1.inventory-exports.create", "api.v1.summary.get",
];

function exactKeys(value, keys) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
}

function same(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function containsAll(actual, required) {
  const values = new Set(actual);
  return required.every((value) => values.has(value));
}

function hasPrefix(actual, required) {
  return actual.length >= required.length && same(actual.slice(0, required.length), required);
}

function compatibleContractVersion(current, baseline) {
  const parse = (value) => /^(\d+)\.(\d+)\.(\d+)$/.exec(value)?.slice(1).map(Number);
  const left = parse(current);
  const right = parse(baseline);
  if (!left || !right || left[0] !== right[0]) return false;
  return left[1] > right[1] || left[1] === right[1] && left[2] >= right[2];
}

function pinnedGoEnvironment(extra = {}) {
  return { ...process.env, GOWORK: "off", GOFLAGS: "-mod=readonly", ...extra };
}

async function pathExists(filename) {
  try {
    await access(filename);
    return true;
  } catch {
    return false;
  }
}

async function sha256(filename) {
  return createHash("sha256").update(await readFile(filename)).digest("hex");
}

async function filesBelow(root) {
  const found = [];
  async function walk(directory) {
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch (error) {
      if (error.code === "ENOENT") return;
      throw error;
    }
    for (const entry of entries) {
      const filename = path.join(directory, entry.name);
      if (entry.isDirectory()) await walk(filename);
      else if (entry.isFile()) found.push(filename);
    }
  }
  await walk(root);
  return found.sort();
}

function postPhase2MutationBoundaryDirectories(productionImports = []) {
  const directories = new Set(POST_PHASE2_MUTATION_BOUNDARY_DIRECTORIES);
  // Scan the complete internal and executable trees before dependency
  // discovery so a source link cannot hide the very import that would have
  // caused its directory to be selected.
  directories.add("cmd/vsk-labs");
  directories.add("internal");
  for (const importPath of productionImports.filter((name) => name.startsWith(MODULE_PREFIX))) {
    directories.add(importPath.slice(MODULE_PREFIX.length));
  }
  return [...directories].sort();
}

async function firstUnsafeBoundaryEntry(root, productionImports) {
  for (const relative of POST_PHASE2_MUTATION_BOUNDARY_ROOTS) {
    try {
      const value = await lstat(path.join(root, relative));
      if (!value.isFile()) return relative;
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }
  async function walk(relativeDirectory) {
    let entries;
    try {
      entries = await readdir(path.join(root, relativeDirectory), { withFileTypes: true });
    } catch (error) {
      if (error.code === "ENOENT") return "";
      throw error;
    }
    for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
      const relative = path.posix.join(relativeDirectory.split(path.sep).join("/"), entry.name);
      if (entry.isSymbolicLink() || !entry.isDirectory() && !entry.isFile()) return relative;
      if (entry.isDirectory()) {
        const unsafe = await walk(relative);
        if (unsafe !== "") return unsafe;
      }
    }
    return "";
  }
  for (const directory of postPhase2MutationBoundaryDirectories(productionImports)) {
    try {
      const value = await lstat(path.join(root, directory));
      if (!value.isDirectory()) return directory;
    } catch (error) {
      if (error.code === "ENOENT") return directory;
      throw error;
    }
    const unsafe = await walk(directory);
    if (unsafe !== "") return unsafe;
  }
  return "";
}

async function commandOutput(root, command, args, options = {}) {
  return (await runCommand(command, args, {
    ...options, cwd: root, capture: true, timeoutMs: 120_000,
  })).stdout.trim();
}

function productionDependencyDigest(imports, reviewedWavesActive = false) {
  const reviewedImports = new Set(REVIEWED_PHASE5_WAVES.flatMap(({ imports: waveImports }) => waveImports));
  const localImports = imports.filter((name) => name.startsWith(MODULE_PREFIX) && !REVIEWED_POST_PHASE2_IMPORTS.has(name) &&
    !(reviewedWavesActive && reviewedImports.has(name))).sort();
  return `sha256:${createHash("sha256").update(`${localImports.join("\n")}\n`).digest("hex")}`;
}

export async function postPhase2MutationBoundaryFiles(root = ROOT, productionImports = null) {
  let imports = productionImports;
  if (imports === null) {
    imports = (await commandOutput(root, "go", ["list", "-deps", "-f", "{{.ImportPath}}", "./cmd/vsk-labs"], {
      env: pinnedGoEnvironment({ CGO_ENABLED: "0", GOOS: "linux", GOARCH: "amd64" }),
    })).split("\n").filter(Boolean);
  }
  const selected = new Set(POST_PHASE2_MUTATION_BOUNDARY_ROOTS);
  for (const relativeDirectory of postPhase2MutationBoundaryDirectories(imports)) {
    for (const filename of await filesBelow(path.join(root, relativeDirectory))) {
      const relative = path.relative(root, filename).split(path.sep).join("/");
      if (relative.endsWith("_test.go") || relative.includes("/testdata/")) continue;
      selected.add(relative);
    }
  }
  return [...selected].sort();
}

export async function postPhase2SourceOverride(root = ROOT, productionImports = []) {
  for (const relative of ["vendor", "go.work", "go.work.sum"]) {
    if (await pathExists(path.join(root, relative))) return relative;
  }
  const localReplaces = await commandOutput(root, "go", ["list", "-m", "-f", "{{if .Replace}}{{if not .Replace.Version}}{{.Path}}=>{{.Replace.Dir}}{{end}}{{end}}", "all"], {
    env: pinnedGoEnvironment(),
  });
  if (localReplaces !== "") return "local-replace";
  const unsafe = await firstUnsafeBoundaryEntry(root, productionImports);
  if (unsafe !== "") return "non-regular-source";
  try {
    await runCommand("go", ["mod", "verify"], {
      cwd: root, capture: true, timeoutMs: 120_000, env: pinnedGoEnvironment(),
    });
  } catch {
    return "module-cache-integrity";
  }
  return "";
}

export async function postPhase2MutationBoundaryDigest(root = ROOT, productionImports = null) {
  const digest = createHash("sha256");
  for (const relative of await postPhase2MutationBoundaryFiles(root, productionImports)) {
    digest.update(relative);
    digest.update("\0");
    digest.update(await readFile(path.join(root, relative)));
    digest.update("\0");
  }
  return `sha256:${digest.digest("hex")}`;
}

async function proofExists(root, proof) {
  const [kind, location, testName] = proof.split(":");
  if (kind === "node-test" && location && !testName) {
    try {
      await readFile(path.join(root, location));
      return true;
    } catch {
      return false;
    }
  }
  if (kind !== "go-test" || !location || !testName || !/^Test[A-Za-z0-9_]+$/.test(testName)) return false;
  const relative = location.replace(/^\.\//, "");
  const files = await filesBelow(path.join(root, relative));
  for (const filename of files.filter((candidate) => candidate.endsWith("_test.go"))) {
    if ((await readFile(filename, "utf8")).includes(`func ${testName}(`)) return true;
  }
  return false;
}

function regexpLiteral(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export async function executeScenarioProofs(manifest, root = ROOT, selected = null) {
  const requested = selected === null ? manifest.scenarios.map(({ id }) => id) : [...selected];
  const byID = new Map(manifest.scenarios.map((scenario) => [scenario.id, scenario]));
  const goGroups = new Map();
  const nodeFiles = new Set();
  for (const id of requested) {
    const scenario = byID.get(id);
    if (!scenario || !await proofExists(root, scenario.proof)) {
      return { status: "fail", codes: ["PHASE2_TRACEABILITY_GAP"], scenarios: [] };
    }
    const [kind, location, testName] = scenario.proof.split(":");
    if (kind === "go-test") {
      const names = goGroups.get(location) ?? [];
      names.push(testName);
      goGroups.set(location, names);
    } else if (kind === "node-test") {
      nodeFiles.add(location);
    } else {
      return { status: "fail", codes: ["PHASE2_TRACEABILITY_GAP"], scenarios: [] };
    }
  }
  try {
    for (const [goPackage, names] of [...goGroups].sort(([left], [right]) => left.localeCompare(right))) {
      const pattern = `^(?:${names.map(regexpLiteral).join("|")})$`;
      await runCommand("go", ["test", "-count=1", goPackage, "-run", pattern], {
        cwd: root, capture: true, timeoutMs: 180_000, env: pinnedGoEnvironment(),
      });
    }
    for (const filename of [...nodeFiles].sort()) {
      await runCommand(process.execPath, ["--test", filename], {
        cwd: root, capture: true, timeoutMs: 180_000, env: pinnedGoEnvironment(),
      });
    }
  } catch {
    return { status: "fail", codes: ["PHASE2_EVIDENCE_STALE"], scenarios: requested };
  }
  return { status: "pass", codes: [], scenarios: requested };
}

async function treeFingerprint(root) {
  const digest = createHash("sha256");
  for (const filename of await filesBelow(root)) {
    digest.update(path.relative(root, filename).split(path.sep).join("/"));
    digest.update("\0");
    digest.update(await readFile(filename));
    digest.update("\0");
  }
  return `sha256:${digest.digest("hex")}`;
}

export async function proveUnavailableMutations(root = ROOT) {
  const temporary = await mkdtemp(path.join(tmpdir(), "vsk-phase2-mutations-"));
  try {
    const binary = path.join(temporary, process.platform === "win32" ? "vsk-labs.exe" : "vsk-labs");
    const state = path.join(temporary, "state");
    await mkdir(path.join(state, "artifacts"), { recursive: true, mode: 0o700 });
    await writeFile(path.join(state, "authority.json"), `${JSON.stringify({
      recoveryEpoch: 1, stateRevision: 9, eventCount: 4, outboxCount: 2,
    })}\n`, { mode: 0o600 });
    await writeFile(path.join(state, "database.sqlite"), "synthetic-phase-2-database-fingerprint\n", { mode: 0o600 });
    await writeFile(path.join(state, "artifacts", "current.json"), "{\"synthetic\":true}\n", { mode: 0o600 });
    await runCommand("go", ["build", "-o", binary, "./cmd/vsk-labs"], {
      cwd: root, capture: true, timeoutMs: 120_000, env: pinnedGoEnvironment(),
    });
    const registry = JSON.parse(await readFile(path.join(root, "schemas/v1/command-registry.json"), "utf8"));
    const planned = registry.commands.filter(({ availability }) => availability === "planned")
      .map(({ path: commandPath }) => commandPath.join(" ")).sort();
    // These are forbidden shortcuts, not future planned commands. They must
    // fail at the real executable boundary before any state or private input
    // can be read, even after inert gate authoring becomes available.
    const prohibitedGateSetters = ["gate close", "gate pass", "gate profile bind", "gate profile apply"];
    const before = await treeFingerprint(state);
    for (const command of [...planned, ...prohibitedGateSetters]) {
      const invocation = spawnSync(binary, [...command.split(" "), "--output", "json", "--state-root", state, "private-canary"], {
        cwd: root, encoding: "utf8", shell: false,
      });
      let envelope;
      try {
        envelope = JSON.parse(invocation.stdout);
      } catch {
        return { status: "fail", codes: ["PHASE2_MUTATION_AVAILABLE"], commands: [], fingerprint: before };
      }
      if (invocation.status !== 2 || invocation.signal !== null || envelope.changed !== false ||
          envelope.status !== "failed" || envelope.errors?.[0]?.code !== "INPUT_INVALID" ||
          /private-canary|state-root|database\.sqlite/.test(invocation.stdout + invocation.stderr)) {
        return { status: "fail", codes: ["PHASE2_MUTATION_AVAILABLE"], commands: [], fingerprint: before };
      }
    }
    const after = await treeFingerprint(state);
    if (after !== before) {
      return { status: "fail", codes: ["PHASE2_MUTATION_AVAILABLE"], commands: [], fingerprint: before };
    }
    return { status: "pass", codes: [], commands: [...planned, ...prohibitedGateSetters], fingerprint: before };
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

export async function collectIntegratedFacts(root = ROOT) {
  const commands = JSON.parse(await readFile(path.join(root, "schemas/v1/command-registry.json"), "utf8"));
  const endpoints = JSON.parse(await readFile(path.join(root, "schemas/v1/endpoint-registry.json"), "utf8"));
  const migrationFiles = (await readdir(path.join(root, "internal/store/migrations")))
    .filter((name) => /^\d{4}_[a-z0-9_]+\.sql$/.test(name)).sort();
  const migrations = await Promise.all(migrationFiles.map(async (file) => ({
    file,
    sha256: await sha256(path.join(root, "internal/store/migrations", file)),
  })));
  const head = await commandOutput(root, "git", ["rev-parse", "HEAD"]);
  const children = [];
  for (const [issue, pr, mergeCommit] of EXPECTED_CHILDREN) {
    let state = "OPEN";
    try {
      await runCommand("git", ["merge-base", "--is-ancestor", mergeCommit, head], {
        cwd: root, capture: true, timeoutMs: 30_000,
      });
      state = "CLOSED";
    } catch {
      state = "OPEN";
    }
    children.push({ issue, pr, mergeCommit, state });
  }
  const productionImports = (await commandOutput(root, "go", [
    "list", "-deps", "-f", "{{.ImportPath}}", "./cmd/vsk-labs",
  ], { env: pinnedGoEnvironment({ CGO_ENABLED: "0", GOOS: "linux", GOARCH: "amd64" }) }))
    .split("\n").filter(Boolean).sort();
  const onePasswordSDKVersion = await commandOutput(root, "go", [
    "list", "-m", "-f", "{{.Version}}", "github.com/1password/onepassword-sdk-go",
  ], { env: pinnedGoEnvironment() });
  const credentialCommand = commands.commands.find(({ path: segments }) => segments.join(" ") === "credential import");
  const credentialImportEndpoint = endpoints.endpoints.find(({ id }) => id === "api.v1.credential-references.import-stream");
  const credentialEndpointIds = endpoints.endpoints.filter(({ id, availability }) => id.includes("credential-reference") && availability === "available").map(({ id }) => id).sort();
  const credentialImportFlags = credentialCommand?.flags?.map(({ name }) => name).sort() ?? [];
  const routerSource = await readFile(path.join(root, "internal/api/router.go"), "utf8");
  const operationsSource = await readFile(path.join(root, "internal/server/operations.go"), "utf8");
  const importStoreSource = await readFile(path.join(root, "internal/store/credential_import.go"), "utf8");
  const fixtureFiles = await filesBelow(path.join(root, "tooling/testdata/phase-2"));
  let privateFixture = false;
  for (const filename of fixtureFiles) {
    const content = await readFile(filename, "utf8");
    if (/BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|ghp_[A-Za-z0-9]|sk-[A-Za-z0-9]|\/Users\/|@vegastack\.(?:com|in)/i.test(content)) {
      privateFixture = true;
    }
  }
  return {
    testedCommit: head,
    schemaVersion: commands.schemaVersion,
    endpointSchemaVersion: endpoints.schemaVersion,
    availableCommands: commands.commands.filter(({ availability }) => availability === "available")
      .map(({ path: segments }) => segments.join(" ")).sort(),
    endpointIds: endpoints.endpoints.map(({ id }) => id).sort(),
    migrations,
    productionExecutable: "cmd/vsk-labs",
    postPhase2MutationBoundaryDigest: await postPhase2MutationBoundaryDigest(root, productionImports),
    postPhase2SourceOverride: await postPhase2SourceOverride(root, productionImports),
    mutationAvailable: commands.commands.some(({ availability, ownerPhase, path: segments }) =>
      availability === "available" && Number(ownerPhase) >= 4 &&
      !REVIEWED_POST_PHASE2_COMMANDS.has(segments.join(" ")) &&
      !REVIEWED_PHASE5_WAVES.some(({ commands: reviewed }) => reviewed.includes(segments.join(" ")))),
    productionImports,
    onePasswordSDKVersion,
    credentialImportFlags,
    credentialEndpointIds,
    credentialImportAvailability: credentialImportEndpoint?.availability ?? "missing",
    credentialImportRemoteAllowed: routerSource.includes("api.v1.credential-references.import-stream") || routerSource.includes("/api/v1/credential-references/"),
    credentialProductionResolverEnabled: !/func productionAdapterRegistry\(\) \*adapter\.Registry \{\s*return adapter\.NewRegistry\(\)\s*\}/s.test(operationsSource),
    credentialLiveGateEnabled: !operationsSource.includes("SecretGate: runengine.UnavailableGateVerifier{}"),
    credentialImportTouchesCurrentAuthority: ["credential_reference_versions", "credential_step_bindings", "credential_resolution_records"].some((table) => importStoreSource.includes(table)),
    privateFixture,
    children,
  };
}

export function validateEvidence(manifest, facts) {
  const codes = new Set();
  const scenarioIDs = [];
  if (!exactKeys(manifest, ["schemaVersion", "phase", "status", "contract", "children", "scenarios", "requirements"]) ||
      manifest.schemaVersion !== 1 || manifest.phase !== "2" ||
      manifest.status !== "implemented-awaiting-operator-acceptance" ||
      !exactKeys(manifest.contract, ["schemaVersion", "productionExecutable", "productionDependencyDigest", "postPhase2MutationBoundaryDigest", "mutationAvailable", "availableCommands", "endpointIds", "migrations", "reviewedWaves"]) ||
      !Array.isArray(manifest.children) || !Array.isArray(manifest.scenarios) || !Array.isArray(manifest.requirements)) {
    codes.add("PHASE2_TRACEABILITY_GAP");
  } else {
    const scenarioSet = new Set();
    for (const scenario of manifest.scenarios) {
      if (!exactKeys(scenario, ["id", "category", "ownerIssue", "proof"]) ||
          !/^[a-z0-9]+(?:[.-][a-z0-9]+)*$/.test(scenario.id) || scenarioSet.has(scenario.id) ||
          !["happy", "denial", "privacy", "recovery", "parity"].includes(scenario.category) ||
          !Number.isInteger(scenario.ownerIssue) || typeof scenario.proof !== "string") {
        codes.add("PHASE2_TRACEABILITY_GAP");
      }
      scenarioSet.add(scenario.id);
      scenarioIDs.push(scenario.id);
    }
    const requirementIDs = [];
    for (const requirement of manifest.requirements) {
      if (!exactKeys(requirement, ["requirementId", "module", "ownerIssue", "status", "scenarioIds"]) ||
          !["covered", "absent", "deferred"].includes(requirement.status) ||
          !Number.isInteger(requirement.ownerIssue) || !Array.isArray(requirement.scenarioIds) ||
          requirement.status === "covered" && requirement.scenarioIds.length === 0 ||
          requirement.scenarioIds.some((id) => !scenarioSet.has(id)) ||
          new Set(requirement.scenarioIds).size !== requirement.scenarioIds.length) {
        codes.add("PHASE2_TRACEABILITY_GAP");
      }
      requirementIDs.push(requirement.requirementId);
    }
    if (!same([...requirementIDs].sort(), REQUIREMENT_IDS) || new Set(requirementIDs).size !== requirementIDs.length) {
      codes.add("PHASE2_TRACEABILITY_GAP");
    }
    const expectedChildren = EXPECTED_CHILDREN.map(([issue, pr, mergeCommit]) => ({ issue, pr, mergeCommit }));
    const actualChildren = manifest.children.map(({ issue, pr, mergeCommit }) => ({ issue, pr, mergeCommit }));
    if (!same(actualChildren, expectedChildren) || manifest.children.some((child) =>
      !exactKeys(child, ["issue", "pr", "mergeCommit", "evidence", "review"]) ||
      !/^https:\/\/github\.com\/vegastack\/vegastack-labs\/issues\/\d+#issuecomment-\d+$/.test(child.evidence) ||
      !/^https:\/\/github\.com\/vegastack\/vegastack-labs\/issues\/\d+#issuecomment-\d+$/.test(child.review))) {
      codes.add("PHASE2_EVIDENCE_STALE");
    }
  }
  if (facts.children.some(({ state }) => state !== "CLOSED")) codes.add("PHASE2_CHILD_INCOMPLETE");
  const reviewedWaves = manifest.contract?.reviewedWaves;
  const waveRecordsValid = Array.isArray(reviewedWaves) && reviewedWaves.length === REVIEWED_PHASE5_WAVES.length &&
    reviewedWaves.every((wave, index) => {
      const expected = REVIEWED_PHASE5_WAVES[index];
      return exactKeys(wave, ["id", "issue", "commands", "imports", "mutationBoundaryDigest"]) &&
        wave.id === expected.id && wave.issue === expected.issue &&
        same(wave.commands, expected.commands) && same(wave.imports, expected.imports) &&
        wave.mutationBoundaryDigest === expected.mutationBoundaryDigest;
    });
  if (manifest.contract && (!waveRecordsValid ||
      manifest.contract.productionDependencyDigest !== PHASE2_BASELINE_DEPENDENCY_DIGEST ||
      manifest.contract.postPhase2MutationBoundaryDigest !== PHASE2_BASELINE_MUTATION_DIGEST)) {
    codes.add("PHASE2_TRACEABILITY_GAP");
  }
  const reviewedCommandPrefixes = ["gate ", "credential ", "audit ", "backup ", "recovery witness "];
  const availableReviewedCommands = facts.availableCommands.filter((name) =>
    reviewedCommandPrefixes.some((prefix) => name.startsWith(prefix)));
  const expectedReviewedCommands = REVIEWED_PHASE5_WAVES.flatMap(({ commands }) => commands).sort();
  const reviewedWaveImportsPresent = REVIEWED_PHASE5_WAVES.every(({ imports }) =>
    imports.every((name) => facts.productionImports.includes(name)));
  const availableCredentialCommands = facts.availableCommands.filter((name) => name.startsWith("credential "));
  const reviewedWavesActive = waveRecordsValid && same(availableReviewedCommands, expectedReviewedCommands) &&
    reviewedWaveImportsPresent &&
    facts.postPhase2MutationBoundaryDigest === reviewedWaves.at(-1).mutationBoundaryDigest;
  const historicalBaselineActive = availableReviewedCommands.length === 0 &&
    facts.postPhase2MutationBoundaryDigest === PHASE2_BASELINE_MUTATION_DIGEST;
  if (manifest.contract && (!same(manifest.contract.endpointIds, EXPECTED_ENDPOINT_IDS) ||
      !containsAll(facts.endpointIds, EXPECTED_ENDPOINT_IDS) ||
      !hasPrefix(facts.migrations, manifest.contract.migrations) ||
      !compatibleContractVersion(facts.schemaVersion, manifest.contract.schemaVersion) || facts.schemaVersion !== facts.endpointSchemaVersion ||
      manifest.contract.productionExecutable !== facts.productionExecutable)) {
    codes.add("PHASE2_CONTRACT_DRIFT");
  }
  if (manifest.contract && (manifest.contract.mutationAvailable !== false || facts.mutationAvailable ||
      !(reviewedWavesActive || historicalBaselineActive) ||
      facts.credentialImportAvailability !== "available" || !same(availableCredentialCommands, [...REVIEWED_CREDENTIAL_IMPORT_WAVE.commands, ...REVIEWED_CREDENTIAL_LIFECYCLE_SURFACE_WAVE.commands].sort()) ||
      !same(facts.credentialImportFlags, CREDENTIAL_IMPORT_FLAGS) || !same(facts.credentialEndpointIds, CREDENTIAL_IMPORT_ENDPOINTS) ||
      !facts.migrations.some((migration) => same(migration, CREDENTIAL_FOUNDATION_MIGRATION)) ||
      !facts.migrations.some((migration) => same(migration, CREDENTIAL_IMPORT_MIGRATION)) ||
      !same(manifest.contract.availableCommands, EXPECTED_AVAILABLE_COMMANDS) ||
      !containsAll(facts.availableCommands, EXPECTED_AVAILABLE_COMMANDS))) {
    codes.add("PHASE2_MUTATION_AVAILABLE");
  }
  if (manifest.contract && (manifest.contract.productionDependencyDigest !== productionDependencyDigest(facts.productionImports, reviewedWavesActive) ||
      availableReviewedCommands.length > 0 && !reviewedWaveImportsPresent ||
      facts.onePasswordSDKVersion !== ONEPASSWORD_SDK_VERSION || facts.credentialImportRemoteAllowed ||
      facts.credentialProductionResolverEnabled || facts.credentialLiveGateEnabled || facts.credentialImportTouchesCurrentAuthority ||
      facts.postPhase2SourceOverride !== "" ||
      facts.productionImports.some((name) => /phase2(?:fixture|harness)/i.test(name)))) {
    codes.add("PHASE2_PRODUCTION_BYPASS");
  }
  if (facts.privateFixture) codes.add("PHASE2_PRIVATE_FIXTURE");
  const ordered = CODE_ORDER.filter((code) => codes.has(code));
  return { status: ordered.length === 0 ? "pass" : "fail", codes: ordered, scenarios: scenarioIDs };
}

async function main() {
  const manifest = JSON.parse(await readFile(path.join(ROOT, MANIFEST_PATH), "utf8"));
  const facts = await collectIntegratedFacts(ROOT);
  for (const scenario of manifest.scenarios) {
    if (!await proofExists(ROOT, scenario.proof)) {
      const result = { status: "fail", codes: ["PHASE2_TRACEABILITY_GAP"], scenarios: [] };
      process.stdout.write(`${JSON.stringify({ schemaVersion: 1, check: "phase-2", testedCommit: facts.testedCommit, ...result })}\n`);
      process.exitCode = 1;
      return;
    }
  }
  const result = validateEvidence(manifest, facts);
  process.stdout.write(`${JSON.stringify({ schemaVersion: 1, check: "phase-2", testedCommit: facts.testedCommit, ...result })}\n`);
  if (result.status !== "pass") process.exitCode = 1;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`phase 2 verification failed: ${error.message}\n`);
    process.exitCode = 1;
  });
}
