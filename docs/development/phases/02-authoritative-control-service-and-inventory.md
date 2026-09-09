# Development phase 2 — Authoritative control service and inventory

Status: active. Phase 1 was accepted by (omkarmohanta09) on 08-09-2026 at integrated `main` commit `ed8629080c7797b3aca11dc9b7a1a9a3fde2c337`. Issues 2.1, 2.2, 2.3, and 2.6 are integrated; Issue 2.4 consumes the frozen 2.3 boundary, and every later issue retains its own dependency and approved-plan prerequisite. Issue 2.10 (#38) owns the combined exit proof and cannot declare this phase accepted without explicit operator acceptance.

## Outcome and authority boundary

Phase 2 establishes one protected, local `vsk-labs server run` authority, one server-owned SQLite state store, inert typed inventory drafts, attributed events, authorized read APIs and clients, verified online recovery copies, and deterministic signed declaration exports. `vsk-labs` remains the only executable. The service uses one versioned HTTP API over its protected Unix-domain socket; there is no second daemon, SQLite client path, or provider-specific core schema.

This phase does not install a service, qualify a live host, read a real Google Sheet, accept an inventory declaration, operate a provider, expose a browser endpoint, execute a plan, mutate infrastructure, publish a release, or close a deployment gate. A draft stays inert. Cross-builds and synthetic operating-system fixtures are development proof, not a Debian host-support or deployment claim.

## Ordered issue index

| Issue ID | Outcome and required proof | Dependencies | GitHub link |
|---|---|---|---|
| **2.1** | Run the single foreground local control service with kernel-authenticated peers, protected socket ownership, health, and bounded signal shutdown. | Accepted Phase 1 at `ed86290`; approved Plan v1. | [Issue 2.1 (#29)](https://github.com/vegastack/vegastack-labs/issues/29) |
| **2.2** | Make the service the only writable SQLite owner with checksummed migrations, transaction/revision primitives, integrity checks, and truthful safe mode. | Accepted Phase 1; its store/server ports are frozen with 2.1. | [Issue 2.2 (#30)](https://github.com/vegastack/vegastack-labs/issues/30) |
| **2.3** | Validate and persist complete provider-neutral, revisioned, inert `valid` or `blocked` inventory drafts with typed provenance, deterministic findings and exact-retry idempotency. | Integrated 2.2 store at `478c1d7`; owns migration `0002` only. | [Issue 2.3 (#31)](https://github.com/vegastack/vegastack-labs/issues/31) |
| **2.4** | Decode one bounded, exact-header, sanitized Labs Sheet1 CSV into the generic inert candidate with complete safe provenance/findings and no Google access. | Integrated 2.3 at `81b0d8e`; owns profile decoder and templates only. | [Issue 2.4 (#32)](https://github.com/vegastack/vegastack-labs/issues/32) |
| **2.5** | Append canonical attributed events and required destination-neutral outbox intents atomically with state transactions. | 2.1 and 2.2. | [Issue 2.5 (#33)](https://github.com/vegastack/vegastack-labs/issues/33) |
| **2.6** | Create verified SQLite Online Backup generations with strict secret-free manifests, atomic no-replace discovery, crash/fault proof, and isolated pre-migration restore without replacing authority. | 2.2; owns no migration and may proceed alongside 2.3 and 2.5. Phase 5 retains encryption, signing, scheduling, retention, writer fencing, real restore/cutover, and recovery-epoch transition. | [Issue 2.6 (#34)](https://github.com/vegastack/vegastack-labs/issues/34) |
| **2.7** | Serve authorized versioned health, state, inventory, and durable-event reads with stable cursors and replay. | 2.1, 2.2, 2.3, and 2.5. | [Issue 2.7 (#35)](https://github.com/vegastack/vegastack-labs/issues/35) |
| **2.8** | Expose status, database status, inventory import/export/diff only as clients of the protected API. | 2.3, 2.4, 2.7, and 2.9. | [Issue 2.8 (#36)](https://github.com/vegastack/vegastack-labs/issues/36) |
| **2.9** | Render, digest, sign, verify, and atomically preserve deterministic secret-free declaration exports. | 2.2, 2.3, and 2.5. | [Issue 2.9 (#37)](https://github.com/vegastack/vegastack-labs/issues/37) |
| **2.10** | Prove the combined Phase 2 outcome across Modules 1, 2, and 7 and present it for explicit acceptance. | 2.1 through 2.9 merged with integrated checks and current contracts. | [Issue 2.10 (#38)](https://github.com/vegastack/vegastack-labs/issues/38) |

## Dependency graph

```text
accepted Phase 1
  +-- 2.1 --+-- 2.5 ----+-- 2.7 --+-- 2.8 --+
  |         |           |         |          |
  +-- 2.2 --+-- 2.3 --+-+-- 2.9 --+          +-- 2.10
             |         |                       |
             +-- 2.4 --+-----------------------+
             +-- 2.6 --------------------------+
```

The graph records prerequisites rather than a required serial schedule. Issues whose frozen interfaces do not overlap may run in separate isolated sessions; each still re-grounds against its exact base and owns its own review and evidence.

## Frozen Issue 2.1 ports

Issue #29 owns the process, protected socket, peer authentication, common result construction, and lifecycle seams. The portable server core carries no SQLite or provider dependency.

- `StateAuthority` is the narrow health/close port that #30 implements behind the composition layer. `Application` is the lifecycle and HTTP port that #35 implements or extends after #30's state authority is available. Neither dependent issue creates another listener or opens SQLite from a client.
- `ApplicationHealth`, `AuthorityHealth`, and generated `ServerStatusData` preserve safe mode, recovery epoch, and state revision without making mutation availability true.
- The server obtains the Linux peer UID from `SO_PEERCRED`, resolves it through a protected profile to one stable principal, and places only that verified principal in request context. Caller headers never establish identity. Permissions and grants are later authoritative SQLite state; the profile contains bindings, not grants.
- `internal/localapi.Client` reaches only the configured Unix socket, while the generated CLI dispatch preserves the exact versioned result envelope. #30 owns database/migration schemas and #35 owns additional `/api/v1` read routes; neither may redefine these ports or create a competing API/result contract.

The server profile is bounded, strict, protected non-secret configuration. It may contain local UID-to-principal bindings, socket facts, and shutdown policy. It contains no credential value, authorization grant, private inventory row, or alternate operational authority.

## Data, migration, and API ownership

Issue #30 exclusively owns SQLite initialization, migration and transaction primitives. Its `0001_store_foundation` migration creates only `system_meta` and the append-only migration ledger; #31 owns `0002` inventory, #33 owns `0003` audit/outbox, #35 owns `0004` read authorization, and #34/#37 own no migration. Fresh exclusive initialization is the only path without a verified prior snapshot. Existing-database upgrades must obtain a verified online copy before SQL, and a failed migration verifies restoration only against an isolated target without replacing authority; Phase 5 retains fencing, authority replacement, and accepted `recovery_epoch` cutover. Issue #34 consumes the supported Online Backup API seam rather than copying a live database. Issue #31 owns generic inventory-draft schemas and validation; #32 maps sanitized CSV into those contracts without adding Labs fields to core types. Issue #33 owns event/outbox atomicity. Issue #35 composes the store-backed application and authorized reads behind #29's existing `Application` route, and #36 consumes those reads through the existing local client. Issue #37 owns canonical declaration export/signing but no private key or database dump. Issue #38 proves the final executable dependency closure.

Issue #34's local recovery layout is `<snapshot-root>/<snapshot-id>/{database.sqlite,manifest.json}`. Same-root `.staging-*` and `.restore-*` directories are never discoverable as generations. Database, manifest, staging-directory, rename, and root-directory sync boundaries are tested in subprocesses: pre-rename interruption remains incomplete, while a post-rename generation that passes strict reopen validation is retained even when no success response was returned. Migration backup or verification failure prevents SQL; migration failure preserves the original error and authority, then tests only an isolated restored copy. This is development recovery evidence, not a live restore or deployment-gate result.

Later issues update only their issue row, owned contract subsection, and accumulated acceptance evidence after Issue #29 merges. Generated definitions remain the single public-contract source; reserved migration and API ownership links are not permission to define parallel formats early.

## Frozen Issue 2.3 inventory-draft boundary

Issue #31 adds generated provider-neutral JSON input and result contracts, `DecodedCandidate{Candidate, Findings}`, strict local decoding, deterministic normalization/validation, and immutable normalized draft storage. The input has no Labs node, domain, provider, Google or Sheet-column field. Issue #32 may translate a sanitized profile source into this contract, but cannot widen core types or reach SQLite; Issues #35 and #36 own later authenticated reads and presentation, so this implementation does not make an inventory command or API route available.

Input is bounded to 4 MiB and JSON depth 32. The combined asset/node/alias/address/observation count is at most 4,096; hardware facts at most 16,384; provenance rows at most 32,768; identities and facts per asset at most 64 each; identifiers/tokens are at most 128 UTF-8 bytes, locators 256, and ordinary text 1,024. Malformed, unknown-field, wrong-schema, over-limit, cancelled or high-confidence secret-bearing input is fatal: it creates no draft, child row or import-key binding and does not advance `state_revision`. Safe semantic conflicts retain the whole normalized candidate plus ordered findings as `blocked`; a conflict never produces a valid-only subset.

Migration `0002_inventory_drafts` owns only the immutable draft namespace. One nonempty opaque idempotency key is retained only as a SHA-256 digest and bound to canonical content. Exact reuse returns the original draft reference without a write or revision increment; changed content under the same key, or a changed exact-source digest under the same nonempty source identity, fails closed. There is no update/delete repair and no transition to declared, effective, qualified, trusted, admitted, named or configured state. A later canonical signed representation must retain `kind=draft`. Existing-database upgrades continue to require Issue #30's verified pre-migration snapshot; failure rolls back, verifies recovery only in an isolated target, and never overwrites the authority automatically.

## Frozen Issue 2.4 Labs CSV profile boundary

Issue #32 adds `internal/profiles/labsinventory` as an offline deployment-profile decoder through Issue #31's `inventory.CandidateDecoder` interface. Format `labs-sheet1-csv`, adapter version `1.0.0`, and header-contract version `1.0.0` bind the exact 15-column case-sensitive projection documented in [Inventory and roles](../../inventory-and-roles.md#offline-labs-sheet1-csv-profile). The source digest covers exact original bytes; parsing is bounded to 4 MiB, 4,097 records including the header, 15 fields per data row, and 1,024 UTF-8 bytes per field.

Every row remains a physical candidate asset. Exact active-row order alone proposes `vsk-node-NN` display aliases; serial is the only imported identity, while reported hostname is another alias observation. Quarantined, retired, blank, or unsupported lifecycle rows consume no ordinal. Factory/current RAM and SSD/HDD values remain separate decimal-byte facts with separate provenance, current marked preferred; invalid current input never silently falls back or survives as raw text. All 15 cells have reported, missing, invalid, or quarantined provenance, and derived aliases carry their own provenance.

Byte/CSV/header/limit/formula/control/private-data and cancellation failures are fatal and sanitized. Safe lifecycle, serial, numeric, duplicate-identity, and alias conflicts preserve the complete candidate plus blocking findings for Issue #31 to normalize and order. The package imports only provider-neutral inventory contracts and Go standard-library parsing; it contains no SQL, migration, generated contract, CLI/API, source file opener, network/provider client, Google/OAuth code, accepted-state transition, or host action. The checked-in [header template](../../examples/labs-sheet1-import-v1-header.csv) and [populated example](../../examples/labs-sheet1-import-v1-example.csv) are synthetic public fixtures only. Issue #36 owns later trusted file opening, source metadata, format selection, authenticated API/CLI dispatch, rendering, and persistence composition.

## Verification, recovery, and combined exit

All fixtures are synthetic fixtures with no real operational data, credentials, private rows, or production signing keys. Narrow tests precede repository-wide race, build, generated-drift, analyzer, and complete public checks. Supported Linux behavior receives build-tagged filesystem, credential, lock, replacement, signal and recovery tests; unsupported targets must fail before touching a supplied path.

Recovery evidence is capability-specific: socket cleanup never removes a replacement, a failed migration preserves evidence and restores only through the approved verified-copy seam, and exports publish only after verification. None of those development tests authorizes a live recovery or makes an off-site disaster-recovery claim.

Issue #38 is the combined acceptance owner. It must map every Phase 2 row to integrated evidence from one reviewed merged commit, prove authorization denials, safe states, the full checksummed migration catalog, immutable complete draft imports, online copies, durable replay, deterministic exports, CLI/API parity, and absence of any available infrastructure mutation. A green child issue, merged PR, or milestone state is insufficient; only explicit operator acceptance can close the phase.

## Effort and approvals

Issue #29 estimates 70–90 agent minutes, a 180-minute 2× checkpoint, 8–10 minutes of operator review, and 5–15 minutes of external public-CI wait if invoked. Its basis is 16–22 source/generated/test/documentation files, six implementation/review turns, Linux and unsupported seams, five target builds, two complete checks, and fresh security review. Each later issue records its own estimate and actuals.

Approval record: (omkarmohanta09) accepted Phase 1 on 08-09-2026, approved the Phase 2 briefs #29–#38, approved Plan v1 for Issues #29 and #30, and authorized their separate parallel implementation sessions on 08-09-2026. That authority covers only named development branches, commits, tests, issue comments, and review. Pull requests, pushes, merges, releases, repository administration, credentials, provider resources, hosts, networks, databases outside synthetic fixtures, deployment, and every live infrastructure action remain separately gated.
