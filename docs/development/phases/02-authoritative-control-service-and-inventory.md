# Development phase 2 — Authoritative control service and inventory

Status: implemented; awaiting operator acceptance. Phase 1 was accepted by (omkarmohanta09) on 08-09-2026 at integrated `main` commit `ed8629080c7797b3aca11dc9b7a1a9a3fde2c337`. Issues 2.1 through 2.9 are integrated on `main` at `8d4a07bedc8d2aaadb479dab73210435c907f24a`; Issue 2.10 (#38) owns the combined candidate, merge, and post-merge proof. Neither this status nor a later merge declares Phase 2 accepted without the operator's explicit acceptance.

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
| **2.5** | Append canonical attributed events and required destination-neutral outbox intents atomically with state transactions. | Integrated 2.1, 2.2, and 2.3 contracts; owns migration `0003` only. | [Issue 2.5 (#33)](https://github.com/vegastack/vegastack-labs/issues/33) |
| **2.6** | Create verified SQLite Online Backup generations with strict secret-free manifests, atomic no-replace discovery, crash/fault proof, and isolated pre-migration restore without replacing authority. | 2.2; owns no migration and may proceed alongside 2.3 and 2.5. Phase 5 retains encryption, signing, scheduling, retention, writer fencing, real restore/cutover, and recovery-epoch transition. | [Issue 2.6 (#34)](https://github.com/vegastack/vegastack-labs/issues/34) |
| **2.7** | Serve authorized versioned health, state, inventory, and durable-event reads with stable cursors and replay. | 2.1, 2.2, 2.3, and 2.5. | [Issue 2.7 (#35)](https://github.com/vegastack/vegastack-labs/issues/35) |
| **2.8** | Expose `status`, `database status`, `inventory import`, `inventory diff`, and `inventory export` only as clients of the protected API, with exact-envelope JSON parity and sanitized human output. | 2.3, 2.4, 2.7, and 2.9. | [Issue 2.8 (#36)](https://github.com/vegastack/vegastack-labs/issues/36) |
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

Issue #32 adds `internal/profiles/labsinventory` as an offline deployment-profile decoder through Issue #31's `inventory.CandidateDecoder` interface. Format `labs-sheet1-csv`, adapter version `1.0.0`, and header-contract version `1.0.0` bind the exact 15-column case-sensitive projection documented in [Inventory and roles](../../inventory-and-roles.md#offline-labs-sheet1-csv-profile). The source digest covers exact original bytes; parsing is bounded to 4 MiB, 4,097 records including the header, 15 fields per data row, and 1,024 UTF-8 bytes per field. The adapter also rejects an expanded candidate that would exceed Issue #31's primary-record, fact, identity, or provenance bounds before it reaches normalization or persistence.

Every row remains a physical candidate asset. Exact active-row order alone proposes `vsk-node-NN` display aliases; serial is the only imported identity, while reported hostname is another alias observation. Quarantined, retired, blank, or unsupported lifecycle rows consume no ordinal. Factory/current RAM and SSD/HDD values remain separate decimal-byte facts with separate provenance, current marked preferred; invalid current input never silently falls back or survives as raw text. All 15 cells have reported, missing, invalid, or quarantined provenance, and derived aliases carry their own provenance.

Byte/CSV/header/limit/formula/control/private-data and cancellation failures are fatal and sanitized. Safe lifecycle, serial, numeric, duplicate-identity, and alias conflicts preserve the complete candidate plus blocking findings for Issue #31 to normalize and order. The package imports only provider-neutral inventory contracts and Go standard-library parsing; it contains no SQL, migration, generated contract, CLI/API, source file opener, network/provider client, Google/OAuth code, accepted-state transition, or host action. The checked-in [header template](../../examples/labs-sheet1-import-v1-header.csv) and [populated example](../../examples/labs-sheet1-import-v1-example.csv) are synthetic public fixtures only. Issue #36 owns later trusted file opening, source metadata, format selection, authenticated API/CLI dispatch, rendering, and persistence composition.

## Frozen Issue 2.5 attributed-event boundary

Issue #33 adds provider-neutral closed audit-event and outbox-record contracts plus store-owned migration `0003_audit_outbox`. Every changed inventory intent commits all draft rows, one ordered canonical event, one generic intent binding, every required destination row, and one `state_revision` increment in the same immediate transaction, or commits none. Exact replay returns the original event and revision without writing. Event IDs equal a separate monotonic `audit_sequence`; corrections append a new event linked to an earlier event for the same target.

Attribution accepts the authenticated principal only from Issue #29's verified request context. A request body cannot assert that identity. A responsible human may come only from a separately trusted server context, while agent name/session values are explicitly `self-reported` evidence and never authenticate or authorize. Event payloads contain fixed bounded identifiers, times, revisions, links, target and optional before/after SHA-256 fingerprints; they contain no map, raw source, snapshot, path, prompt, provider response, raw error or secret.

Each enabled destination creates a durable `pending` row and each disabled destination creates a nonblocking `paused` row. The remaining states are `retry_wait`, `delivered`, and `dead_letter`; delivery permits at most 8 attempts with `min(30s * 2^(attempt-1), 1h)` backoff and stable allowlisted error codes only. Schema, version, canonical bytes and SHA-256 are verified before payload release; mismatch is quarantined as `PAYLOAD_INVALID` and enters safe mode without an external call. `AppendOperationalAudit` is the narrow Issue #37 seam: it appends an event/binding/outbox transaction and advances only `audit_sequence`, never `state_revision`, and cannot run business SQL.

This boundary supplies durable local state and transition/inspection methods only. It does not make an audit query or CLI available and implements no sender, worker, claim/lease loop, provider adapter, external projection, hash chain, signing, retention, or live authority.

## Frozen Issue 2.9 signed draft-export boundary

Issue #37 adds a provider-neutral `inventory-draft-snapshot` service for one explicitly selected immutable `valid` or `blocked` draft revision. A closed encoder produces byte-stable payload JSON, binds its SHA-256 digest to `vsk-labs:inventory-draft-export:v1`, and publishes only after an injected verifier independently accepts the signer metadata and signature. The Linux store writes a protected immutable `artifacts/sha256-<digest>.json`, then atomically advances `current.json`; an interrupted terminal audit write is reconciled by verifying retained artifacts, restoring the prior pointer or absence, and appending `inventory.export.interrupted`. Requested/published/failed/interrupted events use Issue #33's audit-only seam, so exports advance `audit_sequence` but never `state_revision`. There is no Issue #37 migration, export table, private path in a result, or database dump.

The only Phase 2 signing implementation is a fixed public synthetic Ed25519 fixture compiled exclusively in tests. Production composition deliberately supplies neither signer nor verifier: an attempt records a sanitized requested/failed pair and returns `PREREQUISITE_BLOCKED` without calling the artifact store. This is development proof of the contract, not live signing trust or recovery authority. Phase 5 must replace that temporary decision with a qualified deployment policy covering export signing identity and public trust distribution, provider/keystore selection, custody and least privilege, key-ID/fingerprint ownership, rotation overlap and revocation, retained verification keys and offline access, loss/compromise response, restore-time key selection, a tested recovery procedure, positive/negative clean-node evidence, and whether export and audit-checkpoint purposes require distinct keys.

## Verification, recovery, and combined exit

### Issue 2.7 authorized read boundary

The Issue 2.7 candidate owns migration `0004_read_authorization`. It creates empty-by-default local-principal and resource-grant tables; it seeds no service owner, administrator, wildcard, or production grant. Later trusted setup work owns real grant creation. Kernel peer identity is authorized before request path/query/cursor or `Last-Event-ID` parsing, and the resulting scope and grant revision are rechecked inside every short SQLite read. Inventory routes remain beneath `/api/v1/inventory-drafts/{draftId}/revisions/{revision}` and expose draft authority only.

Finite reads use closed generated data schemas in the existing result envelope, `Cache-Control: no-store`, a 4 MiB response ceiling, explicit SQL columns, strict keysets, and a default/cap of 50/200. HMAC-SHA-256 cursors expire after 15 minutes and intentionally become invalid when the server restarts; durable audit event IDs do not. SSE replays strictly after a known ID in batches of 200, reauthorizes every batch, coalesces at most 64 commit hints per subscriber, heartbeats every 15 seconds, applies a 5-second write deadline, and admits at most 16 streams process-wide and 4 per principal. No read transaction remains open while waiting or writing.

### Issue 2.8 draft-only operator boundary

Issue 2.8 (#36) makes `status`, `database status`, `inventory import`, `inventory diff`, and `inventory export` available through the generated CLI and the same protected local API. The three operation routes authorize the authenticated principal and exact resource scope before reading a request body or resolving a candidate. The client can read only an explicit protected config and, for a file candidate, one explicit protected local file; it has no SQLite, provider, Google, shell, arbitrary-network, or server-path route.

Import requires an explicit `typed-json` or `labs-sheet1-csv` format, source revision, UTC capture time, and opaque idempotency key. It creates only a complete immutable `valid` or `blocked` draft. Diff resolves the candidate and latest authorized compatible baseline at one state revision; that baseline is explicitly labeled `draft`, excludes the candidate itself, and returns `PREREQUISITE_BLOCKED` when no compatible baseline exists. It never persists a file candidate. Issue #37 alone may publish the signed secret-free draft export; missing qualified signing trust returns `PREREQUISITE_BLOCKED` without replacing the last verified artifact.

Human output and JSON consume the same typed result. JSON is the exact validated server envelope, including its request ID, revision, status, errors, exit meaning, and final newline. Redirecting client stdout may retain that response, but it does not create or replace the server's verified signed artifact. The human fallback is to inspect every finding and diff, correct the owning source through its human workflow, and import a new immutable draft. Never edit SQLite, the source Sheet, the protected export root, or infrastructure directly.

Rollback before merge is branch abandonment. After merge, migration `0004` is immutable: corrections use a forward migration and corrective pull request. Code rollback is not database recovery, and event IDs are never renumbered or deleted. This candidate evidence does not accept Phase 2, create real grants, deploy the service, or close a live implementation gate; Issue #38 retains combined acceptance.

All fixtures are synthetic fixtures with no real operational data, credentials, private rows, or production signing keys. Narrow tests precede repository-wide race, build, generated-drift, analyzer, and complete public checks. Supported Linux behavior receives build-tagged filesystem, credential, lock, replacement, signal and recovery tests; unsupported targets must fail before touching a supplied path.

Recovery evidence is capability-specific: socket cleanup never removes a replacement, a failed migration preserves evidence and restores only through the approved verified-copy seam, and exports publish only after verification. None of those development tests authorizes a live recovery or makes an off-site disaster-recovery claim.

Issue #33 acceptance evidence includes Linux race/fault/concurrency tests, abrupt subprocess exits before and after commit, reopen verification of canonical bytes/digests and retry state, and whole-file public-canary scans across SQLite and rollback-journal artifacts. A pre-commit crash leaves none of the business/event/intent/outbox layers; a post-commit lost reply leaves all of them and requires safe recovery rather than a guessed write.

Issue #38 is the combined acceptance owner. It must map every Phase 2 row to integrated evidence from one reviewed merged commit, prove authorization denials, safe states, the full checksummed migration catalog, immutable complete draft imports, online copies, durable replay, deterministic exports, CLI/API parity, and absence of any available infrastructure mutation. A green child issue, merged PR, or milestone state is insufficient; only explicit operator acceptance can close the phase.

## Integrated Phase 2 evidence

The checked [`phase-2-evidence.json`](../../../tooling/phase-2-evidence.json) manifest maps the roadmap row and every Phase 2 candidate row from Modules 1, 2, and 7 to one owner and one or more executable scenarios. `node tooling/verify-phase-2.mjs` fails closed on a missing child, traceability gap, command/endpoint/migration drift, available mutation, production fixture reachability, private fixture, or stale evidence. The fixtures and results are publication-safe development fixture proof, not live evidence: they do not qualify a host, grant, signer, backup repository, provider, or deployment gate.

| Delivered issue | Integrated PR and merge | Implementation evidence | Fresh child review |
|---|---|---|---|
| Issue 2.1 (#29) | [PR #40](https://github.com/vegastack/vegastack-labs/pull/40), `61dd286` | [evidence](https://github.com/vegastack/vegastack-labs/issues/29#issuecomment-5585481513) | [review](https://github.com/vegastack/vegastack-labs/issues/29#issuecomment-5585367133) |
| Issue 2.2 (#30) | [PR #41](https://github.com/vegastack/vegastack-labs/pull/41), `478c1d7` | [evidence](https://github.com/vegastack/vegastack-labs/issues/30#issuecomment-5585806131) | [review](https://github.com/vegastack/vegastack-labs/issues/30#issuecomment-5585672312) |
| Issue 2.3 (#31) | [PR #43](https://github.com/vegastack/vegastack-labs/pull/43), `81b0d8e` | [evidence](https://github.com/vegastack/vegastack-labs/issues/31#issuecomment-5588909269) | [review](https://github.com/vegastack/vegastack-labs/issues/31#issuecomment-5588748589) |
| Issue 2.4 (#32) | [PR #44](https://github.com/vegastack/vegastack-labs/pull/44), `2bc14ca` | [evidence](https://github.com/vegastack/vegastack-labs/issues/32#issuecomment-5598837793) | [review](https://github.com/vegastack/vegastack-labs/issues/32#issuecomment-5598430045) |
| Issue 2.5 (#33) | [PR #45](https://github.com/vegastack/vegastack-labs/pull/45), `04f555f` | [evidence](https://github.com/vegastack/vegastack-labs/issues/33#issuecomment-5599207569) | [review](https://github.com/vegastack/vegastack-labs/issues/33#issuecomment-5599181440) |
| Issue 2.6 (#34) | [PR #42](https://github.com/vegastack/vegastack-labs/pull/42), `1dc2e9f` | [evidence](https://github.com/vegastack/vegastack-labs/issues/34#issuecomment-5588858872) | [review](https://github.com/vegastack/vegastack-labs/issues/34#issuecomment-5588704434) |
| Issue 2.7 (#35) | [PR #46](https://github.com/vegastack/vegastack-labs/pull/46), `4118272` | [evidence](https://github.com/vegastack/vegastack-labs/issues/35#issuecomment-5605967158) | [review](https://github.com/vegastack/vegastack-labs/issues/35#issuecomment-5605914477) |
| Issue 2.8 (#36) | [PR #48](https://github.com/vegastack/vegastack-labs/pull/48), `8d4a07b` | [evidence](https://github.com/vegastack/vegastack-labs/issues/36#issuecomment-5609023926) | [review](https://github.com/vegastack/vegastack-labs/issues/36#issuecomment-5608924722) |
| Issue 2.9 (#37) | [PR #47](https://github.com/vegastack/vegastack-labs/pull/47), `34e9e9d` | [evidence](https://github.com/vegastack/vegastack-labs/issues/37#issuecomment-5606248613) | [review](https://github.com/vegastack/vegastack-labs/issues/37#issuecomment-5605983952) |

Reported child effort is intentionally incomplete rather than reconstructed from timestamps: #29 reported 78 minutes 30 seconds against 70–90 estimated; #32 reported about 110 against 60–80; #33 reported about 92 against 90–120; #35 reported about 267 including its CI correction against 95–125; and #37 reported about 276 against 85–115. Issues #30, #31, #34, and #36 did not record an unambiguous total in their current evidence comments. Issue #38 reports its own measured time at hand-back; parallel agent clocks and external CI waits are not added as elapsed wall time.

### Phase 3 handoff

Phase 3 planning may consume only the accepted read contracts: the generated API schemas, protected local identity and authorization boundary, finite pagination/cursors, durable event replay, exact CLI envelopes, and truthful `mutationAvailable=false` state. It must separately plan the embedded Console, browser authentication/session/revocation, generated web client, accessibility, and browser security controls. Phase 3 is not approved or started by this record, and it cannot treat Phase 2 fixtures as live Access, provider, or host evidence.

## Effort and approvals

Issue #29 estimates 70–90 agent minutes, a 180-minute 2× checkpoint, 8–10 minutes of operator review, and 5–15 minutes of external public-CI wait if invoked. Its basis is 16–22 source/generated/test/documentation files, six implementation/review turns, Linux and unsupported seams, five target builds, two complete checks, and fresh security review. Each later issue records its own estimate and actuals.

Approval record: (omkarmohanta09) accepted Phase 1 on 08-09-2026 and approved the Phase 2 briefs and Plan v1 for Issues #29–#38. The operator later authorized the complete dependency-ordered Phase 2 development and shipping workflow, including Issue #38, while release, repository administration, credentials, provider resources, hosts, networks, databases outside synthetic fixtures, deployment, Phase 2 acceptance, and every live infrastructure action remain separately gated.
