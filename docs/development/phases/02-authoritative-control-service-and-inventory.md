# Development phase 2 — Authoritative control service and inventory

Status: active. Phase 1 was accepted by (omkarmohanta09) on 08-09-2026 at integrated `main` commit `ed8629080c7797b3aca11dc9b7a1a9a3fde2c337`. The Issue 2.1 and 2.2 implementation plans are the current approved parallel batch; every later issue retains its own approved-plan prerequisite. Issue 2.10 (#38) owns the combined exit proof and cannot declare this phase accepted without explicit operator acceptance.

## Outcome and authority boundary

Phase 2 establishes one protected, local `vsk-labs server run` authority, one server-owned SQLite state store, inert typed inventory drafts, attributed events, authorized read APIs and clients, verified online recovery copies, and deterministic signed declaration exports. `vsk-labs` remains the only executable. The service uses one versioned HTTP API over its protected Unix-domain socket; there is no second daemon, SQLite client path, or provider-specific core schema.

This phase does not install a service, qualify a live host, read a real Google Sheet, accept an inventory declaration, operate a provider, expose a browser endpoint, execute a plan, mutate infrastructure, publish a release, or close a deployment gate. A draft stays inert. Cross-builds and synthetic operating-system fixtures are development proof, not a Debian host-support or deployment claim.

## Ordered issue index

| Issue ID | Outcome and required proof | Dependencies | GitHub link |
|---|---|---|---|
| **2.1** | Run the single foreground local control service with kernel-authenticated peers, protected socket ownership, health, and bounded signal shutdown. | Accepted Phase 1 at `ed86290`; approved Plan v1. | [Issue 2.1 (#29)](https://github.com/vegastack/vegastack-labs/issues/29) |
| **2.2** | Make the service the only writable SQLite owner with checksummed migrations, transaction/revision primitives, integrity checks, and truthful safe mode. | Accepted Phase 1; its store/server ports are frozen with 2.1. | [Issue 2.2 (#30)](https://github.com/vegastack/vegastack-labs/issues/30) |
| **2.3** | Validate and persist provider-neutral, revisioned, inert inventory drafts with typed provenance and deterministic findings. | 2.2. | [Issue 2.3 (#31)](https://github.com/vegastack/vegastack-labs/issues/31) |
| **2.4** | Convert an explicit sanitized Labs Sheet1 CSV into the generic inert inventory-draft contract without Google access. | 2.3; may follow its frozen interfaces in parallel with generic API work. | [Issue 2.4 (#32)](https://github.com/vegastack/vegastack-labs/issues/32) |
| **2.5** | Append canonical attributed events and required destination-neutral outbox intents atomically with state transactions. | 2.1 and 2.2. | [Issue 2.5 (#33)](https://github.com/vegastack/vegastack-labs/issues/33) |
| **2.6** | Create and verify SQLite Online Backup API snapshots and prove isolated pre-migration recovery. | 2.2; may proceed alongside 2.3 and 2.5 with migration ownership coordinated. | [Issue 2.6 (#34)](https://github.com/vegastack/vegastack-labs/issues/34) |
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

Later issues update only their issue row, owned contract subsection, and accumulated acceptance evidence after Issue #29 merges. Generated definitions remain the single public-contract source; reserved migration and API ownership links are not permission to define parallel formats early.

## Verification, recovery, and combined exit

All fixtures are synthetic fixtures with no real operational data, credentials, private rows, or production signing keys. Narrow tests precede repository-wide race, build, generated-drift, analyzer, and complete public checks. Supported Linux behavior receives build-tagged filesystem, credential, lock, replacement, signal and recovery tests; unsupported targets must fail before touching a supplied path.

Recovery evidence is capability-specific: socket cleanup never removes a replacement, a failed migration preserves evidence and restores only through the approved verified-copy seam, and exports publish only after verification. None of those development tests authorizes a live recovery or makes an off-site disaster-recovery claim.

Issue #38 is the combined acceptance owner. It must map every Phase 2 row to integrated evidence from one reviewed merged commit, prove authorization denials, safe states, migrations, online copies, inert imports, durable replay, deterministic exports, CLI/API parity, and absence of any available infrastructure mutation. A green child issue, merged PR, or milestone state is insufficient; only explicit operator acceptance can close the phase.

## Effort and approvals

Issue #29 estimates 70–90 agent minutes, a 180-minute 2× checkpoint, 8–10 minutes of operator review, and 5–15 minutes of external public-CI wait if invoked. Its basis is 16–22 source/generated/test/documentation files, six implementation/review turns, Linux and unsupported seams, five target builds, two complete checks, and fresh security review. Each later issue records its own estimate and actuals.

Approval record: (omkarmohanta09) accepted Phase 1 on 08-09-2026, approved the Phase 2 briefs #29–#38, approved Plan v1 for Issues #29 and #30, and authorized their separate parallel implementation sessions on 08-09-2026. That authority covers only named development branches, commits, tests, issue comments, and review. Pull requests, pushes, merges, releases, repository administration, credentials, provider resources, hosts, networks, databases outside synthetic fixtures, deployment, and every live infrastructure action remain separately gated.
