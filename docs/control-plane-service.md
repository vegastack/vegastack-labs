# Control-plane service and Console

[Back to README](../README.md) · [Architecture](architecture-and-networking.md) · [Automation](automation-and-agents.md) · [Operations](security-and-operations.md) · [Decisions](decisions-and-sources.md)

This document is the implementation contract for the control-plane server and Console delivered by the portable `vegastack-labs` platform through the `vsk-labs` executable. The VegaStack Labs deployment profile runs them on `vsk-node-04`; that node, Cloudflare ingress and every provider named below are profile configuration, not core assumptions. The local control database replaces the earlier assumption that private site data belongs in a source repository. [D-099](decisions-and-sources.md#d-099) [D-100](decisions-and-sources.md#d-100) [D-103](decisions-and-sources.md#d-103)

## Scope and boundaries

The service provides one consistent operator surface for:

- inventory, immutable node identity, aliases, roles and qualification evidence;
- people, devices, grants and approval policy;
- network endpoints, private-access identities and declared flows;
- service declarations, placement, exposure, resources and backup class;
- provider observations through enabled hosting, monitoring, edge, SCM/CI and backup adapters;
- plan generation, acknowledgement, execution progress, verification and audit;
- encrypted exports, database recovery and manual recovery evidence.

It is not a general shell, secrets manager, configuration editor for arbitrary files, metrics database, Git hosting service or highly available cluster. It runs no user workload or CI job. Coolify and Beszel retain their specialist interfaces; VegaStack Labs Console summarizes and safely orchestrates them.

## Source-of-truth model

| Concern | Authority | Recovery copy |
|---|---|---|
| Site inventory, roles, policy, declarations, approvals and run ledger | local SQLite control database | encrypted online database backups plus signed declarative snapshots |
| Platform schemas, migrations, UI and adapters | immutable `vegastack-labs` platform release containing the `vsk-labs` executable, built from the public code repository | attested release artifacts and retained rollback binary |
| Application build/runtime contract | each application source/artifact authority | source revision plus immutable image/artifact |
| Secret values | selected secrets adapter (VegaStack Labs deployment: 1Password) | provider/offline recovery procedure; the database stores references only |
| Provider/runtime state | owning provider or host | normalized, timestamped database observation; always rebuildable |
| Hardware provenance before admission | profile inventory evidence (VegaStack Labs deployment: physical inspection plus read-only Sheet reconciliation) | approved inventory revision and attached evidence |

SQLite is authoritative for private operational intent, but not for secret values or provider facts. An observation never overwrites intended state. The UI shows `declared`, `observed`, `drifted`, `stale` and `unknown` explicitly.

No routine control-plane operation depends on an SCM/CI/release host. In the VegaStack Labs deployment profile, a GitHub outage may block source fetches, Actions jobs or new releases, but not inventory reads, node recovery, local plans, backups or LAN/console operations.

### SQLite, D1 and R2 decision

SQLite is the authoritative operational database. This is a deliberate failure-domain choice, not merely a default:

| Criterion | Local SQLite | Cloudflare D1 | Decision |
|---|---|---|---|
| LAN/offline operation | same-host ACID database; no WAN dependency | remote Worker/API service; local development is a standalone local-only environment, not offline access to the production database | SQLite keeps read/plan/recovery available during WAN or Cloudflare loss |
| Consistency and writes | one server writer, short transactions, foreign keys and explicit durability settings | writes execute at the primary; read replicas can lag and Sessions are needed for sequential consistency | the small fleet does not benefit from a second distributed consistency model |
| Failure domain | control host/disk, mitigated by verified local and off-site backups | Cloudflare account, network, Worker/API and D1 service join the control path | do not make the selected edge provider a control dependency |
| Recovery | online backup API produces a consistent SQLite copy; exact binary/schema recovery is testable on LAN | Time Travel is useful but restores a D1 database in place; raw SQLite cannot simply be imported as authoritative D1 state | encrypted, tested SQLite restore is the canonical path |
| Complexity | one schema/migration owner and one write ledger | second datastore, projection semantics, API limits and divergent migration/restore tooling | no bidirectional SQLite↔D1 synchronization |

D1 is permitted only as an optional **one-way, sanitized last-known-status projection** for an external status page. A later explicitly enabled projection sender may consume durable outbox intent carrying monotonic `state_revision`, observation time and non-sensitive health summaries; the current Phase 2 audit/outbox layer does not publish externally. The projection has no credentials or endpoints for declarations, acknowledgement, execution or secret resolution; it never writes back, wins a conflict, supplies a recovery input or changes the meaning of a local plan. Staleness is always visible, publication failure queues/retries without blocking local operations, and disabling/deleting the projection leaves control functionality unchanged. [Cloudflare D1 read replication](https://developers.cloudflare.com/d1/best-practices/read-replication/) · [D1 local development](https://developers.cloudflare.com/d1/best-practices/local-development/) · [D1 Time Travel](https://developers.cloudflare.com/d1/reference/time-travel/) · [D1 import/export](https://developers.cloudflare.com/d1/best-practices/import-export-data/) [D-105](decisions-and-sources.md#d-105)

R2 is an off-site object destination, not a database. The backup adapter takes a consistent SQLite snapshot, verifies it, records a manifest, client-side encrypts it with a key held separately from the bucket token, verifies that a separately administered bucket-lock rule covers the destination prefix for at least the declared window, uploads with a narrow bucket-scoped writer, and verifies object presence/hash plus effective lock coverage. R2 bucket locks are bucket/prefix configuration—not S3 per-object Object Lock headers—and the data writer cannot change them. Provider-side encryption and durability are useful layers but do not replace client-side confidentiality, retention, restore drills or a second recovery copy. [R2 data security](https://developers.cloudflare.com/r2/reference/data-security/) · [R2 bucket locks](https://developers.cloudflare.com/r2/buckets/bucket-locks/) · [R2 S3 compatibility](https://developers.cloudflare.com/r2/api/s3/api/) · [R2 API tokens](https://developers.cloudflare.com/r2/api/tokens/) · [R2 durability](https://developers.cloudflare.com/r2/reference/durability/) [D-100](decisions-and-sources.md#d-100)

## VegaStack Labs Debian runtime architecture

```text
Browser
  -> Cloudflare Access + Tunnel
  -> qualified application-node Tunnel connector
  -> TLS-verified private vsk-labs server origin (connector sources only)
       -> authenticated API and embedded static UI
       -> shared validation, policy, plan and adapter packages
       -> /var/lib/vsk-labs/control.db
       -> enabled read adapters and managed hosts
       -> constrained executor: exact approved plan only

Local CLI / recovery
  -> /run/vsk-labs/control.sock or forced SSH command
  -> the same API/application service; never direct SQLite access
```

There is one signed `vsk-labs` executable. On the VegaStack Labs control host, `vsk-labs.service` runs `vsk-labs server run` under an unprivileged `vsk-labs` account. The static web bundle is embedded into that binary, so the production node needs no Node.js server. Build-time JavaScript dependencies and authenticated design-registry credentials never reach the control node. Other supported deployment profiles may choose an equivalent OS service manager, but v1 server support is deliberately limited by the [support matrix](automation-and-agents.md#os-and-architecture-support-matrix).

The Console is a control-plane supporting service, not a Coolify workload. A Coolify failure must not remove the diagnostic/control UI. For the Labs profile, the HTTPS origin binds the declared reserved LAN interface and its host firewall admits only the selected qualified connector sources. Connectors verify the origin certificate/name; TLS-verification bypass is prohibited. The server independently verifies the configured Access identity on every browser/API request; source filtering alone never authenticates a person. Actual addresses, certificate trust/renewal and allow/deny/direct-origin tests must pass before browser activation. The local API remains on the protected Unix socket. [Cloudflare origin TLS parameters](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/) Generic installations without a browser adapter retain local/SSH CLI operation, not an unauthenticated Console. When Cloudflare/Workspace is unavailable, the web UI fails closed and recovery continues through personal SSH plus the Unix-socket CLI or local console.

### Implemented embedded and remote-read boundary

Issue #53 embeds the verified static export and its SHA-256 manifest in the same Go executable as the API. The server serves only manifest-listed files, maps only known exported routes to their `.html` files, never falls back from `/api` to HTML, and rejects traversal, encoded traversal, directory listing, unknown content types, and write methods. HTML, fixed build manifests and other non-content-addressed entry files use `no-store`; only files under the generated content-addressed `_next/static/chunks/` path use immutable caching. The generated Content Security Policy is derived from the accepted build, and every response denies framing and content sniffing. No Node.js process or runtime website directory is part of serving.

Server-profile schema `1.1.0` contains one provider-neutral `remoteRead` object. It is off only when `enabled` is `false` and every other remote field is `null`. Enabling it requires an exact non-wildcard IP bind address and port, exact lowercase HTTPS public origin, absolute clean certificate/key paths, the registered identity-adapter name, and an absolute protected adapter-profile path. Cloudflare issuer, audience, certificates URL, clock skew, token bound, and known-key outage limit live only in the separate Cloudflare Access adapter profile.

The Unix listener and application start first. An invalid optional remote block is retained as `preflight-unavailable` while the valid local profile starts; remote asset, identity, certificate, bind, or serving failure likewise changes only `remoteReadState` and `remoteReadReason` in `vsk-labs server status`. None stops or widens the local listener. `remoteReadState` is `disabled`, `starting`, `ready`, or `unavailable`, and the reason is a fixed typed value rather than a path, provider response, or raw error. Both listeners drain under the same five-second service shutdown bound.

The remote browser router admits only generated available `GET` API endpoints plus the three explicit session POSTs. Local inventory import, diff and export operations are never reachable through the remote listener. Resource-grant denials write one sanitized append-only audit event containing principal attribution and a one-way target fingerprint; audit failure keeps the request denied and becomes an integrity failure. The remote listener caps open connections and in-flight requests independently so remote load cannot grow without bound inside the process that owns local recovery.

On Linux, the origin certificate and private key must be non-empty regular files with one link, owned by the running service UID, no symlink anywhere in the resolved path, and no more than 1 MiB each. The key is exactly `0600`; the public certificate may be `0600`, `0640`, or `0644`. The server reads both through already-validated descriptors and clears the PEM key bytes after parsing. Rotate them through the approved host-configuration workflow by replacing the real files; do not point the profile at a convenience symlink.

When remote read is unavailable, use the protected local client path only:

1. Run `vsk-labs server status --config <protected-server-profile> --output json` from the control host or an already approved constrained SSH path.
2. Read `remoteReadState` and `remoteReadReason`; do not add direct HTTP, bypass Access, weaken TLS, or expose the Unix socket.
3. Correct the protected profile, adapter profile, certificate, or bind conflict through the normal host-configuration workflow, then restart the same `vsk-labs server run` service.
4. Prove local health first, then authenticated Console navigation, session creation, authorized API reads, direct-origin denial, and clean shutdown. A remote recovery never changes SQLite authority or grants by itself.

## SQLite contract

### VegaStack Labs Linux-server files and ownership

| Path | Purpose | Required mode |
|---|---|---:|
| `/var/lib/vsk-labs/` | database and migration state | directory `0700`, owner `vsk-labs` |
| `/var/lib/vsk-labs/control.db` | operational database | `0600`, owner `vsk-labs` |
| `/run/vsk-labs/control.sock` | local authenticated API | `0660`, owner `vsk-labs`, approved operator group |
| `/var/lib/vsk-labs/exports/` | staged signed snapshots before backup collection | `0700`; never public web content |

These paths are the VegaStack Labs Debian server profile, not portable client paths. The server obtains them from platform-aware defaults plus explicit configuration and records the resolved paths in diagnostics. The database stays on the control node's local filesystem. It is never placed on NFS, SMB, R2 FUSE, a container volume shared across hosts or a writable user directory.

### Durability and concurrency

V1 uses SQLite rollback journaling with `journal_mode=DELETE`, `synchronous=FULL`, foreign keys enabled, a bounded busy timeout and one application writer. This is sufficient for the small fleet and minimizes concurrency/checkpoint failure modes. Official SQLite documentation confirms that WAL supports concurrent readers but requires same-host shared state and one writer; current official guidance also identifies a WAL-reset corruption bug fixed only in SQLite 3.51.3 and specified backports. V1 therefore does **not** enable WAL merely for perceived performance. [SQLite WAL](https://sqlite.org/wal.html)

Rules:

- only the `vsk-labs` server process opens the writable database;
- the CLI, web UI, backup job and agents use the API/socket, never the file;
- writes are short transactions; provider calls and host operations never occur inside a database transaction;
- every mutable row carries an integer revision; API updates require the caller's observed revision and reject lost updates with `409 conflict`;
- the global `state_revision` increments exactly once for every committed intent change;
- the monotonic `recovery_epoch` changes only during an accepted control recovery; every plan, acknowledgement, lease and run binds it, and any mismatch blocks mutation;
- plan creation pins the recovery epoch, state revision, observation fingerprints, policy version and tool version;
- execution remains disabled during recovery until an out-of-band administrative fence has removed the former control instance's network path and mutating credentials; the epoch invalidates copied plans but is not itself a distributed fence;
- `integrity_check`, migration status, free disk and backup age are health checks;
- disk-full, corruption, migration mismatch or an unknown schema version switches the service to read-only safe mode and blocks execution.

WAL may be reconsidered only if the pinned SQLite library includes the official fix, all connections remain same-host, the connection/checkpoint design is documented, power-loss/concurrency tests pass and backup handling includes the WAL state correctly. [SQLite backup API](https://sqlite.org/backup.html)

#### Implemented Phase 2 ownership boundary

Issue 2.2 (#30) supplies the CGO-free, Linux-server SQLite authority behind the control service. It retains one `database/sql` connection, holds one same-owner writer-lock sidecar, requires an absolute clean path beneath a local `0700` directory, creates the database as `0600`, and rejects symlinks, hard links, owner/mode changes, network filesystems, and path replacement. It reads back rollback journaling, `synchronous=FULL`, foreign keys, and the bounded busy timeout before reporting ready. Non-Linux client builds continue to compile but cannot open an authoritative database.

The embedded migration ownership is intentionally staged. #30 owns only `0001_store_foundation`, containing `system_meta` and the append-only `schema_migrations` ledger. #31 owns `0002` inventory, #33 owns `0003` audit, and #35 owns `0004` read authorization. #34 and #37 own no migration. In particular, #30 does not create principals, grants, inventory, audit-event, outbox, snapshot, or export tables; the broader data-model table below remains the target contract for its owning issues.

Migration `0002_inventory_drafts` is a deliberately separate normalized namespace for immutable import candidates, source/idempotency fingerprints, child records, safe provenance and ordered findings. It stores no raw import, unknown column, adjacent cell, provider response, plaintext secret or accepted inventory row. A safe semantic conflict persists atomically and completely as `blocked`; a fatal parse, bound, cancellation or secret failure persists zero rows. `valid` and `blocked` describe validation only. There is no SQL, domain or API transition from these tables to declared/effective inventory in Phase 2, and a canonical projection is explicitly `kind=draft`.

An opaque import key is stored only as its SHA-256 digest. Exact canonical-content reuse is the sole no-op and returns the original draft reference without advancing `state_revision`; key/content or stable-source/exact-digest reuse conflicts fail closed. Corrections create a new immutable draft rather than updating or deleting stored evidence. Existing databases receive `0002` only after the full applied checksummed prefix is verified and a recovery copy is proven through Issue #30's recovery seam; fresh exclusive initialization applies the entire checked catalog in order.

Migration `0003_audit_outbox` adds `audit_sequence`, append-only `audit_events` and `intent_keys`, and durable destination-neutral `outbox` rows without creating another database owner. A changed inventory draft and its event/binding/outbox rows commit atomically with one `state_revision` increment; exact replay writes nothing. `AppendOperationalAudit` uses the same transaction engine with no business callback and advances `audit_sequence` only, which freezes the event seam required by #37 without granting export or delivery behavior.

Canonical event fields are exactly schema/version, event ID/time, recovery epoch/state revision, event type/correlation, optional causation/correction links, verified principal ID/method, optional trusted responsible-human ID, optional self-reported agent name/session/source, target kind/ID, and optional before/after SHA-256 fingerprints. Optional fields remain present as JSON `null`. Outbox metadata exposes ID, event/destination, payload schema/version/digest and dedupe digest, status, attempt bounds, next-attempt/stable-error fields, and created/updated/delivered times; inspection never returns payload bytes. Enabled destinations start `pending`, disabled destinations start `paused`, and attempts move only through `retry_wait`, `delivered`, or `dead_letter`. There are 8 attempts with deterministic exponential delays from 30 seconds to 1 hour. Payload schema/version/canonical bytes/digest are checked before internal release; mismatch dead-letters as `PAYLOAD_INVALID` and enters safe mode.

Fresh exclusive initialization is the only path that does not require a verified pre-migration snapshot. Every upgrade first validates the applied ledger as an exact checksum-bound catalog prefix, then obtains a verified online copy through the narrow `MigrationRecovery`/`MigrationSource` boundary. A failed migration rolls back and preserves the authority file and failure evidence. Recovery verification restores the snapshot only to a separate isolated target; it never renames, copies, or restores over the authority automatically. Authority replacement, external fencing, accepted `recovery_epoch` cutover, and restart with a retained binary remain Phase 5 operator-owned recovery work.

#35 composes and injects the store-backed application behind the #29 server boundary; neither the CLI nor the Console opens SQLite. #38 verifies that ownership closure through the built executable. Until those issues land, the store package is a tested internal foundation and does not claim that the persistent service is complete.

### Core data model

| Table/group | Required data and invariants |
|---|---|
| `system_meta`, `schema_migrations` | schema version, state revision, monotonic recovery epoch, active instance UUID, recovery-pending/mutation-enabled state, last successful integrity check; migrations are append-only and checksum verified |
| `inventory_drafts` and normalized draft children | immutable `valid`/`blocked` review candidates, exact-source and canonical-content digests, safe field provenance and deterministic findings; no raw source, declaration/effective state or transition method |
| `assets`, `nodes`, `aliases`, `qualifications` | later accepted inventory: immutable node ID, typed/scoped provenance and verified access identity; serial uniqueness only for applicable physical inventory policy; names/aliases, lifecycle, role, capacity and evidence; no alias collision |
| `network_endpoints`, `access_devices`, `allowed_flows` | unique address/endpoint bindings, access-adapter identity, approval state and declared positive/negative paths; VegaStack Labs Mesh fields live in the Cloudflare extension |
| `people`, `external_subjects`, `devices`, `grants` | stable provider-neutral subject binding including local OS/SSH identities, lifecycle, desired/applied/effective role/project/shell grants and policy versions, approver and revision; VegaStack Labs Workspace claims live in the identity-adapter extension; no credential value |
| `approval_requests`, `acknowledgements` | provider-neutral request/proof identity, subject/target/reason digests, risk, responsible local human, expiry, nonce, state revision, recovery epoch and single-use state; provider interaction fields remain in the acknowledgement-adapter extension |
| `approver_mappings` | inert desired/applied/effective mapping revision from provider subject to local human principal and allowed approval classes; additions/widening require prior effective authority and cannot self-authorize |
| `services`, `environments`, `placements` | owner, source/artifact reference, policy class, exposure, resources, backup, health/migration and rollback contract |
| `adapter_instances`, `capabilities`, `resource_refs` | typed adapter kind/version, enabled capabilities, provider-neutral resource key and separately validated provider extension; no core provider fields |
| `secret_refs` | logical ID, secret-adapter instance plus opaque locator, owner/consumers, rotation/expiry and last nonreversible fingerprint; database constraints reject value-shaped fields |
| `provider_resources`, `observations`, `refresh_runs` | adapter/resource identity, normalized observation, captured time, staleness/error and sanitized raw-response hash |
| `change_requests`, `plans`, `plan_steps` | normalized intent, immutable plan digest, bound recovery epoch, preconditions, risk, expiry, expected interruption, verification and recovery |
| `runs`, `run_steps`, `run_events`, `leases` | execution state, exact plan/tool/recovery-epoch identity, bounded lease, per-step attempt/result and resumability |
| `gate_definitions`, `gate_evidence`, `gate_checks`, `gate_evaluations` | versioned/scoped gate owner and applicability, resolved profile/policy provenance and subject/capability effect; collector/attachment digests and restricted references; deterministic observed/expected results, expiry, recovery epoch and current activation state |
| `audit_events`, `intent_keys` | ordered canonical event, verified attribution, action/target/before-after fingerprints/correlation and exact-replay binding; updates and deletes denied to the service path |
| `backup_records`, `restore_tests` | recovery point, manifest digest, verification, destination and measured RPO/RTO |
| `outbox` | immutable canonical event bytes plus destination-neutral dedupe and bounded `pending`/`retry_wait`/`paused`/`delivered`/`dead_letter` transition metadata; no sender or raw error |

Provider-specific payloads may use validated JSON columns only after redaction and size limits. Raw logs, environment values, private keys, tokens, database dumps and full provider responses are prohibited.

“Append-only” inside SQLite is currently an application control, not immutable evidence against a root user or disk compromise. Issue #33 supplies ordered IDs, canonical payload hashes, denied update/delete, corrections as new linked events, and crash-safe local transactions; it does **not** implement a previous-event hash, checkpoint signature, external custody, retention lock, or compromise-detection claim. Phase 5 must add the separately protected signing identity, hash-chain/checkpoint verification and independently recoverable encrypted export before the platform may claim tamper evidence under D-106. A recovery from integrity failure or uncertain commit stops mutation, preserves the database, exposes only sanitized health, uses Issue #30's verified-copy/isolated-restore workflow, and reconciles through a new event rather than editing history. [D-106](decisions-and-sources.md#d-106)

### Effective authority and generic lifecycle

The [portable lifecycle](platform-lifecycle.md#effective-authority-and-revocation) defines effective grants/policy separately from inert desired state. Planning cannot authorize itself, start a timer or enable a capability. Expanded authority activates only after approved apply and verification; approved denials persist through partial failure. The prior effective authority authorizes the change. Read-only callers cannot commit declaration/plan intent. Profile changes and private Slack approver imports obey the same activation rule. [Human acknowledgement](platform-lifecycle.md#human-acknowledgement-trust-boundary) requires a fresh verified Slack action for normal v1 bootstrap/mutation; peer UID, SSH identity, cached session, TTY, approver-file edit or actor label alone is insufficient. Slack remains a typed adapter and never becomes database, audit or execution authority. [D-122](decisions-and-sources.md#d-122)

### Migrations

Migrations are embedded in the attested server binary and have sequential IDs plus checksums. Startup may apply only forward-compatible migrations approved for that release.

1. Stop new plans and wait for or safely interrupt active runs.
2. Create an online backup, inspect its schema/revision/integrity, and bind it to the target catalog.
3. Acquire the exclusive migration lock and confirm expected current schema.
4. Apply one transaction where SQLite permits; record each migration checksum.
5. Run foreign-key and integrity checks plus API smoke tests.
6. Fsync the committed database and its parent, recheck file identity, and start normal operation only after all checks pass.

On migration or post-check failure, the implementation rolls back where SQLite still permits, preserves the authoritative file and evidence, verifies the snapshot by restoring only to an isolated target, and remains mutation-disabled in safe mode. It does not automatically replace authority. The Phase 5 recovery procedure owns fencing the former writer, explicitly accepting the recovery point, replacing authority, advancing `recovery_epoch`, starting the compatible retained binary, and verifying the result. Never run an older binary against a newer schema.

#### Implemented Phase 2 migration-recovery primitive

Issue 2.6 (#34) implements the production `MigrationRecovery` port as a provider-neutral artifact service under `internal/backup`; only `internal/store` opens SQLite. Before migration SQL, the store creates the destination through SQLite Online Backup in bounded 128-page steps, closes the backup handle, and inspects the completed copy for integrity, foreign keys, schema, revision, recovery epoch, and an exact checksummed migration-catalog prefix. A failed backup, close, inspection, cancellation, capacity write, sync, or publication step blocks migration and returns no verified snapshot.

Each attempt uses a random 128-bit ID and an owner-only staging directory beneath one absolute, local `0700` snapshot root. The database and strict secret-free manifest are `0600`; the implementation rechecks file type, owner, mode, hard-link count, device/inode identity, size, and SHA-256 before publication. It syncs the database, manifest, and staging directory, then uses Linux `RENAME_NOREPLACE` to create the immutable final generation and syncs the root. The rename is the discovery point: pre-rename remnants are ignored, while a valid post-rename generation remains discoverable even if the caller never received success. A new attempt never replaces or removes an earlier generation.

After migration failure, verification reopens the generation by canonical ID, revalidates the manifest and database, restores through the store-owned SQLite connection into a fresh same-root disposable target, and reinspects the prior schema and revision. It removes that target after verification and never opens, renames, or overwrites the authoritative database. The original migration failure remains primary and the service stays mutation-disabled. This local primitive owns no database migration, public command, API route, scheduler, retention, encryption, signing, off-site copy, writer fencing, authority replacement, recovery-epoch transition, or live cutover; those remain Phase 5 recovery work.

## API contract

All browser and CLI behavior uses one versioned API. HTTP JSON uses `/api/v1`; the local socket uses the same routes. Responses use the single canonical camelCase [machine envelope](automation-and-agents.md#command-surface)—including `schemaVersion`, `runId`/`requestId`, `recoveryEpoch`, `stateRevision`, `toolVersion`, `status`, `errors` and `data`—plus command/endpoint-specific schemas. Do not duplicate a snake_case envelope.

### Read and declaration endpoints

| Method and path | Purpose |
|---|---|
| `GET /api/v1/summary` | fleet, service, CI, backup, alert and change totals |
| `GET /api/v1/sources` | bounded health and freshness state for the database, nodes and optional domain capabilities |
| `GET /api/v1/nodes`, `GET /api/v1/nodes/{id}` | declared identity, role, qualification and observed state |
| `GET /api/v1/services`, `GET /api/v1/services/{id}` | declaration, placement, exposure, health and provider links |
| `GET /api/v1/people`, `/devices`, `/grants` | authorized lifecycle and access views |
| `GET /api/v1/network` | endpoints, reservations, ports, paths and private-access/overlay status; provider extensions carry Mesh-specific fields |
| `GET /api/v1/providers` | adapter health, credential-reference health and last refresh |
| `GET /api/v1/backups`, `/restore-tests` | recovery-point age, verification and restore evidence |
| `GET /api/v1/gates`, `GET /api/v1/gates/{id}` | design/activation state, applicable subjects, evidence age/checks and exact remediation; `?phase=<n>` filters admission gates |
| `GET /api/v1/plans`, `/runs`, `/audit` | attributed lifecycle history with sanitized evidence |
| `GET /api/v1/events` | Server-Sent Events stream for refresh/run progress; reconnects from durable event ID |
| `POST /api/v1/declarations/{declarationId}/revisions` | validate and append one provider-neutral draft declaration revision using exact optimistic revision and recovery-epoch checks; cannot execute infrastructure |
| `GET /api/v1/declarations/{declarationId}/revisions/{revision}` | read one exact authorized immutable declaration revision |
| `POST /api/v1/gates/{id}/evidence-drafts` | validate a typed evidence bundle and create an inert change; never sets the evaluation directly |

#### Implemented Phase 3 domain-status screens

The embedded Console currently exposes People, Services, Backups, and Providers as status-only screens. Each screen calls only the generated `GET /api/v1/sources` client operation with one exact server-side source filter and shows the safe capability state and timestamps. A current observation means only that the status observation is current; it does not mean that domain records or operations exist. Real people, service, recovery-point, and provider record endpoints, filtering, pagination, details, and actions remain owned by their later implementation phases.

The browser never downloads a broad source list and hides rows locally. Authorization and schema failures remove affected cached data; only a retryable temporary dependency failure may show a previously authorized status under an explicit stale warning. These screens add no provider call, credential path, database table, mutation, or operational authority.

List endpoints use stable cursor pagination, explicit sorting and server-side filters. Unknown filters/fields are rejected rather than ignored. API and CLI share generated schemas and fixtures; human UI strings are not an API.

### Implemented draft-operation endpoints

| Method and path | Effect and boundary |
|---|---|
| `POST /api/v1/inventory-drafts/import` | Decode and persist one complete immutable inert `valid` or `blocked` draft; exact idempotent replay is a no-op. |
| `POST /api/v1/inventory-diffs` | Compare an exact draft or bounded file candidate with the latest authorized compatible draft at one pinned revision; never persist the file candidate. |
| `POST /api/v1/inventory-exports` | Select one exact inert draft and delegate only to Issue #37's verified signed publisher; the caller cannot choose a server path or signing material. |

For all three routes, kernel-backed authentication and exact capability/resource authorization finish before any body byte, draft candidate, baseline, or export subject is read. Import creates no accepted or effective declaration. Diff explicitly labels its baseline `draft` and returns `PREREQUISITE_BLOCKED` if none exists. Export also returns `PREREQUISITE_BLOCKED` when production signing trust is unavailable and preserves the prior verified artifact. Responses use the same closed typed envelope as the CLI; raw source rows, paths, private fields, signing material, and internal errors are never returned.

### Implemented declaration and immutable-plan endpoints

`POST /api/v1/declarations/{declarationId}/revisions` and `POST /api/v1/declarations/{declarationId}/plans` now use the same local server-owned SQLite authority as every other mutation. The declaration ID in the generated route is authorized before strict body decoding and must exactly match the duplicated body binding; both endpoints are denied by the remote browser mutation admission boundary, and neither handler resolves secret values, invokes an adapter, or performs a network call. The matching exact-revision declaration read and exact-plan read endpoints are available through the generated read contract.

Declaration operations are ordered by their explicit sequence; set-like extensions and plan target bindings are normalized before hashing. Each append-only declaration revision records only generated closed-contract fields and digests. Planning rechecks the current recovery epoch, state revision, source draft revision, and observation fingerprint, then appends a separate `committed` desired declaration revision together with the immutable canonical JSON plan, lossless readable plan, audit event, idempotency binding, and next state revision in one transaction. An interrupted plan insert rolls back the committed declaration and plan while preserving the inert source draft. Authoritative stored bytes require the exact generated contract; compatible-read conversion is presentation-only. Exact retries return the original bytes; changed reuse of the same key fails with `STATE_CONFLICT`.

Every plan expires exactly 30 minutes after creation. Its ID and digest bind the declaration and reason, prior/new state revision, recovery epoch, current-fact fingerprint, sorted target set, authored operation sequence, policy/tool/contract versions, executor binding, readable digest, and expiry. Until Issue #71's policy result is integrated by the authorization issue, production server wiring uses the conservative `destructive` + `human` classification and central executor identifier; it cannot accidentally preauthorize or understate a plan.

### Implemented durable run engine

The server now owns one in-process durable run engine. `POST /api/v1/plans/{planId}/execute`, `GET /api/v1/runs/{runId}`, `POST /api/v1/runs/{runId}/cancel`, and `POST /api/v1/runs/{runId}/resume` are generated available endpoints. Run mutations remain unavailable on the remote browser listener; authorized run reads can use the existing read boundary. Execution loads immutable server state and records a current effective-authorization decision before reading the request body, then binds the exact plan digest, recovery epoch, policy branch, acknowledgement when required, target facts, executor, adapter, operation, artifact, and idempotency key.

Each ordered step records an active target lease and intent before adapter dispatch, records a sanitized receipt after the effect, and requires a separate adapter verification before success. A receipt cannot prove success by itself. The typed adapter value contains only closed plan fields and logical secret references for that adapter; it rejects commands, URLs, filesystem paths, changed targets, and cross-adapter secret references. Production composition starts with an empty registry and explicitly rejects `test.fake`; the deterministic fake exists only in tests.

Exact duplicate submission returns the original durable run, and concurrent copies of the same exact request share one proof-consumption lane. A conflicting target lease fails closed before any effect and leaves the run safely interrupted. A client disconnect after durable creation does not cancel server-owned execution, while server shutdown cancels its separate execution context so a cooperative adapter durably interrupts and releases its lease at the next safe boundary. Process restart releases stale in-process leases and reconciles any running step: a known pre-effect interruption is resumable only when the plan declared it idempotent, while an intent or receipt without completed independent verification becomes `partial` with recovery required and is never replayed blindly. Cancellation is observed before the next step or at the current safe boundary and never claims rollback. Startup also prunes detailed local run events older than 30 days and terminal sanitized run summaries 180 days after their last terminal update; the append-only audit event remains on the existing audit/outbox/SSE spine for its separately governed retention.

### Plan and execution endpoints

| Method and path | Effect and boundary |
|---|---|
| `POST /api/v1/declarations/{declarationId}/plans` | load one exact draft revision, verify current local facts, and atomically append its committed desired revision plus an immutable 30-minute plan bound to the active recovery epoch; no external mutation |
| `POST /api/v1/plans/{id}/acknowledgements` | accept only the server-verified provider-neutral proof derived from the configured Slack workspace/user action, bound to the exact request/digests/risk/expiry/nonce/state revision/recovery epoch; a client assertion cannot acknowledge |
| `POST /api/v1/plans/{id}/execute` | queue only the exact unexpired approved digest after reauthorization and precondition checks |
| `POST /api/v1/runs/{id}/executor-claims` | allow only the plan-declared enrolled external executor to claim one epoch-bound, target/digest-limited lease; VegaStack Labs uses this for the accepted protected CI→Coolify adapter |
| `POST /api/v1/runs/{id}/receipts` | accept the executor's sanitized provider run/deployment ID and step result; independent adapter observation still decides verified success |
| `POST /api/v1/runs/{id}/cancel` | request safe interruption at a declared boundary; it is not an assumed rollback |
| `POST /api/v1/runs/{id}/resume` | resume only idempotent incomplete steps after rechecking state; changed facts require a new plan |
| `POST /api/v1/runs/{id}/rollback-plan` | generate a separate recovery plan from recorded compensation/recovery data |

The executor accepts typed operations only. It rejects arbitrary commands, changed targets, stale observations, expired plans, unknown plan major versions, a plan/acknowledgement/lease recovery-epoch mismatch, a non-active instance UUID, recovery-pending state, missing acknowledgement or preauthorized policy, insufficient role, active conflicting lease and unverified recovery-fence prerequisites. An external executor additionally must match the declared project, workflow/ref trust evidence, adapter instance, target, artifact digest and one-time claim. A started run keeps its plan identity after the 30-minute creation window only within that recovery epoch; an interrupted run from an earlier epoch can never resume or add steps/targets.

State machine:

```text
draft -> planned -> awaiting_acknowledgement -> approved -> queued -> running
                                                     |          |
                                                     |          +-> succeeded
                                                     |          +-> failed
                                                     |          +-> partial
                                                     |          +-> interrupted
                                                     +-> expired/cancelled
```

No state is inferred from a disconnected browser. Durable run events and post-checks determine the result.

## Authentication, authorization and browser security

### Portable contract

- The portable server accepts only declared authentication modes: local OS peer credentials on a protected same-host transport, or a configured identity/reverse-proxy adapter that yields a cryptographically verified issuer, subject, audience and expiry. It never authorizes an email/header supplied by an untrusted proxy.
- Remote CLI authentication produces a short-lived server session bound to the external subject, client/device and audience, or uses the constrained SSH transport. Long-lived client material is stored in the OS credential facility, not a portable plaintext config file. A provider login proves identity; local `people`/`grants` policy still decides read, author, acknowledge and execute capabilities.
- Browser access is same-origin only. Disable permissive CORS; require an exact Host and reject every present mismatched Origin. Unsafe requests require the one exact Origin. Because ordinary same-origin browser GET/HEAD requests are not guaranteed to carry `Origin`, a safe request without it must instead carry the exact browser-controlled Fetch Metadata tuple `Sec-Fetch-Site: same-origin`, `Sec-Fetch-Mode: cors`, and `Sec-Fetch-Dest: empty`; missing, duplicated, or different values fail closed. Mutations additionally require their declared anti-CSRF control.
- Session cookies, if used for UI state, are `Secure`, `HttpOnly` and `SameSite=Strict`; no local password database is created.
- Session creation, renewal, logout and emergency revocation are audited. Short expiry and server-side revocation are mandatory; changing a person's lifecycle or device grant invalidates active sessions before another apply.
- Content Security Policy denies inline/unapproved script, framing and unexpected network destinations. API responses use `no-store` for sensitive operational data.
- Read, author, acknowledge and execute are distinct capabilities. The server reauthorizes every plan transition and execution.
- Secret values never enter HTML, JSON, SSE, SQLite, logs, traces, browser storage or downloadable audit exports.
- Rate limits apply separately to reads, refreshes, plan generation and execution. Execution also takes a target/provider lease.
- Direct origin access is blocked by bind address and host firewall. Acceptance includes a bypass test from every untrusted network path in the deployment profile.

### VegaStack Labs Cloudflare/Workspace binding

Cloudflare Access authenticates Google Workspace users before the browser origin. The Go server independently validates the exact `Cf-Access-Jwt-Assertion` signature, RS256 algorithm, key identifier, issuer, audience, issue/not-before/expiry times and configured skew on every request; it does not trust an email or forwarded-identity header. The provider adapter yields only opaque issuer/subject/audience identity to core code, and that binding maps to an existing local principal and grants. This project intentionally keeps authentication in the one `vsk-labs` Go executable instead of adding Better Auth or a Node authentication authority. [D-125](decisions-and-sources.md#d-125)

The adapter refreshes Cloudflare signing keys when the server starts and when it sees an unknown `kid`; concurrent misses observed against one cache generation coalesce into one fetch. A key-endpoint outage may continue only for a key already present in a cache refreshed successfully within the previous 24 hours; an unknown key or older cache fails closed. Browser admission requires TLS, one exact Host, one valid Access assertion, and—except for initial session creation—one current `vsk_labs_session` cookie. Session POSTs also require one exact Origin. A safe GET/HEAD may omit Origin only when the exact browser-controlled same-origin/cors/empty Fetch Metadata tuple is present; any present mismatched Origin and any incomplete/duplicate substitute fail closed. Only after those checks does the server attach the mapped principal and run the existing per-resource authorizer before query or body parsing. [Fetch Origin header](https://fetch.spec.whatwg.org/#origin-header) [D-125](decisions-and-sources.md#d-125)

The local session is a random value held only in a host-only `Secure`, `HttpOnly`, `SameSite=Strict` cookie at path `/`; SQLite stores its SHA-256 digest, never the value. It expires after 15 minutes idle or 8 hours absolute, cannot outlive the external JWT, rotates exactly once on renewal, and becomes invalid after replay, local logout, binding/principal revocation, grant-revision change, or recovery-epoch change. A detected time expiry durably changes the active row to `expired` exactly once in the same audited transaction. Principal-wide revocation is scoped to the current append-only session generation, so a replay may deduplicate only until a newer session exists, and every call verifies that no targeted active session remains. Creation, renewal, logout, expiry, revocation, verified-principal denial and recovery invalidation write bounded audit fingerprints without token, cookie, email, private-claim or raw-provider-error values. Local logout clears only this cookie and explicitly does not sign the user out of Cloudflare or Google Workspace.

Browser failure never enables a direct-origin or unauthenticated Console bypass. During a Cloudflare, Workspace or JWKS outage, operators use the independent protected local OS-peer/Unix-socket CLI path. The additive browser-session migration follows the normal pre-migration backup and isolated restore check; rollback uses that verified pre-migration database with the previous executable, not an attempt to make old code open the newer schema. Acceptance tests authorized/unauthorized requests, direct-origin denial from LAN and Mesh, current and stale key outages, session invalidation, and continued local recovery. [Cloudflare Access JWT validation](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/)

## Provider and host adapters

The portable interface is capability-based: `observe`, `plan`, `apply`, `verify`, `diagnose` and, where truthful, `compensate`. Every adapter publishes its configuration schema, version, permissions, consistency/freshness limits, idempotency key behavior, retry classes and manual fallback. The core stores an adapter instance plus provider-neutral resource key; it does not add fields such as GitHub repository ID, Cloudflare account ID or Coolify UUID to universal schemas.

The VegaStack Labs deployment selects these concrete credentials and direct adapter engines. SQLite remains desired-state authority; v1 introduces no Terraform/OpenTofu state file. [D-112](decisions-and-sources.md#d-112)

| Adapter | Console credential | Mutating credential and behavior |
|---|---|---|
| Coolify | team-scoped `read`, never `read:sensitive`, through documented `/api/v1` | separate team-scoped `write`/`deploy` identity released only to the plan-declared executor; VegaStack Labs application deploys use the protected CI executor, while platform/recovery operations remain centrally administered |
| Beszel | read-only service user/API session | Console never changes Beszel; reconciliation uses the owning adapter |
| Cloudflare | scoped read token for Access/Mesh/Tunnel observations through pinned `cloudflare-go` v7 | separate least-privilege token for objects owned by the VegaStack Labs adapter; reviewed raw REST only where the SDK lacks the required endpoint |
| GitHub SCM/CI | no credential for configured public resources; fine-grained read token only for approved private discovery/Actions views | workflow `GITHUB_TOKEN` inside Actions or a purpose-specific credential for the exact optional operation; no VegaStack-owned App by default |
| 1Password | metadata/reference validation only during read/plan | scoped service account resolves exact references only after execute authorization |
| Debian/macOS hosts | sanitized collectors over the declared automation identity | Ansible/SSH step with exact target, role and recovery checks |
| Backup repositories | manifest/heartbeat read identity | narrow writer for the declared backup or audit export; no retained-payload deletion or lock-policy grant; only qualified mutable coordination-object operations are allowed |

The browser never calls providers directly. Adapter refreshes happen outside request transactions, normalize/redact before storage and use bounded timeout, exponential backoff with jitter, rate-limit awareness and a circuit breaker. A partial outage returns available data plus explicit `stale`/`unknown` source state; it never paints the fleet green. GitHub credential choices and the only narrow App-required optional functions are listed in the [GitHub dependency matrix](decisions-and-sources.md#github-dependency-matrix).

## Web application and VegaStack Design System

The VegaStack Labs Console uses the supported VegaStack Design System path: Next.js 16, React 19, TypeScript, Tailwind CSS v4, Base UI and `@vegastack/design`. It is built as static assets and embedded into the `vsk-labs` executable; server-side Next.js APIs are prohibited in production so there is no Node runtime. This design-system choice does not alter the provider-neutral API/domain contract. [VegaStack quickstart](https://design.vegastack.com/docs/guides/quickstart) [D-102](decisions-and-sources.md#d-102)

The repository pins the verified `provider` and `dashboard-01` registry closure at Design System `0.6.0`. The authenticated maintainer refresh verifies signed upstream items, copies their source, and records local hashes; ordinary public CI verifies only those committed bytes and needs no registry credential. The dashboard block is repository-owned after copy-in, so an intentional adaptation requires an explicit local acceptance command and review of both its source and lock diff. The generated `web/out` tree is served during development only by the loopback preview helper and is tested in pinned Chromium; production continues to embed the same static files in `vsk-labs server run`.

Build requirements:

1. Install `@vegastack/design` and import only `@vegastack/design/preset.css`; do not duplicate the Tailwind import.
2. In an authenticated maintainer lane, copy the `@vegastack/provider` registry item with `shadcn add @vegastack/provider`; it is not an npm package. Review and pin the copied source before it enters this public repository. Once approved source is checked in, ordinary public builds use that local copy without a registry token and keep `VegaStackProvider`, theme hydration handling and the global CSS import intact.
3. Start from `@vegastack/dashboard-01`, move its shell into the shared dashboard layout, then replace fixture data with the generated VegaStack Labs API client.
4. Maintainers acquire/update owned components through the authenticated VegaStack shadcn registry, then publish only approved redistributable pinned source/dependencies. Ordinary public checkout builds require no registry token; validate distribution rights and the credential-free path before frontend issue readiness. Registry tokens remain in maintainer local/CI secret storage only.
5. Public CI validates pinned local component integrity, build and accessible doctor checks without private credentials. Authenticated refresh/update checks run in a separate maintainer lane; no public fork receives its tokens. Review update diffs before overwrite; copied components are owned source, not silently auto-updated.
6. Build light/dark, desktop/mobile and keyboard/accessibility lanes before release. The target is WCAG 2.2 AA.

### Required component map

| Platform need | VegaStack components |
|---|---|
| Frame and navigation | [App Shell](https://design.vegastack.com/docs/components/app-shell), [Sidebar](https://design.vegastack.com/docs/components/sidebar), [Page Header](https://design.vegastack.com/docs/components/page-header), Breadcrumb, Tabs |
| Fleet summary | Stat, Card, Chart, Badge, Status Icon, Relative Time |
| Nodes/services/users | Table for simple views; Data Grid for sortable/filterable operational records; Property List for detail |
| Search and filtering | Command Menu, Filter Bar, Combobox, Pagination |
| Declaration editing | Field, Settings Row, Select, Switch and Textarea with explicit validation; no silent autosave for risk-bearing fields |
| Plans and runs | Stepper, Timeline, Progress Indicator, Code Block for sanitized JSON and Action Bar |
| Feedback | Alert, Toast, Skeleton, Spinner and Empty; every asynchronous action has loading, empty, partial, stale, error and retry states |
| Confirmation | Dialog for review; Alert Dialog for destructive/high-blast-radius acknowledgement; Button state owns pending/disabled behavior |

Do not reimplement local lookalikes when the registry owns the behavior. Platform-specific compositions may be local, but token names, focus, keyboard semantics, responsive behavior and state handling remain inherited from the component contract.

### Screen contract

| Screen | Minimum functional capability |
|---|---|
| Overview | fleet/service/CI/backup totals, stale-source banner, active incident, recent attributed operations and next safe action |
| Nodes | add/import/discover, compare declared/observed, qualify, quarantine, nominate role, inspect flows and generate plan |
| Applications | Generic hosting-resource/adapter status (Coolify in the Labs profile), placement, exposure, digest, backup/health and provider deep link; no undeclared placement editing |
| Builds and CI | runners, trust class, jobs, capacity/admission and sanitized failure evidence |
| Backups | recovery points, age/integrity, restore tests, RPO/RTO and run/restore-plan actions |
| People and devices | Local/SSH and configured external identity-binding status (Workspace in the Labs profile), grants, quarantine, onboard/suspend/offboard plans and positive/negative verification |
| Changes | drafts, immutable plan diff, risk/approval, acknowledgement, live run timeline and recovery action |
| Settings and integrations | read health and editable safe declarations; credential references only, never values |
| Gates | phase/capability readiness, design versus activation state, evidence age/check results, prerequisite order and safe collection action; no manual pass toggle |

Every page shows observation time and source. Unknown is visually distinct from healthy. Destructive buttons are unavailable until a valid plan and required recovery point exist.

The first implemented read slice is deliberately narrower than that final screen contract. Overview reads the authorized service summary and seven independent source states. Nodes reads the newest authorized inert draft plus separately paginated nodes, aliases and observations, and keeps opaque cursors and record identifiers out of the URL. Gates currently reports only whether the gate-source capability is available; it does not display, infer or change gate results. Detailed gate records arrive only with the later phase that owns their schemas and evidence. All three routes use the generated same-origin client through an in-memory TanStack Query boundary: automatic retry, polling, focus/reconnect refresh and persistence are disabled; only retryable dependency failures may retain previously authorized data under an explicit stale warning, while access/session/schema/integrity failures clear it.

## Control-plane nomination and bootstrap

The generic [local control-plane creation](platform-lifecycle.md#local-control-plane-creation) replaces mandatory workstation-first bootstrap. An authenticated administrator nominates the current supported host; the host does not attest itself or obtain authority from its name. The Labs profile chooses `vsk-node-04`, while another installation chooses its own host without code changes. Normal v1 bootstrap also requires the selected Slack acknowledgement adapter; this is a capability prerequisite, not a Labs hostname or core schema constant.

A generated guided setup uses account-free read-only preflight, the explicit finite local installation plan/manifest, then the same `vsk-labs server run` API/SQLite/plan engine. Only that server initializes or opens writable SQLite. A trusted local console or already verified SSH session with recovery access establishes the initial OS administrator binding; there is no first-web-visitor claim or mandatory Workspace account. Before SQLite exists, the manifest carries the initial workspace/user-to-local-principal mapping and logical Slack app/bot secret references. `vsk-labs server run` opens Socket Mode using app-level `connections:write`, presents requests using bot `chat:write`, verifies the exact bootstrap action, and atomically consumes the manifest. The consumed manifest becomes protected audit/recovery evidence and never remains a mutable execution authority.

Start with authenticated local-only setup. Complete local hardening, native credential resolution and operation-specific recovery before scoped foundation-node preparation. Add operator clients and managed nodes through separate workflows. Initial local service creation does not require the entire fleet, Mesh pilot, Coolify, 1Password, R2, public DNS or browser ingress, but missing/unavailable Slack blocks manifest consumption. Their selected capabilities activate only after their own evidence passes. No qualified-control, independent-restore or site-ready claim is made prematurely.

For Labs, inventory import uses the approved Sheet/physical evidence as a normal inert draft/plan; unresolved identities block only affected bindings. Router/switch UI actions remain guided human steps where no tested adapter exists. Qualified application nodes later host the connector pair and marker; the spare/reserve remain free of those duties. After the actual Mesh pilot and recovery/access qualification, accept the selected control and site capabilities. A local service failure never makes an operator client an alternate controller.

Same-host Ansible/elevation, reboot checkpoints and independent access rollback follow the lifecycle contract. Missing host trust, privileges, safe recovery, firmware facts or Apple consent is a visible prerequisite, not an agent-invented bypass. Exact kernel/privilege and adapter mechanisms must pass their implementing issue's real tests. See [phase 0 ownership](development/phases/00-development-foundation.md#ordered-issue-index).

## Backup, export and recovery

The control database is `critical` data. Use SQLite's online backup API through the `vsk-labs` server; never copy a live database file with a generic filesystem command. Each backup records schema/tool/SQLite versions, state revision, database hash, integrity result, size, encryption repository object and timestamps.

- create a local online snapshot every 15 minutes and before each migration/apply;
- feed snapshots into the selected restic v2 `critical-local` and `critical-offsite` repositories; R2 frequency/retention remains governed by the accepted critical class and bucket lock;
- export a signed, secret-free declarative snapshot after every intent revision;
- export append-only sanitized audit batches through the transactional outbox;
- alert on failed integrity, snapshot age, off-site age, outbox backlog or insufficient disk;
- quarterly, restore onto an isolated clean control node and prove login, inventory, plan generation, provider refresh and CLI/manual recovery.

The backup adapter pins restic `0.19.1` or a separately reviewed later patch by binary digest, obtains its password through a narrow `RESTIC_PASSWORD_COMMAND`, keeps backup-write and retention/prune authority separate, and follows the check/restore cadence in [Implementation gates](implementation-gates.md#backup-engine-and-repository-topology--g-008). [D-109](decisions-and-sources.md#d-109)

Issue #37 implements only the inert draft-snapshot part of that future export path. It serializes one immutable `valid` or `blocked` inventory draft as a deterministic self-contained `inventory-draft-snapshot`, signs the payload digest for `vsk-labs:inventory-draft-export:v1`, independently verifies it through a separate provider-neutral port, writes immutable digest-addressed bytes, and atomically advances a protected `current.json`. It contains no raw input, secret, approval, plan, run, database page, provider response, local path, session, or authority transition; `kind=draft` remains explicit.

Production currently composes no signer or verifier and fails closed with `PREREQUISITE_BLOCKED`; only a fixed synthetic test identity exists. Issue #28's release-verification policy is a separate trust domain and is not reused. Phase 5 must replace this temporary development choice with qualified export identity and public trust distribution, provider/keystore selection, custody and least privilege, key-ID/fingerprint ownership, rotation overlap and revocation, retained verification keys and offline access, loss/compromise response, restore-time key selection, a tested recovery procedure, clean-node positive/negative evidence, and a decision on export versus audit-checkpoint key separation. Until then, these bytes are neither an accepted declaration nor live recovery authority.

Database restore order. A replacement starts read-only with `recovery_pending=true`; moving an alias alone is never a fence:

1. Freeze the damaged node and preserve the database/files/log hashes.
2. Install the same attested binary/SQLite-compatible release on a clean qualified node.
3. Retrieve and verify the selected encrypted online backup and manifest.
4. Restore to an isolated path, run integrity/foreign-key/migration checks and start read-only.
5. Administratively fence the former instance outside the copied database: stop/disable or quarantine its host and Mesh/network identity; revoke its selected resolver/service identity (1Password in the Labs profile); revoke or rotate every mutating provider/API, Coolify, SSH, backup and audit-export credential it could resolve; remove its control SSH key from managed nodes. If the host is lost, the relevant provider/host administrators and approved independent console/operator recovery procedures perform those revocations before proceeding. The account-free path rotates/removes local-resolver-derived SSH and signing authority through the same fencing contract; it does not require a provider account.
6. In one recovery transaction, assign a new active instance UUID, increment `recovery_epoch`, invalidate all unstarted plans/acknowledgements/leases and retain their history as superseded. Record the recovery reason, prior/new epoch and fence evidence in the audit chain.
7. Issue only new-instance credentials with the documented narrow scopes, re-resolve their references through the selected local or external secret adapter (1Password for the Labs profile) and independently prove old credentials/host paths are denied at every mutating adapter and managed-node boundary. Epoch comparison protects the recovered database; credential/network revocation protects against a still-running old copy.
8. Refresh all provider/host observations and show drift without applying it.
9. Verify Access, CLI socket, roles, audit, backup and a new-epoch no-op plan; obtain cutover acknowledgement.
10. Move the `control-plane` alias, set `recovery_pending=false`/mutation enabled, and execute a disposable canary. Never run two writable control services against copied state.

If no database backup survives, initialize a clean database from the latest signed declarative snapshot, rebind the bootstrap admin through a new exact Slack-approved installation manifest, refresh providers and reconstruct runtime state. This loses unexported operational history and approvals; all old plans are invalid and no mutation is permitted until the anchored audit-continuity procedure is accepted, grants are revalidated and the old writer is fenced. Loss of every approved Slack user enters only the separately authorized break-glass recovery path; it is not an automatic approval fallback.

## Reliability and acceptance

## Implemented local read API

The protected Unix-domain service now composes generated schema-major-1 reads for health, database status, platform summary, immutable inventory drafts and their asset/node/alias/observation children, plus durable audit events. Every route uses the kernel-authenticated local principal. SQLite grants are empty by default, exact capability/resource scopes are checked before input parsing and again in the row query, and revocation closes an event stream at its next batch. Safe mode keeps mutation unavailable and exposes only an authorized store-certified read projection.

Finite pages default to 50 and stop at 200. Their opaque process-keyed cursors bind endpoint, query, scope, grant revision, recovery epoch, state snapshot and keyset position; they expire after 15 minutes and after restart. Event IDs are durable and resume strictly after `Last-Event-ID`. Streams batch 200 events, retain 64 coalesced wakeups, heartbeat every 15 seconds, use a 5-second write deadline, and cap concurrency at 16 total and 4 per principal.

The browser read boundary is generated at `web/generated/read-api.ts` from the same endpoint metadata and JSON Schemas as the Go API. It exposes named functions only for registered `available` `GET /api/v1` routes, accepts an injected same-origin fetch transport, percent-encodes path and query values, and returns the canonical result envelope after strict schema-major and closed-object validation. Callers cannot supply an arbitrary URL or method. Cancellation, network loss, malformed JSON, schema mismatch, unsupported major, cursor conflict, denial and provider unavailability remain distinct sanitized errors; authorization failures are never retried.

The generated SSE iterator sends an optional opaque `Last-Event-ID`, accepts only the registered audit-event stream, checks each frame ID against its decoded durable event ID, bounds frames, and never reconnects or retries by itself. Consumers retain the last successfully processed ID and explicitly start a new iterator to resume. `go run ./tooling/generate-contracts --write` owns the file, and `go run ./tooling/generate-contracts --check` fails when it is missing or changed; Console code must not hand-maintain parallel models or bypass this client to reach SQLite or a provider.

The human-equivalent procedure uses the same protected socket and API: authenticate as an explicitly bound OS peer, obtain an explicit database-backed read grant through the later trusted setup workflow, issue the generated local request, verify the result schema/revision and `no-store` response, and for events retain only the last successfully received durable ID. On denial, stale cursor, revocation, restart-expired cursor, slow connection, or safe-mode limitation, stop and resolve the grant/recovery prerequisite; never open SQLite, add a TCP listener, infer health from absence, or bypass the API. Before merge, abandon the branch to roll back. After migration `0004` reaches a database, correct forward and recover from a verified database copy under the normal recovery procedure.

### Implemented Phase 3 source-health projection

`GET /api/v1/sources` is the provider-neutral source-status list. Its fixed source IDs are `database`, `nodes`, `gates`, `people`, `services`, `backups`, and `providers`. Database health and the newest immutable inventory observation come from the existing authoritative SQLite read transaction. The other five entries are capability slots: until their owning typed adapters exist, they report `unavailable` and do not pretend that a live provider was checked. This issue adds no provider SDK, refresh worker, alert route, accepted inventory, or new persistence owner.

The server, never the caller, owns freshness. Database-integrity and local-inventory observations become `stale` after 24 hours. A later optional adapter receives its own one-hour default until its owning issue records a more specific policy. State precedence is `unavailable` for an absent capability, `failed` for a present source whose collection failed or reports an impossible future collection time, `unknown` when no collection time exists, `stale` after the source limit, and otherwise `healthy`. The response exposes only those stable states, safe fixed reasons and known timestamps. Adapter failure text, provider-native identifiers, credentials and private evidence are discarded before projection.

Source pages use the same 1–200 limit, process-keyed opaque cursor, revision/epoch snapshot and authorization-first handling as the other finite lists. The `source` and `state` filters and `id-asc`/`id-desc` sorting are bounded and included in the cursor binding. A `platform.source.read` grant names one exact source ID; granting the full fixed set requires seven explicit grants, with no implicit wildcard. Ungranted sources are omitted without an existence oracle. `/api/v1/summary` adds only counts by source state and the worst current state. A failed or stale optional source never disables database, inventory or unrelated authorized reads.

## Implemented draft-operation API and CLI

The protected service now composes the three generated operation routes above with the five available operator commands: `status`, `database status`, `inventory import`, `inventory diff`, and `inventory export`. The CLI remains a thin local-socket client. File opening happens only for an explicit protected input, while decoding, validation, persistence, baseline resolution, export publication, authorization, and state ownership stay server-side. JSON output preserves the validated server envelope byte for byte; human output renders only its typed data.

This is an inert-draft development boundary. Production composition intentionally has no qualified signer/verifier, so a real export cannot publish yet. The implementation does not accept inventory, install or deploy the service, qualify a host, contact a provider, mutate infrastructure, or close a deployment gate.

The service is implementation-complete only when tests prove:

- schema migrations upgrade and restore the previous release without data loss;
- power loss, process kill and disk-full simulations do not report an uncommitted plan/run as successful;
- duplicate requests are idempotent and concurrent edits produce a visible conflict;
- a copied pre-recovery database cannot execute after epoch cutover: old plans/leases return `RECOVERY_EPOCH_MISMATCH`, and old host/credentials fail network, SSH and provider mutation tests before the replacement is enabled;
- stale/failed provider data is never rendered healthy;
- an unprivileged browser cannot retrieve secrets, call a provider directly, execute arbitrary input or bypass Access at the origin;
- roles prohibit read/author/acknowledge/execute combinations outside policy;
- plan digest/revision/expiry drift blocks execution;
- interrupted operations resume only at declared idempotent steps and produce accurate `partial` status otherwise;
- online backup plus clean-node restore meets the control-plane recovery objective;
- loss of the Console leaves Coolify, Beszel, backups and CLI/manual recovery usable;
- external monitoring detects API/control-node silence;
- a public credential-free checkout and the protected maintainer lane pass their distinct component checks, including typecheck, build, local component integrity, unit/integration, keyboard, axe, light/dark and mobile/desktop visual gates.

## Implementation sequence

| Increment | Deliverable | Exit proof |
|---|---|---|
| 1. Foundation | SQLite schema/migrations, local API/socket, inventory import/export, audit and fixtures | migration, conflict, integrity and recovery tests pass |
| 2. Read Console | embedded VegaStack UI plus node/Coolify/Beszel/backup read adapters | partial/stale/error states and Access bypass tests pass |
| 3. Declaration workflow | revisioned forms, validation, plan generation and diff | browser and CLI create identical plan digest |
| 4. Controlled execution | acknowledgement, leases, executor, SSE progress and resume | authorization/idempotence/failure injection passes on disposable targets |
| 5. Full adapters | selected VegaStack Labs edge, SCM/CI, host, service, people/device and notification workflows | positive/negative permissions and recovery proven per adapter; disabled optional adapters leave core workflows usable |
| 6. Acceptance | clean-node rebuild, encrypted restore, external watchdog and operator runbooks | phase-3 control-plane gate and operations acceptance evidence complete |

No increment is deployed merely because its documentation or UI exists. Each live adapter remains gated by the broader phase prerequisites and the plan/run authorization policy: explicit human apply, or only the documented exact preauthorized operational/low-risk-deployment class.
