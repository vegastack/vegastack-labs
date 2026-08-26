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

D1 is permitted only as an optional **one-way, sanitized last-known-status projection** for an external status page. The transactional outbox publishes monotonic `state_revision`, observation time and non-sensitive health summaries. The projection has no credentials or endpoints for declarations, acknowledgement, execution or secret resolution; it never writes back, wins a conflict, supplies a recovery input or changes the meaning of a local plan. Staleness is always visible, publication failure queues/retries without blocking local operations, and disabling/deleting the projection leaves control functionality unchanged. [Cloudflare D1 read replication](https://developers.cloudflare.com/d1/best-practices/read-replication/) · [D1 local development](https://developers.cloudflare.com/d1/best-practices/local-development/) · [D1 Time Travel](https://developers.cloudflare.com/d1/reference/time-travel/) · [D1 import/export](https://developers.cloudflare.com/d1/best-practices/import-export-data/) [D-105](decisions-and-sources.md#d-105)

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

### Core data model

| Table/group | Required data and invariants |
|---|---|
| `system_meta`, `schema_migrations` | schema version, state revision, monotonic recovery epoch, active instance UUID, recovery-pending/mutation-enabled state, last successful integrity check; migrations are append-only and checksum verified |
| `assets`, `nodes`, `aliases`, `qualifications` | immutable node ID, typed/scoped provenance and verified access identity; serial uniqueness only for applicable physical inventory policy; names/aliases, lifecycle, role, capacity and evidence; no alias collision |
| `network_endpoints`, `access_devices`, `allowed_flows` | unique address/endpoint bindings, access-adapter identity, approval state and declared positive/negative paths; VegaStack Labs Mesh fields live in the Cloudflare extension |
| `people`, `external_subjects`, `devices`, `grants` | stable provider-neutral subject binding including local OS/SSH identities, lifecycle, desired/applied/effective role/project/shell grants and policy versions, approver and revision; VegaStack Labs Workspace claims live in the identity-adapter extension; no credential value |
| `services`, `environments`, `placements` | owner, source/artifact reference, policy class, exposure, resources, backup, health/migration and rollback contract |
| `adapter_instances`, `capabilities`, `resource_refs` | typed adapter kind/version, enabled capabilities, provider-neutral resource key and separately validated provider extension; no core provider fields |
| `secret_refs` | logical ID, secret-adapter instance plus opaque locator, owner/consumers, rotation/expiry and last nonreversible fingerprint; database constraints reject value-shaped fields |
| `provider_resources`, `observations`, `refresh_runs` | adapter/resource identity, normalized observation, captured time, staleness/error and sanitized raw-response hash |
| `change_requests`, `plans`, `plan_steps`, `acknowledgements` | normalized intent, immutable plan digest, bound recovery epoch, preconditions, risk, expiry, expected interruption, verification and recovery |
| `runs`, `run_steps`, `run_events`, `leases` | execution state, exact plan/tool/recovery-epoch identity, bounded lease, per-step attempt/result and resumability |
| `gate_definitions`, `gate_evidence`, `gate_checks`, `gate_evaluations` | versioned/scoped gate owner and applicability, resolved profile/policy provenance and subject/capability effect; collector/attachment digests and restricted references; deterministic observed/expected results, expiry, recovery epoch and current activation state |
| `audit_events` | append-only actor/action/target/before-after fingerprints/correlation; updates and deletes denied to the service path |
| `backup_records`, `restore_tests` | recovery point, manifest digest, verification, destination and measured RPO/RTO |
| `outbox` | committed notifications/audit exports waiting for delivery, with retry count and next attempt |

Provider-specific payloads may use validated JSON columns only after redaction and size limits. Raw logs, environment values, private keys, tokens, database dumps and full provider responses are prohibited.

“Append-only” inside SQLite is an application control, not immutable evidence against a root user or disk compromise. Each audit event therefore includes the previous event hash, sequence and canonical payload hash. The server periodically signs a batch checkpoint with a separately protected signing identity and exports the batch/checkpoint through the outbox to the declared independently recoverable, encrypted and tamper-evident destination. The Labs profile additionally requires retention-locked off-site storage. The account-free profile proves independent checkpoint custody/recovery without requiring a cloud account; same-host storage alone is insufficient. Verification detects gaps, reordering, edits and rollback to an older checkpoint; it cannot prove events that an already-compromised server suppressed before export. A recovery compares the local chain with the last independent checkpoint and enters read-only incident mode on any mismatch. An explicitly accepted older recovery follows the [anchored continuity procedure](platform-lifecycle.md#recovery-and-retained-dependencies): recover a verified suffix or preserve both histories and anchor a new segment to the prior checkpoint with a declared lost interval; never replay old provider mutations or resurrect revoked grants. No administrator UI may rewrite or “repair” history; corrections are new linked events. [D-106](decisions-and-sources.md#d-106)

### Effective authority and generic lifecycle

The [portable lifecycle](platform-lifecycle.md#effective-authority-and-revocation) defines effective grants/policy separately from inert desired state. Planning cannot authorize itself, start a timer or enable a capability. Expanded authority activates only after approved apply and verification; approved denials persist through partial failure. The prior effective authority authorizes the change. Read-only callers cannot commit declaration/plan intent. Profile changes obey the same activation rule. [Human acknowledgement](platform-lifecycle.md#human-acknowledgement-trust-boundary) additionally requires a qualified separate human action where an agent can use the ordinary account credentials; peer UID, SSH identity, cached session, TTY or actor label alone is insufficient.

### Migrations

Migrations are embedded in the attested server binary and have sequential IDs plus checksums. Startup may apply only forward-compatible migrations approved for that release.

1. Stop new plans and wait for or safely interrupt active runs.
2. Create an online backup and pass integrity verification.
3. Acquire the exclusive migration lock and confirm expected current schema.
4. Apply one transaction where SQLite permits; record each migration checksum.
5. Run foreign-key and integrity checks plus API smoke tests.
6. Start normal operation only after all checks pass.

On failure, stop the new service, preserve the failed copy/evidence, restore the verified pre-migration database, start the previous retained binary and verify. Never run an older binary against a newer schema.

## API contract

All browser and CLI behavior uses one versioned API. HTTP JSON uses `/api/v1`; the local socket uses the same routes. Responses use the single canonical camelCase [machine envelope](automation-and-agents.md#command-surface)—including `schemaVersion`, `runId`/`requestId`, `recoveryEpoch`, `stateRevision`, `toolVersion`, `status`, `errors` and `data`—plus command/endpoint-specific schemas. Do not duplicate a snake_case envelope.

### Read and declaration endpoints

| Method and path | Purpose |
|---|---|
| `GET /api/v1/summary` | fleet, service, CI, backup, alert and change totals |
| `GET /api/v1/nodes`, `GET /api/v1/nodes/{id}` | declared identity, role, qualification and observed state |
| `GET /api/v1/services`, `GET /api/v1/services/{id}` | declaration, placement, exposure, health and provider links |
| `GET /api/v1/people`, `/devices`, `/grants` | authorized lifecycle and access views |
| `GET /api/v1/network` | endpoints, reservations, ports, paths and private-access/overlay status; provider extensions carry Mesh-specific fields |
| `GET /api/v1/providers` | adapter health, credential-reference health and last refresh |
| `GET /api/v1/backups`, `/restore-tests` | recovery-point age, verification and restore evidence |
| `GET /api/v1/gates`, `GET /api/v1/gates/{id}` | design/activation state, applicable subjects, evidence age/checks and exact remediation; `?phase=<n>` filters admission gates |
| `GET /api/v1/plans`, `/runs`, `/audit` | attributed lifecycle history with sanitized evidence |
| `GET /api/v1/events` | Server-Sent Events stream for refresh/run progress; reconnects from durable event ID |
| `POST /api/v1/declarations/{type}` | validate and create a revisioned draft declaration |
| `PATCH /api/v1/declarations/{type}/{id}` | optimistic revision update; cannot execute infrastructure |
| `POST /api/v1/gates/{id}/evidence-drafts` | validate a typed evidence bundle and create an inert change; never sets the evaluation directly |

List endpoints use stable cursor pagination, explicit sorting and server-side filters. Unknown filters/fields are rejected rather than ignored. API and CLI share generated schemas and fixtures; human UI strings are not an API.

### Plan and execution endpoints

| Method and path | Effect and boundary |
|---|---|
| `POST /api/v1/plans` | normalize a typed draft, refresh observations, atomically commit its inert desired-state revision and create an immutable 30-minute plan bound to the active recovery epoch; no external mutation |
| `POST /api/v1/plans/{id}/acknowledgements` | bind the authenticated human, reason, exact digest/targets/risk and active capability |
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
- Browser access is same-origin only. Disable permissive CORS; require allowed Origin/Host checks and an anti-CSRF token for mutations.
- Session cookies, if used for UI state, are `Secure`, `HttpOnly` and `SameSite=Strict`; no local password database is created.
- Session creation, renewal, logout and emergency revocation are audited. Short expiry and server-side revocation are mandatory; changing a person's lifecycle or device grant invalidates active sessions before another apply.
- Content Security Policy denies inline/unapproved script, framing and unexpected network destinations. API responses use `no-store` for sensitive operational data.
- Read, author, acknowledge and execute are distinct capabilities. The server reauthorizes every plan transition and execution.
- Secret values never enter HTML, JSON, SSE, SQLite, logs, traces, browser storage or downloadable audit exports.
- Rate limits apply separately to reads, refreshes, plan generation and execution. Execution also takes a target/provider lease.
- Direct origin access is blocked by bind address and host firewall. Acceptance includes a bypass test from every untrusted network path in the deployment profile.

### VegaStack Labs Cloudflare/Workspace binding

Cloudflare Access authenticates Google Workspace users before the browser origin. The server validates the Access JWT signature, issuer, audience and expiry on every request; it does not trust an email header alone. The verified Workspace subject maps to local grants. Browser admission fails closed when Access/Workspace is unavailable; LAN/console recovery continues through the constrained CLI transport, never through an unauthenticated Console bypass. Acceptance tests both authorized/unauthorized external requests and direct-origin denial from LAN and Mesh. [Cloudflare Access application token](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/application-token/)

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

Build requirements:

1. Install `@vegastack/design` and import only `@vegastack/design/preset.css`; do not duplicate the Tailwind import.
2. Install `@vegastack/provider` before components and keep `VegaStackProvider`, theme hydration handling and global CSS import intact.
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

## Control-plane nomination and bootstrap

The generic [local control-plane creation](platform-lifecycle.md#local-control-plane-creation) replaces mandatory workstation-first bootstrap. An authenticated administrator nominates the current supported host; the host does not attest itself or obtain authority from its name. The Labs profile chooses `vsk-node-04`, while another installation chooses its own host without code changes.

A generated guided setup uses read-only preflight, the explicit finite local installation plan/manifest, then the same `vsk-labs server run` API/SQLite/plan engine. Only that server initializes or opens writable SQLite. A trusted local console or already verified SSH session with recovery access establishes the initial OS administrator binding; there is no first-web-visitor claim or mandatory Workspace account. The consumed bootstrap manifest becomes protected audit/recovery evidence and never remains a mutable execution authority.

Start with authenticated local-only setup. Complete local hardening, native credential resolution and operation-specific recovery before scoped foundation-node preparation. Add operator clients and managed nodes through separate workflows. Initial local service creation does not require the entire fleet, Mesh pilot, Coolify, 1Password, R2, public DNS or browser ingress. Their selected capabilities activate only after their own evidence passes. No qualified-control, independent-restore or site-ready claim is made prematurely.

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

If no database backup survives, initialize a clean database from the latest signed declarative snapshot, rebind the bootstrap admin, refresh providers and reconstruct runtime state. This loses unexported operational history and approvals; all old plans are invalid and no mutation is permitted until the anchored audit-continuity procedure is accepted, grants are revalidated and the old writer is fenced.

## Reliability and acceptance

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
