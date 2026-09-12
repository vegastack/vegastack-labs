# Automation and agents

[Back to README](../README.md) · [Control service](control-plane-service.md) · [Architecture](architecture-and-networking.md) · [Operations](security-and-operations.md) · [Decisions](decisions-and-sources.md)

## Platform contract

`vsk-labs` is the VegaStack Labs platform's single operator-facing control surface for a small physical compute fleet. Humans, Codex, Claude Code and future Hermes integrations may express intent differently, but every mutation converges on the same schema, plan, policy, deterministic adapter, verification and audit record. Natural language is never the source of truth. [D-090](decisions-and-sources.md#d-090) [D-091](decisions-and-sources.md#d-091)

V1 is one opinionated infrastructure operations platform, not a general-purpose extension framework: supported providers/modules are compiled and tested together, and there is no plugin API. Add extensibility only after a second real site proves the boundary. [D-090](decisions-and-sources.md#d-090)

```text
human or agent intent
        |
vsk-labs validation + authorization
        |
revisioned declaration draft + readable/JSON plan
        |
Console/CLI review and risk-appropriate acknowledgement
        |
explicit central apply
        |
host automation / hosting / edge / SCM-CI / secrets adapter
        |
post-checks + sanitized audit result
```

## Code and operational-state boundary

### Public `vegastack-labs` platform (MIT)

Contains reusable implementation and no VegaStack secrets:

```text
cmd/                    Go CLI and control-service entry points
internal/               database, API, schemas, policy, planning, adapters, audit
internal/migrations/    append-only checksummed SQLite migrations
api/                    OpenAPI and generated client schemas
web/                    Next/React VegaStack UI source; static bundle embedded in Go
ansible/roles/          idempotent host roles
schemas/                versioned public JSON/YAML schemas
.agents/skills/         canonical focused Agent Skills
docs/                   generic operator/developer documentation
AGENTS.md                canonical agent contract
CLAUDE.md                imports AGENTS.md
tests/                   unit, fixture, plan and integration tests
```

### Control database

The control-plane SQLite database contains private operational intent, observations, plans and audit metadata:

```text
assets/nodes/aliases        serials, node IDs, lifecycle, facts and network identities
people/devices/grants       roles, projects, device/SSH public keys and lifecycle
network/policy              reservations, switch ports, aliases, approvals and defaults
services/environments       declarations, placement, exposure, resources and backup
secret_refs                 adapter instance plus opaque locator only; no value
plans/runs/audit/outbox     immutable plan lifecycle and sanitized evidence
```

Source-control providers store platform and application code; they are not required to read or mutate private site declarations. The VegaStack Labs deployment profile currently selects GitHub for source, Actions CI and releases, but those are replaceable adapters. Database rows change only through the validated API/CLI, carry optimistic revisions and emit encrypted backups plus signed secret-free snapshots. Generated output is never hand-edited. CI fails if rendered instructions, schemas or skill copies drift from their source. [D-090](decisions-and-sources.md#d-090) [D-100](decisions-and-sources.md#d-100) [D-104](decisions-and-sources.md#d-104)

Audit attribution keeps authentication separate from evidence metadata. The service derives the authenticated principal only from its verified request context; caller JSON cannot supply or override it. A responsible human is accepted only from another trusted server context. Agent name and session are bounded, explicitly `self-reported`, and never authorize a request. Agents, CLIs and adapters cannot open SQLite, append an event independently of its business transaction, or call a provider merely to deliver an outbox row. Issue #33 exposes only a store-owned operational append seam and bounded local outbox transitions for later composition.

Issue #37's draft-export service follows the same boundary. Agents and human-facing clients select a draft reference but never a destination, filename, key, verifier, or trust root. Provider-neutral signer/verifier and artifact-store ports are server composition only; the service signs the canonical payload digest for `vsk-labs:inventory-draft-export:v1`, independently verifies it, and returns secret-free bytes without a local path. It does not reuse Issue #28's release trust. Production composition currently provides no signer or verifier and fails closed; the only key is a fixed public test fixture. A human-equivalent recovery inspects and verifies the same immutable artifact/current-pointer state and records the same interrupted audit outcome—never edits files or guesses success. Phase 5 must replace the temporary development trust decision with the real qualified deployment policy and tested custody, rotation, revocation, retained-key, compromise, offline, restore-selection and clean-node procedures.

### Generic lifecycle and profile selection

[Portable lifecycle](platform-lifecycle.md) owns generic setup/enrollment, native credential resolution, typed identity, versioned profile/gate applicability, Slack-only v1 human acknowledgement and safe exit. Product core cannot assume a node number, mandatory physical serial, Labs domain, Sheet or router model. Slack is a typed acknowledgement adapter selected for normal v1 bootstrap/mutation, not a provider field in portable core records. Public builds have a credential-free contributor path. The Labs profile remains separately selected; its defaults are not universal values.

### Required declarations and schemas

Every YAML declaration validates against a versioned public JSON Schema before it can plan. At minimum:

| Schema | Required intent |
|---|---|
| asset/node | typed/scoped provenance and verified access identity, immutable node ID, lifecycle, discovered facts/evidence time, endpoint references, role aliases and qualification state |
| person/device/grant | stable local person plus external-subject bindings, broad roles, projects, shell nodes, public-key/device identity, approver and lifecycle state |
| approval request/proof | provider-neutral request/subject/target/reason digests, risk, responsible local human, action, expiry, nonce, state revision and recovery epoch; adapter-specific workspace/user/envelope fields stay in the adapter extension |
| approver import | workspace/user-to-local-principal mappings and allowed approval classes, prior effective policy revision and proposed inert revision; no token/signing-secret values and no self-activation |
| network | named endpoints, address bindings, aliases/routes and allowed flow matrix; provider-specific private-access fields live in adapter extensions |
| service/environment | owner, SCM/artifact reference, policy class, placement, exposure/audience, resource/storage/growth, health/migrations, backup and rollback contract |
| adapter instance/resource | capability type, implementation/version, provider-neutral resource key and separately validated provider extension |
| secret reference | logical ID, owner/consumers, secrets-adapter instance, opaque locator, scope, rotation/expiry and last verified fingerprint—never value |
| policy | approval classes, maintenance, tested platform versions, backup/retention/RPO/RTO, alert/thermal/capacity thresholds |
| gate/evidence | gate ID/version, subjects, phase/capability effect, owner, design/activation state, evidence facts/checks/digests, expiry and recovery epoch |
| plan/run/audit | normalized inputs, source revision/facts/tool versions, targets/operations/preconditions, risk/approval, interruption, verification, rollback and sanitized result |

Schemas reject unknown identifiers, duplicate ownership, undeclared exposure/backup class, conflicting hardware/address/alias identity, inline secret-shaped fields and cross-reference failures. Generated artifacts carry recovery epoch, control state revision, snapshot digest, source revision/release build ID and generator/schema version so drift is attributable.

The earlier `mac-dev-env-setup` project is a requirements mine, not a compatibility target. Preserve its useful operator experiences—developer worktrees, persistent terminal sessions, account lifecycle, onboarding, environment tiers, update notices and Mac services—but implement a clean `vegastack-labs` platform from scratch. Do not inherit unsigned self-updates, cross-user passwordless shells, broad team-readable secrets, automatic dangerous aliases or backups that contain only remote listings. [D-007](decisions-and-sources.md#d-007)

## Engine responsibilities

| Layer | Responsibility |
|---|---|
| one Go `vsk-labs` executable | CLI plus `server run`; validation, local/remote API, database ownership, discovery UX, schemas, authorization, planning, approvals, adapter orchestration, JSON output and audit |
| Ansible | Supported Debian/Ubuntu/macOS host state over SSH: complete onboarding baseline, security tools/settings, accounts, keys, packages, firewall, Docker/role prerequisites, timers, monitoring and verification |
| Typed provider adapters | versioned SCM, CI, release, registry, identity, secrets, edge, hosting, backup and notification bindings with previewable desired state and least-privilege credentials |
| Optional capability modules | explicitly enabled discovery/events, managed source-build/PR feedback, rich provider status, external notification and remote-status projection behavior; disabled modules leave local core workflows usable |
| Scripts | small deterministic helpers only when a native module is unavailable; every script is versioned, tested and called through the CLI |
| SQLite control database | authoritative private desired state, revisions, plan/run lifecycle and historical intent |
| Next/React web bundle | VegaStack Labs deployment profile's VegaStack Design System operator interface embedded into the same `vsk-labs` executable; it calls the same API as the CLI |

The VegaStack Labs deployment profile selects direct typed adapters rather than a second Terraform/OpenTofu state engine: the Cloudflare adapter uses the official `cloudflare-go` v7 client plus reviewed raw REST only for a required missing endpoint, and the Coolify adapter uses `/api/v1`. SQLite remains desired-state authority. Any optional GitHub-owned resource uses its SCM/CI adapter and smallest credential. Do not mix direct console writes and adapter ownership for one object. [Implementation gates](implementation-gates.md#provider-ownership--g-012-through-g-016-g-019) [D-112](decisions-and-sources.md#d-112)

The core is agentless: the control plane applies Ansible over SSH and provider APIs. Managed nodes do not run a custom privileged `vsk-labs` daemon. The CI adapter in `server run` launches pinned one-job ephemeral runner listeners over constrained SSH; no second controller service or permanently privileged runner is introduced. Phones/tablets are operator endpoints, not managed servers; the Labs guidance selects Cloudflare One Client and SSH clients. Generic account-free local/SSH inspection, preparation and recovery—and the separate Slack-only v1 acknowledgement prerequisite—are defined in [portable lifecycle](platform-lifecycle.md). [D-008](decisions-and-sources.md#d-008) [D-111](decisions-and-sources.md#d-111) [D-122](decisions-and-sources.md#d-122)

Agentless operation and the Mac node numbering/role placements are **derived architecture choices**, not silently promoted transcript answers. They remain current because they are the smallest design satisfying the selected central-control/security model; a reviewed decision can replace them without rewriting user evidence.

An infrastructure object has exactly one mutation owner recorded as `{adapter-instance, code-owner, resource-key}`. Import captures current state before ownership; the first plan must be no-op or explain every delta. A direct provider change is emergency drift: freeze the owning adapter for that object, record actual state, recover service, then import/reconcile as a new database revision. Actual adapter owners, credentials and canary permission evidence remain `G-016` activation inputs; the engine choice is closed.

## Command surface

The final tree is generated from command metadata. The initial contract is:

```text
vsk-labs status --config <path> [--output human|json] [--schema-version 1]
vsk-labs database status --config <path> [--output human|json] [--schema-version 1]
vsk-labs doctor
vsk-labs plan [--change <draft-id>] [--output json]
vsk-labs apply --plan-id <plan-id> [--output json]
vsk-labs audit

vsk-labs inventory import --config <path> --file <path> --format <typed-json|labs-sheet1-csv> --source-revision <revision> --captured-at <UTC-RFC3339> --idempotency-key <opaque-key> [--expected-state-revision <revision>] [--output human|json] [--schema-version 1]
vsk-labs inventory diff --config <path> (--draft-id <id> --draft-revision <revision> | --file <path> --format <typed-json|labs-sheet1-csv> --source-revision <revision> --captured-at <UTC-RFC3339>) [--output human|json] [--schema-version 1]
vsk-labs inventory export --config <path> --draft-id <id> --draft-revision <revision> [--output human|json] [--schema-version 1]
vsk-labs gate list [--phase <n>] [--ready-for-input] [--output json]
vsk-labs gate inspect --gate <gate-id> [--output json]
vsk-labs gate check [--phase <n>] [--gate <gate-id>] [--output json]
vsk-labs gate evidence --gate <gate-id> --file <path> [--output json]
vsk-labs node discover|add|inspect|nominate|quarantine|replace
vsk-labs user onboard|offboard|suspend|resume
vsk-labs device request|approve|revoke
vsk-labs service plan|deploy|rollback
vsk-labs backup status|run|verify
vsk-labs restore plan|run|verify
vsk-labs maintenance plan|run
vsk-labs connect --node <id> --port <n>
vsk-labs control-plane plan|verify|recover
vsk-labs database backup|verify|restore|export
vsk-labs server run [--config <path>]
vsk-labs server status
vsk-labs release inspect|verify
```

Interactive commands guide humans; noninteractive commands accept explicit flags/files and return versioned, stable JSON on stdout while diagnostics go to stderr. Both invoke identical validation and policy. V1 supports the native clients in the matrix below. This gives Codex, Claude Code, CI and humans one parseable contract instead of screen-scraping prose. [D-097](decisions-and-sources.md#d-097)

Issue #36 makes the five status/inventory commands above available only through the authenticated protected API/client route; the Issue #31 library is not a separately available CLI or database path. The client validates the complete flag shape and may read only the explicit protected config and candidate file. The server authorizes before reading the request body, then performs decoding, validation, persistence, compatible-draft baseline selection, and Issue #37 export delegation. Input is strict and bounded. A structurally safe semantic conflict is retained completely as an inert `blocked` draft with deterministic findings; malformed, unknown, oversized, secret-bearing, cancelled, or unauthorized input writes nothing. An opaque idempotency key is retained only as a digest: exact key plus canonical-content retry returns the original reference without a state change, while conflicting reuse fails closed.

JSON mode writes the validated server envelope exactly once without restamping or reserialization; its request ID, revisions, status, errors, exit meaning, and final newline remain the API's. Human mode renders only the typed data from that envelope. Redirected stdout is a client record, not the server's digest-addressed signed artifact. A missing compatible diff baseline or unavailable qualified export trust is `PREREQUISITE_BLOCKED`; neither condition is guessed around.

The `audit` command in the final-tree sketch also remains planned. Issue #33 creates no audit query/API/CLI, sender, worker, external projection or notification path; later issues must expose authorized reads and separately select any optional destination adapter.

The human-equivalent import procedure is: select the explicit protected config and local provider-neutral file; provide its format, source revision, UTC capture time, and opaque idempotency key; inspect every ordered finding and diff; correct the source using that source's human-owned workflow; then submit a new immutable snapshot and key. Do not edit SQLite, the source Sheet, the export root, remove findings, overwrite a stored draft, infer identity from hostname/address/row position, or treat `valid` as accepted. Database or migration failure uses the same checked-catalog, verified-copy and isolated-restore procedure as every server-owned store change. A signed projection still says `kind=draft`; declaration/effective transition remains Phase 4 work.

`gate list`, `inspect` and `check` are read-only. `gate evidence` validates a typed evidence bundle and creates an inert draft/change ID; it cannot declare success. The ordinary `plan --change` and `apply --plan-id` path records the evidence, after which the server derives the gate evaluation from generated checks. [Implementation gates](implementation-gates.md#gate-semantics) [D-108](decisions-and-sources.md#d-108)

`server run` is the only long-running entry point. It stays in the foreground, handles graceful termination and is started/stopped/restarted by `systemd` in the supported server profile. `server status` is a read-only API/health query, not a second service manager. Every plan consumer uses the exact `--plan-id` grammar above; positional plan IDs, alternate service-lifecycle verbs and mutation-flavored `--dry-run` aliases are rejected so examples cannot drift.

All risk-bearing infrastructure mutation enters the same immutable plan/run/lease state machine. `apply --plan-id` is the only **human** mutation entry point. An exact, previously approved noninteractive policy may start only (a) the fixed operational jobs below or (b) the declared low-risk application-deployment run whose protected CI executor is already bound in the plan; it is not a second command grammar or blanket authority. Domain verbs such as `node add`, `service deploy`, `restore run`, `maintenance run`, `user suspend` and `control-plane recover` are typed **change constructors**: they validate inputs and return a draft/change ID (and may immediately request its plan), but cannot execute it. `plan --change <draft-id>` is the one atomic transition that validates current facts, commits the inert desired-state revision and stores its immutable plan; committing intent changes no external system. Initial setup follows the finite local installation manifest and server-owned handoff in [portable lifecycle](platform-lifecycle.md#guided-setup-and-the-initial-authority); it is not a general offline apply mode and needs no separate operator workstation. Read-only `verify`, `inspect`, `status`, `doctor`, `diff` and `audit` never create a draft.

### Generated Phase 4 contract

Issue #66 defines the public contract but does not make `plan`, `apply`, or any Phase 4 endpoint runnable. They remain `planned` until their owning engine issues implement and test the routes. The generated provider-neutral schemas are closed authoritative inputs: unknown fields, missing bindings, unknown states, secret-shaped names, and unknown schema majors fail. A read-only compatibility decoder may accept a documented additive field at the top level of the same major; nested bindings stay exact, and compatible reads cannot authorize, persist, execute, lease, receipt, or calculate a canonical digest.

An immutable plan binds its declaration and prior/current state revisions, recovery epoch, aggregate observation fingerprint, aggregate target and reason digests, ordered operations with exact targets and artifacts, policy/tool/contract versions, authorization branch, executor mode/identity, readable digest, lifecycle status, creation time, and an expiry exactly 30 minutes later. Human acknowledgements add their own identity, exact plan/target/reason bindings, human and authority identities, nonce digest, proof digest, received time, state revision, recovery epoch, and expiry. No field carries a secret value.

Runs bind the authorization decision, nullable human acknowledgement, policy version, executor mode/identity/binding digest, steps, verification state/digest, changed result, state revision, and recovery epoch. Their states are `queued`, `running`, `succeeded`, `failed`, `partial`, `interrupted`, and `cancelled`; only generated transitions are valid, and terminal states cannot restart. Cancellation records an intent to stop and never asserts rollback: recovery remains `not-requested`, `required`, or a `separate-plan`.

An external lease and every receipt repeat the exact plan, run, step, operation, executor, adapter, target, artifact, binding, nonce, and recovery-epoch tuple. Permission lasts 60 seconds, check-in is due after 20 seconds, and `maximumExpiresAt` prevents extension beyond that authority window. Lease state is `active`, `expired`, `released`, or `revoked`; receipt state is `running`, `succeeded`, `failed`, or `partial`. A receipt is an untrusted executor claim until server verification records the run's verification result, and any widened binding is rejected.

A separately declared class covers repetitive, non-destructive operational jobs such as consistent backup creation, integrity verification, provider observation refresh and retention-safe audit export. Approving the policy/schedule authorizes only its exact sources, destinations, adapter version, maximum work and retention rules; each timer invocation creates a run ID, checks current policy/preconditions and audits the result without a new human acknowledgement. It cannot restore, delete protected recovery points, change retention, add targets or resolve broader credentials. `backup run` invokes this same fixed policy on demand; any policy/configuration change still uses plan/apply. [D-081](decisions-and-sources.md#d-081)

## OS and architecture support matrix

“Supported” is a release gate: the named package, install/upgrade/rollback, paths, permissions, transport and smoke/integration fixtures must pass on the real OS/architecture. “Profile-validated” additionally means the VegaStack Labs deployment exercises it. Anything else is rejected before mutation rather than treated as best effort. Go can target more combinations, but buildability alone is not platform support. [Go environment](https://go.dev/doc/install/source#environment) [D-107](decisions-and-sources.md#d-107)

| Surface | OS / architecture | V1 status | Package and service contract | Required release evidence |
|---|---|---|---|---|
| control-plane server | Debian 13, Linux `amd64` | supported; VegaStack Labs profile-validated | signed `.deb`; `systemd` unit runs `vsk-labs server run`; local filesystem SQLite | clean install, permissions, reboot/start/stop, migration, power-loss, upgrade/rollback and clean-node restore |
| control-plane server | other Linux, Linux `arm64`, macOS, Windows | unsupported in v1 | installer refuses server enablement | explicit negative fixtures; future support requires a service/storage/recovery design and real-host lane |
| managed node | Debian 13, Linux `amd64` | supported; VegaStack Labs profile-validated | agentless SSH/Ansible; POSIX paths owned by the selected host role | clean/rebuild, shell/quoting, account/firewall/service/package idempotence and rollback tests |
| managed node | Ubuntu Server 26.04 LTS, Linux `amd64` | supported public role after its mandatory real-host lane passes; not selected by VegaStack Labs | agentless SSH/Ansible; exact point release pinned in release policy | clean/rebuild role matrix, upgrade and negative unsupported-version test; mutation remains blocked until this lane exists |
| managed node | current and previous macOS, Apple `arm64` | supported native Mac roles; VegaStack Labs profile-validated | SSH plus signed/notarized helper only if a role needs one; `launchd` for persistent jobs | standard/admin-account separation, Keychain, paths, sleep, Screen Sharing, launchd, update/rollback and cross-user denial |
| managed node | Linux `arm64`, macOS `amd64`, Windows any | unsupported in v1 | discovery may report; mutation blocks | no implied support from CLI builds |
| operator CLI | Linux `amd64`/`arm64` | supported | signed archive; `.deb`/APT optional managed channel | XDG paths, Secret Service credential path, direct-argv execution, install/atomic update/rollback and JSON golden tests |
| operator CLI | macOS `amd64`/`arm64` | supported | signed/notarized universal or per-arch archive; Homebrew manifest may install it | Application Support/Keychain, quarantine/notarization, shells, case-insensitive filesystem and update/rollback tests |
| operator CLI | Windows 11 `amd64` | supported | Authenticode-signed `.exe`/ZIP; WinGet manifest | PowerShell and `cmd.exe`, spaces/Unicode/long paths, Credential Manager/DPAPI, CRLF, proxy, update/rollback and JSON golden tests |
| operator CLI | Windows `arm64` or older Windows | unsupported in v1 | package resolver refuses incompatible asset | explicit architecture/version error |
| browser client | current and previous Chrome/Edge/Firefox; current and previous Safari | supported where vendor still security-supports release | no local install; responsive Console | keyboard-only, screen reader/semantic, WCAG 2.2 AA, zoom, light/dark, mobile widths and stale/offline states |
| build runner | Linux `amd64` | supported VegaStack Labs runner adapter after phase-4 qualification | one-job ephemeral job environment; controller outside job | hostile-job isolation, cleanup, log export, cancellation, architecture and thermal/resource tests |
| build runner | macOS `arm64` | optional/profile-selected, preview-sensitive until revalidated | one native lower-priority job under dedicated service identity | real-host trust/admission/cleanup plus provider support revalidation; hosted/manual fallback |
| build runner | other OS/architecture | unsupported in v1 | no runner enrollment | negative enrollment test |
| optional provider integration | server-side adapter on supported Debian `amd64`; client OS independent | supported only per enabled adapter/version capability matrix | pinned API version and adapter extension schema; provider credential never reaches operator client | official-source recheck, sandbox/canary capability test, positive/negative permission test, outage/staleness/manual-fallback and offboarding test |

### Phase 0.4 host-action contracts

The schema `vegastack-labs.dev/phase-0.4-contract-fixture` version `1.0.0` defines five contracts: `host-control-matrix`, `privileged-execution`, `native-credentials`, `macos-admission` and `admission-evidence`. They are contract/fixture proof only; later phases implement the public Go schemas, Ansible roles and real-host collectors.

`privileged-execution` binds `planId`, `planDigest`, `bundleDigest`, `targetHostId`, `declarationRevision`, `recoveryEpoch`, `issuedAt`, `expiresAt`, `observedAt`, `automationPrincipalId`, the single executable/mode, resident/state flags, the approved/requested action sets and `recoveryPrecheck`. The server prepares the immutable bundle and invokes the root-owned one-shot mode through the dedicated non-root automation identity. The privileged side independently verifies every binding before dispatching typed built-in actions; it does not accept an Ansible module name, shell command, pathname, inventory pattern or replacement target as authority. Wrong binding is `AUTHORIZATION_DENIED`, expired input is `PLAN_STALE`, an epoch mismatch is `RECOVERY_EPOCH_MISMATCH`, and lost independent recovery is `PREREQUISITE_BLOCKED`.

`native-credentials` binds `credentialRef`, native resolver metadata, `consumerId`/`requestedConsumerId`, current/required material versions, status, cloud/hardware-protection facts, rotation, revocation and independent recovery. The resolver is account-free, uses the platform credential-store abstraction, accepts absence of TPM-class protection as an explicit supported state and never falls back to plaintext. A denied path returns only the reference and stable error category; rejected material is never echoed.

`macos-admission` combines the exact resolved Mac release/build with Mesh network facts, a default-deny identity/device/destination/port policy, declared Remote Login user, disabled password/direct-root login, native application-firewall truth, explicit no-PF/no-MDM facts, supported local TCC consent, reboot verification and physical-console recovery. `admission-evidence` binds each result to immutable host identity, `host-security-v1`, release build, declaration revision and recovery epoch. Daily maximum age is `86400` seconds; a relevant change invalidates older evidence immediately. Stale/failed evidence blocks only new admission, role expansion and new workload credentials, not a safe existing workload or separately authorized recovery.

### Cross-platform client contract

- Resolve configuration, cache, state and log paths through the OS API: XDG directories on Linux, `~/Library/Application Support/VegaStack Labs` and related Library locations on macOS, and Known Folders such as `%LocalAppData%\VegaStack Labs` on Windows. Server-only `/etc`, `/run` and `/var/lib` examples never appear as portable client defaults.
- Store refresh/session credentials in Secret Service/libsecret where available on Linux, Keychain on macOS and Credential Manager backed by DPAPI on Windows. A permission-restricted file is an explicit headless fallback with a visible warning and rotation path; environment variables are single-process CI inputs, never durable storage. [Apple Keychain Services](https://developer.apple.com/documentation/security/keychain-services) · [Windows DPAPI](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)
- Construct child processes with argument arrays and explicit working directories/environment allowlists; never generate a shell string. Test POSIX shells, PowerShell and `cmd.exe`, spaces, quotes, Unicode, separators, drive letters, case collisions, symlinks/junctions, line endings and executable suffixes.
- Prefer the versioned HTTPS API for remote clients. Same-host server recovery may use an authenticated Unix-domain socket on supported Unix systems; no remote/cross-platform flow depends on it. SSH fallback uses a constrained server command and an explicit host-key policy, not shell aliases.
- Release manifests map `(os, arch)` to an immutable digest and minimum server/API schema. Clients verify signature/digest before atomic replacement, retain the prior binary, never overwrite a running executable in place and emit byte-for-byte equivalent canonical JSON across platforms. macOS artifacts are signed/notarized; Windows binaries/manifests are signed; Linux archives carry the common release signature. [Apple notarization](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution) · [Windows code signing](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options) · [WinGet manifests](https://learn.microsoft.com/en-us/windows/package-manager/package/manifest)

Machine output uses one envelope; fields shown here are required, while command-specific `data` validates against its named schema:

```json
{
  "schema": "vegastack-labs.dev/run-result",
  "schemaVersion": "1.0.0",
  "toolVersion": "<site-pinned-version>",
  "command": "plan",
  "requestId": "<opaque-id>",
  "runId": "<durable-run-id-or-null>",
  "status": "succeeded|blocked|failed|partial|interrupted|cancelled",
  "changed": false,
  "recoveryEpoch": 3,
  "stateRevision": 42,
  "snapshotDigest": "<sha256-or-null>",
  "releaseBuildId": "<attested-build-id>",
  "sourceRevision": "<immutable-source-revision-or-null>",
  "planId": "<content-derived-id-or-null>",
  "errors": [{"code": "<stable-code>", "target": "<id>", "retryable": false}],
  "data": {}
}
```

JSON mode emits exactly one envelope on stdout; progress/diagnostics go to stderr and secret values go nowhere. Stable error codes and process exit codes are public constants with fixtures. Backward-compatible fields are additive within a major schema; consumers reject an unknown major and ignore documented unknown additive fields. Human output is not an API. `--output json` cannot prompt: missing input or acknowledgement returns a blocked result and no mutation.

### Exit and error registry

| Exit | Meaning | Required top-level error codes |
|---:|---|---|
| `0` | read/plan/apply completed successfully; inspect `changed` for a no-op | none |
| `2` | command usage, parse or schema validation failed before authorization | `INPUT_INVALID`, `SCHEMA_UNSUPPORTED`, `UNSUPPORTED_PLATFORM`, `EVIDENCE_INVALID` |
| `3` | caller could not be authenticated or the session expired/revoked | `AUTHENTICATION_REQUIRED`, `SESSION_EXPIRED` |
| `4` | authenticated caller lacks scope or required acknowledgement | `AUTHORIZATION_DENIED`, `APPROVAL_REQUIRED` |
| `5` | optimistic conflict, stale/expired plan or evidence, recovery-epoch mismatch or incompatible client/server state | `STATE_CONFLICT`, `PLAN_STALE`, `EVIDENCE_EXPIRED`, `RECOVERY_EPOCH_MISMATCH`, `VERSION_INCOMPATIBLE` |
| `6` | prerequisite/gate, target, credential reference or provider is unavailable | `PREREQUISITE_BLOCKED`, `GATE_BLOCKED`, `TARGET_UNREACHABLE`, `DEPENDENCY_UNAVAILABLE` |
| `7` | execution began and failed or stopped partial; per-step state is authoritative | `EXECUTION_FAILED`, `EXECUTION_PARTIAL`, `RECOVERY_REQUIRED` |
| `8` | database/audit/migration integrity failure; server is in safe mode | `INTEGRITY_FAILURE`, `MIGRATION_BLOCKED` |
| `9` | caller cancellation or process interruption reached a declared safe boundary | `INTERRUPTED` |

Every nonzero JSON response still emits one valid envelope with one or more ordered errors. The first error determines the process exit; additional errors never change it. Network timeouts do not collapse into “failed”: the client returns `DEPENDENCY_UNAVAILABLE` if no run started, or queries the run ID and returns its durable `EXECUTION_*` state if it did.

`cancelled` means no execution step began (for example, a queued run was withdrawn); it returns exit `9` with `INTERRUPTED` and `changed=false`. `interrupted` means execution began and stopped at a declared boundary; it returns exit `9`, reports truthful `changed`, and lists completed/incomplete steps. If state is uncertain or compensation is required, the durable status is `partial` and exit `7`, never `interrupted` merely because the client disconnected.

### Release and version model

- Publish immutable signed release assets through the configured release adapter with checksums, SBOM and build provenance; clients verify the release manifest, repository/issuer identity and asset digest before activation. The VegaStack Labs deployment profile selects GitHub Releases/Actions and may use GitHub artifact attestations, but the core update schema names no GitHub object. [GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations)
- Package managed clients through Homebrew, a signed `.deb`/APT repository and WinGet. Show an update notice; never silently overwrite the running binary.
- The control database pins exactly one `vsk-labs` toolchain version. The control plane must run that version before mutation; clients fetch/cache the exact attested release or stop with one clear upgrade command.
- Change the site pin through a reviewed database revision, verify the new release in a canary/read-only run, back up the database, and activate atomically with a retained rollback binary.

Release assets use Sigstore keyless blob signing and stored verification bundles; clients bind the exact OIDC issuer plus repository/workflow identity and verify offline-capable bundle evidence. The site retains the active release plus two prior complete verified release sets. Exact release repository/workflow identity and feed URLs remain `G-017` evidence until pinned and verified; repository existence alone is insufficient. The active-plus-two count covers the immediate rollback cache, not the longer [recovery dependency archive](platform-lifecycle.md#recovery-and-retained-dependencies). [Implementation gates](implementation-gates.md#platform-releases-and-generated-registries--g-017-g-018) [D-098](decisions-and-sources.md#d-098) [D-114](decisions-and-sources.md#d-114)

Release CI builds each platform from the tagged commit in an isolated workflow, records source/ref/toolchain/dependency inputs, produces SBOM/checksums and provenance, creates a Sigstore bundle under the selected identity, and publishes immutable assets. Installation verifies checksum, bundle, issuer and repository/workflow identity before atomic activation. The active and two prior site-pinned binaries/schemas remain executable for rollback. A compromised/missing feed or unverifiable artifact fails closed and leaves the current binary untouched. Package manifests point to the same verified release assets and cannot replace a binary silently.

### Operator experience contract

- Read-only and `plan` are the safe defaults; on the human branch, `apply` is always a separate explicit action. A preauthorized CI policy creates only its exact low-risk run and never impersonates a human apply.
- `doctor` reports one actionable failure at a time with the failing invariant, evidence, exact remediation or linked manual runbook, and whether retry is safe.
- Human plans show targets, changes, risk/approval class, secret references, expected interruption, verification and recovery before the acknowledgement prompt. JSON plans expose the same fields and a schema version.
- Every long operation has a run ID, per-target progress, bounded timeout and idempotent resume/reconcile behavior; disconnecting a terminal never implies success or automatic retry.
- Success output says what changed and what was verified. Failure output says what did and did not change, whether rollback ran, and the next safe action—without secret values.
- Agent skills ask the human only for genuinely missing policy/input; they must surface the same plan instead of paraphrasing away targets or risk.
- The Console uses the supported VegaStack Design System components and generated API client; it cannot introduce an alternate planning or authorization path. [Control-plane service](control-plane-service.md#web-application-and-vegastack-design-system)
- Shared-Mac setup provides per-user worktrees and persistent terminal sessions as conveniences, but they never cross home-directory, credential or process-ownership boundaries. [D-007](decisions-and-sources.md#d-007)

## Normal change flow

1. An authorized human or delegated agent runs a read-only discovery or opens a typed declaration draft through the CLI or Console.
2. The `vsk-labs` server reads the public schema and a consistent control-database revision.
3. The engine validates identity, scope, current facts, secret references, optimistic row revisions and invariants.
4. Planning atomically commits the smallest inert declaration revision and its identical readable/JSON plan through the shared engine, binding the active recovery epoch.
5. Authorization follows exactly one branch. **Human branch:** an authorized human reviews the declaration diff, targets, risk, recovery and immutable plan digest, then uses the configured Slack acknowledgement adapter; self-approval is allowed within that person's policy boundary, and an agent never supplies the Slack action. **Preauthorized branch:** only an exact eligible low-risk application-environment policy, named executor and digest/target boundary may authorize the run without a new human action; an agent cannot classify itself into or widen that policy. Production-like deployment always uses the human branch.
6. Committing a declaration changes no infrastructure. Plans expire after 30 minutes or immediately when declared/observed preconditions change.
7. In the human branch, the Console, CLI socket or constrained SSH client presents the exact request and the human approves or rejects it through Slack; the client itself cannot acknowledge. In the preauthorized branch, the server queues only the exact policy-bound run after the admitted CI identity submits the matching digest evidence.
8. The control plane reauthorizes the human **or** exact policy/CI identity, checks the recovery epoch/state revision/digest plus acknowledgement or policy authorization, and refreshes target preconditions.
9. Deterministic adapters execute under a scoped lease, verify and emit a sanitized per-target result plus durable events. A declared external executor may claim only its exact lease; in the VegaStack Labs deployment profile, protected CI directly calls Coolify for application deployment after risk-based authorization.
10. Drift scans report later divergence but never silently repair it. [D-092](decisions-and-sources.md#d-092) [D-093](decisions-and-sources.md#d-093) [D-100](decisions-and-sources.md#d-100)

Plans are immutable and short-lived. A plan ID is derived from the recovery epoch, normalized state revision, observation fingerprints, target set, ordered operations, tool/schema/policy versions and expiry. V1 plan validity is 30 minutes. Any changed recovery epoch, revision, target facts, policy, credential scope or elapsed validity invalidates it and requires regeneration. A run that began in time retains its immutable plan identity only within the same epoch; a retry may resume only declared idempotent steps after current preconditions pass.

An acknowledgement binds recovery epoch, plan ID/digest, target-set and reason digests, responsible local human, authenticated Slack workspace/user/action/envelope, authority used, timestamp/expiry, nonce and risk class. `vsk-labs server run` receives the interaction over Socket Mode and verifies its authenticated envelope, configured identity, freshness, single use and current local authorization before recording a provider-neutral proof. The minimum declared permissions are app-level `connections:write` and bot `chat:write`; credentials are logical secret references only. An agent can request/present a plan but cannot create the Slack action. Missing Slack is `PREREQUISITE_BLOCKED`, an outage/token failure is `DEPENDENCY_UNAVAILABLE`, wrong workspace/user is `AUTHORIZATION_DENIED`, stale state/plan is `PLAN_STALE` or `STATE_CONFLICT`, and an epoch mismatch is `RECOVERY_EPOCH_MISMATCH`. Noninteractive automation uses a separately declared policy identity only for exact operations already approved without a human; VegaStack Labs permits this for eligible low-risk application-environment deployments, never as blanket fleet/network/identity/control authority. Production-like deployment requires the assigned maintainer. [D-122](decisions-and-sources.md#d-122)

The account-free remote operator path uses constrained SSH to the control host and the versioned `vegastack-labs.api-ssh` `1.0.0` framing guard. A request carries only a request ID, bound SSH principal/device, declared API operation, direct argument array, payload digest and recovery epoch; framing also validates declared versus actual payload length. A response frame carries the same protocol/version and request ID, declared/actual payload length and the canonical versioned API envelope; protocol, length and correlation mismatches are rejected before consumers use its result. It supports authorized reads and inert draft/plan preparation, and can submit an exact apply only after the server has a valid Slack proof or exact preauthorized policy. It accepts no arbitrary shell command, metacharacter-bearing shell text, pathname or direct SQLite request. Bind the authenticated SSH principal/device to server grants; reject client-asserted identity, malformed length/version, unknown operations and principal/device mismatch. This transport is not an acknowledgement source or second mutation grammar. A disconnected client queries the durable run/request ID; it neither retries nor assumes failure. If control is unavailable, `plan/apply` stops and the human uses the generated manual recovery path—no client silently becomes an alternate controller.

For Ansible-owned state, planning runs inventory/schema checks plus check/diff against the exact hosts, removes volatile noise and stores the ordered expected change fingerprints. Apply uses the same release/state revision/inventory/limit, serializes lockout-sensitive changes, and runs role post-checks followed by a second check-mode pass. Unexpected differences or non-idempotence produce `partial`/`failed`, preserve per-host state and stop the next batch. Provider adapters use the same read-plan-precondition-apply-read-verify contract and declare whether compensation is safe; a failed irreversible step never reports “rolled back.”

## Approval and execution boundaries

| Operation | Required boundary |
|---|---|
| Status, discovery, audit and non-committing preview | Immediate if caller may read the underlying scope |
| Draft/plan creation that commits intent | Change-authoring scope, optimistic revision match and the prior effective authority; no infrastructure or permission activation |
| Create or edit a declaration revision | No live mutation; caller must have change-authoring scope and optimistic revision match |
| Routine additive change within assigned project | Maintainer's verified Slack acknowledgement; self-approval allowed within effective policy; explicit apply |
| Exact eligible low-risk application-environment deployment | Previously approved policy identity; protected CI may claim only the plan-bound digest/resource lease; no per-run human acknowledgement |
| Ordinary production-like deploy with passing policy | Assigned maintainer's verified Slack acknowledgement; exact image digest and health rollback required |
| Add/remove node, shell grant, public exposure or backup-policy change | Infrastructure-admin Slack acknowledgement |
| Network, identity, secret-provider or control-plane change | Infrastructure-admin Slack acknowledgement plus recovery precheck |
| Destructive/high-blast-radius change | Explicit target list, stronger confirmation and verified recovery point |
| Emergency direct action | Break-glass credential, reason, narrow time/targets and conspicuous audit |

An interactive coding-agent setting that suppresses the agent's own prompts does not weaken these controls. Infrastructure credentials, `vsk-labs` policy, plan freshness and verified Slack acknowledgement remain the enforcement boundary. Every agent-assisted apply records both the responsible human and the agent/session identity. Slack notification delivery cannot acknowledge or authorize a plan. [D-094](decisions-and-sources.md#d-094) [D-095](decisions-and-sources.md#d-095) [D-122](decisions-and-sources.md#d-122)

## Audit record

Every mutation records:

- requesting human and agent, if any;
- reason and normalized inputs;
- control state revision, snapshot digest and plan ID;
- policy decision and acknowledging human;
- provider/Ansible execution ID and exact targets;
- before/after fingerprints without secret values;
- per-target result, health checks and rollback result;
- timestamps, tool/engine/schema versions and sanitized log hash.

Routine operational logs remain local for 30 days; encrypted security/execution audit records remain in R2 for six months. An agent may inspect authorized audit metadata but cannot reveal secret payloads. [D-073](decisions-and-sources.md#d-073) [D-085](decisions-and-sources.md#d-085)

## Representative workflows

### Add a supported managed host

```text
discover identity + OS/version/architecture -> unadmitted inventory record
-> qualification + verified bootstrap/recovery path
-> revisioned node/role + applicable hardening profile -> plan/review
-> explicit apply -> Ansible OS-specific security baseline + verification
-> declared Mesh/role/services -> repeat affected security/health probes
-> verified admission -> workload eligibility
```

No AI-generated one-off playbook may bypass the reviewed role. If a capability is missing, the agent authors a public engine change with schema, tests and documentation first.

Every managed host, including replacements, reimages and the control-plane bootstrap target, requires [basic hardening before workload admission](host-onboarding-and-hardening.md). Ansible owns the complete host-side security and role configuration through the approved `vsk-labs` workflow. Use the existing OS/architecture support matrix and typed, tested host profiles; no universal shell script or an unsupported-version fallback. Bare discovery and the minimum scoped access needed to harden a host do not grant workload eligibility or general fleet credentials. A quarantine record alone does not prove network isolation. The selected tools and daily/after-change drift/admission outcome are confirmed; exact profile settings, elevation and control-by-control probes remain phase 0 qualification work, not implemented commands or passed gates. Provider enrollment remains owned by its typed adapter, and OS/consent prerequisites that cannot be automated remain explicit gates.

### Onboard a person/device

```text
Workspace prerequisite -> revisioned role/device declaration
-> Cloudflare quarantine enrollment -> inventory match or human approval
-> assigned standard accounts + per-device keys + aliases
-> allowed/denied verification -> audit
```

### Add a service later

The application repository owns its Dockerfile/Compose contract, migrations and health checks. The control database owns environment names, policy classification, placement, domains/exposure, secret references, resource limits and backups; Coolify configuration is derived from those declarations. [D-058](decisions-and-sources.md#d-058)

Environment names are arbitrary but map to one of `dev-like`, `preprod-like` or `prod-like`; policy follows the class, not string matching on names such as `prod`. Production-like resources require explicit CPU, memory, storage/growth, backup and rollback settings. Lower classes receive visible conservative defaults. `vsk-labs` recommends placement from observed capacity, but a human approves it. Application-specific placement is intentionally deferred from this draft.

## Agent compatibility

### Canonical instructions

Codex reads layered `AGENTS.md` files. Claude Code reads `CLAUDE.md` and officially supports importing `AGENTS.md`, so this repository keeps one concise canonical contract and a one-line Claude import. [OpenAI AGENTS.md](https://developers.openai.com/codex/guides/agents-md) · [Claude Code project memory](https://code.claude.com/docs/en/memory)

The always-loaded contract contains only invariants, supported commands, test requirements, secret boundaries and approval rules. Detailed procedures live in skills and generated command help.

CI performs tool-specific acceptance on every contract change: Codex starts at repository root and a nested fixture and reports the expected instruction chain; Claude `/context` reports `CLAUDE.md` and imported `AGENTS.md`; generated skill inventories/content hashes match canonical sources; a mock agent plan yields the same plan ID as direct CLI; and prohibited direct-provider/secret operations are denied. Instruction text is guidance, not authorization—these tests cannot replace CLI policy/OS credentials.

### Operator profiles and agent isolation

Each Mac developer account has its own home, checkout/worktrees, SSH keys, Git identity, Codex/Claude configuration, vendor authentication and caches. Vendor AI subscription/licensing and account procurement are outside `vsk-labs`; infrastructure attribution is based on the local person, delegated agent/session, plan and acknowledgement—not a shared vendor login. Never copy `auth.json`, Claude credentials or another user's tool state between accounts. [D-075](decisions-and-sources.md#d-075)

The selected high-autonomy experience is available to every interactive developer/agent profile, but never to `root`, system/service users, CI identities or any account holding fleet-wide credentials. Use it only in trusted repository workspaces with OS-user isolation and least-privilege host access. Codex/Claude permission modes do not grant `vsk-labs` authority; the site CLI still requires a current authorized plan and verified Slack acknowledgement for the human branch.

For good day-to-day UX, generate optional per-repository safeguards alongside the skills:

- Codex profiles keep filesystem/network reach scoped to the trusted workspace and use the smallest approval/sandbox setting compatible with the task.
- Claude project settings deny reads of secret material and use deterministic `PreToolUse` hooks to block direct live-infrastructure/provider commands, directing the operator to `vsk-labs` instead. Deny rules/hooks are defense in depth; `vsk-labs` remains the enforcement boundary. [Claude permissions](https://code.claude.com/docs/en/permissions) · [Claude hooks](https://code.claude.com/docs/en/hooks)
- Agent sessions may inspect and plan concurrently, but only the central engine mutates the fleet. Direct shell/provider access is a logged human break-glass path, not a convenience fallback.

### Focused lifecycle skills

The implementation repository must ship and test these initial Agent Skills; this documentation package specifies them but does not pretend that absent `.agents/skills/` files already exist:

- `vegastack-labs-inspect`
- `vegastack-labs-manage-users`
- `vegastack-labs-manage-devices`
- `vegastack-labs-manage-nodes`
- `vegastack-labs-manage-services`
- `vegastack-labs-manage-network`
- `vegastack-labs-backup-restore`
- `vegastack-labs-maintenance`
- `vegastack-labs-incident-response`

Each `SKILL.md` declares triggers, allowed inputs, read/write scope, exact `vsk-labs` commands, approval class, verification and failure handling. Scripts exist only for deterministic behavior. OpenAI's current guidance defines skills as `SKILL.md` plus optional scripts/references and recommends focused jobs. Keep v1 skills repository-scoped in `.agents/skills`; plugin packaging is optional only after several repositories need the same stable bundle. [OpenAI skills](https://developers.openai.com/codex/skills/) [D-096](decisions-and-sources.md#d-096)

Claude Code loads generated equivalent skills from `.claude/skills`; CI checks them against canonical `.agents/skills` content. Hermes v1 consumes the reviewed canonical read/plan skills plus the machine-readable command/identity/approval contract; it receives no separate privileged implementation. Current official Hermes configuration documents recursive project-context discovery with priority `.hermes.md`, then `AGENTS.md`, then `CLAUDE.md`; acceptance still verifies the loaded file/precedence and command contract on the pinned Hermes release instead of assuming cross-tool equivalence. [Hermes configuration](https://hermes-agent.nousresearch.com/docs/user-guide/configuration) · [Hermes CLI](https://hermes-agent.nousresearch.com/docs/user-guide/cli) · [Hermes tools](https://hermes-agent.nousresearch.com/docs/user-guide/features/tools/)

The iMac starts with Hermes Blank Slate and no bundled/catalog skills. An administrator pins one reviewed repository checkout, verifies the `.agents/skills/` hashes/precedence and runs `hermes skills trust` for exactly that root; Hermes project skills are not loaded before trust. The manager account may read the trusted checkout but cannot modify its skills, trusted-root store or agent binary. Only the canonical read/plan skills are exposed; gateway/cron/skill self-creation and catalog install remain disabled. Upgrade/offboarding revokes the trusted root, removes the checkout/profile binding and verifies no project skill loads. A self-reported agent/profile/session string is evidence metadata, not identity: the server issues or validates an authenticated service/session principal bound to the Hermes OS account and records that principal plus the self-reported tool context. The responsible human authenticates and acknowledges any permitted apply separately. `hermes doctor`, trusted-root/skill inventory, precedence/provenance, allowed read/plan and denied mutation/secret/direct-provider probes are part of acceptance. [Hermes skills and trust](https://hermes-agent.nousresearch.com/docs/user-guide/features/skills/) · [Hermes CLI](https://hermes-agent.nousresearch.com/docs/user-guide/cli) · [Hermes configuration](https://hermes-agent.nousresearch.com/docs/user-guide/configuration)

| Operator | OS/runtime identity | Default authority | Required attribution |
|---|---|---|---|
| Human CLI | personal standard account + personal SSH key | read/plan and assigned grants | human, device and local session |
| Codex/Claude | same person's isolated interactive account/session | no authority beyond delegating human; high autonomy only inside trusted workspace | human plus tool/session and plan acknowledgement |
| GitHub Actions CI (VegaStack Labs adapter) | ephemeral job identity; protected deploy identity separate | declared repository/job/environment only | workflow run, commit, job, actor and credential class; the built-in `GITHUB_TOKEN` does not imply a VegaStack-owned App |
| Hermes | iMac standard manager profile | read/plan only by default | responsible human plus Hermes profile/session |
| `vsk-labs` executor | constrained control-plane service | execute a current acknowledged plan only | plan/run ID, executor version and adapter identities |

## Human-manual fallback

## Shared local read surface

Humans and agents consume the same generated `/api/v1` contracts over the protected local socket and receive the same database-backed resource checks, cursors, revisions, safe-mode distinctions, redaction, and durable event IDs. Agent autonomy does not create a grant and cannot widen a draft scope. This surface adds no browser session, TCP/HTTPS listener, SSH transport, provider request, external notification, second daemon, or direct SQLite client path.

Every automated workflow ships a generated manual runbook using the same facts:

- exact prerequisites and targets;
- commands/API requests with secret references, never values;
- expected before/after state;
- validation and rollback/recovery steps;
- instructions for attaching sanitized evidence to the same run/audit record and external incident issue where applicable.

Manual work does not mean undocumented direct fixes. If emergency action cannot use `vsk-labs`, the operator records the reason and actual commands, then reconciles desired state through a new database revision after service restoration.
