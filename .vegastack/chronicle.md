# Project chronicle

Entries dated before 10-09-2026 are reconstructed from approved milestones, merged issues, and their recorded evidence at the operator's request. New entries follow the `dev-chronicle` format and are added newest first.

## 10-09-2026 — Platform reads now say when their information is stale or unavailable ([#52](https://github.com/vegastack/vegastack-labs/issues/52))

- **What:** Authorized clients can read one provider-neutral source list covering the database, nodes, gates, people, services, backups, and providers. Each source reports `healthy`, `stale`, `unknown`, `unavailable`, or `failed`, and the existing summary includes counts plus the worst current state.
- **Why:** The Console must distinguish current evidence from missing, old, failed, or impossible future information instead of showing absent future adapters as healthy.
- **How it went:** Linux-only verification caught that an empty grant could not exist under the accepted authorization schema, so full access was represented by seven explicit least-privilege grants. Review also bound node freshness to the requested revision snapshot, kept optional fixtures outside SQLite transactions, rejected future-dated evidence, and preserved the exact Phase 2 evidence while Phase 3 added contracts. Integration with Issue #51 then generated and exercised strict browser types, decoding, and bounded source-filter serialization.
- **Changed:** Fixed source-state evaluator and safe reasons · exact source grants · revision-bound source pagination · `/api/v1/sources` · source summary counts · generated Go, JSON Schema, docs, and strict browser client · failure-isolation and redaction proof.
- **Decisions:** 24-hour local database/inventory freshness · one-hour default for future optional adapters · seven exact source grants with no wildcard · unavailable future capabilities remain visible but create no live adapter, worker, provider dependency, or operational authority.

— approved by (omkarmohanta09) · built by Codex · branch feat/52-source-health-read-contracts

## 10-09-2026 — Browser reads now share one generated safe contract ([#51](https://github.com/vegastack/vegastack-labs/issues/51))

- **What:** The canonical endpoint and schema metadata now generates a dependency-free TypeScript client for every available finite read and event stream. Console code gets fixed same-origin functions, strict response decoding, pagination, cancellation, resumable events, and stable failures without constructing URLs or importing Go, provider, or database internals.
- **Why:** Every later Console screen needs one browser boundary that cannot drift away from the protected server API or quietly widen into mutation and provider access.
- **How it went:** The first independent review found two contract gaps: browser-only failure codes and a narrow secret-field filter. Both were corrected by generating the stable code union from canonical metadata and strengthening nested/open schema exposure checks; the second review was clean.
- **Changed:** Available-read endpoint metadata · generated TypeScript types and strict decoders · fixed same-origin GET methods · bounded finite responses and SSE frames · cancellation and explicit event resume without retry · generated-file drift checks · secret-bearing schema rejection.
- **Decisions:** none in the durable register; the additive public contract moved to 1.7.0, streamed events retain the canonical nested shape, and accepted Phase 2 evidence permits additive same-major contracts while still rejecting removal, rollback, or mutation enablement.

— approved by (omkarmohanta09) · built by Codex · branch feat/51-browser-safe-read-client

## 10-09-2026 — Phase 3 foundation plans preserve one safe control plane ([milestone](https://github.com/vegastack/vegastack-labs/milestone/4))

- **What:** Detailed implementation plans are ready for the generated browser read client, truthful source-health model, and secure remote browser sessions. Together they give the future Console a finite typed API, honest unavailable/stale states, and revocable browser access without creating another operational authority.
- **Why:** These foundations can be built while the private Design System registry remains blocked, and they close the contracts the later Console screens depend on.
- **How it went:** Planning found that endpoint metadata needed an explicit availability field and that Issue #54 did not need to wait before implementation, only before integration. Better Auth was considered, but the approved one-Go-executable/static-Console architecture made a Node authentication runtime the wrong fit; the existing Go JOSE library and Go-owned SQLite sessions keep the boundary smaller. Cloudflare signing-key outage behavior was separated from session expiry and bounded instead of trusting cached keys forever.
- **Changed:** Plans posted for Issues #51, #52, and #54 · #54 Brief v2 approved · #54 hard implementation dependency on #51 removed · merge order #51 before #52/#54 retained · plans lint clean.
- **Decisions:** Generate a dependency-free strict TypeScript read client · expose one paginated source-status endpoint plus compact summary · keep remote authentication inside `vsk-labs server run` · validate Cloudflare RS256 JWTs and store only digested local sessions · lazy JWKS refresh with a 24-hour known-key outage limit · 15-minute idle and 8-hour absolute browser-session expiry · record D-125 and its sources when Issue #54 lands.

— approved by (omkarmohanta09) · planned by Codex · no implementation branch

## 10-09-2026 — The complete Phase 3 read-Console batch is ready for decisions ([milestone](https://github.com/vegastack/vegastack-labs/milestone/4))

- **What:** Development Phase 3 has been converted into nine complete issue briefs covering the static Console and browser-test foundation, generated browser client, truthful source-health contracts, embedded same-origin serving, protected remote identity and revocable sessions, both read-screen groups, integrated browser/security/accessibility proof, and exact-commit phase acceptance.
- **Why:** The roadmap spans Platform Core plus Modules 3, 8, and 9. Planning only the visible Console pages would have omitted the client, authentication, staleness, privacy, recovery, and integrated proof that make those pages safe and truthful.
- **How it went:** The current default branch, all nine module parents, the Phase 3 roadmap row, control-plane/security specifications, existing Go/web boundaries, official Next.js static-export behavior, and Cloudflare JWT-validation requirements were reconciled before slicing. Every brief passed the intake linter, uses the native issue type and module parent where applicable, and records real GitHub blockers. The supplied registry variables were inspected without revealing their values and locally excluded from Git; direct reads of both required private registry items still returned `403 Forbidden`. Follow-up proved the public docs need no token, the registry itself is Access-protected, the Client ID has the expected service-token shape, and the supplied secret matches neither documented Cloudflare Access secret format; no ownership by the VegaStack Cloudflare account is assumed.
- **Changed:** Milestone #4 · Issues #50–#58 · four dependency waves · explicit no-mutation/no-live-provider boundary · Playwright/Chromium evidence lane · `vegastack/agent-dev-review-evidence` selected · one remaining registry-policy blocker.
- **Decisions:** The operator approved the browser lane, existing private evidence repository, per-request Access JWT plus revocable local session, 15-minute idle/8-hour absolute expiry, local-only logout, system-theme/toggle behavior, 44-pixel control targets, and Chromium desktop/mobile Phase 3 coverage. The briefs remain `needs-operator`; plans intentionally have not been drafted.

— requested by (omkarmohanta09) · prepared by Codex · no implementation branch

## 10-09-2026 — Phase 2 is proven and accepted ([#38](https://github.com/vegastack/vegastack-labs/issues/38))

- **What:** The authoritative local service, SQLite authority, inert inventory workflow, audit trail, recovery snapshots, protected reads, CLI parity, and signed draft-export boundary now work together as one accepted Phase 2 result. A deterministic manifest maps the whole phase to 31 executable scenarios.
- **Why:** Passing child issues was not enough; the phase needed one integrated proof that no hidden authority, privacy, recovery, or mutation gap remained.
- **How it went:** The first PR check exposed shallow Git history in CI. The cause was reproduced, CI was changed to fetch full history, a regression guard was added, and the corrected PR, post-merge CI, clean-main replay, and third Claude review all passed.
- **Changed:** Complete traceability · integrated happy/denial/privacy/recovery/parity tests · full-history CI guard · exact-main acceptance evidence · Phase 2 milestone closed after explicit operator acceptance.
- **Decisions:** none; fixture evidence remains separate from release, deployment, and live infrastructure authority.

— approved by (omkarmohanta09) · built by Codex · branch chore/2.10-phase-two-acceptance

## 09-09-2026 — Inventory workflows now run through the protected CLI ([#36](https://github.com/vegastack/vegastack-labs/issues/36))

- **What:** Operators can use `vsk-labs` to inspect status, import an inert inventory draft, compare drafts, and request a verified export through the protected local API. JSON output preserves the server envelope exactly, while human output is rendered from the same typed result.
- **Why:** Phase 2 needed one safe operator surface without direct SQLite, provider, shell, or arbitrary-network access.
- **How it went:** Landed interfaces revealed a package-cycle risk, an undersized export-response limit, and an authorization-registration footgun. The design was reconciled, the footgun was fixed after review, and all five target builds plus PR/post-merge CI passed.
- **Changed:** Five generated operator commands · three authorization-first APIs · typed JSON and Labs CSV decoding · deterministic draft diff · protected file reading · verified export delegation.
- **Decisions:** none; production signing trust remains deliberately unavailable until its later policy and custody work.

— approved by (omkarmohanta09) · built by Codex · branch feat/2.8-inventory-cli-parity

## 09-09-2026 — Draft exports are deterministic, signed, and secret-free ([#37](https://github.com/vegastack/vegastack-labs/issues/37))

- **What:** An exact immutable inventory draft can be encoded deterministically, signed through typed ports, independently verified, and published as an immutable artifact with an atomic current pointer and audit history.
- **Why:** Recovery and external verification need a safe declarative artifact, not a database dump or an unsigned best-effort export.
- **How it went:** Review closed a production-trust bypass. Merging the authorized-read work created four conflicts and a contract-version collision; both feature sets were preserved, contracts were regenerated at version 1.5.0, and the integration review and CI passed.
- **Changed:** Canonical draft snapshot · signing and verification ports · immutable artifact publication · interruption reconciliation · attributed export audit events.
- **Decisions:** none; production composition has no signer or verifier and fails closed until Phase 5 supplies real policy, keys, custody, rotation, and recovery proof.

— approved by (omkarmohanta09) · built by Codex · branch feat/2.9-signed-declaration-export

## 09-09-2026 — Authorized reads and durable event replay are available ([#35](https://github.com/vegastack/vegastack-labs/issues/35))

- **What:** The protected local service now exposes versioned status, database, inventory-draft, child-record, and event-stream reads. Every read is tied to the kernel-authenticated principal and rechecked against resource scope inside SQLite.
- **Why:** CLI and future Console clients need a single read authority with bounded pagination, safe cursors, and reconnectable events.
- **How it went:** PR CI found Linux migration tests hard-coded to the previous schema number and migration name. The tests were made catalog-derived, production code stayed unchanged, and a fresh review plus PR/post-merge CI passed.
- **Changed:** Generated read schemas/routes · scoped SQL reads · authenticated expiring cursors · bounded SSE replay · read authorization migration.
- **Decisions:** none; no real grants, browser access, or inventory mutations were introduced.

— approved by (omkarmohanta09) · built by Codex · branch feat/2.7-versioned-read-api

## 09-09-2026 — Labs CSV can become a safe inert inventory draft ([#32](https://github.com/vegastack/vegastack-labs/issues/32))

- **What:** A sanitized 15-column Labs Sheet1 CSV can be decoded offline into the provider-neutral inventory candidate model with exact provenance, lifecycle handling, identities, aliases, and hardware facts.
- **Why:** The deployment profile needed a practical import format without placing Google, Sheet-specific fields, or live provider access in platform core.
- **How it went:** Hosted CI exposed a timezone-dependent fixture, and a later merge required reconciling shared Phase 2 documents with the audit work. The fixture was made timezone-explicit, both feature contracts were preserved, and the fourth Claude review was clean.
- **Changed:** Bounded CSV adapter · exact header/version contract · public synthetic template and example · privacy/formula/control rejection · complete provenance and findings.
- **Decisions:** none; this adapter opens no files and contacts no live Sheet or provider.

— approved by (omkarmohanta09) · built by Codex · branch feat/2.4-labs-inventory-csv

## 09-09-2026 — Operational changes now produce durable attributed evidence ([#33](https://github.com/vegastack/vegastack-labs/issues/33))

- **What:** Inventory intent, its attributed audit event, intent binding, and required outbox rows now commit atomically or not at all. Durable retry states and crash/restart proofs preserve a truthful history.
- **Why:** Later plans, exports, notifications, and recovery need one local evidence trail that cannot silently separate from the state change it describes.
- **How it went:** Generated nullable enums and future migration fixtures needed reconciliation. The final candidate passed complete and clean-checkout runs, and Claude found no blocking issue.
- **Changed:** Audit/outbox contracts · migration 0003 · verified-context attribution · atomic event/outbox persistence · bounded retries · operational audit append seam.
- **Decisions:** none; there is still no external sender, worker, provider projection, retention deletion, or signing checkpoint.

— approved by (omkarmohanta09) · built by Codex · branch feat/2.5-attributed-audit-events

## 09-09-2026 — SQLite snapshots and pre-migration recovery are verified ([#34](https://github.com/vegastack/vegastack-labs/issues/34))

- **What:** The store can create verified online SQLite snapshots, publish them without replacement, discover only complete generations, and prove an isolated pre-migration restore without replacing the live authority.
- **Why:** Schema changes and crashes need a recoverable boundary before later phases can build more stateful capabilities.
- **How it went:** The branch had to integrate the newly merged inventory migration without rewriting either feature. Catalog-aware recovery remained intact, all fault tests passed, and Claude's third review was clean.
- **Changed:** Online Backup API use · secret-free manifests · protected staging/publication · crash-linearized discovery · isolated restore verification · fail-closed migration gating.
- **Decisions:** none; scheduling, encryption, retention, R2/restic, authority cutover, and live recovery remain later work.

— approved by (omkarmohanta09) · built by Codex · branch feat/2.6-online-snapshot-restore

## 08-09-2026 — Inventory candidates are typed, bounded, immutable drafts ([#31](https://github.com/vegastack/vegastack-labs/issues/31))

- **What:** Provider-neutral inventory input is strictly decoded, normalized, checked for conflicts and secret-shaped values, and stored only as a complete immutable `valid` or `blocked` draft.
- **Why:** Inventory data needed a safe internal model before any Labs adapter, CLI, API, or declaration workflow could rely on it.
- **How it went:** Review found one blocking issue and the Linux store tests exposed a single-connection deadlock risk. Both were corrected without creating a second database owner; the final Claude review was clean.
- **Changed:** Generated inventory schemas · bounded JSON decoder · deterministic normalization/findings · migration 0002 · exact idempotency and source-conflict rules.
- **Decisions:** none; drafts cannot become declared, effective, qualified, or applied in this phase.

— approved by (omkarmohanta09) · built by Codex · branch feat/2.3-inventory-draft-model

## 08-09-2026 — SQLite became the single durable operational authority ([#30](https://github.com/vegastack/vegastack-labs/issues/30))

- **What:** The control service now owns one CGO-free SQLite store with checked migrations, revisions, safe intent transactions, online pre-migration copies, isolated restore proof, and explicit read-only safe mode.
- **Why:** Every later declaration, audit, inventory, and recovery capability needs one durable local authority with no direct client access.
- **How it went:** The branch was integrated with the local-service work and the combined generated/provenance contracts were resealed. Review reached a clean third round with only a future compatibility note for the inventory migration.
- **Changed:** SQLite lifecycle · migration catalog 0001 · state revision conflicts · integrity/filesystem checks · recovery-safe migration flow · database health.
- **Decisions:** none; no inventory, grants, audit, automatic authority replacement, deployment, or live database was added.

— approved by (omkarmohanta09) · built by Codex · branch feat/2.2-sqlite-durability-foundation

## 08-09-2026 — One protected local control service now owns the API boundary ([#29](https://github.com/vegastack/vegastack-labs/issues/29))

- **What:** `vsk-labs server run` operates as the single foreground control service, while `server status` reaches it through a protected local socket. Linux peer credentials bind the caller to a configured local principal before the request enters the application.
- **Why:** The platform needed one server-owned path before SQLite, authorization, inventory, and the Console could safely exist.
- **How it went:** Review tightened peer/authentication and socket behavior, and repository-wide tests were intentionally delayed until generated command dispatch landed later in the same issue. The final candidate and PR/post-merge checks passed.
- **Changed:** Protected profile loading · Unix socket ownership/cleanup · local principal binding · generated health contracts · bounded lifecycle and shutdown · unsupported-platform denial.
- **Decisions:** none; no database authority, grant, provider, service installation, or live host qualification was claimed.

— approved by (omkarmohanta09) · built by Codex · branch feat/2.1-local-control-service

## 08-09-2026 — Release bundles can be verified offline before use ([#28](https://github.com/vegastack/vegastack-labs/issues/28))

- **What:** `vsk-labs` can inspect and verify release manifests and artifacts offline, reject tampering and incompatibility, and preserve a provider-neutral trust boundary.
- **Why:** Future installation and rollback require deterministic verification before any artifact is executed or trusted.
- **How it went:** The temporary trust-policy choice was explicitly documented, the implementation was reviewed on the exact integrated tree, and the final review had no unresolved finding.
- **Changed:** Offline manifest/artifact verification · stable failures · tamper and compatibility fixtures · documented temporary trust boundary.
- **Decisions:** none in the durable register; real production policy and signing identity were deliberately deferred and recorded for later replacement.

— approved by (omkarmohanta09) · built by Codex · branch feat/1.3-offline-release-verification

## 07-09-2026 — The portable `vsk-labs` executable now has one client boundary ([#25](https://github.com/vegastack/vegastack-labs/issues/25))

- **What:** A single buildable CLI now dispatches generated commands, produces stable JSON/error/exit behavior, resolves portable client paths and credential references, and invokes transports through direct argument arrays.
- **Why:** Every later platform feature needs the same trustworthy command and client behavior on Linux, macOS, and Windows.
- **How it went:** The first independent review found six must-fix items and the first Claude attempt returned no result. The fixes strengthened generated ownership, process tests, credential allowlisting, dependency analysis, cleanup, and five-target builds; final Codex and retried Claude reviews were clean.
- **Changed:** Executable and dispatcher · help/version/results · planned-command blocking · cancellation/request IDs · portable path/credential/transport contracts · cross-platform guards.
- **Decisions:** none; no server, database, provider adapter, plan engine, or live operation was added.

— approved by (omkarmohanta09) · built by Codex · branch feat/1.2-portable-cli

## 07-09-2026 — Public contracts now come from one metadata graph ([#24](https://github.com/vegastack/vegastack-labs/issues/24))

- **What:** One typed provider-neutral registry now generates Go contracts, JSON Schemas, command/endpoint registries, documentation, error codes, and exit behavior deterministically.
- **Why:** Hand-maintained parallel schemas would drift as the CLI, API, Console, and agents grew.
- **How it went:** Review found a dead symlink-resolution branch and a registry/schema validation mismatch. Both were fixed, generated output stayed path-safe and atomic, and the second Claude review was clean.
- **Changed:** Metadata registry · generators · drift checks · two foundation commands · 49 explicitly unavailable future commands · public-lane integration.
- **Decisions:** none; later command details remained unassigned rather than being invented early.

— approved by (omkarmohanta09) · built by Codex · branch feat/1.1-generated-contracts

## 07-09-2026 — Phase 0 evidence was reconciled after merge ([#22](https://github.com/vegastack/vegastack-labs/issues/22))

- **What:** The Phase 0 record now distinguishes verified implementation evidence, historical CI billing failure, and the two non-squash merge divergences without rewriting history.
- **Why:** Phase acceptance needed to describe what actually landed, not what the intended merge route said should have happened.
- **How it went:** Three review rounds found and fixed malformed-JSON leakage, incomplete stale-document guards, and permissive evidence URL/owner validation.
- **Changed:** Current Phase 0 evidence · stricter offline validator · documented squash-or-stop route · protected historical facts.
- **Decisions:** none.

— approved by (omkarmohanta09) · built by Codex · branch chore/0.6-phase-zero-post-merge-evidence

## 07-09-2026 — Phase 0 was audited and handed to Phase 1 ([#18](https://github.com/vegastack/vegastack-labs/issues/18))

- **What:** Every Phase 0 child merge was audited once, a checked evidence index and validator were added, shared-spine ownership across Modules 1–9 was confirmed, and the Phase 1 handoff was made metadata-graph-first.
- **Why:** The first executable phase needed verified foundations and explicit ownership, not assumptions based on closed issues.
- **How it went:** GitHub Actions was blocked by the external billing state, so the record kept CI as unverified instead of pretending it passed. Review clarified which historical merges diverged from the current squash route.
- **Changed:** Phase 0 evidence index · offline validation · parent ownership map · Phase 1 handoff.
- **Decisions:** none.

— approved by (omkarmohanta09) · built by Codex · branch chore/0.5-phase-zero-handoff

## 04-09-2026 — Host security and admission contracts became machine-checkable ([#17](https://github.com/vegastack/vegastack-labs/issues/17))

- **What:** Four host profiles, seven role IDs, eleven controls, one-shot privilege bindings, native credential references, Mesh-only Mac admission, and recurring evidence transitions are represented by sanitized deterministic fixtures.
- **Why:** Host onboarding must prove hardening, privilege, credential, and admission behavior before any workload is allowed.
- **How it went:** The implementation and independent Claude review were clean; two small fixture-naming/count-coupling nits were recorded without weakening the contract.
- **Changed:** Host-security fixture package · 69 positive/negative cases · downstream phase ownership · public verification.
- **Decisions:** D-123 and D-124 were reconciled into the authoritative register and documents.

— approved by (omkarmohanta09) · built by Codex · branch chore/0.4-host-security-admission

## 04-09-2026 — Bootstrap and human-proof rules became executable contracts ([#16](https://github.com/vegastack/vegastack-labs/issues/16))

- **What:** Installation manifests, local setup state, Slack acknowledgement, approver import, constrained SSH, and profile/gate resolution now have a machine-checked 77-case contract corpus.
- **Why:** The future runtime needed precise fail-closed bootstrap and acknowledgement behavior before implementation could safely begin.
- **How it went:** Three review rounds refined framing lengths, signed-manifest facts, provider-neutral structure, and private-value checks. No live Slack, server, database, or credential was introduced.
- **Changed:** Six contract families · deterministic validation · secret-safe denials · provider-neutral setup boundary.
- **Decisions:** D-122 was reconciled into the normative bootstrap and approval documents.

— approved by (omkarmohanta09) · built by Codex · branch chore/0.3-bootstrap-profile-human-proof

## 27-08-2026 — A clean checkout can build and verify the public scaffold ([#5](https://github.com/vegastack/vegastack-labs/issues/5))

- **What:** The repository gained its reproducible public development scaffold, pinned checks, build/test entry points, and clean-checkout verification path.
- **Why:** Later agents and contributors needed a known-good base that requires no private VegaStack credentials.
- **How it went:** The initial foundation landed before chronicle recording was enabled; this entry is reconstructed from the accepted Phase 0 milestone.
- **Changed:** Public Go/web/test scaffold · reproducible check command · credential-free development foundation.
- **Decisions:** none.

— approved by (omkarmohanta09) · built by Codex · branch historical branch not recorded

## 27-08-2026 — The issue-driven development route was established ([#3](https://github.com/vegastack/vegastack-labs/issues/3))

- **What:** The repository adopted the staged brief, plan, implementation, independent review, PR, merge, evidence, and acceptance workflow used by later phases.
- **Why:** A large infrastructure platform needed explicit human gates and recoverable agent handoffs instead of ad-hoc changes.
- **How it went:** This was the first workflow pilot and predates chronicle recording; the entry is reconstructed from the accepted Phase 0 milestone.
- **Changed:** Development mandate · issue states · review and shipping gates · evidence conventions · phase sequencing.
- **Decisions:** none.

— approved by (omkarmohanta09) · built by Codex · branch historical branch not recorded
