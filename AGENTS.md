# VegaStack Labs agent contract

## Working first — simplicity mandate

Operator instruction on 08-10-2026: build the smallest useful working cluster-management executable first. Reuse the existing `vsk-labs` executable, server-owned SQLite, API, authorization and plan/acknowledgement flow. Do not add services, daemons, signing systems, trust ceremonies, proof registries, generic frameworks or advanced recovery machinery merely to anticipate future needs. Every new component must be necessary for the immediate working feature; prefer extending an existing path.

Additional hardening and advanced recovery are deferred until a concrete need is established and their scope is separately agreed. The earlier comprehensive Phase 6 brief approval does not require implementing those additions now. Supersede the expanded plans and revise the delivery order around a small end-to-end working slice. Do not report deferred controls or full-v1/native acceptance as passed, and do not describe a registered machine as security-qualified.

Keep the existing basic authorization, explicit mutation approval, secret handling and data-preservation boundaries. Nodes04/05 remain absolutely excluded, including reads, CI and indirect effects. This simplicity mandate grants no live access, deployment, VM operation, release or permission to bypass existing checks. It changes development priority and implementation scope, not infrastructure authority.


## Protected live hosts — hard exclusion

Operator instruction on 07-10-2026: **`vsk-node-04` and `vsk-node-05` are out of scope until the operator explicitly lifts this exclusion for named targets and actions.** They host live applications and databases. This supersedes earlier read-only permission, CI-pool permission, role assignments and test-host exceptions for these machines.

- No connection or operation: no SSH, discovery, probes, read-only inspection, CI jobs, deployment, installation, configuration, service changes, restarts, reboot, shutdown, backup/restore, credential rotation/revocation, deletion or formatting.
- The exclusion follows the physical machines through IP addresses, DNS names, aliases, inventory IDs, role names and runner identities. Never bypass it by renaming a target or using a provider, controller, shared network/service or wildcard group. Exclude indirect actions that could affect their workloads, databases, connectivity or credentials.
- Before any authorized infrastructure operation, resolve its full target set from already available records without contacting these hosts. If identity or indirect impact cannot be ruled out, stop before connecting. Do not use either host as a proxy, controller, test machine or recovery target.
- Historical inventory and synthetic fixtures may retain their names; those records confer no operational permission. No replacement control host is selected by this exclusion.
- Do not dispatch CI from any revision using the shared `vsk-runner` selector. A hostname check after assignment is insufficient. The self-hosted job is disabled pending verified scheduling labels/groups that exclude both hosts before assignment and review of the replacement workflow. Never modify runner services or registrations on these hosts to achieve the exclusion.
- General batch, implementation, test or deployment approval does not lift this rule. Other real targets still require their own scoped approval.


## Purpose

This repository defines the portable `vegastack-labs` infrastructure operations platform and the concrete VegaStack Labs deployment profile. The platform is delivered through one CLI/executable, `vsk-labs`. Humans, Codex, Claude Code and Hermes use the same schemas, plans, approvals and typed adapters.

Read `README.md` first, especially its architecture boundary, then the relevant focused document or skill. For repository development, also read `docs/development/operating-mandate.md` and the current phase plan. `docs/decisions-and-sources.md` is the evidence index. Private operational state belongs in the control-plane SQLite database, never this public repository or an SCM host. GitHub is the selected VegaStack Labs source/CI/release provider, not a platform-core or runtime dependency.

## Current phase

The checked-in material is a reviewed specification with unresolved deployment gates. Documentation alone grants no live authority. Do not deploy infrastructure, change Cloudflare/Coolify/1Password/Google Workspace, modify the source Google Sheet, or operate managed hosts unless the user explicitly authorizes implementation after every prerequisite gate is closed.

Repository development has a separate, narrow authority path. Within a user-approved development batch, agents may create or update its named GitHub issues and milestone, branches, commits, pull requests, development comments and reviews, and may merge only when that batch permits it and its required checks and fresh review pass. Approval of one batch grants no authority over another. Repository settings/rulesets, releases, credentials, provider resources and live infrastructure always require separate explicit authorization.

The user selected complete v1 development and verification before the first lab onboarding rehearsal. Use isolated, explicitly scoped development test environments; do not use the inventory fleet as an early rollout. A separately authorized disposable test-host exception may run only the named development checks, carries no workload admission or fleet evidence, and ends when the operator revokes it or the Phase 9 managed-runner path replaces it. Read the development roadmap's delivery path and D-117. Software acceptance does not close live deployment gates or authorize rollout.

## Invariants

### Portable platform

- The platform is delivered through one executable: `vsk-labs`. The persistent server entry point is `vsk-labs server run`, managed by the host OS service manager; never invent a second daemon or executable.
- Platform-core types are provider-neutral. GitHub, Cloudflare, Coolify, Harbor, Google Workspace, 1Password and R2 appear only in typed adapters or the VegaStack Labs deployment profile.
- Keep **optional capability** separate from both adapter and deployment profile: repository discovery/events, PR feedback, remote projections and external notifications are enabled only by explicit policy plus a compatible adapter, and their absence cannot disable local core operation.
- No VegaStack-owned GitHub App is a core or v1 deployment requirement. Treat a GitHub App as an optional adapter credential unless the documented narrow function technically requires it; use the smallest mechanism in the GitHub dependency matrix.
- Local SQLite is authoritative operational state. Off-site object storage is disaster recovery; an optional D1/status projection is one-way, sanitized, stale-tolerant and never an approval, control or synchronization authority.

### VegaStack Labs deployment profile

- Cloudflare Mesh is the only bidirectional private overlay; Cloudflare Tunnel publishes selected services.
- Local infrastructure traffic uses reserved wired-LAN addresses; remote private traffic uses Mesh.
- Coolify control, application and CI roles respect the documented node boundaries.
- Harbor is a Coolify-managed application workload, not a dedicated infrastructure node.
- Mac mini accounts for teammates are individual standard accounts; the iMac is a v1 Hermes host.
- Chaabi Prod migration and application-by-application placement are outside v1.

### Cross-layer safety

- Revisioned control-database declarations are desired state; editing a declaration never changes infrastructure until an approved plan executes.
- The CLI, Console and agents use the same API/engine and never open SQLite directly.
- A live mutation requires a current plan and policy authorization. Human acknowledgement is mandatory unless the documented exact low-risk application-deployment class is already preauthorized; production-like deployment always requires the assigned maintainer.
- Every agent-assisted mutation records both the responsible human and the agent/session.
- Managed hosts have no custom privileged `vsk-labs` agent; normal execution is central Ansible/SSH or a tested provider adapter.
- Every new, replaced or reimaged managed host must pass its applicable approved OS/role hardening baseline before workload admission. Ansible owns host security and role configuration through `vsk-labs`; discovery is not admission, and unsupported platforms or missing verification cannot be treated as secure. See the requirement and proposed tool/profile design in `docs/host-onboarding-and-hardening.md`.
- Never print, log, commit or place a plaintext secret in a prompt, plan, issue or audit record.

## Generic OSS lifecycle

Read `docs/platform-lifecycle.md` for generic creation/enrollment, account-free read/preparation and recovery, and the Slack-only v1 human-acknowledgement prerequisite for bootstrap and mutation. A role binding such as `vsk-node-04`, a Labs gate, domain or physical serial is not a core prerequisite. Only the server owns writable SQLite, including initial setup; the finite pre-database installation manifest is not an alternate controller. Local OS-peer/constrained SSH identities use the same effective grants as external identities but cannot create a human acknowledgement. Preserve the distinction between a running local setup service and a qualified capability. Physical media disposition is outside platform scope.

## Operating workflow

1. Inspect current declared and observed state.
2. Read `docs/implementation-gates.md`, run the applicable gate check and ask only for currently ready evidence that cannot be discovered; never re-ask a closed design choice.
3. Use a tested, site-pinned `vsk-labs` command or focused skill. Do not invoke a provider CLI, raw API or one-off live playbook for convenience.
4. Validate inputs, authorization, recovery preconditions and secret references.
5. Produce a revisioned declaration draft plus identical readable and JSON plans.
6. Run required checks; committing the declaration revision remains inert.
7. Authorize the immutable plan by one documented branch: explicit human acknowledgement, or the exact preapproved low-risk application-deployment policy. Production-like deployment is always the human branch. Execute through the plan-declared central or external adapter; no agent chooses or widens the branch.
8. Verify allowed and denied behavior, health and rollback/recovery.
9. Write a sanitized audit result and reconcile any emergency action into a new database revision.

If the operation is not implemented, add schema, deterministic adapter/Ansible role, tests and documentation through a normal public-engine change before it can touch the fleet.

## Authorization boundaries

- Read-only inspection: allowed only within the caller's read scope.
- Assigned-project routine change: maintainer acknowledgement; self-approval permitted by policy.
- Node, shell, public exposure or backup-policy change: infrastructure-admin acknowledgement.
- Network, identity, secret-provider or control-plane change: infrastructure-admin acknowledgement plus recovery precheck.
- Destructive or broad change: explicit target list, stronger confirmation and verified recovery point.
- Emergency direct action: narrow break-glass credential, reason, time/target bounds and conspicuous audit.

An agent's own prompt-bypass or autonomy setting is not infrastructure authorization. High-autonomy profiles are allowed only for individual interactive standard-user accounts in trusted workspaces; never enable them for root, system/service, CI or fleet-credential identities. Agents cannot acknowledge their own apply or invoke plaintext secret reveal by default.

## Implementation rules

- Go owns CLI UX, schemas, policy, planning, adapter orchestration and structured output.
- Gate definitions, evidence schema and evaluators are generated platform metadata. A gate can pass only from applied, current, recovery-epoch-bound evidence; documentation or an agent assertion is never activation evidence.
- The `vsk-labs` server process, launched with `server run`, owns the control database, versioned API, embedded Console and exact-plan executor on the control plane.
- Ordinary public builds/tests need no private VegaStack credentials; authenticated component refresh and official release signing remain separate maintainer workflows.
- The Console uses VegaStack Design System components and a generated API client; it must not create alternate authorization, provider or SQLite access paths.
- Ansible owns idempotent host configuration over SSH.
- An infrastructure object has one declarative owner; do not mix direct API and IaC ownership.
- Scripts are small, versioned and tested helpers called through `vsk-labs` only.
- Generated files are not hand-edited; CI must detect generation drift.
- Stable machine output is versioned JSON on stdout; human diagnostics go to stderr. Do not parse prose.
- SCM hosts store platform/application code. Do not recreate a Git-backed runtime dependency, hard-code a provider in core schemas or export secrets/private operational state into Git.
- Portable operator-client code must use platform path/credential abstractions and direct argument arrays. Remote and cross-platform transports cannot assume a POSIX shell, `/var` paths, case-sensitive filesystems or a Unix socket; a local Unix-domain socket remains valid where the OS supports it.
- Never copy or share Codex/Claude authentication state between macOS user accounts; vendor authentication is separate from fleet identity.
- Preserve user changes and unrelated work. Never use destructive Git/filesystem recovery to hide drift.
- Prefer reversible operations and fail closed on stale plan, missing approval, provider outage or identity mismatch.

### Development branch names

- Use a type-based branch name: `feat/<issue-id>-<short-slug>` for a `feature` issue, `fix/<issue-id>-<short-slug>` for a `bug`, and `chore/<issue-id>-<short-slug>` for a `chore`.
- Examples are `feat/2.1-inventory-read-api`, `fix/4.3-reject-stale-plans`, and `chore/0.1-development-route`.
- Do not prefix branches with an agent or tool name such as `codex/` or `claude/`. The branch describes the work regardless of which human or agent performs it.
- Branch creation never grants development, merge, release, repository-administration or infrastructure authority; the approved issue and workflow remain controlling.

## Verification

Until 22-09-2026 04:30 AM IST (Asia/Kolkata; machine cutoff `2026-09-21T23:00:00Z`), do not invoke Claude or Claude Code for cross-agent or independent review. Operator instruction on 18-09-2026: use fresh independent Codex reviewers, label the method accurately, and preserve all review and shipping gates. If Claude is specifically required with no permitted alternative, report the blocker rather than invoking it or waiving review.

During implementation and review fixes, run only the narrow unit, schema, fixture, security, failure, recovery, and integration checks affected by the current change. Each issue runs one successful local `pnpm check:affected` proof against the exact current remote-main base and exact clean local/remote/evidence branch head immediately before pull request creation. Changed Go packages receive focused tests and vet while repository-wide compilation and affected boundary checks remain. If review or conflict resolution changes that head, rerun the local affected proof. Accepted Phase 3, Phase 4, and Phase 5 phase-wide suites are outside the routine plan; run an owning phase's explicit acceptance command only when that issue requires it.

Public CI has no `pull_request` or `push` trigger. Opening a pull request or merging to `main` starts no CI workflow. Use `workflow_dispatch` only for an explicitly selected routine full check or a named native acceptance input. Routine-full host eligibility is limited to nodes 01, 06, 07 and 08 after the 07-10-2026 exclusion; dispatch is suspended until scheduling excludes protected hosts before assignment. GitHub assigns an online runner; inventory listings alone do not prove availability. Under the temporary Issue #81 exception, named native acceptance (including a mixed full/native dispatch) remains restricted to disposable `vsk-node-01` or `vsk-node-06`; the job must verify the exact hostname before checkout and receives no fleet-admin or deployment credentials. Accepted Phase 3, Phase 4, and Phase 5 phase-wide suites are not part of routine checks; an owning phase's explicit acceptance command remains required when its issue names it. Never use live production-like targets for an unreviewed test.

## Skills

Use focused lifecycle skills from `.agents/skills/`. A skill may reason and inspect, but live changes must call deterministic `vsk-labs` workflows and obey the same approval boundary. Do not create a generic privileged “manage everything” skill.

## Human fallback

Every automated workflow must have a human-readable procedure with identical prerequisites, targets, verification and recovery. Manual emergency commands must be recorded and followed by a reconciliation database revision.

## Dates and times

- Use `DD-MM-YYYY` for human-readable project dates, for example `26-08-2026`.
- Use the 12-hour clock with explicit uppercase AM/PM in Indian Standard Time: `hh:mm AM/PM IST` or `hh:mm:ss AM/PM IST` when seconds matter. Use `Asia/Kolkata` as the scheduling timezone; IST is UTC+05:30. A full display timestamp is `26-08-2026 04:38 PM IST`. Include AM/PM on both ends of a time range.
- Apply this convention to documentation, plans, issue/PR descriptions and comments, reports, and agent updates. Convert an instant to IST before displaying it; do not merely relabel a UTC time.
- Preserve required machine/protocol formats such as ISO 8601/RFC 3339 timestamps in JSON, APIs, evidence and generated metadata. Do not rewrite source paths, URLs, identifiers or historical machine artifacts for display formatting. Never invent a time or timezone for a date-only historical record.

## Effort estimates

Estimate agent-executed work, never human engineering days/hours. Per phase report expected agent minutes, a 2× checkpoint timebox, user review time, external waits, and the basis (files/turns plus command/runtime floors). For multi-phase work, log starts/ends and report actual versus estimate.
