# VegaStack Labs

`vegastack-labs` is a portable infrastructure operations platform with a centralized control plane for operating and governing small physical compute fleets. It is delivered as a single `vsk-labs` executable providing the CLI, control-plane server, local API and VegaStack Labs Console, deterministic plan/apply engine and typed provider-adapter contracts. The concrete VegaStack Labs environment described here is a **deployment profile** of the platform: eight active ThinkPads, a Mac mini, an iMac, wired gigabit networking and selected Cloudflare, Coolify, Harbor, GitHub, Google Workspace, 1Password and R2 adapters.

This repository is the **v1 implementation and operating specification**, including the confirmed generic OSS lifecycle and a separate VegaStack Labs deployment profile. It authorizes no deployment by itself, contains no live secrets, and remains activation-gated by the physical/provider/implementation evidence in the [gate ledger](docs/implementation-gates.md#gate-ledger). Every material user decision, derived design choice and official-source dependency is indexed in [Decisions and sources](docs/decisions-and-sources.md).

## VegaStack Labs deployment profile objectives

V1 will provide:

- a repeatable Debian 13.6 baseline for active ThinkPads;
- a dedicated, rebuildable Coolify and automation control plane;
- three independent Coolify application nodes;
- four concurrent Linux CI jobs after thermal qualification;
- one native macOS ARM64 CI slot and a shared development server on the Mac mini;
- an iMac host for Hermes agents;
- direct gigabit LAN paths, Cloudflare Mesh for bidirectional remote access, and Cloudflare Tunnel for selected public/protected services;
- Google Workspace-backed identity, auditable onboarding/offboarding, least privilege, backup/recovery, monitoring, and controlled maintenance;
- one deterministic, version-pinned operating surface for humans, Codex, Claude Code, and future Hermes integrations;
- a functional, Access-protected VegaStack Labs Console/API backed by local SQLite, with the same planning, authorization and audit engine as the CLI. [D-003](docs/decisions-and-sources.md#d-003) [D-006](docs/decisions-and-sources.md#d-006) [D-098](docs/decisions-and-sources.md#d-098) [D-099](docs/decisions-and-sources.md#d-099) [D-100](docs/decisions-and-sources.md#d-100)

## Architecture boundary

Every normative statement belongs to exactly one layer. Provider names in examples never become platform-core schema fields or unconditional prerequisites.

| Layer | Owns | Must not assume |
|---|---|---|
| **Portable platform core** | provider-neutral domain model; one `vsk-labs` executable; `vsk-labs server run`; API/Console; SQLite lifecycle; deterministic plans, approvals and audit; stable schemas/JSON; client and managed-node contracts | VegaStack hardware, domain names, GitHub, Cloudflare, Coolify, Harbor, Google Workspace, 1Password, R2 or a Unix operator client |
| **Typed provider adapters** | versioned provider bindings for SCM, CI, artifact/release, registry, identity, secrets, edge access, hosting, backup and notifications | authority over core state; an adapter outage cannot silently become a control-plane outage |
| **Optional capabilities** | explicitly enabled features whose absence preserves local core operation: repository discovery/events, managed source builds and PR feedback, rich status projection, external notifications, remote status pages and the one-way D1 projection | hidden enablement, mandatory provider fields, control/approval authority or a failure mode broader than the declared feature |
| **VegaStack Labs deployment profile** | the fixed node map, `labs.vegastack.com`, Cloudflare Mesh/Tunnel, Coolify, Harbor, GitHub Actions, Google Workspace, 1Password, R2, Debian/macOS, physical topology and the exact optional capabilities selected below | portability claims; these choices are selected configuration, not universal platform requirements |

The platform remains useful with all remote provider adapters unavailable: authorized local/LAN operators can read inventory, create local plans, recover SQLite and use manual runbooks. An unavailable adapter may block only operations that actually require that provider. GitHub is the selected source, CI and release host for this deployment, not a runtime database or platform-core dependency. No VegaStack-owned GitHub App is required for v1; the exact function-by-function classification is in the [GitHub dependency matrix](docs/decisions-and-sources.md#github-dependency-matrix). [D-103](docs/decisions-and-sources.md#d-103) [D-104](docs/decisions-and-sources.md#d-104)

## Generic product lifecycle

An outside user installs `vsk-labs` on a supported host and explicitly chooses to create a control plane, connect an operator client, or enroll a managed node. No node number, company domain or physical Sheet is a portable prerequisite. Account-free local and constrained-SSH access supports inspection and inert preparation, local credentials and recovery; normal v1 bootstrap and mutation additionally require the configured Slack acknowledgement adapter. The [portable lifecycle contract](docs/platform-lifecycle.md) owns setup, credentials, profile/gate applicability, effective authority, enrollment, interruption, recovery and safe exit. `vsk-node-04` is only this deployment's chosen control host.

## Boundaries

- Workloads are mixed personal/business and noncritical. Planned downtime and manual recovery are acceptable. [D-002](docs/decisions-and-sources.md#d-002)
- Application-by-application placement is deferred. Chaabi Prod migration is outside v1. [D-004](docs/decisions-and-sources.md#d-004)
- Harbor is included only as a Coolify-managed application workload on an application node; it is not a dedicated infrastructure node. [D-023](docs/decisions-and-sources.md#d-023)
- The first release does not promise high availability for stateful workloads or the control plane. Backups and tested rebuilds are the recovery model.
- No infrastructure change occurs merely because documentation, a pull request, or an AI-generated plan exists. An authorized human acknowledges explicit apply, except an exact low-risk application-deployment class may run under its previously approved environment policy; production-like deployment still requires the assigned maintainer's acknowledgement. [D-055](docs/decisions-and-sources.md#d-055) [D-092](docs/decisions-and-sources.md#d-092) [D-094](docs/decisions-and-sources.md#d-094)
- AI vendor authentication/licensing is outside the infrastructure identity model. Teammates keep separate OS accounts, tool state and credentials; no shared agent login is required for audit attribution. [D-075](docs/decisions-and-sources.md#d-075)

V1 deliberately does **not** include Kubernetes/Swarm, distributed storage, automatic stateful failover, VLAN redesign, mobile-device management, a custom privileged daemon on managed nodes, system-wide private DNS, a second switch, bidirectional SQLite↔cloud-database synchronization or a generic plugin framework. The same `vsk-labs` executable provides the server process through the `server run` subcommand under the control host's OS service manager; there is no second daemon or executable. These exclusions may be reconsidered only from measured need; they are not hidden implementation work.

## VegaStack Labs deployment authority and ownership

| Concern | Source of truth | Operational owner |
|---|---|---|
| Hardware identity and discovered capacity | local control database, initially reconciled from the read-only Sheet and physical evidence | infrastructure admin |
| Intended network, roles, people, services and policy | revisioned local control database | infrastructure admin; project maintainer only inside assigned service scope |
| Reusable schemas, migrations, roles, commands and runbooks | attested public `vegastack-labs` platform release containing the `vsk-labs` executable, pinned in the control database | platform maintainers |
| Current provider/runtime state | timestamped observations returned by enabled adapters and hosts | the owning adapter/provider; drift is reported against declared database state |
| Phase/capability admission | versioned gate definitions plus current evidence/evaluations in SQLite | accountable gate owner; activation still requires the named real-world evidence |
| Secret values | 1Password | vault owner; only logical references appear in the database |
| Application build/runtime contract | application repository | assigned project maintainer |

The VegaStack Labs deployment currently selects GitHub for platform/application source, Actions CI and release distribution. Ordinary Git, CI and release capabilities are expressed through replaceable adapters, and normal site operation does not require GitHub or a private Git repository. Encrypted online database backups and signed declarative snapshots provide off-node recovery. If declarations and observed state disagree, `plan` must stop or show the drift; neither an agent nor an operator silently chooses a winner. [D-100](docs/decisions-and-sources.md#d-100) [D-104](docs/decisions-and-sources.md#d-104)

## V1 shape

```text
Internet
   |
Cloudflare Tunnel (two shared connectors)
   |
Coolify-managed public/protected applications

Remote team devices
   |
Cloudflare Mesh + Google Workspace identity
   |
managed nodes (bidirectional private connectivity)

ACT / primary HX510
   : wireless EasyMesh backhaul
secondary HX510
   |
TP-Link ES216G
   +-- 8 active ThinkPads
   +-- Mac mini M4
   `-- iMac M1
```

Local service traffic uses reserved LAN addresses. Remote private traffic uses Mesh. Selected public traffic uses Tunnel. The physical LAN and console remain usable if the Internet or Cloudflare is unavailable. [D-032](docs/decisions-and-sources.md#d-032) [D-040](docs/decisions-and-sources.md#d-040) [D-041](docs/decisions-and-sources.md#d-041)

## Role summary

| Role | Assigned node | Notes |
|---|---|---|
| Control plane | `vsk-node-04` | Coolify, the `vsk-labs` server service (launched with `server run`), embedded Console/API, SQLite, backup orchestration and management services only |
| Linux CI | `vsk-node-01`, `vsk-node-06` | Target four concurrent ephemeral-container jobs after burn-in |
| Coolify applications | `vsk-node-03`, `vsk-node-05`, `vsk-node-07` | Harbor is a workload on this pool; its exact node remains a phase-5 placement decision |
| Qualified spare | `vsk-node-02` | Clean, tested recovery capacity |
| Capacity reserve | `vsk-node-08` | Unassigned in v1; may replace a failed/overloaded role |
| macOS CI + development | `vsk-node-09` | Mac mini M4; one CI job; individual standard accounts |
| Hermes | `vsk-node-10` | iMac M1; Hermes agent host only in v1 |

The serial mapping and the one live-sheet conflict that must be resolved before applying names are in [Inventory and roles](docs/inventory-and-roles.md).

## Phases and success criteria

Development phases are **0–11**, defined by the [development roadmap](docs/development/roadmap.md). Complete and verify the full v1 software before the first lab onboarding rehearsal. The separate deployment stages below describe this profile; they are not universal product phases or extra development issues. Read-only preparation is allowed only within its separately authorized scope.

| Deployment stage | Work | Required admission/exit evidence |
|---|---|---|
| 0. Local foundation and scoped discovery | On the selected supported control host, the administrator uses the finite local setup workflow. Reconcile private inventory and inspect the site. | Trusted initial host/session and signed release; exclusive local service/SQLite ownership. Hardware/serial conflicts block affected operations, not unrelated local setup. No fleet, recovery or site-ready claim. |
| 1. LAN and host preparation | Guided ES216G/HX510 actions, approved reservations, supported host adoption/hardening and qualification; prepare required application-node connectors/marker without user workloads. | Per-target identity, device recovery, persistent addressing, effective hardening, wired/thermal/capacity evidence and retained LAN/console access. No bulk clean-install assumption or automatic wipe. |
| 2. Identity and Mesh pilot | Enable only the approved identities, paths and pilot after their prerequisites exist. | Actual G-005 30-day results and allowed/denied/revocation/LAN-recovery tests. Local control already exists but has not bypassed this acceptance. |
| 3. Selected control capabilities | Qualify secret/backup/recovery, Coolify, monitoring and minimal protected Console ingress using qualified application-node connectors. | Scoped G-007/G-008/G-011/G-014/G-016/G-017 evidence plus applicable G-012/G-013 ingress evidence; independent clean-target recovery, audit continuity, CLI/Console parity and origin denial. No user apps or CI on the Labs control host. |
| 4. CI and application capacity | Admit selected Linux application/build roles and supported Mac roles. | Real OS/role capacity, effective security, job admission/isolation and recovery tests; four Linux jobs only after qualification. Spare/reserve roles preserved. |
| 5. Application ingress and Harbor | Extend ordinary application routes and deploy/migrate Harbor through Coolify with declared app permissions. | Qualified route redundancy and client endpoints, actual source/data recovery, signed digest delivery and scoped credentials. No special Harbor infrastructure privileges. |
| 6. Operations acceptance | Rehearse normal lifecycle, updates, alerts, revocation, incidents and disaster recovery. | All applicable site evidence and measured recovery objectives; outstanding partial/uncontained states cannot count as success. |

The [portable lifecycle readiness table](docs/platform-lifecycle.md#preparation-versus-activation) owns the boundary between local setup, permitted foundation preparation and qualified capabilities. Every mutation still needs its exact plan/policy authorization; this ordering grants none.

## Public development checks

The public development scaffold pins Go 1.27.0, Node.js 24.20.0 and pnpm 11.24.0. A normal checkout installs only public dependencies and needs no VegaStack registry credential:

```text
corepack pnpm install --frozen-lockfile
corepack pnpm check
```

These checks validate repository safety, current documentation links and JSON, exact dependency provenance/licenses, preserved historical artifacts, the generated-contract and portable CLI foundations, and the statically exported web scaffold. See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, optional maintainer registry placeholders and delivery rules. This foundation is not the complete `vsk-labs` product and does not claim that the server, control database or Console workflow is implemented.

## Implemented executable foundation

The Phase 1 foundation now builds one executable at `cmd/vsk-labs`. Its `help` and `version` commands consume the checked-in generated registry for command names, flags, help data, schema version, stable errors and exit codes. Human output uses stdout for successful reads and stderr for diagnostics; `--output json` produces one versioned result envelope without prompts. Every other documented command remains visibly planned and returns `PREREQUISITE_BLOCKED` without starting work.

The same foundation includes provider-neutral packages for portable client paths, opaque credential-reference verification and registered direct-argument transport. These are safety boundaries, not live implementations: they do not open SQLite, reveal a credential, invoke a process, implement SSH or contact any provider.

The public check cross-builds `cmd/vsk-labs` for Linux AMD64/ARM64, macOS AMD64/ARM64 and Windows AMD64 into an isolated temporary directory that is removed afterward. This proves compilation only. It does not qualify installation, native credential stores, service management, signing, notarization or supported releases. The control server, API, database, authentication, declaration/plan/apply engines, Console workflows, provider adapters, `G-018` completion and Module 1 acceptance remain future work.

## Documentation map

- [Portable product lifecycle](docs/platform-lifecycle.md) — generic OSS setup, account-free read/preparation and recovery, Slack-only v1 human acknowledgement, profile boundaries, enrollment and safe exit.
- [Architecture and networking](docs/architecture-and-networking.md) — LAN, ES216G/HX510, Mesh, Tunnel, names, Coolify and CI.
- [Network device capabilities and operations](docs/network-device-operations.md) — researched ES216G/HX510 limits, DHCP ownership, guided device operations, diagnostics and recovery; exact firmware/UI behavior remains qualification evidence.
- [Control-plane service and Console](docs/control-plane-service.md) — SQLite, API, UI, provider adapters, nomination/bootstrap, security, backup and acceptance.
- [Inventory and roles](docs/inventory-and-roles.md) — complete asset register, immutable naming and hardware-aware mapping.
- [Security and operations](docs/security-and-operations.md) — identity, secrets, updates, backups, recovery, observability, power and runbooks.
- [Host onboarding and hardening](docs/host-onboarding-and-hardening.md) — mandatory Ansible-driven host admission; researched tool/OS profiles, configuration, recovery and verification proposals awaiting detailed phase approval.
- [Automation and agents](docs/automation-and-agents.md) — `vsk-labs`, SQLite/API, Ansible/IaC, approvals, skills and manual fallback.
- [Development planning and operating mandate](docs/development/README.md) — approved phase/issue workflow, readiness, branch conventions, review, delivery and evidence rules.
- [Implementation gates and evidence procedures](docs/implementation-gates.md) — all 23 audit items, selected mechanisms, evidence schema, numeric acceptance and phase admission.
- [Decisions and sources](docs/decisions-and-sources.md) — evidence register, coverage, GitHub dependency matrix, assumptions, unresolved items and official references.
- [Historical machine-checkable audit register](docs/audit-register.json) — transcript/decision evidence, coverage state and audit matrices from the reviewed snapshot. Its document hashes identify that snapshot, not later documentation edits; the human date-format update of 26-08-2026 does not regenerate or revalidate this evidence.
- [AGENTS.md](AGENTS.md) and [CLAUDE.md](CLAUDE.md) — cross-agent repository contract.

## Terminology

| Term | Meaning here |
|---|---|
| API / CLI / CI | application programming interface / command-line interface / continuous integration |
| SCM / Git | source-code management provider / the provider-neutral distributed version-control transport |
| OCI / SBOM | Open Container Initiative image/artifact / software bill of materials |
| PAT / JWT / IdP / OIDC | personal access token / JSON Web Token / identity provider / OpenID Connect |
| LAN / WAN / DNS / DHCP / CIDR | local/wide-area network; Domain Name System; Dynamic Host Configuration Protocol; classless inter-domain routing prefix |
| TLS / SSH / HTTP / FQDN | Transport Layer Security; Secure Shell; Hypertext Transfer Protocol; fully qualified domain name |
| MTU / LAG | maximum transmission unit / link aggregation group |
| CORS / CSRF / CSP / WAF | cross-origin resource sharing; cross-site request forgery; Content Security Policy; web application firewall |
| RPO / RTO / HA / DR | recovery-point objective; recovery-time objective; high availability; disaster recovery |
| DPAPI / XDG | Windows Data Protection API / the XDG Base Directory conventions used by Linux clients |
| WCAG / SSO / UPS | Web Content Accessibility Guidelines; single sign-on; uninterruptible power supply |

## Review gate

Do not run an apply whose exact phase/capability gate lacks a current passing evaluation. The [gate ledger](docs/implementation-gates.md#gate-ledger) distinguishes closed design from required physical/provider/implementation evidence and names the earliest affected phase; later CI/alert/application inputs do not block earlier read-only discovery or an otherwise-qualified LAN/base-OS phase. Every human live apply still requires its entry evidence, current plan and authorized acknowledgement; the narrow preauthorized low-risk CI branch requires the same entry evidence and plan but uses its approved policy identity. [D-108](docs/decisions-and-sources.md#d-108)
