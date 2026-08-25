# VegaStack Labs

`vegastack-labs` is a portable infrastructure operations platform with a centralized control plane for operating and governing small physical compute fleets. It is delivered as a single `vsk-labs` executable providing the CLI, control-plane server, local API and VegaStack Labs Console, deterministic plan/apply engine and typed provider-adapter contracts. The concrete VegaStack Labs environment described here is a **deployment profile** of the platform: eight active ThinkPads, a Mac mini, an iMac, wired gigabit networking and selected Cloudflare, Coolify, Harbor, GitHub, Google Workspace, 1Password and R2 adapters.

This repository is the **reviewed v1 implementation and operating specification**. It authorizes no deployment by itself, contains no live secrets, and remains activation-gated by the physical/provider/implementation evidence in the [gate ledger](docs/implementation-gates.md#gate-ledger). Every material user decision, derived design choice and official-source dependency is indexed in [Decisions and sources](docs/decisions-and-sources.md).

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

Phases are ordered gates. A phase may prepare declarations for the next phase, but it may not perform that phase's live mutation before the previous exit evidence is reviewed.

| Phase | Entry and dependencies | Work | Measurable exit gate |
|---|---|---|---|
| 0. Review and discovery | This specification and gate ledger reviewed; read-only access to assets and vendor consoles | Close `G-001`–`G-004`, `G-009` and affected `G-010`; inspect serials, disks, batteries, thermals, NICs, UPS, HX510 controls and ES216G revision/firmware | Credential-like Sheet values removed and rotated; serial map approved; all active nodes have signed evidence bundles and deterministic gate evaluations |
| 1. LAN and base OS | Phase 0 closed; switch config export/restore and console recovery understood | Label/cable ports; reserve addresses; clean-install and harden Debian 13.6 | Every managed wired link negotiates 1 Gb/s and has no increasing errors during the approved sustained transfer test; reservations survive reboot; WAN/backhaul baseline recorded; external scan finds no unintended listeners; an admin reaches every node with Cloudflare disconnected |
| 2. Identity and Mesh pilot | Phase 1 network stable; Workspace identities and approved device inventory exist | Configure audiences, quarantine/approval, host firewalls and a limited Mesh pilot | Pilot devices complete 30 days with reboot/WAN-loss/update/reconnect tests; declared TCP/UDP/ICMP flows pass and denied flows fail; MTU/throughput baseline recorded; revoke/re-enroll and LAN recovery are proven |
| 3. Control plane | Mesh pilot usable; `G-007`, `G-008`, `G-011`, `G-014`, applicable `G-016` and `G-017` evidence passes | Install/bootstrap the `vsk-labs` server service, SQLite, embedded Console/API, Coolify and central plan/run coordination; add remote nodes; deploy Beszel and backup/alert plumbing | Access allow/deny and direct-origin bypass tests pass; CLI and browser produce the same plan digest; a clean spare restores the control database, pinned Coolify version, `APP_KEY` and SSH keys; one standard and one critical sample restore function; no user app or CI job runs on control |
| 4. CI and application capacity | Phase 3 control/recovery healthy; `G-006`, affected `G-010`, `G-018`, `G-020` and `G-021` evidence passes | Qualify Linux builders/app nodes; configure Mac accounts and one native job | Four total Linux jobs pass the fixed sustained representative load without throttling, swap pressure, filesystem exhaustion or cross-job access; untrusted/fork code never reaches home runners; the Mac CI/fallback and Hermes lanes meet their declared budgets; spare-role restore is rehearsed |
| 5. Ingress and Harbor | Phase 4 capacity proven; `G-012`, `G-013`, `G-015`, applicable `G-016` and first-project `G-019` evidence passes | Bring up two Tunnel connectors; deploy/migrate Harbor; verify signed digest promotion | No router forwarding; either connector can be removed without losing declared ingress; Access allow/deny tests pass; a signed/attested image is verified and deployed by digest; robot rotation and an isolated Harbor restore/cutover rollback are proven |
| 6. Operations acceptance | All prior gates and related unresolved inputs closed | Rehearse lifecycle, maintenance, incident, backup and break-glass runbooks | Onboard/suspend/offboard, patch canary/rollback, site-silence alert, quarterly-style restore and manual recovery all produce the required attribution/evidence; critical restore tests meet 6 h/4 h node-loss and 24 h/24 h site-loss objectives |

## Documentation map

- [Architecture and networking](docs/architecture-and-networking.md) — LAN, ES216G/HX510, Mesh, Tunnel, names, Coolify and CI.
- [Control-plane service and Console](docs/control-plane-service.md) — SQLite, API, UI, provider adapters, nomination/bootstrap, security, backup and acceptance.
- [Inventory and roles](docs/inventory-and-roles.md) — complete asset register, immutable naming and hardware-aware mapping.
- [Security and operations](docs/security-and-operations.md) — identity, secrets, updates, backups, recovery, observability, power and runbooks.
- [Automation and agents](docs/automation-and-agents.md) — `vsk-labs`, SQLite/API, Ansible/IaC, approvals, skills and manual fallback.
- [Implementation gates and evidence procedures](docs/implementation-gates.md) — all 23 audit items, selected mechanisms, evidence schema, numeric acceptance and phase admission.
- [Decisions and sources](docs/decisions-and-sources.md) — evidence register, coverage, GitHub dependency matrix, assumptions, unresolved items and official references.
- [Machine-checkable audit register](docs/audit-register.json) — transcript/decision evidence, coverage state and audit matrices generated from this review.
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
