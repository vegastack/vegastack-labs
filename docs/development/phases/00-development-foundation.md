# Development phase 0 — Development foundation and specification reconciliation

Status: reconciled requirements for solution/issue preparation, 26-08-2026. Phase 0 batch 1, containing only issue 0.1, was approved on 27-08-2026 and is in progress. The mandate, phase boundaries, full-v1-before-lab timing, generic control-plane-first UX, account-free SSH baseline and recorded operational outcomes are confirmed. Later issue solutions, permissions and batches remain separately approved.

## Outcome

A newly assigned agent can read the current generic contract, distinguish it from the Labs profile, run reproducible public checks and deliver an approved issue through a permitted review/merge route. Initial setup begins on a selected supported control host; later operator and managed-node enrollment are separate. No requirement assumes the developer's fleet, private account or domain.

Read [AGENTS](../../../AGENTS.md), [portable lifecycle](../../platform-lifecycle.md), [mandate](../operating-mandate.md), [roadmap](../roadmap.md) and the [issue template](../issue-template.md). This phase prepares implementation; it does not deploy or use the inventory fleet as a test environment.

## Requirements and exclusions

- Preserve development phases 0–11 and issue IDs 0.1, 0.2, 1.1 etc.; complete software and required isolated tests before first lab onboarding rehearsal.
- Preserve one executable/server-owned SQLite, Ansible, exact plans/human authority and no privileged managed-node agent.
- Basic local/SSH management needs no third-party account. The supported local authentication, constrained API-over-SSH and native credential resolver are real implementation obligations, not renamed provider fields.
- Generic host identity is typed and does not require a physical serial. Labs retains its explicit Sheet/physical identity and inventory policy. Do not imply untested OS/virtualization support.
- Keep public reusable code/configuration separate from private operational declarations/evidence. Profiles and adapters are typed compiled capabilities, not arbitrary code plugins.
- Selected Labs connectors/marker use qualified application nodes from 03/05/07; 02 remains spare and 08 reserve. Exact pair, fingerprint and qualification are later evidence.
- Harbor is an ordinary Coolify application. No special fleet/client privileges, implicit private DNS or host role are added.
- Physical media disposition is excluded; logical offboarding, credential revocation, retained data and safe product detach/uninstall remain required.
- No live host/provider changes, device resets, OS reinstalls, repository administration, release publication, MDM, VLAN redesign, automatic HA or expanded platform support.

## Solution and readiness work

### Development foundation

0.1 settles the narrowly named development permission and actual checks/review/merge route. Development branches follow the repository's type-based `feat/`, `fix/`, or `chore/` convention and never identify the executing agent. A fresh review agent does not automatically satisfy independent GitHub approval. Do not bypass repository protection or infer authority from this requirements update.

0.2 specifies the minimal Go/web/test scaffold, pinned toolchain, MIT/package provenance and public contributor checks. Preserve the chosen design system: approved redistributable component source/public dependencies must permit normal clean-checkout builds with no private registry token. Authenticated refresh and official release/integration jobs are protected maintainer lanes. Validate links/examples and current generated ownership; leave historical audit JSON/reports unchanged rather than fabricate a generator for old evidence.

### Generic bootstrap and profile contract

0.3 implements no fleet changes: it finalizes the [local setup contract](../../platform-lifecycle.md#local-control-plane-creation) into concrete interfaces and acceptance. Define the finite one-use installation manifest, verified OS administrator binding, atomic server-owned database initialization, audit import/consumption, constrained remote API transport and each interruption boundary. The workstation is optional; a host name never grants control authority. The same issue must obtain solution approval for an account-free human-acknowledgement boundary inaccessible to a same-account coding process, including bootstrap; ordinary UID/SSH/session credentials and a yes prompt do not prove human presence. Map the adversarial replay/impersonation tests in the portable lifecycle before the affected implementation issues become ready. Distinguish local setup, narrowly permitted foundation preparation, qualified capabilities and site acceptance. No blanket bootstrap bypass or client fallback executor.

Gate definitions carry owning layer, applicability/version and resolved profile provenance. Labs gates apply only to applicable Labs resources; missing mandatory evidence never becomes passed. Profile/default updates remain inert until approved apply and cannot activate their own policy. Test a minimal/no-account and second synthetic site as well as the Labs profile.

For site network actions, preserve router-owned DHCP, standalone ES216G, collision/host-identity verification and explicit manual UI evidence when no adapter exists. Actual firmware decides whether the existing outside-pool policy works; no inside-pool change is presumed approved. Resolve HTTP-only management risk only from actual capabilities. Application-node connectors require a qualified protected path to the control origin; loopback alone is not reachable from another node. Initial local administration does not depend on that browser path.

### Hardening and access boundaries

0.4 maps approved security outcomes to each OS/role and defines the exact candidate mechanisms to qualify. Selected Linux tools are SSH-only Fail2ban, bounded auditd and AIDE on control, alongside native SSH/firewall/confinement/account/update controls. Daily and after-change checks block new workload admission, role expansion and new workload credentials on failed/stale mandatory evidence while preserving existing workloads and recovery. Exact settings/expiry, dynamic-ban bounds and probe definitions must be pinned before role implementation readiness.

Keep native malware/revocation-data updates separate from the existing seven-day OS/package soak and maintenance policy. Preserve encryption, Debian IPv6 and scoped Coolify SSH decisions. No automatic wipe, major upgrade, broad account removal or security-control disablement.

Prove Ansible privilege boundaries and independent lockout rollback; arbitrary privileged modules are not constrained by a prose sudo allowlist. The local resolver must prove cold-start operation, per-consumer denial, rotation and independent recovery without cloud accounts or a silent TPM requirement. Mac consent and source-filter enforcement require a compatible tested path; no MDM, privileged resident agent, TCC/SIP bypass or unqualified portable PF dependency. An unresolved mechanism is a design/qualification issue, not an instruction for the executor to guess.

## Ordered issue index

These are outcomes and ownership, not complete executable issue bodies or published/ready issues.

| Issue ID | Outcome and required proof | Dependencies | GitHub link |
|---|---|---|---|
| **0.1** | Development authority/delivery is unambiguous; inspected permitted route and fresh-agent scope test. | User confirms exact named-repository development boundary and first delivery route. | [0.1 (#3)](https://github.com/vegastack/vegastack-labs/issues/3) |
| **0.2** | Public clean checkout runs pinned checks; no private credential prerequisite; current generation/provenance and representative negative fixtures pass. | 0.1; reviewed toolchain/dependency/check solution. | Not published |
| **0.3** | Generic control-plane setup/profile/identity/transport contracts are noncircular; normal/interrupted paths and minimal/non-Labs/Labs fixtures mapped to downstream owners. | 0.1; confirmed product requirements; use 0.2 checks when available. | Not published |
| **0.4** | OS/role security and local credential admission have reviewed control-to-test mappings, bounded privileges and recovery; unsupported mechanisms remain explicitly blocked. | 0.3; material candidate mechanisms reviewed before implementation. | Not published |
| **0.5** | Demonstrate integrated clean-checkout checks, one real approved issue's delivery/review evidence, consistent contracts and phase-1 handoff. | 0.1–0.4 completed and verified. | Not published |

Execution defaults to sequential; parallel work needs batch approval and settled interfaces. A material discovery changes the issue back to planning and stops only dependents. Never publish assumptions as acceptance.

## Acceptance and execution defaults

- Public build/check lane succeeds without VegaStack credentials and detects malformed input, site leakage and applicable generated drift.
- The actual approved pilot issue follows the permitted review/merge route and includes evidence; no dummy issue is created for activity.
- Generic and selected-profile documents agree; source links resolve; historical evidence is not relabeled current.
- Requirements for effective authority, complete revocation, compromise precedence, actual-job CI admission, audit continuity, recovery dependency retention and safe detach/uninstall have explicit downstream owners in the lifecycle/roadmap.
- Tests are specified for real OS/kernel/reboot and scoped provider behavior where needed. Cross-compilation/containers alone cannot certify those surfaces. No unavailable test lane is silently waived.

## Approval and next batch

Batch approval record: the repository owner approved **Phase 0 batch 1**, containing only [0.1 (#3)](https://github.com/vegastack/vegastack-labs/issues/3), in the current Codex task; approval recorded **27-08-2026 11:26:58 AM IST**. Codex is the coordinator. The approved development-only scope permits the issue/milestone, `chore/0.1-development-route`, commits, PR, development comments/reviews and agent merge after the issue's checks and fresh review pass. It excludes repository settings/rulesets, releases, credentials, providers, the Google Sheet, hosts, networks and every other live infrastructure action.

Issue 0.2 is the next proposed batch only after its solution, prerequisites, complete body and estimate are ready for separate approval. Use the mandate's existing five labels and one coordinator; no new tracker or approval layer.

Each executable issue must pin actual files, supported versions, input/output/error semantics, verification commands/environments, recovery/stop conditions and an agent-minute estimate with basis, 2× checkpoint, user review and separate waits. No current implementation suite is claimed. The real 30-day Mesh pilot remains a later deployment wait after full software acceptance.
