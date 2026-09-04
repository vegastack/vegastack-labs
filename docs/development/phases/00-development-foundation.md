# Development phase 0 — Development foundation and specification reconciliation

Status: reconciled requirements for solution/issue preparation, 04-09-2026. Phase 0 issues [0.1 (#3)](https://github.com/vegastack/vegastack-labs/issues/3), [0.2 (#5)](https://github.com/vegastack/vegastack-labs/issues/5) and [0.3 (#16)](https://github.com/vegastack/vegastack-labs/issues/16) are completed. [Issue 0.4 (#17)](https://github.com/vegastack/vegastack-labs/issues/17) is the current approved implementation batch. The mandate, phase boundaries, full-v1-before-lab timing, generic control-plane-first UX, account-free read/preparation and recovery baseline, Slack-only v1 acknowledgement decision and recorded operational outcomes are confirmed. Later issue solutions, permissions and batches remain separately approved.

## Outcome

A newly assigned agent can read the current generic contract, distinguish it from the Labs profile, run reproducible public checks and deliver an approved issue through a permitted review/merge route. Initial setup begins on a selected supported control host; later operator and managed-node enrollment are separate. No requirement assumes the developer's fleet, private account or domain.

Read [AGENTS](../../../AGENTS.md), [portable lifecycle](../../platform-lifecycle.md), [mandate](../operating-mandate.md), [roadmap](../roadmap.md) and the [issue template](../issue-template.md). This phase prepares implementation; it does not deploy or use the inventory fleet as a test environment.

## Requirements and exclusions

- Preserve development phases 0–11 and issue IDs 0.1, 0.2, 1.1 etc.; complete software and required isolated tests before first lab onboarding rehearsal.
- Preserve one executable/server-owned SQLite, Ansible, exact plans/human authority and no privileged managed-node agent.
- Basic local/SSH inspection, inert preparation, native credential handling and recovery need no third-party account. Normal v1 bootstrap and mutation require the typed Slack acknowledgement adapter; constrained API-over-SSH is transport, not approval authority.
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

0.3 implements no fleet changes: it finalizes the [local setup contract](../../platform-lifecycle.md#local-control-plane-creation) into concrete interfaces and acceptance. Define the finite one-use installation manifest, verified OS administrator binding, atomic server-owned database initialization, audit import/consumption, constrained remote API transport and each interruption boundary. The workstation is optional; a host name never grants control authority. The operator selected Slack as v1's only normal acknowledgement adapter and accepted that a configured workspace/account/app, approved user mapping and network availability are bootstrap/mutation prerequisites. Ordinary UID/SSH/session credentials and a yes prompt do not prove human presence. Socket Mode runs inside `vsk-labs server run`; Slack proves the approved user's action but is never audit or execution authority. Map the adversarial workspace/user, replay, substitution, outage and self-add tests before affected runtime issues become ready. Distinguish local setup, narrowly permitted foundation preparation, qualified capabilities and site acceptance. No blanket bootstrap bypass or client fallback executor. Account-free human approval is deferred beyond v1; break-glass remains separately authorized recovery, not a routine fallback.

Gate definitions carry owning layer, applicability/version and resolved profile provenance. Labs gates apply only to applicable Labs resources; missing mandatory evidence never becomes passed. Profile/default updates remain inert until approved apply and cannot activate their own policy. Test a minimal/no-account and second synthetic site as well as the Labs profile.

Downstream ownership is singular: [#7](https://github.com/vegastack/vegastack-labs/issues/7) owns the provider-neutral approval request/proof and Slack adapter orchestration; [#9](https://github.com/vegastack/vegastack-labs/issues/9) owns Slack-user-to-local-principal mappings; [#12](https://github.com/vegastack/vegastack-labs/issues/12) owns logical Slack secret references and delivery; [#15](https://github.com/vegastack/vegastack-labs/issues/15) owns review/approve/reject presentation. [#14](https://github.com/vegastack/vegastack-labs/issues/14) owns notifications only; notification delivery cannot acknowledge or authorize a plan.

For site network actions, preserve router-owned DHCP, standalone ES216G, collision/host-identity verification and explicit manual UI evidence when no adapter exists. Actual firmware decides whether the existing outside-pool policy works; no inside-pool change is presumed approved. Resolve HTTP-only management risk only from actual capabilities. Application-node connectors require a qualified protected path to the control origin; loopback alone is not reachable from another node. Initial local administration does not depend on that browser path.

### Hardening and access boundaries

0.4 maps approved security outcomes to each OS/role through `host-security-v1` and 69 independently checked cases across `host-control-matrix`, `privileged-execution`, `native-credentials`, `macos-admission` and `admission-evidence`. Selected Linux tools are SSH-only Fail2ban with retry/window/ban values `5/600/600`, bounded auditd and AIDE on control, alongside native SSH/firewall/confinement/account/update controls. Daily (`86400` second maximum) and after-change checks block new workload admission, role expansion and new workload credentials on failed/stale mandatory evidence while preserving safe existing workloads and recovery.

Keep native malware/revocation-data updates separate from the existing seven-day OS/package soak and maintenance policy. Preserve encryption, Debian IPv6 and scoped Coolify SSH decisions. No automatic wipe, major upgrade, broad account removal or security-control disablement.

The selected Ansible boundary is a dedicated non-root identity invoking only the root-owned, non-resident one-shot mode of `vsk-labs`, with exact plan/host/action/expiry/recovery checks and independent lockout rollback. The native resolver proves cold start, per-consumer denial, rotation/revocation and independent recovery without cloud accounts, plaintext fallback or a TPM requirement. The selected Mac path is default-deny Cloudflare Mesh plus constrained SSH and declared Remote Login users, native application firewall, supported local consent and physical-console recovery; no MDM, privileged resident agent, TCC/SIP bypass, product-managed PF or direct-LAN automation fallback. Runtime and real-OS qualification remain with Phases 5–7 and 11.

## Ordered issue index

These are outcomes and ownership, not complete executable issue bodies or published/ready issues.

| Issue ID | Outcome and required proof | Dependencies | GitHub link |
|---|---|---|---|
| **0.1** | Development authority/delivery is unambiguous; inspected permitted route and fresh-agent scope test. | User confirms exact named-repository development boundary and first delivery route. | [0.1 (#3)](https://github.com/vegastack/vegastack-labs/issues/3) |
| **0.2** | Public clean checkout runs pinned checks; no private credential prerequisite; current generation/provenance and representative negative fixtures pass. | 0.1; reviewed toolchain/dependency/check solution. | [0.2 (#5)](https://github.com/vegastack/vegastack-labs/issues/5) |
| **0.3** | Generic control-plane setup/profile/identity/transport and Slack-only acknowledgement contracts are noncircular; normal/interrupted paths and minimal/non-Labs/Labs fixtures map to downstream owners. | 0.1 and 0.2 complete; approved Slack-only v1 decision and implementation plan. | [0.3 (#16)](https://github.com/vegastack/vegastack-labs/issues/16) |
| **0.4** | OS/role security and local credential admission have reviewed control-to-test mappings, bounded privileges and recovery; the public verifier exercises 69 cases and explicitly blocks unsupported mechanisms. | 0.3 complete; privilege and Mac mechanisms approved. | [0.4 (#17)](https://github.com/vegastack/vegastack-labs/issues/17) |
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

Batch approval record: the repository owner approved **Phase 0 batch 2**, containing only [0.2 (#5)](https://github.com/vegastack/vegastack-labs/issues/5), in the current Codex task on 27-08-2026. The approved development-only scope permits the issue, `chore/0.2-public-development-scaffold`, commits, public CI runs, PR, development comments/reviews and agent merge/closure after the approved checks and fresh review pass. It excludes repository settings/rulesets, releases, credentials, private registry source publication, providers, the Google Sheet, hosts, networks and every live infrastructure action. Use the mandate's existing five labels and one coordinator; no new tracker or approval layer.

Batch approval record: the repository owner approved implementation of **Phase 0 issue 0.3**, [#16](https://github.com/vegastack/vegastack-labs/issues/16), on 04-09-2026 after approving its Slack-only v1 decision and Plan v1. The development-only scope permits `chore/0.3-bootstrap-profile-human-proof`, commits, issue comments, sanitized fixtures, public checks and fresh review. PR creation, merge, release, repository administration, credentials, live Slack/provider actions, hosts, networks, databases and infrastructure remain separately gated.

Batch approval record: the repository owner approved the brief and Plan v1 for **Phase 0 issue 0.4**, [#17](https://github.com/vegastack/vegastack-labs/issues/17), on 04-09-2026 after confirming the bounded Ansible privilege and constrained macOS management decisions. The development-only scope permits `chore/0.4-host-security-admission`, documentation, deterministic JavaScript verification, sanitized fixtures, issue/parent summaries, public checks and fresh review. PR creation, merge, release, repository administration, credentials, provider configuration, hosts, networks, databases and every live infrastructure action remain separately gated.

Each executable issue must pin actual files, supported versions, input/output/error semantics, verification commands/environments, recovery/stop conditions and an agent-minute estimate with basis, 2× checkpoint, user review and separate waits. The Phase 0.4 suite proves public contracts and sanitized fixtures only; it is not real-host admission evidence. The real 30-day Mesh pilot remains a later deployment wait after full software acceptance.
