# VegaStack Labs documentation and platform-architecture audit — completion report

> Superseded for current gap status by [VegaStack Labs gap-closure report](gap-closure-report.md). This file preserves the pre-closure audit snapshot and the 23 gaps that the follow-up pass resolved into exact design and activation gates.

Date: 2026-08-25
Scope: documentation-only

## Outcome

The complete nine-file documentation set was audited end to end. Eight files received material corrections; `CLAUDE.md` was verified as the intentionally thin pointer to the canonical agent contract. A justified machine-checkable `docs/audit-register.json` was added to the existing output tree. No infrastructure, external system, Google Sheet, repository, message or production state was changed.

The result cleanly separates:

1. the portable provider-neutral platform core;
2. typed provider adapters;
3. optional capabilities; and
4. the concrete VegaStack Labs deployment profile.

The platform is delivered through one executable named `vsk-labs`; its service entry point is `vsk-labs server run`. The core uses SQLite as authoritative operational state, encrypted retention-protected R2 backups for disaster recovery, and no Git repository as private runtime state. D1 is at most a one-way sanitized last-known-status projection and is never a control, offline-recovery or bidirectional-synchronization dependency.

## GitHub App answer

No VegaStack-owned GitHub App is required by the portable platform core or by the accepted v1 VegaStack Labs deployment path.

| Function | App classification | Smallest supported mechanism |
|---|---|---|
| Source hosting and ordinary Git operations | NOT REQUIRED | Git over SSH/HTTPS; GitHub is the selected replaceable SCM adapter. |
| GitHub Actions CI | NOT REQUIRED | Workflow permissions and per-job `GITHUB_TOKEN`; that token is internally issued for GitHub's own Actions App and does not require VegaStack to own/register an App. |
| Coolify private-repository access | NOT REQUIRED | Repository-scoped read-only SSH deploy key, or prebuilt digest deployment. |
| Coolify source picker and managed push/PR events | ONE SUPPORTED ADAPTER / OPTIONAL | Coolify's GitHub App integration, limited to selected repositories. |
| Coolify automated PR comments | REQUIRED FOR OPTIONAL FEATURE | Coolify GitHub App with the documented pull-request write permission; omit in v1 if not selected. |
| Webhooks and deployment events | NOT REQUIRED | Repository webhook, Coolify webhook/API or typed hosting-event adapter. |
| Repository discovery | NOT REQUIRED | Explicit enrollment plus GitHub API/CLI with the smallest repository-metadata credential; App is optional for durable organization-wide automation. |
| Build/status reporting | NOT REQUIRED normally | Actions' own token or commit-status API. An external integration writing rich Check Runs is the narrow App-required optional case under GitHub's explicit rule. |
| Release downloads and update checks | NOT REQUIRED | Public release endpoint or narrowly scoped token for a private feed; releases remain adapter-backed. |
| Application deployment | NOT REQUIRED | Epoch-bound `vsk-labs` plan/lease; protected CI calls Coolify with a team-scoped `write`+`deploy` token for the exact admitted digest. |
| Agent workflows and audit attribution | NOT REQUIRED | `vsk-labs` session identity, plan/run IDs, workflow metadata and independently observed provider event IDs. |
| Authentication and least privilege | NOT GENERALLY REQUIRED | Deploy keys, `GITHUB_TOKEN`, fine-grained PATs or OIDC where supported; use a purpose-specific App only when its short-lived installation tokens, multi-repository boundary or App-only API capability is actually selected. |

The accepted site path is protected CI to Coolify. AWS, Hetzner and client-infrastructure targets remain concerns of each application's repository workflow and are outside this v1 site profile unless a future hosting adapter is explicitly onboarded.

## Material corrections

- Replaced the separate `vsk-labsd` concept with the single platform service command.
- Made platform-core, adapter, optional-capability and VegaStack Labs profile ownership explicit throughout schemas, commands and UX.
- Reconciled all transcript decisions and supersession chains, including the Console mandate, fixed physical topology/names, Cloudflare Mesh/Tunnel choices, Coolify/Harbor roles, Macs, deferred application placement and Chaabi Prod exclusion.
- Classified every GitHub surface and removed stale App-required implications.
- Defined the SQLite migration/concurrency/integrity lifecycle, R2 encryption/retention/restore controls, optional D1 projection boundary and recovery-epoch plus external-writer fencing sequence.
- Corrected the accepted risk-based deployment flow: an exact eligible low-risk environment policy may preauthorize a deployment; production-like deployment always requires the assigned maintainer.
- Added precise server, managed-node, CLI, browser, runner and optional-integration support rows for Windows, Linux, macOS and relevant architectures.
- Added implementation-readiness ownership, prerequisites, intended state, sequence, automation/approval, verification, diagnosis, recovery and phase gates for nine subsystems.
- Tightened threat boundaries, secrets/token scopes, Access/LAN behavior, authorization, audit attribution, recovery, supply chain, update/signing, offboarding and outage handling.
- Normalized every human-readable questionnaire pointer to the physical answer record plus question key.

## Verification

- Transcript: 2,144 contiguous physical JSONL records parsed. The declared records 1–2,074 are the authoritative snapshot; the 70-record tail was reviewed and labeled separately. Five compaction records were treated as replacement lineage, not duplicated history.
- Evidence: 178 questionnaire answers + 14 raw user messages = 192 user-evidence rows; 59 user-question fragments; 43 separately classified assistant recommendations/facts; 92 normalized decisions; 45 coverage rows.
- Matrices: 25 GitHub dependency cases; 15 OS/architecture rows; four architecture classes; nine implementation-readiness rows.
- Documents: nine Markdown files, 2,297 lines.
- Links/tables/examples: 499 local links with zero broken; zero malformed tables; one JSON example, valid.
- Naming/commands: 127 command-reference lines with zero stale commands; no stale `vsk-labsd` or singular-domain requirement.
- Traceability: 187 human-document question references with zero dangling; zero dangling official-source IDs or decision IDs.
- Integrity: all nine Markdown SHA-256/byte/line entries match `audit-register.json`. Register SHA-256: `6b0c68dd16a641d5fb496655538377b02749aedf84571476791dcc27d73229e7`.
- Independent final passes: transcript authority PASS; architecture/security/provider semantics PASS; documentation/mechanical PASS.

## Remaining deployment gates

These are genuine unresolved inputs, not documentation defects:

1. **Inventory integrity — phase 1 and every hostname/role apply:** physically decide which serial owns `vsk-node-05`; remove and rotate credential-like Sheet values; approve one serial map.
2. **Discovery — affected host admission/capacity roles:** collect exact models, Mac serial/CPU, disk/battery/thermal/firmware/NIC/link and burn-in facts.
3. **LAN facts — phase 1 network apply:** record subnet, gateway, pool/reservation details and HX510 control availability.
4. **Switch receipt — phase 1 cabling/configuration:** record SKU/revision/firmware, port map/labels and configuration restore proof.
5. **Mesh beta acceptance — phase 2 pilot:** verify account/client/device-policy prerequisites and approve reconnect/MTU/throughput plus 30-day exit criteria.
6. **CI implementation — phase 4 runner enrollment:** select/test the one-job controller, external log sink, runner groups/labels and repository enrollment.
7. **Secrets — phase 3 provider activation:** define 1Password layout, service-account scope, offline custody and recovery test.
8. **Backup implementation — phase 3 acceptance:** select repository engine/format, R2 lock configuration, capacity forecast and key-recovery procedure.
9. **Power — always-on role acceptance:** document UPS model, outlets, runtime and shutdown/boot behavior.
10. **Measured acceptance thresholds — phase 1/4 role acceptance:** approve thermal, memory/swap, disk, link and WAN/backhaul gates from measured evidence.
11. **External alert path — phase 3 operations:** select primary/secondary people and an off-site channel independent of the control plane and GitHub.
12. **Phase 5 ingress:** select two Tunnel connector hosts after qualification.
13. **Phase 2 pilot:** select the LAN managed-network TLS marker host, certificate-rotation owner and availability expectation.
14. **Phase 3 bootstrap:** pin the initial Coolify version and installer-artifact procedure.
15. **Phase 5 Harbor migration:** confirm version, size/growth, layout, users/projects/robots, hostname, measured target node, backup adapter and clean migration plan.
16. **First provider mutation:** select Cloudflare and Coolify ownership/IaC mechanisms. GitHub ownership is gated only if an optional GitHub resource is created.
17. **First platform release/phase 3:** select release/feed URLs, signing identity and rollback-retention count.
18. **First mutating release:** generate/freeze the JSON, error and exit-code registry with cross-platform compatibility tests.
19. **First application digest deploy:** name the Coolify token owner/team map and GitHub Environment owner; prove positive and negative token/lease boundaries.
20. **Phase 4 runner admission:** revalidate macOS ARM64 runner status, choose fallback and set measured Mac resource limits.
21. **Phase 4 iMac acceptance:** set Hermes concurrency/resource limits from measured behavior.
22. **Each later service onboarding:** define owner, environments, resource limits, backup class, exposure and placement.
23. **Post-v1:** plan Chaabi Prod only after v1 acceptance.

## Effort actual versus estimate

| Workstream | Initial estimate | Actual timed agent clock | 2× checkpoint |
|---|---:|---:|---:|
| Transcript/register | 22 min | 41.5 min | 44 min |
| Architecture/evidence | 35 min | 25.2 min | 70 min |
| Root synthesis/editing | 45 min | 57.5 min | 90 min |
| Validation | 24 min | 43.8 min | 48 min |

Planned aggregate was 126 agent-minutes; known timed actual was 168.0 agent-minutes. The calendar span was 69.2 minutes because the workstreams ran in parallel. No external wait, CI run or deployment was involved. Suggested focused human review is 30 minutes: 8 minutes for decisions/GitHub, 8 for platform/data/security, 7 for deployment/inventory gates and 7 for agent/support/command contracts.
