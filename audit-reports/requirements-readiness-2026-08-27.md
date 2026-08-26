# Requirements reconciliation and implementation-readiness report

Status: coordinator synthesis after requirements reconciliation and independent audit. This report does not replace the canonical specifications, approve an implementation batch, prove software behavior, close actual site evidence or authorize live work.

## Baselines and authority

The reconciliation started **26-08-2026 11:50:10 PM IST** in the saved project. It preserved the original 20-file frozen snapshot captured **26-08-2026 08:34:01 PM IST** at HEAD `a3fc5414e9805fc211737a167878d516df5ead97`, including the user's uncommitted drafts. The historical audit register and the two original audit reports remain byte-for-byte unchanged.

The first fresh-audit baseline contained 21 files and was captured **26-08-2026 11:58:29 PM IST**. The independent task checked all hashes, read the full current requirements and wrote its designated temporary review artifact. Its initial verdict found five actionable contract gaps. The coordinator corrected those requirements and produced a second 21-file immutable baseline at **27-08-2026 12:07:58 AM IST** for focused re-verification.

## Reconciled product contract

The canonical [portable lifecycle](../docs/platform-lifecycle.md) now defines the OSS product separately from the VegaStack Labs deployment profile:

- a user installs one `vsk-labs` executable on a supported host and explicitly creates the control plane there;
- the finite local setup establishes one server-owned SQLite authority, then operators and managed nodes join through separate workflows;
- basic supported SSH management works without Cloudflare, Workspace, 1Password, GitHub or another third-party account;
- local OS/SSH identities, the native credential resolver and independent local recovery use the same authorization, plan, audit and recovery engine as optional external adapters;
- browser Console access remains capability-gated and cryptographically authenticated; there is no anonymous path or new password database;
- node numbers, physical serials, company domains, Sheet data, topology and provider accounts belong only to typed profiles where applicable;
- unsupported OS/provider/virtualization combinations remain unsupported rather than receiving best-effort mutations;
- public checkout builds/tests need no private VegaStack credentials or private network, while declared public dependency downloads remain allowed.

The README deployment stages now start with restricted local control, then separately qualify foundation hosts, Mesh, protected Console/control capabilities, CI/application capacity, ordinary application ingress/Harbor and operational acceptance. Development phases **0–11** and issue IDs such as **0.1**, **0.2** and **1.1** remain unchanged. The complete v1 software and required tests must pass before the first live lab onboarding rehearsal.

## Operational corrections

The lifecycle and focused documents now explicitly cover:

| Area | Current requirement |
|---|---|
| Authority | Desired, applied and effective policy/grants are separate. A proposed change cannot authorize itself; successful denials survive unrelated partial failures. |
| Approval | OS UID, SSH identity, cached session, TTY or an actor label does not distinguish a same-account coding agent from its human. The affected path remains unavailable until a separately protected, account-free human action/proof is reviewed and qualified. |
| Offboarding | Revoke independently authenticated application/provider accounts and established sessions; preserve administrator recovery; persist unreachable/unverified targets; never compensate an approved containment by restoring a compromised credential. |
| Backup/audit | Preserve both histories when an older restore accepts a named lost interval, anchor the new segment to independent evidence, invalidate old plans/grants and fence the former writer. Retain every artifact, key reference, signature and image needed for each retained recovery point. |
| Restic/R2 | Restic v2/R2 remains a candidate. Mutable coordination objects, writer permissions, retained payloads and deduplicated dependencies require compatibility proof; do not disable locks, widen payload deletion or shorten retention. |
| Secrets | 1Password logical purposes are not permission boundaries. Differing reader sets require separate physical vaults and direct provider-credential denial tests. The exact matrix remains a reviewed G-007 solution. |
| Tunnel | Replicas of one tunnel share tunnel-scoped credential authority. The current topology candidate requires tunnel-wide staged rotation and force-disconnection after compromise; per-replica revocation is not claimed. Shared blast radius/interruption requires phase-7 review before activation. |
| Controller | Later Coolify installation preserves the already initialized `vsk-labs` identity, SQLite and audit. A failure cannot automatically reimage the controller; any full rebuild is a separate destructive recovery plan. |
| Hardening | SSH-only Fail2ban, bounded auditd and AIDE on control are selected. Daily/after-change failed or stale evidence blocks new workloads, role expansion and workload credentials, while existing workloads, diagnostics and recovery continue. Native security-data updates are separate from the seven-day OS/package soak. |
| CI | Admission must bind the actual assigned job before user code or secrets under shared-label races. The concrete guard remains phase-9/G-006 design work; groups, labels and ephemeral mode are not proof. |
| Applications | Harbor is an ordinary Coolify application with no special fleet, host or client privileges. Manual app-owner actions are allowed only when an adapter lacks scope, with the same verification/audit contract. |
| Exit | Disable, detach, replacement and uninstall enumerate dependencies and preserve applications/data/audit/recovery by default. Physical media custody, sanitization, destruction and disposal remain outside scope. |

## Audit finding disposition

| Finding | Requirements disposition | Readiness effect |
|---|---|---|
| F1 — mixed-trust 1Password vaults | Corrected to physical vault separation by reader set and direct-provider negative tests. | G-007 exact matrix still needs solution review and authorized disposable-provider proof. |
| F2 — fictional per-replica Tunnel credentials | Corrected to real tunnel-scoped token, staged replica rotation and compromise disconnect semantics. | G-012 risk/interruption acceptance or an explicitly reviewed alternative remains open; no topology/cost expansion was inferred. |
| F3 — same-account agent acknowledgement | Added an explicit portable trust boundary and adversarial tests across bootstrap/local/SSH/browser paths. | 0.3 must select an account-free separately protected human-proof mechanism before phases 3–4 enable apply. |
| F4 — Coolify reimage after controller creation | Removed. Later installation preserves the controller; destructive rebuild uses independent recovery/fencing. | Contract contradiction closed; mechanism still needs normal phase-6/8 tests and G-014 evidence. |
| F5 — stale “closed” ledgers/workstation bootstrap | Current decision/readiness ledgers now defer to per-gate state, mark G-006/G-007/G-008/G-012 accurately and supersede mandatory workstation setup. | Metadata contradiction closed; historical evidence remains unchanged. |

## Readiness verdict

**The requirements are ready for continued phase-0 solution and implementation-issue preparation.** They are not a blanket assertion that every future issue is executable. The material choices above are visible, phase-owned and fail closed; an implementation agent is not expected to invent them.

The first executable issue is still not authorized or complete. Issue 0.1 needs named-repository development permission, an inspected satisfiable review/check/merge route, a complete issue body, estimate and batch approval. Issue 0.2 then owns the public scaffold/check/provenance lane. Issues 0.3–0.4 own the reviewed generic setup, human approval, hardening/privilege/Mac and credential-boundary solutions. Later phases retain actual OS/provider/recovery tests. Software acceptance and actual VegaStack Labs site acceptance remain separate.

No GitHub issue/label/settings change, commit, release, provider resource, credential, host, network device or live infrastructure action occurred.

## Verification record

- Original historical JSON/reports: unchanged hashes.
- Current Markdown local paths/fragments: no broken targets in the coordinator check; the first independent audit also found **667 local link occurrences**, including **576 fragments**, with zero broken targets.
- Fenced JSON examples and the audit-register JSON: parse successfully.
- Existing OS/architecture support matrix: unchanged.
- Whitespace/patch check: `git diff --check` passes.
- Independent first audit: all 21 baseline hashes unchanged; actual **5.6 agent minutes** versus 10 estimated, no external waits.
- Focused corrected-baseline re-verification: all 21 hashes unchanged; F1–F4 coherent, F5 materially repaired, and one residual D-114 wording conflict identified and corrected exactly as recommended. It found **672 local links**, including **581 fragments**, with zero broken targets; both JSON examples parse. Actual **2.9 agent minutes** versus 4 estimated, no external waits/research.
- Final coordinator checks after the D-114 correction: local links/fragments resolve, JSON parses and `git diff --check` passes.

These are documentation consistency checks, not implementation tests, provider evidence or live gate results.

## Effort and timing

Coordinator reconciliation/check start: **26-08-2026 11:50:10 PM IST**. Final coordinator verification: **27-08-2026 12:12:17 AM IST**. Actual coordinator elapsed clock: **22.1 agent minutes** versus 20 estimated and about 25 after the five-finding adjustment; within the 40-minute checkpoint. Basis: 18 normative source documents plus one new lifecycle and this report, cross-document/link/JSON/diff checks, five finding corrections and two audit handoffs. The first independent audit used **5.6 agent minutes** versus 10 estimated; focused re-verification used **2.9** versus 4. Those tasks overlapped coordinator work and therefore are not added to calendar duration. No CI, deploy, provider-test or other external acceptance wait occurred; three one-minute local audit-status waits were included in coordinator elapsed time. Suggested user review: **7–10 minutes** for the verdict, three open solution decisions and affected phase ownership.
