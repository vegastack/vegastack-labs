# Security and operations

[Back to README](../README.md) · [Control service](control-plane-service.md) · [Architecture](architecture-and-networking.md) · [Automation](automation-and-agents.md) · [Decisions](decisions-and-sources.md)

This document is the concrete VegaStack Labs deployment security/operations profile. Cloudflare, Workspace, Coolify, GitHub, Harbor, 1Password, R2, Debian/macOS and the physical assumptions below are selected adapters and site choices; portable platform invariants are defined in the README, control-service and automation contracts.

## Security model

VegaStack Labs assumes a physically trusted site, a separate guest Wi-Fi network, noncritical workloads and a flat main LAN in v1. Those assumptions reduce hardware and routing complexity, but they do not make the LAN trusted. Identity, SSH/TLS, host firewalls, least-privilege credentials and audit records remain mandatory. [D-002](decisions-and-sources.md#d-002) [D-033](decisions-and-sources.md#d-033)

Default host policy:

- deny inbound traffic except declared LAN/Mesh/service flows;
- no password SSH; per-person, per-device keys only;
- immutable node identity and pinned SSH host key across LAN/Mesh addresses;
- scoped no-prompt elevation only for commands required by an approved role;
- separate Coolify SSH key and `vsk-labs` automation key;
- no application, CI runner or agent receives fleet-admin credentials;
- no inbound router port forwarding;
- runtime containers receive only the secrets required by that workload. [D-065](decisions-and-sources.md#d-065) [D-070](decisions-and-sources.md#d-070)

The revisioned control-database network declaration owns the actual LAN CIDR and each port; rules are generated and tested, never copied as an untracked firewall script. Minimum intended flows are:

| Source | Target | Allowed service | Constraint |
|---|---|---|---|
| approved admin LAN addresses and approved admin Mesh identities/range | managed nodes/Macs | SSH `22`; macOS Screen Sharing on its declared service port | personal account/key and pinned host identity still required |
| `control-plane` | Debian nodes | SSH `22`, declared Beszel/backup health paths | dedicated Coolify or automation key; source restricted to control LAN/Mesh identities |
| approved users | Coolify/Harbor/dashboards | HTTPS `443` | protected/private audience plus application authentication |
| builders/job containers | GitHub, Harbor and explicitly mapped dependency endpoints | outbound HTTPS `443` and DNS/NTP through site policy | build/test jobs cannot initiate to control/Coolify/app SSH/databases/secret provider; only a separately admitted deploy job may reach the `vsk-labs` submit/claim API and Coolify HTTPS with its mapped project/team token |
| application nodes | Harbor and declared dependencies | HTTPS `443` plus each service's declared database/API port | app identity only; no fleet/control credentials |
| backup pull identity | declared workload export endpoints | declared adapter port/path | read-only source; workload never mounts backup repository read/write |
| selected qualified Tunnel connectors | control-plane Console origin | declared private HTTPS port | reserved connector sources only, verified origin TLS and independent Access identity verification; no direct LAN/Mesh browser bypass |
| Tunnel connectors and Mesh clients | Cloudflare endpoints | only current official connector/client egress requirements | no inbound WAN rule; exact ports/protocols revalidated before apply |

Everything not declared is denied inbound; builders additionally deny east-west initiation as above. Apply firewall changes one node at a time with an existing console/LAN session held open: install proposed rules, open a second positive session, run negative probes, then close the old session. Automatic rollback restores the previous rules if the positive check or timer acknowledgement fails. Emergency local console can load the versioned baseline; it may not disable the firewall indefinitely.

### SSH bootstrap and recovery

Phase 1 records each host key fingerprint from local console before accepting any network SSH connection. `known_hosts` pins immutable node ID rather than its changing LAN/Mesh address. Automation and Coolify use separate keys, principals and allowed-source rules; private user keys are per person **and** device. Disable password and direct root login for people after the tested admin account/elevation path works; if Coolify needs privileged SSH, admit only its dedicated key/source and audit it separately. Reimage/replacement changes a host key only with serial/console evidence and an explicit inventory update. A mismatch stops automation; it is never auto-accepted with `StrictHostKeyChecking=no`.

## Managed-host hardening

**Confirmed requirement, 26-08-2026:** every new, replaced or reimaged managed host, including the control-plane bootstrap target, must receive basic hardening before workload admission. The user explicitly requires Ansible to perform the security and role configuration needed to add the machine to the lab. Reachable SSH or a successful package install is not admission evidence. [D-116](decisions-and-sources.md#d-116)

The focused [host onboarding and hardening contract](host-onboarding-and-hardening.md) owns common controls, OS/role differences, Ansible sequence, recovery and verification. Linux SSH-only Fail2ban, bounded auditd and AIDE on control are selected; exact profile settings remain qualification work. OS-native firewalls/confinement and macOS controls remain required where applicable; Lynis is an optional audit aid, not an admission authority.

Phase 0.4 pins those settings in the machine-checked `host-security-v1` corpus. Ansible uses a dedicated non-root account and may elevate only into the root-owned, one-shot `host-action-once` mode of the single `vsk-labs` executable. That mode revalidates the exact plan, digests, host, declaration revision, recovery epoch, expiry and action set; refuses arbitrary module, command and target input; stores no desired state; and exits after the exact bundle. A fresh independent recovery session and local rollback must already be verified and armed. [D-123](decisions-and-sources.md#d-123)

The native account-free credential resolver uses the platform credential-path abstraction and binds every logical reference/material version to one declared consumer. It must work at cold start without Workspace, 1Password or TPM-class hardware, and it has no plaintext fallback. Wrong consumer, stale/revoked material, incomplete rotation or unavailable independent recovery blocks use. Planning and fixtures expose only reference IDs, status and versions; never material.

Profiles preserve the support matrix, encryption decisions, maintenance policy and live-authorization boundaries. Mandatory control evidence is collected daily and after relevant changes. Stale, missing, failed, unknown or skipped evidence blocks `admit-workload`, `expand-role` and `issue-workload-credential`; it does not silently stop a safe existing workload or erase an explicitly authorized recovery path. No host has been inspected, configured or admitted by this documentation; real OS, reboot, idempotence and recovery qualification remains Phase 6 evidence.

## Identity and authorization

### Sources of truth

| Concern | Authority |
|---|---|
| Person can authenticate | Existing Google Workspace account |
| Broad `admin` / `user` intent | Revisioned local control-database grants |
| Protected-app and Mesh enforcement | Cloudflare policies generated from declared intent and Google identity |
| Debian/macOS account and SSH grants | Control inventory applied by `vsk-labs` |
| Coolify project/team roles | Coolify, reconciled against private intent |
| Service secret access | 1Password vault/service-account policy |
| Infrastructure change authority | `vsk-labs` policy plus authenticated plan acknowledgement |

Google Workspace account creation, suspension and licensing are prerequisites performed in Workspace; v1 does not automate the Workspace Admin lifecycle. Cloudflare's Workspace integration supports login, device enrollment and group-aware Access policy. [Cloudflare Google Workspace IdP](https://developers.cloudflare.com/cloudflare-one/integrations/identity-providers/google-workspace/) [D-060](decisions-and-sources.md#d-060) [D-061](decisions-and-sources.md#d-061)

### Slack human acknowledgement boundary

V1 human proof uses one optional Slack Socket Mode adapter inside `vsk-labs server run`; it does not add a webhook, public listener, daemon, or direct Slack type to platform core. The server presents one exact current plan to the configured workspace, Slack user, channel, and approve/reject action IDs. The card is bound to the plan, target and reason digests, state revision, recovery epoch, expiry, authority, human, and a one-time nonce. The local database retains only the generated provider-neutral request, nonce digest, terminal proof, consumption marker, and sanitized audit attribution—never Slack tokens, rotating WebSocket URLs, raw envelopes, or the raw nonce.

Socket Mode credentials remain logical protected references resolved only in memory. Missing configuration blocks normal human approval; provider outage returns dependency unavailable and does not enable a CLI, browser, OS-peer, SSH, or agent confirmation fallback. Every valid envelope ID is acknowledged promptly, refresh/disconnect causes bounded reconnect, and malformed, wrong-workspace, wrong-user, wrong-action, stale, widened, changed-epoch, expired, rejected, or replayed input remains non-executable. Rejection and expiry are terminal for that plan. Approval is also terminal and its exact proof can be consumed by execution once; a second use requires a newly generated current plan. Remote browser admission continues to reject this POST before API dispatch.

Before enabling the adapter, the operator must configure the exact Slack identifiers and protected token references through the later deployment-profile workflow, verify an independent local recovery path, and exercise approve, reject, outage, reconnect, restart, expiry, and replay denial against a non-production test plan. If the connection becomes unavailable, repair the declared provider path and restart the same server process; do not reveal credentials, reuse a rotating URL, edit acknowledgement rows, or bypass the proof. Database rollback follows the standard verified pre-migration-copy procedure and must preserve the durable audit/history evidence.

### Browser identity and session response

Protected Console reads pass the fixed order `TLS and exact Host plus request-origin proof → Cloudflare Access JWT → local session → mapped principal → resource grant → input parsing`. Session POSTs require one exact Origin. Because ordinary same-origin browser GET/HEAD requests may omit Origin, a safe read without it must carry exactly `Sec-Fetch-Site: same-origin`, `Sec-Fetch-Mode: cors`, and `Sec-Fetch-Dest: empty`; any present mismatched Origin and any missing, duplicated, or different substitute fail closed. Initial session creation stops after the verified binding resolves to an active local principal; renewal and logout additionally require the current bound session, and none of those three session operations enables an infrastructure mutation. The server accepts only the Access JWT assertion, verifies it independently, and stores only opaque identity and session digests. A browser session is idle-limited to 15 minutes, absolute-limited to 8 hours, bounded by the external JWT, rotated on renewal, and invalidated by logout, replay, principal/binding revocation, grant-revision change, or recovery-epoch change. Time expiry durably changes the row and audit exactly once; repeated principal revocation is session-generation scoped and must leave zero active targeted sessions before it succeeds. Local logout ends only the `vsk-labs` session; it does not claim to end Cloudflare or Workspace login. [Fetch Origin header](https://fetch.spec.whatwg.org/#origin-header) [D-125](decisions-and-sources.md#d-125)

An invalid origin, token, key, session or grant returns only a stable safe error. Operators must not paste JWTs/cookies into logs or retry through a direct origin. A signing-key outage permits an already-known key only until 24 hours after the last successful key fetch; an unknown key or older cache is denied. Diagnose sanitized server health, system time, configured issuer/audience/origin and key-cache age, then restore the provider path or use protected local OS-peer CLI recovery. Local recovery is deliberately independent of Cloudflare and browser-session state.

The implemented remote listener accepts TLS 1.3 only and starts after the protected local listener and database application are healthy. It admits only generated available GET reads and the three session POSTs; local inventory operations are denied before API dispatch. Static bootstrap bytes require the exact TLS host plus a verified external identity; they contain no operational records or secrets. API reads require that external identity, the revocable local browser session, and the existing resource grant. The one exception is `POST /api/v1/session`, which receives only the verified external identity so it can create the local session; it does not receive an authorized principal or bypass resource checks. A resource-grant denial is persisted as a sanitized attributed fingerprint before the safe denial returns; an audit failure never permits the request.

The Phase 3 People, Services, Backups, and Providers Console routes are capability-status views only. They request one exact authorized `/api/v1/sources` row and display its safe state and freshness; they do not request identities, grants, service data, recovery evidence, provider records, raw errors, endpoints, or credential references. A healthy row is labelled only as a current status observation, while detailed records and every operation remain unavailable until their later owning phases.

Phase 3 browser acceptance is credential-free and loopback-only. The pinned Chromium lane reaches the embedded Console through the real TLS Go server, then proves same-origin reads, security headers, session denial/expiry/revocation/logout, bounded signing-key outage, and independent local Unix-socket recovery. Evidence is allowlisted before retention; cookies, authorization material, JWTs, private canaries, machine paths, external endpoints, links, binary traces, and screenshots are not retained by the v1 lane. Manual keyboard, zoom/reflow, theme, reduced-motion, and browser-version steps are recorded in `docs/development/phase-3-browser-evidence.md` with stable pass/fail scenario names only.

Remote startup and runtime failures are deliberately separate from local service health, including an invalid optional remote block. Operators diagnose the fixed typed `remoteReadReason` through the Unix-socket `server status` command and repair the declared profile or service-UID-owned TLS/identity material before restarting. The Linux key must be one non-linked regular `0600` file owned by the service UID; the matching certificate has the same owner and may be `0600`, `0640`, or `0644`. Both are bounded to 1 MiB and opened without symlink traversal. Never work around `preflight-unavailable`, `authentication-unavailable`, `listener-unavailable`, or `serve-failed` by binding a wildcard address, accepting plaintext HTTP, forwarding a claimed identity header, exposing the socket, or running a second web server. Keep the prior verified executable and matching server-profile schema as the rollback pair; rolling back the remote transport does not replace or downgrade SQLite. Remote connections and in-flight requests are capped; capacity rejection never consumes the independent Unix listener.

The session tables are durable, hash-only and additive. Before applying their migration, retain and verify the standard local pre-migration copy. If migration or startup verification fails, preserve both files and diagnostics, restore the verified copy into an isolated path, run the previous executable against that copy, and only then perform an acknowledged authority cutover. Never delete session/audit rows or edit a migration checksum to force rollback.

### Roles

- `vegastack-labs-admins`: logical fleet, network, identity, secret-provider and control-plane authority.
- `vegastack-labs-users`: logical access to explicitly assigned projects and services.
- project maintainer: broad control within assigned projects, including an ordinary production-like deploy that passes policy.
- shell grant: separate per-node capability; ordinary users do not receive shell merely by being users.
- agent identity: an execution identity that always carries the delegating human and has no independent right to escalate.

These are private-policy role names, not a claim that identically named Google Groups already exist. If Workspace groups are later chosen as IdP inputs, their immutable identity/membership mapping is declared and reconciled rather than inferred from a display name. An admin may also be a user; permissions are the union, and actions still record the active capability. The initial lead administrator is `mk@vegastack.com`; additional administrator identities are revisioned control-database records, not hard-coded in the public engine. [D-062](decisions-and-sources.md#d-062) [D-064](decisions-and-sources.md#d-064)

### Onboarding

1. Admin confirms the person already has an eligible Google Workspace identity.
2. `vsk-labs user onboard` creates a validated, inert database declaration with requested broad role, projects, devices and shell grants.
3. After plan review and declaration commit, the user self-enrolls the Cloudflare One Client into quarantine.
4. Desktop serial inventory may auto-approve an exact match; every unmatched device requires human approval. Mobile devices use Cloudflare's unique client ID and always require the human approval path because serial checks are unsupported there. [Cloudflare device serial checks](https://developers.cloudflare.com/cloudflare-one/reusable-components/posture-checks/client-checks/corp-device/)
5. `vsk-labs plan --change <draft-id>` atomically commits the inert grant/device intent and immutable plan; an authorized human reviews/acknowledges it and invokes `vsk-labs apply --plan-id <plan-id>`.
6. The apply creates assigned standard accounts, installs only that device's public SSH key, generates CLI/SSH aliases, and reconciles application access.
7. Verification proves both allowed and denied paths and records a sanitized run result. [D-043](decisions-and-sources.md#d-043) [D-063](decisions-and-sources.md#d-063)

Preflight also rejects an identity that is suspended/unknown, an already-bound device/key, an unowned project, an absent second recovery administrator for an admin grant, or a requested privilege outside the approver's scope. Failure before apply closes the draft/change request or expires its plan without live state. Failure during apply freezes further grants and reverses completed access in dependency order; it does not leave an unverified partially onboarded user active.

Cloudflare does not provide a native administrator approval queue for this design; `vsk-labs` implements quarantine around observed registrations. A desktop may auto-approve only an exact declared serial/hardware match. A phone/tablet binds the observed registration ID and Mesh IP to the human approval; re-registration returns it to quarantine. Host firewalls admit only approved source identities/addresses. V1 has no MDM, so the 30-day pilot is mandatory and mobile setup is a guided Cloudflare One Client plus SSH-client procedure, not managed-host enrollment. [D-043](decisions-and-sources.md#d-043)

### Offboarding and emergency suspension

Normal offboarding is a reviewed declaration and immutable plan followed by explicit apply. Before the final work time, transfer repository/service/data ownership and inventory any shared credential the person could access. At apply: remove new-session eligibility/audiences; revoke Cloudflare registrations and SSH keys; remove Coolify/project/1Password access; stop that user's Mac/agent sessions and CI tokens; disable local accounts without deleting homes; rotate affected shared credentials; verify both denied former access and retained team access. Preserve homes/audit under the declared retention, then delete only through a separate approved action.

`vsk-labs user suspend` is the reversible emergency change constructor: an authorized admin supplies a reason, reviews its immediately generated high-priority plan and executes it through the canonical `apply --plan-id` path. A Workspace administrator separately suspends the Workspace identity when account compromise/termination warrants it; that external account action remains a human prerequisite/checklist item. The apply blocks Cloudflare enrollment/Access and managed-node keys/accounts, revokes active sessions/tokens where supported, preserves data, verifies retained-admin access and writes a conspicuous audit event linked to provider record IDs. Resume requires a new current plan and positive identity/device checks. Permanent removal still follows review. [Google Directory users](https://developers.google.com/workspace/admin/directory/v1/guides/manage-users) [D-068](decisions-and-sources.md#d-068)

Because Workspace lifecycle is a prerequisite rather than a v1 mutation, `vsk-labs` produces a human checklist and verifies observed state but never mutates Workspace. A Workspace administrator attaches native event IDs—never a password or recovery code. Quarterly access review reconciles active/suspended Workspace identities, control-database roles, Cloudflare registrations/audiences, local accounts/SSH keys, Coolify teams, GitHub access and 1Password service accounts; stale access becomes a reviewed removal declaration/plan. Workspace Admin audit events are available through the official Reports API (current documented maximum query window: 180 days), so the six-month audit export must run within that window. [Google Admin activity report](https://developers.google.com/workspace/admin/reports/v1/guides/manage-audit-admin)

### Complete revocation and containment

Offboarding includes every independently authenticated identity/key/session for that person, including configured GitHub access and application-local identities such as Harbor. Use an existing scoped adapter or assign the owning human/application administrator a verified checklist action; no additional platform privileges are acquired for an app. Stop or contain established Linux/Mac/agent sessions, not only new logins. Record per-target verified denial and unresolved actions; successful revocations are not compensated by regranting access. The approved plan may include bounded isolation preserving administrator recovery. An unavailable host/provider remains unresolved and must reconcile before readmission. Physical custody, sanitization and disposal are outside product scope.

Routine rotation compensation never overrides an approved suspected-compromise containment decision: a compromised old credential remains revoked even if the replacement is unhealthy. Preserve the incident evidence and use the recovery path.

## Shared Macs

### Mac mini M4

- one individual standard macOS account per teammate;
- separate admin account(s) for maintenance; no routine admin rights for development accounts;
- separate home directory, repository checkout, SSH keys, Git identity, agent state and caches per person;
- administrator-managed base tools come from one versioned manifest and are read-only to standard users; project/per-user toolchains and caches remain inside that user's home. No shared writable package cache, shell socket or cross-user process-control group;
- SSH and Screen Sharing allowed only through declared LAN/Mesh policy;
- one CI service identity and one native ARM64 job at a time;
- a work Apple ID may remain signed in only on the designated owner/admin account; it is never shared with standard users or used by CI, services or agents. Record account recovery and Activation Lock ownership before any reset; personal Apple IDs are outside the operating model;
- high-autonomy Codex/Claude profiles are per-person and have no fleet, 1Password service-account or CI-controller credential;
- declared work data and infrastructure state are backed up, not disposable caches. [D-054](decisions-and-sources.md#d-054) [D-066](decisions-and-sources.md#d-066) [D-067](decisions-and-sources.md#d-067)

Account bootstrap is administrator-owned and declarative: create the standard account, require a unique login secret, install the managed base-tool manifest, create only that user's Git/SSH/agent directories, authenticate vendor tools interactively inside that session, enroll the device once at OS level, and run cross-user negative tests before handoff. Never preload another user's home or clone `auth.json`, Claude/Codex state, SSH keys or terminal sockets. Removal follows offboarding and preserves/exports declared work before the account is disabled.

Daily operator flow is: sign into the personal standard account; run `vsk-labs doctor` and refresh authorized control state through the API; use a personal application/code worktree when needed; inspect/plan through the Console, pinned CLI or focused skill; review the same readable/JSON plan; provide human acknowledgement only inside the user's authorized scope; then inspect sanitized result/audit. Direct provider shells are break-glass, not the normal Codex/Claude workflow.

The Mac runner is a separate service identity and checkout, never launched from a teammate's home. Its scheduler enforces one job, lower CPU priority, declared memory/disk/time limits and a minimum free-space reserve, and prevents sleep only for the job. Exact numeric budgets are phase-4 discovery inputs. Admission stops when an interactive-health probe, temperature, memory pressure, disk reserve or power condition fails; the job is cancelled/cleaned and can use GitHub-hosted CI or wait. A standard teammate cannot inspect/control the runner or another user's processes merely to clear capacity.

### iMac M1

The iMac is an always-on, low-concurrency Hermes host in v1. It has a designated maintenance-admin account and a separate standard Hermes manager account only—not five interactive developer accounts. It is not a Coolify control/application node or the shared team development server. Both Macs keep system sleep disabled while allowing display sleep, and expose SSH/Screen Sharing only on declared LAN/Mesh paths. [D-067](decisions-and-sources.md#d-067) [D-069](decisions-and-sources.md#d-069)

Hermes is installed at one reviewed release from its official repository/package path; never execute its mutable `curl | bash` installer or `hermes update` unreviewed on this persistent host. Start with Hermes **Blank Slate** so only the minimum file/terminal toolsets exist, then explicitly disable or omit gateway/messaging, cron, delegation, browser/web, third-party skills/plugins/MCP and memory capture until each has a reviewed use case. Official Hermes documents that configuration, OAuth and secret material live under `~/.hermes/`; lock that tree to the manager account, keep provider secret references in 1Password, and include needed config/session/memory in encrypted backup without exposing it to other Mac users. [Hermes quickstart](https://hermes-agent.nousresearch.com/docs/getting-started/quickstart) · [Hermes configuration](https://hermes-agent.nousresearch.com/docs/user-guide/configuration)

Official Hermes currently offers OpenAI Codex/ChatGPT subscription device-code authentication. Provider procurement/licensing remains outside `vsk-labs`: authenticate only the designated manager profile, never copy a developer's Codex/Claude state, and do not treat provider login as fleet identity. Hermes calls only read/plan `vsk-labs` commands by default. A mutation requires the same external human acknowledgement as any other agent and runs under a separately attributed session; Hermes never receives 1Password service-account, SSH fleet-admin, Coolify admin or break-glass credentials.

Maintenance order is: encrypted Hermes backup; record current version/config/tool inventory; update a disposable or secondary profile; run `hermes doctor`, provider chat/session-resume, allowed/denied tool and `vsk-labs` read-only tests; then update the manager profile in the maintenance window. On failure, stop the gateway/cron if any, restore the prior pinned release and config backup, run `hermes doctor`, and retain CLI/SSH manual operations. The 8 GB iMac admits one active agent task unless measured evidence approves otherwise; memory pressure or loss of responsiveness stops new work.

## Secrets

The VegaStack Labs deployment selects 1Password CLI plus a 1Password Teams service account as its single authoritative provider. The public engine may support a separate `sops-age` provider, but a site selects exactly one; there is no automatic cross-provider fallback. 1Password documents that service accounts are non-person identities with controllable vault/action access and usage reporting. [1Password service accounts](https://www.1password.dev/service-accounts) [D-071](decisions-and-sources.md#d-071)

Rules:

- reference secrets by stable logical name, never inline value;
- service-account access is limited to physical vaults with matching authorized reader sets; item/field references are not provider-enforced isolation;
- resolve only during an approved operation; materialize only to the target;
- redact command output and logs; use nonreversible fingerprints for drift checks;
- fail closed when 1Password is unavailable;
- agents cannot invoke plaintext reveal by default;
- an authorized human reveals assigned values only in 1Password's native interface;
- rotate on a 365-day default with reminders at 30 and 7 days before expiry: create replacement, distribute, health-check, obtain admin acknowledgement, then revoke old;
- on failed health checks, stop, restore the previous secret/reference, verify service, and leave the old credential active until the issue is resolved;
- preserve a sealed offline recovery credential/key under the lead admin's custody and explicitly accept/test the resulting key-person dependency. [D-072](decisions-and-sources.md#d-072) [D-073](decisions-and-sources.md#d-073)

The `secret_refs` control table records logical ID, owner, consuming identities/targets, 1Password reference, rotation/expiry class and last verification—never a value. Control, Cloudflare, Coolify, Registry, Backup, project and Break Glass remain logical purpose categories; physical vaults must additionally split differing reader sets as required by G-007. The previous one-vault-per-purpose layout is superseded. Review the exact matrix before activation; machine retrieval uses narrow service accounts and human-only recovery material remains inaccessible to them. Actual vault/item UUIDs and grants remain `G-007` evidence. Before phase 3, an admin imports that map and proves through positive/negative tests that CI jobs, Hermes, app containers and project maintainers cannot retrieve fleet/control/backup credentials. [Implementation gates](implementation-gates.md#1password-layout--g-007) [D-110](decisions-and-sources.md#d-110)

The VegaStack Labs deployment profile retains the accepted scoped CI automation. Each enrolled project's Coolify token is stored as a GitHub Environment secret only for its admitted deploy environment/job; the source value and ownership record remain in 1Password, and SQLite stores only its reference/fingerprint. `vsk-labs` may install or rotate that encrypted Environment secret with a selected-repository fine-grained PAT carrying only `Environments: write`; a purpose-specific GitHub App is optional, not required. Automating reviewer/protection configuration is a separate capability requiring `Administration: write` and is disabled unless explicitly owned. The deploy job's Coolify token is bound to one Coolify team and carries `write`+`deploy` because it must change the digest and trigger the resource; it has neither `root` nor `read:sensitive`, but compromise can affect every resource in that team. Rotation creates a replacement, updates the Environment secret, runs one positive exact-digest deploy plus denied cross-team/extra-permission tests, then revokes the old token and proves `401`. The exact Coolify automation account/owner, team map and GitHub environment owner are phase-5 gates. [GitHub Actions Secrets API](https://docs.github.com/en/rest/actions/secrets) · [Coolify API tokens](https://next.coolify.io/docs/core/security/credentials/api-tokens) [D-055](decisions-and-sources.md#d-055) [D-104](decisions-and-sources.md#d-104)

An operation resolves references only after authorization/plan checks, holds values in memory or a permission-restricted temporary channel for the shortest supported time, prevents shell tracing/process-list leakage, and deletes temporary material on success/failure. A plan can validate reference existence and access metadata but never fetch a value. Rotation inventory binds both old and new fingerprints, dependent targets, health checks and revocation status to one run ID; inability to verify every consumer stops revocation.

### Immediate credential hygiene item

The live inventory workbook contains account/credential-like fields in plaintext. Their values are intentionally omitted. Before phase 1:

1. Treat exposed values as compromised and rotate them.
2. Remove secret values from the workbook.
3. Keep only secret references and ownership metadata in the control database.
4. Review Sheet and Drive access/audit history.
5. Record completion without pasting old or new values into the database, Git or audit evidence. [D-015](decisions-and-sources.md#d-015)

V1 does not require Linux full-disk encryption because physical security is an accepted site assumption. This leaves a documented risk: theft of a running or unencrypted control-plane disk can expose locally usable credentials. FileVault/LUKS remain discoverable host capabilities and may become policy later. [D-074](decisions-and-sources.md#d-074)

## Backup and recovery

Coolify control-plane backup and application-data backup are different. Coolify's instance backup preserves dashboard state, but workload volumes require independent protection; the matching `APP_KEY` and Coolify SSH keys are required for recovery. [Coolify backup guidance](https://coolify.io/docs/knowledge-base/how-to/backup-restore-coolify)

### Classes

| Class | Schedule | Destinations | Retention | Expected loss if site and SSD are lost |
|---|---|---|---|---|
| `none` | no data snapshot | application code plus signed declarations only | n/a | all mutable workload data |
| `standard` | daily | encrypted central 512 GB SSD | 7 days | standard data is lost |
| `critical` | local every 6 h; R2 daily | encrypted SSD plus independent encrypted R2 repository | 14 days; R2 objects locked for the window | restore from R2 |

Systemd timers run the schedules because they expose last/next state and catch up after reboot. Workload nodes do not mount the backup SSD read/write. The control-plane pull service uses narrow read access to declared dumps/paths; critical R2 credentials cannot alter bucket-lock policy. [Cloudflare R2 bucket locks](https://developers.cloudflare.com/r2/buckets/bucket-locks/) [D-080](decisions-and-sources.md#d-080) [D-081](decisions-and-sources.md#d-081)

Every stateful service declares a typed adapter or consistency hook: database-native dump, application export, quiesce/snapshot sequence, or a documented unsupported state. Copying a live database directory is not an accepted backup.

The implemented Phase 2 database primitive is deliberately narrower than the complete backup policy in this section. It creates an owner-only local pre-migration generation with SQLite Online Backup, a strict secret-free manifest, no-replace publication, and isolated restore verification; a failed attempt never overwrites the last valid generation or permits migration SQL. It does not yet encrypt, sign, schedule, retain, prune, upload, perform a real authority restore, fence writers, advance the recovery epoch, or prove disaster recovery. Phase 5 owns those policy and cutover capabilities, including turning the local primitive into the scheduled and off-site workflow below.

Phase 2 also implements a narrower secret-free inventory-draft export. It verifies a self-contained signed document in memory, writes it once under its final SHA-256 artifact name with owner-only permissions, fsyncs it, and atomically replaces a protected `current.json` pointer without deleting older artifacts. Startup reconciliation treats an unmatched requested event as interrupted: it independently verifies the relevant current and prior artifacts, compare-restores the prior pointer or absence when necessary, retains all immutable bytes, and records one sanitized terminal event. This local behavior is not a backup, accepted declaration, or live restore authority. Its fixed Ed25519 identity is test-only; production has no signing key or trust policy and blocks. Phase 5 must define and prove identity distribution, provider/keystore and custody, least privilege, key ownership, rotation/overlap/revocation, retained verification keys, offline access, compromise/loss response, restore-time key selection, recovery steps, clean-node positive/negative verification, and key separation from audit checkpoints.

The selected candidate is restic repository format v2; the writer/lock/retained-payload compatibility mechanism remains open under G-008 and must be proven without weakening safety. Use separate `standard`, `critical-local` and `critical-offsite` repositories. Pin restic `0.19.1` or a reviewed later patch by binary digest; use `RESTIC_PASSWORD_COMMAND` backed by the narrow 1Password reference; use `keep-within` retention; and separate routine writer from retention/prune and R2 lock administrators. Before phase 3, `G-008` still requires actual repository IDs, measured capacity, R2 credential/lock evidence and functional sealed recovery without the control node. [Implementation gates](implementation-gates.md#backup-engine-and-repository-topology--g-008) [D-109](decisions-and-sources.md#d-109)

Every backup declaration names owner, source paths/volumes, consistency adapter, class/schedule, expected size/growth, encryption/recovery-key reference, retention, restore target and functional test. Minimum data-set coverage is:

| Subsystem | Required recoverable state | Excluded/recreated state |
|---|---|---|
| VegaStack Labs Control Plane | SQLite online backup, schema/tool/SQLite versions, signed declarative snapshot, audit/outbox state and bootstrap manifest references | provider observation cache may be discarded and refreshed; secret values are never present |
| Coolify control | database, matching `APP_KEY`, `/data/coolify/ssh/keys`, pinned version and restore manifest | application volumes; those belong to workload adapters |
| Harbor | version/config/certificates, database-consistent state, registry blobs and all persistent Compose volumes | cache that the pinned version can safely regenerate |
| Other stateful service | application-declared export/dump plus persistent files and migration/restore instructions | build image and source already pinned in the code repository/Harbor |
| Mac mini/iMac | declared work, infrastructure state, required agent configuration/session/memory under encrypted access | package caches and replaceable checkouts; provider tokens remain governed as secrets |
| Network/hosts | ES216G export, approved HX510 reservation record, host-key/public-key inventory and signed declarative snapshot | live DHCP leases and regenerated OS packages |
| Beszel/CI | declarations and audit/log evidence required by retention | disposable runner workspaces and rebuildable monitoring hub state |

Each run writes a signed/hashed manifest with run ID, node/service, adapter/version, source snapshot point, object/file counts, plaintext logical size, encrypted repository IDs, start/end, consistency result and non-secret errors. The backup job is not successful until repository integrity and manifest/object presence pass. Capacity forecast alerts before retention cannot fit; it never silently deletes locked/critical history or reduces retention.

### Recovery objectives

The selected balanced objectives are:

| Event | Recovery-point objective | Recovery-time objective |
|---|---:|---:|
| Single node/disk failure | at most 6 hours of critical data | restore service within 4 hours |
| Total site plus local SSD loss | at most 24 hours of critical data | restore critical service within 24 hours |

These are service objectives, not high-availability promises. `standard` data has only the declared local daily copy and no site-loss guarantee; `none` is rebuilt from declarations. A service that cannot meet its selected class must fail validation or declare a reviewed exception. [D-088](decisions-and-sources.md#d-088)

### Verification and recovery cases

- after every run: verify command exit, manifest, size bounds, snapshot presence and repository integrity metadata;
- weekly: run restic metadata checks and a rotating `restic check --read-data-subset=1/4`; monthly: complete a full `restic check --read-data` and verify repository readability;
- quarterly: restore at least one representative `critical` and one `standard` service into isolated targets and prove a functional query/login, not merely file extraction;
- control node lost: install a clean qualified spare, restore the verified VegaStack Labs control database/snapshot with the matching release, retrieve 1Password/offline recovery material, restore Coolify database/keys, refresh observations and then reconcile remote servers;
- workload disk lost: restore declaration, image and data to a qualified app node;
- site and SSD lost: only `critical` data has an off-site recovery path. [D-082](decisions-and-sources.md#d-082)

A restore always targets an isolated path/host first unless the incident runbook proves that impossible. The operator selects an immutable recovery point, verifies manifest/engine/key/version, restores, runs subsystem functional and access-control tests, records elapsed time/data point and obtains acknowledgement before cutover. A failed restore preserves the target/evidence, does not overwrite the only remaining copy, and escalates to the next earlier verified recovery point or manual rebuild. Quarterly evidence must state whether RPO/RTO were actually met; file extraction alone is a failure.

### Failure alerts

A sanitized backup failure is sent through the notification adapter. The VegaStack Labs deployment profile selects one deduplicated GitHub issue containing node, class, run ID, error class, last success and local log reference—never dumps, secrets or raw logs. The next verified success closes it. GitHub is an alert destination, not the source of the failure record; the local outbox/audit remains authoritative.

For total-site silence, the control plane writes only a sanitized heartbeat/alert event to a separate R2 status bucket using a narrow write-only credential. A Cloudflare Worker checks every five minutes and alerts when the heartbeat is 15 minutes stale. The Worker—not any home node—holds a purpose-specific GitHub Issues credential for the one selected alert repository; it has no backup-bucket credential, Contents, Actions, Checks, Deployments or runner permission. A fine-grained PAT with `Issues: write` is technically sufficient. A dedicated Issues-only GitHub App is optional and operationally preferable only if VegaStack Labs chooses a durable organization-owned machine identity. [D-083](decisions-and-sources.md#d-083) [D-104](decisions-and-sources.md#d-104)

The public code repository owns Worker code/schema; the control database owns site configuration, issue repository/labels and credential references; Cloudflare/GitHub own only their runtime delivery state. The direct typed Cloudflare adapter owns its declared Worker resources; deploy only after `G-011` records the human recipients, the independent secondary channel and the selected Issues credential class/owner. Acceptance stops the home heartbeat and proves one deduplicated issue appears after the selected stale interval, then resumes heartbeat and proves verified recovery closes it. Worker failure, credential expiry/suspension or GitHub outage must itself alert through that secondary path, which depends on neither the home control plane nor GitHub. Queue/retry is bounded and deduplicated. Rollback returns to the last attested Worker release and leaves backup data untouched. App/PAT ownership, permission, storage, rotation and offboarding requirements are in the [GitHub dependency matrix](decisions-and-sources.md#github-dependency-matrix).

## Observability and audit

V1 uses Beszel only, rebuilt declaratively and without Docker-socket access. It observes host CPU, memory, disk, temperature and reachability; Coolify and declared application health checks provide container/service signals. The external watchdog covers total control-plane silence. No Prometheus, Grafana, Loki or distributed log pipeline belongs in v1. [D-084](decisions-and-sources.md#d-084)

The control database owns the Beszel hub/agent version, node endpoints, metric/alert policy and secret references. The hub runs on control; each node agent runs as a dedicated unprivileged service with no Docker socket, host mutation tool or general shell credential. Firewall admits the agent/hub flow only between declared identities. Bootstrap the hub, add one node, verify metric freshness and an induced reachability alert/recovery, then enroll the fleet. On hub loss, restore declarations and re-enroll with rotated credentials; monitoring history is not allowed to block infrastructure recovery. If a node agent fails, diagnose service, version, time, firewall and endpoint identity before reinstalling—never grant Docker/root access to “make metrics work.”

Alert on sustained, actionable conditions:

- node unreachable;
- disk capacity/health trend;
- thermal throttling or unsafe sustained temperature;
- failed backup or stale heartbeat;
- application health failure or repeated deployment rollback;
- certificate/registration expiry;
- CI queue/concurrency saturation;
- unexpected privileged login or configuration drift.

Routine logs stay local for 30 days. Encrypted access, security and infrastructure-execution audit records remain in R2 for six months. Alert routing is explicit: a critical failure alerts on the first confirmed failure; a transient warning alerts after two consecutive failures; low-risk update/capacity notices go to a daily digest. Alerts deduplicate and close only on verified recovery. [D-085](decisions-and-sources.md#d-085)

The implemented Phase 2 audit layer is append-only by application control, not yet tamper-evident. It atomically stores one bounded canonical event and required durable outbox rows with the business intent, assigns a strict local sequence, rejects routine update/delete, and records corrections as new same-target links. It persists only stable error codes and fingerprints—never raw errors, payload maps, provider responses, paths, prompts or secrets. Eight-attempt destination state is deterministic; a disabled destination is `paused`, exhaustion is `dead_letter`, and schema/digest mismatch becomes `PAYLOAD_INVALID` before payload release. No sender or external call exists yet.

Phase 5 must implement the D-106 hash chain, separately protected checkpoint signing, encrypted retention-locked export, independent silence monitoring and recovery comparison before the platform claims tamper evidence. A root or disk compromise remains outside the current application controls. On corruption or uncertain commit, stop mutation, preserve the authority file and rollback artifacts, inspect only sanitized health, use the verified-copy and isolated-restore procedure, and reconcile the accepted result as a new event; never update/delete history or guess whether an external delivery occurred. [D-106](decisions-and-sources.md#d-106)

Before phase 3 acceptance, the control policy must name the primary/secondary human recipient and external delivery channel for each severity; the transcript did not select a messaging provider. An unowned alert or a route that depends only on the failed subsystem fails validation. Every alert includes first/last occurrence, affected immutable node/service, observed condition/threshold, last known good, runbook and correlation ID, without secrets or raw payloads.

## Failure-mode matrix

| Failure | Detection / safe state | Continuity and recovery | Release acceptance |
|---|---|---|---|
| WAN or Cloudflare outage | edge/identity observations become stale; browser and Mesh fail closed | LAN/console plus constrained CLI remain; running workloads and SQLite continue; no public route is weakened | disconnect WAN/Cloudflare and prove local read, backup and manual recovery |
| GitHub/SCM/CI/release outage | source/build/release adapters report unavailable with timestamps | installed server, local plans, backups and running apps continue; queue inert digest/status delivery and use pinned source/offline build runbook | block GitHub and prove no core/control read depends on it |
| Coolify outage | hosting adapter stale/unavailable; no deploy starts | existing containers may continue; independent VegaStack Labs Console/CLI diagnoses; recover matched Coolify DB/`APP_KEY`/SSH keys or use documented host recovery | stop Coolify and prove control UI, database and backup remain usable |
| control process/node loss | local health and external heartbeat fail | all applies fail closed; use qualified spare, matching binary, verified SQLite backup and fenced alias cutover | clean-node restore meets RTO and old node cannot resume as writer |
| SQLite corruption/disk full | integrity, foreign-key, migration or disk check enters read-only safe mode | preserve evidence, restore an isolated verified backup, refresh observations and reauthorize cutover | corruption/disk-full injection never reports a mutation successful |
| partial apply/interruption | durable per-step state is `partial`/`interrupted`; lease prevents overlap | resume only declared idempotent steps after preconditions, otherwise create a recovery plan/manual runbook | kill connection/process at every step boundary and verify truthful state |
| stale plan or observation | digest/revision/fingerprint/expiry mismatch | reject before credential resolution/mutation; refresh and create a new plan | concurrent edit/provider-drift fixtures return `PLAN_STALE`/`STATE_CONFLICT` |
| split-brain control recovery | instance UUID, state revision, recovery epoch and recovery-pending/fence evidence disagree | keep replacement read-only; stop/quarantine old host, revoke its Mesh/1Password/SSH/provider mutation paths, select one verified history, assign new instance UUID, increment epoch and invalidate old plans before alias movement | old epoch returns `RECOVERY_EPOCH_MISMATCH`; old host/credentials are denied by every mutating boundary before one canary enables the replacement; epoch alone is explicitly not treated as an external fence |
| credential expiry/revocation | adapter-specific auth failure is distinct from target failure | block only dependent operation, queue safe notifications where applicable, rotate with overlapping verification; never fall back to broader credential | expiry/suspension/rotation and denied-scope tests for every adapter |
| managed-node or disk loss | host identity/reachability/disk health alert | quarantine; reassign movable role to qualified capacity; restore declared data/image and verify before alias/placement change | spare rebuild and one stateful workload restore rehearsed |
| backup/export failure | run unsuccessful until manifest/hash/object/lock checks pass; off-site-age alert | preserve last verified point; stop unsafe pruning; repair credential/capacity/engine and repeat; use earlier independent point | corrupt/missing object, expired token, full SSD and failed lock tests |
| incompatible upgrade/schema/architecture | signature, support matrix, API/schema and pre-migration checks block activation | retain current binary; restore pre-migration backup and previous binary; unsupported asset never executes | wrong OS/arch, unknown schema major and failed migration fixtures |
| physical theft/compromise | device loss or tamper indication triggers incident, credential and audit review | suspend identities, rotate reachable secrets, fence node and rebuild clean; accepted unencrypted-Linux residual may expose local material | recovery drill records residual risk and proves independent backup/key custody |
| manual break-glass change | normal applies freeze; reason, actor, time/target bound and command/evidence hash recorded | recover service with smallest action, then import/observe and reconcile through a new plan; never call drift “clean” | runbook exercise proves later reconciliation and credential revocation |

No failure automatically elects a client or D1 projection as a new controller. Recovery always establishes one authoritative SQLite writer and invalidates every pre-failure plan before mutation resumes.

## Incident procedure

## Local read authorization and event redaction

Migration `0004_read_authorization` starts with no principals or grants. A socket binding authenticates a kernel peer but grants nothing. Reads require one of `control.health.read`, `database.status.read`, `platform.summary.read`, `platform.source.read`, `inventory.draft.read`, or `audit.event.read`, plus its exact provider-neutral resource kind and, for a draft detail or child, the canonical draft revision ID. A source grant uses resource kind `platform-source` and one exact source ID; access to the fixed source set requires one grant for each source, with no implicit wildcard. Revoked, absent, wrong-kind, cross-resource, resolver, and store failures deny without a protected row or existence oracle. The grant revision and digest are revalidated in the same short transaction as each query; SSE repeats authorization before each batch.

Event streaming emits only the closed generated audit projection: bounded attribution, target, revision, correlation/link fields, and optional fingerprints. It never emits SQL, database paths, raw source, raw errors, prompts, provider responses, outbox bytes, or secret values. Slow/disconnected consumers lose no durable database event: they reconnect from the last successfully received ID. Commit notifications contain no event bytes and are hints only; durable SQLite replay remains authoritative.

Source-health reads follow the same disclosure boundary. They expose a fixed provider-neutral source ID, a fixed capability name, one of `healthy`, `stale`, `unknown`, `unavailable`, or `failed`, known observation timestamps and a fixed safe reason. They never return an adapter error body, provider identifier, credential reference, private evidence or supplied diagnostic text. An absent adapter is `unavailable`, a source without a timestamp is `unknown`, and neither may be rendered healthy. One optional-source failure changes only that source and its aggregate summary count; local database and inventory reads remain independently authorized and usable.

1. **Detect and own:** acknowledge the alert, assign incident lead, record start/scope and preserve clocks/log hashes. Never paste secrets into the issue.
2. **Classify and contain:** distinguish node, LAN/power, Cloudflare, control plane, workload, credential or compromise. Stop new applies/deploys; revoke or isolate only the affected identity/path; preserve LAN/console recovery.
3. **Recover:** select the subsystem runbook and last verified recovery point; state expected data loss/downtime; require the operation's approval class; restore to isolated/replacement capacity when possible.
4. **Verify:** prove functional health, exact running versions/digests, allowed and denied access, backup/monitoring, and no unresolved drift. Re-enable traffic/jobs gradually.
5. **Close and reconcile:** attach sanitized evidence, rotate exposed credentials, reconcile emergency changes as a new database revision, record actual RPO/RTO and create follow-up tests. Closure requires verified recovery, not merely silence from the alert.

If automation/control is unavailable, use direct LAN/console and the generated manual runbook. Break-glass access is time/target/reason bounded and logged locally for later import. Suspected compromise favors credential revocation and clean rebuild over restoring potentially altered binaries.

Recovery points retain their required binary/schema, images, signatures and key references for their full declared lifetime. The normal three-release rollback cache is separate from the recovery archive; capacity pressure blocks unsafe cleanup instead of silently deleting dependencies. Older audit recovery follows the [anchored history procedure](platform-lifecycle.md#recovery-and-retained-dependencies).

## Updates and maintenance

Default maintenance window: **Sunday 02:00 AM–05:00 AM IST (Asia/Kolkata)**.

- inventory available updates continuously;
- apply routine OS/package updates after a uniform seven-day soak;
- retain automatic native malware-definition/revocation-data updates as an explicitly separate classified update type; do not apply the OS-release hold to those data updates;
- canary one qualified non-control node, then patch eligible nodes in bounded role-aware batches; reboot only when required;
- preserve one recovery path and validate service health between batches;
- refresh Cloudflare/Coolify connectors one at a time so a second path remains healthy; update the control plane last after a fresh verified state backup;
- manage Coolify, Docker, Beszel and other platform upgrades monthly, pin exact versions and disable blind production auto-update;
- allow an administrator to override the soak for an actively exploited critical issue, with reason, plan and post-checks;
- use conditional automatic application rollback only when a declared health check can prove the previous digest is healthy. [Coolify update settings](https://coolify.io/docs/knowledge-base/self-update) [D-086](decisions-and-sources.md#d-086)

Debian 13.6 is the current stable point release, released 11-07-2026. Security repositories remain enabled; point releases do not replace routine package updates. [Debian releases](https://www.debian.org/releases/) · [Debian 13 errata](https://www.debian.org/releases/stable/errata)

### Debian baseline and rebuild

The pinned `vegastack-labs` Ansible role plus revisioned node declaration owns intended host state. For a clean/replacement ThinkPad: verify serial/disk/battery/firmware and official Debian image checksum; install the selected 13.x point release locally with only declared disks; record partition/filesystem/encryption residual; apply hostname/time/network and the bootstrap admin key from console; verify official security repositories; run the base role for packages, accounts/elevation, SSH, firewall, Cloudflare client, Docker only where needed, timers/log retention and monitoring; reboot; then prove pinned host key, reservation, LAN/console recovery, Mesh, allowed/denied ports, time, updates and role checks. Capture discovered facts and idempotence before assigning aliases/workload. A failure returns the node to quarantine or a clean reinstall—never a partially hand-configured role.

Before a point/major upgrade, read the current Debian release notes and test the image/role on the spare. Debian 13 changes include `/tmp` behavior, possible network-interface naming changes and OpenSSH/remote-upgrade caveats; preflight records free space, package holds, interface/MAC/reservation, SSH/console fallback, services and a current recovery point. Apply canary first, reboot if required, compare facts/ports/services and run idempotence. If package rollback is unsupported or schema/filesystem state changed, recover by clean-installing the prior approved image and restoring declarations/data rather than improvising a downgrade. [Debian 13 release notes](https://www.debian.org/releases/stable/release-notes/)

## Power, battery and thermal operations

- Record UPS model, protected outlets, measured load, tested runtime and shutdown behavior; admission requires load at or below 60% of rated continuous capacity, at least 15 minutes measured runtime and shutdown completion with at least 5 minutes remaining. “UPS exists” is not verification.
- Use a spaced vertical rack with every intake/exhaust unobstructed and no chassis touching.
- Inspect batteries for swelling and record health. Configure vendor-supported charge thresholds where available; do not invent a universal threshold.
- Enable power-on-after-loss where hardware supports it and test unattended boot.
- Burn in each assigned role under its expected concurrency and ambient conditions for the fixed 8-hour common profile; use the numeric thermal, memory, disk, link, WAN, CI and Mac rules in the gate appendix.
- Reduce CI concurrency automatically if throttling, unsafe temperature, memory pressure or disk contention persists.
- Keep the quarantined charging-fault asset disconnected until repaired and qualified. [D-087](decisions-and-sources.md#d-087)

[Implementation qualification defaults](implementation-gates.md#common-numeric-qualification--g-005-g-009-g-010-g-020-g-021) are normative v1 acceptance values. Real measurements remain mandatory; agents cannot turn a default into observed evidence. [D-115](decisions-and-sources.md#d-115)

## Minimum runbook set

Each runbook must have prerequisites, plan, approval class, deterministic command, verification, rollback/recovery and human-manual equivalent:

- control-plane rebuild;
- control-database integrity failure, online backup and clean-node restore;
- node add/replace/quarantine;
- user onboard/offboard/emergency suspend;
- Mesh device approve/revoke and LAN-only recovery;
- Coolify server reconnect and application rollback;
- backup failure, local restore and R2 disaster restore;
- ES216G config restore and loop isolation;
- CI runner drain/re-register;
- 1Password service-account rotation;
- Harbor restore and later clean migration cutover.
