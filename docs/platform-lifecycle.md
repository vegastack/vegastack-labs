# Portable product lifecycle

Status: requirements reconciled from user confirmations on 26-08-2026. This is the canonical generic lifecycle contract, not a report of implementation, phase/batch approval or live authority. [Architecture boundary](../README.md#architecture-boundary) · [Control engine](control-plane-service.md) · [Development roadmap](development/roadmap.md)

## Product, profile and support

`vsk-labs` is the OSS product; VegaStack Labs is one deployment using it. Product setup selects a supported control host, never a hard-coded node number. The Labs profile binds that role to `vsk-node-04`; its hardware, domain, accounts, topology, capacity and policies do not become core prerequisites. Preserve the four existing layers: core, typed adapter, optional capability and deployment profile. An installed adapter does not enable a feature, and selecting a profile grants no authority.

Basic management of supported reachable SSH nodes must require no third-party account: local setup, individual operator authentication, inventory/enrollment, plans, human approvals, Ansible execution, verification, audit, credential revocation and documented recovery must work without Cloudflare, Workspace, 1Password, GitHub or other account enrollment. This does not promise air-gapped dependency installation, automatic OS provisioning, arbitrary provider support, or an unauthenticated web UI. Provider-dependent operations explicitly name their required capability and supported adapter.

Keep the [existing support matrix](automation-and-agents.md#os-and-architecture-support-matrix). A single supported control host with zero managed nodes is a valid initial installation. Arbitrary control/application/CI colocation, unsupported OS/architecture combinations, multiple active controllers, automatic HA and a multi-tenant hosted control service are not implied. Hardware/virtualization kinds require tested profile support; a provider-neutral identity schema alone does not qualify a new environment.

### Minimum capability matrix

| Capability | Required inputs | Behavior without third-party accounts |
|---|---|---|
| Local setup, read/plan/approve/apply and recovery | Trusted local administrator; supported signed release/OS; protected local service and applicable recovery preconditions | Required v1 path through OS peer authentication and the same engine. |
| Remote operator CLI | Approved individual SSH public key/device grant; independently pinned control identity; reachable declared endpoint | Required v1 constrained SSH transport for the versioned API, including reads and planning, not only apply. No general command shell is exposed by that transport. |
| Supported managed SSH node | Verified node/host-key identity; scoped automation access; protected local credential resolver; qualified OS/role | Required v1 central Ansible path. No mandatory node binary or resident privileged agent. |
| Local credential resolution/rotation/recovery | Native protected storage, explicit consumers and recoverable key custody | Required v1 resolver; secret values remain outside SQLite, declarations, plans, logs and prompts. |
| Backup and audit recovery | Declared encrypted local/independent destination, capacity and recoverable keys | Local supported backup path requires no cloud account. Same-host copies alone do not satisfy node-loss recovery or independent audit-checkpoint requirements. |
| Browser Console | A qualified cryptographically authenticated browser ingress/session adapter | CLI operation never depends on browser availability. Without a configured supported browser adapter, Console is unavailable with a clear reason; no password database or unauthenticated bypass is added. |
| Hosting, registry, CI, remote overlay, cloud backup and notifications | Explicit policy enablement plus a supported configured adapter and its gates | Only those features require their providers; absence leaves applicable core workflows usable. |

The base local credential resolver is an OS-profile implementation, not a new general secrets manager. On the supported Debian control profile, qualify native systemd encrypted service credentials for persistent host-bound material and restrictive runtime delivery to the service. Persist only opaque references in SQLite; import/generate/rotate via an approved plan and protected input, never CLI secret arguments or printed output. Pin the actual supported systemd behavior in the implementing issue. Host-key encryption protects access but does not claim resistance to root or whole-disk theft when the host key is on the same disk. Do not silently require TPM hardware. Independent encrypted recovery must include what is needed to recover/re-encrypt onto a new host without copying its old execution authority; prove this before node-loss readiness. If qualification fails, the affected implementation issue must return a concrete local resolver design, not silently require 1Password. [systemd credential contract](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd-creds.xml)

## Identity and configuration

Core nodes have immutable logical IDs, verified SSH/access identities and typed provenance. Physical serial, cloud/VM instance identity and installation identity are distinct evidence kinds with explicit issuers/scopes. Serial uniqueness is mandatory only where the selected physical inventory policy requires it; do not fabricate serials for virtual hosts or treat a hostname/IP as identity. Reimage, cloning and replacement require the existing approved binding-change procedure. Names and role aliases are separate; changing a role never silently transfers a person's/device's authority.

A versioned profile supplies validated policy defaults and supported adapter selections; private site declarations supply actual resource bindings and explicit overrides. Resolution order is product safety/support constraints, selected versioned profile defaults, then authorized site declarations within those constraints. The resolved values and provenance are visible in plans. Profile updates produce inert revisioned changes; they never apply infrastructure, enable features, grant permissions or weaken retention automatically. Unknown fields, unsupported capabilities and conflicting ownership fail validation.

Each gate has a stable scoped identity/version, owning layer, subjects, applicability predicate and prerequisites. Core safety gates cannot be bypassed by profile choice. Inapplicable adapter/profile gates display `not-applicable` with the derived reason; this is not a passed evidence result. Enabled-but-unproven requirements remain blocked. Evidence and approvals bind the relevant resolved profile/policy version and existing recovery epoch. The Labs G-001–G-023 catalog is not a mandatory checklist for other sites.

## Guided setup and the initial authority

The guided interface offers create-control-plane, connect-operator, enroll-node, and resume/recover journeys through generated metadata. Exact command spellings are finalized in phase 1; a wizard is a client of the existing change/plan/apply engine, never a second mutation grammar. Noninteractive calls require complete typed inputs and explicit authorization; missing input never means automatic yes. CLI, Console and agents receive equivalent plans and errors.

### Local control-plane creation

1. Inspect the selected machine, supported OS/release, installation identity, existing database/service state, privileges, time, disk, dependencies and recovery access. Verify the signed release. An existing or ambiguous installation takes resume/recovery/adoption; never silently reinitialize it. A scan cannot prove a compromised OS clean. Initial OS trust and any reimage decision remain human prerequisites.
2. The administrator nominates this host from a trusted local console, or an already verified SSH session with a usable recovery path. Bind the responsible human and verified OS identity; do not trust an arbitrary email, agent assertion, environment variable or first web visitor. Show the finite initial installation plan and obtain human acknowledgement.
3. Before SQLite exists, the same engine uses one protected, one-use installation manifest containing the approved host/release/administrator binding, exact minimal operations, progress and audit handoff. A narrowly scoped installation step establishes the service identity, protected paths, authenticated local socket and OS service entry. This is the sole pre-database exception, limited to this host and this manifest, not a generic offline executor. Only `vsk-labs server run` initializes/opens writable SQLite. Use exclusive initialization, ownership/path checks and transactional manifest consumption; a crash never creates two authorities or loses the original approval trail.
4. Start the unprivileged persistent service with local authenticated access only. It imports the bootstrap records and disables further use of the manifest as authority. The same local CLI now calls its API. No external account, public DNS, Mesh pilot, external browser ingress or whole-fleet inventory import is required merely to start this restricted local service.
5. Through separate current plans, establish local hardening, credential resolution, backup/key recovery, inventory and the selected capabilities. Ansible owns host configuration; approved elevation is bounded to the declared work. No root server, broad convenience sudo grant or privileged AI/node agent is introduced. Before risky SSH/firewall changes, arm recovery independent of the executor session.
6. Verify each readiness capability independently. A running local service is not control acceptance, host workload admission or site readiness. The wizard reports remaining evidence, manual prerequisites and next permitted action without declaring a broad success.

### Preparation versus activation

| State/capability | What is allowed | What remains blocked |
|---|---|---|
| Uninitialized | Read-only preflight and the explicitly acknowledged finite local installation manifest | Fleet changes, external provider credentials, public ingress and workload admission. |
| Local setup service | Authenticated local inspection/planning; exact local hardening, credential and recovery setup plans | Unrelated fleet work and any claim of recovery or security qualification not yet proven. |
| Foundation preparation | Individually approved discovery/bootstrap/hardening of identified foundation nodes once control identity, scoped credentials, retained access and operation-specific recovery are verified | User workloads, CI and broad provider authority until their security/role gates pass. This is not a skip-gates mode. |
| Qualified capability | Only operations whose current OS/role, identity, privilege, recovery and adapter evidence passes | Other capabilities remain visibly pending, even if the local service is healthy. |
| Site accepted | All applicable deployment acceptance including independent probes/restores and actual pilot evidence passes | Nothing gains authority merely from the status; every subsequent mutation still needs its plan/policy branch. |

A local file backup may protect a reversible configuration step but cannot certify independent recovery. When no second probe/restore target exists yet, retain those acceptance blockers and permit only the bounded preparation needed to establish them. Identify that dependency in the plan; do not substitute localhost probes for external denial tests. In the Labs profile the early local setup is followed by scoped LAN/foundation preparation, the actual Mesh pilot and control/site qualification. The full software must still be complete before the first live onboarding rehearsal.

### Interruptions and controller self-management

Durable run events and observed postconditions decide what happened. Re-running setup queries that state; it never blindly repeats a provider mutation, resets an admin or reinstalls a database. Unstarted plans expire after the existing 30 minutes. A run begun in time may retain its identity only under the documented same-epoch resume rule; changed facts, privileges, scope or epoch require a new plan. Revoke the human/device and continuation must stop.

Controller-local Ansible is an explicit OS-profile execution mode for approved control-host configuration; other nodes retain SSH/Ansible. Its invoking identity and actual privilege boundary must be proven, not inferred from a sudo command list. Ansible's local connection does not use a remote-user setting, and its reboot action refuses local-controller reboot. Controller reboot/upgrade therefore checkpoints the exact run and boot identity, schedules the approved OS action, starts the existing service after boot, verifies persistence/health and reauthorizes continuation. Never implement it by pretending localhost is an independent remote executor. [Ansible local connection](https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/local_connection.html) · [reboot action](https://raw.githubusercontent.com/ansible/ansible/stable-2.19/lib/ansible/plugins/action/reboot.py)

Disk-full, corrupt database, unknown schema or missing recovery material produces a visible recovery state, not automatic initialization. Access rollback uses the native OS timer/service facility and survives the failed session; local console recovery remains necessary when the OS cannot boot or networking is irrecoverable. No operator machine self-promotes when control is unavailable.

## Operator and managed-node enrollment

**Operator:** install a supported client, verify the selected instance through a trusted channel, authenticate an individual identity, and obtain explicit device/person scopes. Local OS-peer and constrained SSH identities map to the same effective grants as external identities. Store client material using the existing OS credential abstraction. Invitations are short-lived, single-use and bound to instance/device/intended scope; possession alone cannot grant administrator status. Never copy SQLite, fleet keys, provider tokens or another user's AI login. Different devices are separately revocable.

**Managed node:** from control, inspect an explicitly authorized reachable target, bind node/provenance/SSH identity, select a supported role and plan minimal bootstrap access, Ansible hardening and qualification. An optional local `vsk-labs` enrollment helper can verify the controller and present evidence, then exit; it grants no persistent privileged agent or self-selected role. Missing Python/SSH, unknown host key, offline host and Mac consent are explicit prerequisites, not assumed success. Operator enrollment and managed-node enrollment are separate even on one device.

Unsupported OS/provider/role combinations are rejected before mutation. A physical host and a qualified VM may use different identity evidence; verification must match the actual profile. Existing services remain observation-only until an import plan establishes one owner and explains every change. No full provider account is adopted merely because one service was imported.

## Effective authority and revocation

Desired declaration revisions remain inert. Authorization, timers and capability admission consult only the effective policy/grant/profile state, never a proposed row. A change is authorized under the prior effective authority and cannot authorize itself. Persist the desired/applied/effective distinction and partial outcomes. Expansion becomes effective only after the approved transition and required verification; approved denials become effective at their declared containment boundary and are not undone merely because another target failed. Read scope permits inspection/preview without committing intent; committing a draft/plan requires author scope.

Offboarding enumerates independently authenticated local and configured application/provider accounts, keys and sessions, including active sessions rather than only future logins. Use existing scoped adapters or an assigned human/app owner; do not acquire extra privileges for Harbor or another application. Persist every unresolved revocation. An approved offboarding plan may include bounded isolation, preserving administrator recovery access; an unreachable target remains uncontained/pending until verified. Reconnect requires reconciliation before readmission. Routine secret rotation may preserve a healthy old credential, but an approved compromise-containment decision takes precedence and must never be rolled back to regain availability.

### Human acknowledgement trust boundary

An OS UID, SSH key or cached browser session proves an authenticated account, not whether a human or an agent sharing that account made the request. Agent/session labels, a TTY and a typed yes are not human-presence proof. This limitation applies to Codex/Claude as well as Hermes, including the initial installation acknowledgement. Never label those mechanisms alone as server-enforced prevention of agent self-approval.

Delegated agent credentials have no acknowledgement scope. Where ordinary account credentials are available to an agent, human acknowledgement additionally needs a separately protected human action/proof unavailable through those credentials, bound to the exact plan/installation manifest, targets, expiry and recovery epoch. Replaying a login or an old acknowledgement is insufficient. The server rejects missing/unqualified proof rather than accepting self-reported actor type. An approved exact-policy run remains its separate branch, never a human impersonation.

0.3 must select and obtain solution approval for a feasible account-free approval UX and explicit threat assumptions before phases 3–4 implement this boundary. A separate OS approval identity/session or an independent approval channel is a candidate to qualify, not a claim that another window under the same UID is isolated. Do not infer a mandatory hardware key, vendor account, new password database or privileged managed-node agent. Initial trusted-console use and recovery must fit that same reviewed boundary. Until qualification passes, the affected human apply path is unavailable; fixtures may not masquerade as a shipping fallback.

Acceptance runs an adversarial process with every ordinary credential available to the coding agent: local/SSH/browser acknowledgement attempts, omitted/forged agent context and replay must fail without the separately protected human action. A real human must still approve the exact plan with no third-party account; a changed digest, target, expiry or epoch invalidates the proof.

## Recovery and retained dependencies

A recovery point includes its required release/schema, configuration, images/digests/signatures, data consistency method, key references and independent verification history. Preserve those dependencies while the point or rollback promise is retained; the active-plus-two binary cache does not cap the recovery archive. Block unsafe garbage collection or surface a capacity decision instead of silently breaking the recovery promise.

When restoring behind an independent audit checkpoint, recover and verify the missing audit suffix where possible, without replaying its provider mutations. Otherwise require explicit human acceptance of a named lost interval and create a new recovery segment anchored to the prior independent checkpoint and recovered database hash. Preserve both histories; never reuse sequence identities ambiguously or overwrite the newer export. Invalidate old plans/sessions, revalidate grants and fence the former instance before restoring mutation authority. A mismatch without this authorized continuity procedure stays read-only.

For backup adapters, mutable coordination objects and retained payload dependencies are distinct. Qualification must prove refresh/unlock/stale-lock behavior, concurrent exclusion and payload protection for the full lifetime of retained points, including deduplicated older objects. The selected restic/R2 candidate is not design-closed until a compatible permission/retention layout is proven. If it cannot meet the agreed safety contract, return a concrete alternative for review; never broaden writer payload deletion, disable locking or silently shorten retention. Exact site resources and real integration evidence remain later gates.

## Disable, detach, replace and uninstall

These are different operations. Disabling a capability stops new work but does not delete resources or revoke credentials still needed by active work/recovery. Before disconnecting an adapter, enumerate dependencies, drain or stop runs, identify retained recovery dependencies, transfer explicit ownership and preserve a human recovery path. Unavailable/unsupported migration becomes a blocker with a documented handoff, not invented conversion. Revoke only platform-owned scoped credentials and verify denial.

Default product uninstall preserves application data, externally managed workloads, audit and recovery artifacts; it removes only the explicitly selected owned installation components after a reviewed plan and handoff. Destruction requires its own target list, recovery preconditions and stronger confirmation. Local account offboarding preserves homes per policy. Physical custody, media sanitization/destruction, repair handoff and disposal are outside product scope; logical inventory and credential retirement remain included.

## Public build and generic experience

The chosen VegaStack Design System and product branding remain. Ordinary public checkout builds and tests must require no VegaStack private account, registry token or access to its private network. Declared public dependency downloads are allowed; this is not an air-gapped build promise. Use approved redistributable pinned component source/public dependencies; validate distribution rights before publishing. Authenticated maintainer component refresh and protected release/integration jobs are separate from public contributor checks. No fork receives private credentials or official signing authority.

Views describe nodes, hosting resources, identity bindings and capabilities; adapter views may show provider-specific detail. Distinguish empty, unconfigured, disabled, unsupported, unhealthy, stale and policy-blocked. A basic installation with zero nodes and no optional adapters must provide a useful next action, not simulate integrations or render an outage. A second synthetic deployment uses different identities, names, size and applicable policy values without changing core code. It tests portability; it is not evidence for an unimplemented production provider.

## Acceptance and phase ownership

Each issue identifies its layer, generic behavior, adapter-specific behavior, selected Labs values, unsupported cases and required evidence. Required scenario coverage is:

| Journey/fault | Required outcome |
|---|---|
| Fresh supported host, no accounts/domain/other nodes | Restricted local control initializes, owns SQLite once and offers account-free SSH management with exact pending gates. |
| Wrong OS/host, existing installation or cloned identity | Reject or route to explicit adoption/recovery; no reset, fake serial or second authority. |
| Concurrent setup, first-admin race, bad paths or tampered manifest | One authenticated initialization; deny takeover, symlink/environment substitution and stale bootstrap reuse. |
| Missing privileges/dependencies, package locks or offline downloads | Bounded retry/prerequisite report; no unsigned installer, convenience sudo or false success. |
| Power loss, terminal loss or lost provider response at each step | Recover truthful durable state; re-observe ambiguous effects; no duplicate mutations or dropped audit. |
| Controller reboot/upgrade or failed firewall/IP change | Durable self-management and independent access rollback; new boot and permitted/denied paths verified. |
| Corruption, full disk, old backup or returning old controller | Safe mode, anchored audit recovery and external credential/network fencing before cutover. |
| Expired plan, revoked approver, changed profile or scope | Current authorization and epoch checks stop unauthorized continuation; desired edits do not activate. |
| No independent probe/restore target, missing backup key or provider | Precise pending capability; only scoped preparation, never invented qualification. |
| Operator invite replay/lost device; node reimage/offline/Mac consent | Bound enrollment, denial/revocation and explicit remaining prerequisites; no resident privileged agent. |
| Different topology, identifiers/timezone, no managed router or no integrations | Core code unchanged; only applicable profile/adapter gates run; unsupported capabilities fail clearly. |
| Disable/detach/uninstall with active work and retained recovery points | Dependency-safe handoff, no unrequested deletion or unrelated revocation; artifacts remain recoverable. |
| Ordinary rotation versus suspected compromise | Health-preserving routine compensation cannot undo approved containment. |
| Actual CI job differs from trigger-approved job | Admission validates actual assigned identity before user steps/secrets, including concurrent-job race tests. |
| Local/SSH/Console/agent and public fork | Same plan/denial contracts; no self-approval; public build works without private credentials. |

0.3 owns generic bootstrap, profile/applicability and local identity contracts; 0.4 owns hardening/privilege boundaries. Phases 1–5 implement metadata, API/state, effective authorization, local secret resolution, gate evidence, backup/audit and recovery; 6–7 implement host/operator enrollment and access; 8–10 implement application/CI/maintenance and safe exit; 11 proves the integrated supported matrix before any lab rehearsal. Missing real OS, provider or recovery proof cannot be replaced with fixtures. Requirements approval does not publish an issue or grant a development batch/live permission. [Readiness distinctions](development/roadmap.md#implementation-readiness)
