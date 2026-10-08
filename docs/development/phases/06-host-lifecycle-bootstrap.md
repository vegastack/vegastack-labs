# Phase 6 — Host lifecycle and control-plane bootstrap

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


Issue 6.3 solution approved on 07-10-2026 against `b9074cc675a7862b0878c60ef8ec135bc91ebabb`. This records the approved 6.3 development batch; it grants no operational authority.

## Working-first registration delivery — 08-10-2026

The operator approved reduced briefs and concrete plan v2 for [#222](https://github.com/vegastack/vegastack-labs/issues/222) and [#232](https://github.com/vegastack/vegastack-labs/issues/232). Issue #222 extends the existing API and plan/acknowledgement/run engine with one `host.adopt` database effect and an `adopted-unadmitted` read projection. The immutable plan includes the administrator's exact identity/target confirmation in JSON and readable form. There are no new signing systems, services, host-side actions or admission claims.

Issue #232 consumes these contracts after #222 integration. Other Phase 6 implementation remains deferred under the simplicity mandate. Registration tests cover synthetic identity, stale/current grants, exact approval/lease binding, duplicates, audit rollback and unchanged admission state. Isolated Linux software integration requires its own explicit environment approval; it does not qualify a real OS baseline or authorize fleet onboarding.

## Destination and existing decisions

Implement a portable path from a named untrusted candidate to separately approved, verified host admission, role installation, control-plane bootstrap and recovery. One `vsk-labs` executable, server-owned SQLite, central typed adapters/Ansible, and the existing exact-plan acknowledgement/executor remain controlling. Discovery cannot prove hardening or apply quarantine. D-123 and D-126–D-130 govern privilege, Debian enforcement and disposable qualification. Mac mini/iMac remain required within v1 in a later Phase 6 batch; Ubuntu remains parked. Complete v1 precedes the first fleet onboarding rehearsal.

## Ownership map

These are development IDs, not permission to create or execute every future issue. Preserve already published references. The earlier 6.3 batch below is historical. The separately approved working-first batch on 08-10-2026 is #222 database registration followed by #232 CLI integration; expanded hardening/recovery work stays deferred.

| ID | Outcome / dependency |
|---|---|
| 6.1 (#213) | Completed inert identity/profile/role/fact contracts; both host gates deferred. |
| 6.2 (#214) | Completed Debian design research and disposable-test strategy, merged through #216. |
| 6.3 (#217) | Bounded Debian discovery, private observations and explicit blockers; approved target-authorization prerequisite below. |
| 6.4 | Proposed ownership of host adoption and privileged exact-action foundation; depends on discovery and its accepted identity contracts. |
| 6.5 | Preserve published Debian enforcement/profile qualification ownership. |
| 6.6 | Reserved proposed Mac mini/iMac enforcement owner, later batch within v1. |
| 6.7 | Preserve published allowed/denied, reboot/idempotence, controller-loss and local rollback qualification ownership. |
| 6.8 | Preserve host hardening/admission gate owner; binds actual applied evidence, never discovery alone. |
| 6.9 | Preserve role/service installation and post-install qualification ownership. |
| 6.10 | Proposed control-plane bootstrap and operator node workflow owner; consumes the same server services. |
| 6.11 | Proposed replacement/reimage recovery owner; reconcile exact boundary with bootstrap before its batch. |
| 6.12 | Preserve integrated host/role/recovery acceptance owner; depends on every contributing Phase 6 delivery including Mac. |

No existing downstream issue is renumbered. Exact briefs for later batches require their own planning and approval. Scope overlaps in proposed 6.4/6.10/6.11 must be closed before those batches, not guessed during 6.3.

## Approved current batch: 6.3 only

The approved brief identified one additional security decision, approved by the operator: the server currently has no host-discovery target binding that establishes which endpoint/key/credential it may use. Inventory drafts and schema-valid host identities cannot grant that authority.

Approved: include a private, revisioned discovery-target binding in 6.3. An inert draft identifies exactly one literal IP/port, non-root SSH user, independently verified public host key, credential reference/version, expected OS/architecture and optional existing inventory reference. Activation/replacement/revocation use the existing exact-plan flow and control-plane-admin human acknowledgement, as required by the existing role matrix for control-plane risk. Activation changes only the control database; it performs no SSH, credential import, host adoption or host mutation. Discovery uses only an active binding and a current per-target grant. Merely importing inventory or editing a declaration never enables a connection.

Alternative: deliver this target-binding foundation separately before 6.3. This reduces each review's size but needs another approved issue and integration step. Do not implement an insecure shortcut accepting addresses/keys from discovery requests or a profile file as independent authority.

Use a dedicated typed SSH collector, not the operator-to-server SSH transport. Recommend directly using the already pinned `golang.org/x/crypto` version (currently indirect), with an in-memory credential lifetime and pinned public-key comparison. Direct use becomes a reviewed dependency, with provenance refreshed through the existing owner. No dependency upgrade, new service or privileged component is proposed.

## Proof and rollout boundary

6.3 uses synthetic loopback SSH peers, temporary SQLite and deterministic adapters. Native Debian behavior remains unqualified until separately authorized disposable testing under D-130. Neither CI availability nor a recorded fleet address authorizes discovery against that host. Public routine CI uses the existing approved pool; CI must not discover or alter its runner. Both host gates remain deferred until 6.8.

The later phase exit must demonstrate approved enrollment, denied unsupported/stale/partial evidence, exact role admission, repeat/idempotence, recovery and replacement, and native qualification of the full v1 matrix. 6.12 owns integration evidence; Phase 11 still owns final supported-matrix acceptance. Do not close Phase 6 after Linux discovery.

## Approval record

- (omkarmohanta09), 07-10-2026: approved #217 brief v1 and requested planning then implementation.
- 6.3 phase solution, target activation boundary and plan approved in issue comment 6036497058. Coordinator: Codex in this conversation.
- PR creation, merge, deployment, actual-host collector qualification and new credentials retain separate authority. The operator permits scoped read-only infrastructure inspection, but no real-machine changes; 6.3 verification uses only isolated fixtures. No live targets are named or approved by this document.

## Implementation qualification status

The database-only target effect uses the existing core run-effect router, including persisted plan/run/step/lease and consumed acknowledgement checks. It requires a recovery verifier; production uses the existing unavailable verifier until that prerequisite is qualified. The discovery credential consumer likewise has no automatic production resolver registration. Both fail closed. Test fixtures explicitly supply synthetic recovery/profile/credential proofs and a loopback SSH peer; no actual host account or command execution is qualified here. The operator separately approved starting/stopping the workstation-local `vsk163-custody` VM for isolated Linux tests on 07-10-2026; this is not cluster or fleet authority.

## Working-first CLI delivery

Issue [#232](https://github.com/vegastack/vegastack-labs/issues/232) activates only `node discover`, `node add` and `node inspect`. Their typed clients use the existing local or constrained SSH operator transport, with exact route/command bindings and unchanged server grants. Discovery still needs an activated exact target and qualified existing prerequisites. Add prepares a database-only draft; the existing plan/acknowledgement/apply flow registers it as `adopted-unadmitted`. Inspect reads the database and makes no host connection. The generated registry keeps all other node/control-plane lifecycle commands planned.

Verification uses a built Linux executable, a temporary server database and synthetic loopback SSH peer; the human acknowledgement adapter is a fixture. No fixture qualifies live discovery, host security, workload admission or Phase 6 completion. The standing shipping instruction permits PR/merge/continuation for this approved Linux working-first batch after its exact local proof and independent review. Shared CI remains suspended; infrastructure and releases retain separate approval.
