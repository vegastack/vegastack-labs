# Phase 6 — Host lifecycle and control-plane bootstrap

Issue 6.3 solution approved on 07-10-2026 against `b9074cc675a7862b0878c60ef8ec135bc91ebabb`. This records the approved 6.3 development batch; it grants no operational authority.

## Destination and existing decisions

Implement a portable path from a named untrusted candidate to separately approved, verified host admission, role installation, control-plane bootstrap and recovery. One `vsk-labs` executable, server-owned SQLite, central typed adapters/Ansible, and the existing exact-plan acknowledgement/executor remain controlling. Discovery cannot prove hardening or apply quarantine. D-123 and D-126–D-130 govern privilege, Debian enforcement and disposable qualification. Mac mini/iMac remain required within v1 in a later Phase 6 batch; Ubuntu remains parked. Complete v1 precedes the first fleet onboarding rehearsal.

## Ownership map

These are development IDs, not permission to create or execute every future issue. Preserve already published references. Only 6.3 is the approved current implementation batch.

| ID | Outcome / dependency |
|---|---|
| 6.1 (#213) | Completed inert identity/profile/role/fact contracts; both host gates deferred. |
| 6.2 (#214) | Completed Debian design research and disposable-test strategy, merged through #216. |
| 6.3 (#217) | Bounded Debian discovery, private observations and explicit blockers; proposed target-authorization prerequisite below. |
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

Approved: include a private, revisioned discovery-target binding in 6.3. An inert draft identifies exactly one literal IP/port, non-root SSH user, independently verified public host key, credential reference/version, expected OS/architecture and optional existing inventory reference. Activation/replacement/revocation use the existing exact-plan flow and infrastructure-admin human acknowledgement. Activation changes only the control database; it performs no SSH, credential import, host adoption or host mutation. Discovery uses only an active binding and a current per-target grant. Merely importing inventory or editing a declaration never enables a connection.

Alternative: deliver this target-binding foundation separately before 6.3. This reduces each review's size but needs another approved issue and integration step. Do not implement an insecure shortcut accepting addresses/keys from discovery requests or a profile file as independent authority.

Use a dedicated typed SSH collector, not the operator-to-server SSH transport. Recommend directly using the already pinned `golang.org/x/crypto` version (currently indirect), with an in-memory credential lifetime and pinned public-key comparison. Direct use becomes a reviewed dependency, with provenance refreshed through the existing owner. No dependency upgrade, new service or privileged component is proposed.

## Proof and rollout boundary

6.3 uses synthetic loopback SSH peers, temporary SQLite and deterministic adapters. Native Debian behavior remains unqualified until separately authorized disposable testing under D-130. Neither CI availability nor a recorded fleet address authorizes discovery against that host. Public routine CI uses the existing approved pool; CI must not discover or alter its runner. Both host gates remain deferred until 6.8.

The later phase exit must demonstrate approved enrollment, denied unsupported/stale/partial evidence, exact role admission, repeat/idempotence, recovery and replacement, and native qualification of the full v1 matrix. 6.12 owns integration evidence; Phase 11 still owns final supported-matrix acceptance. Do not close Phase 6 after Linux discovery.

## Approval record

- (omkarmohanta09), 07-10-2026: approved #217 brief v1 and requested planning then implementation.
- 6.3 phase solution, target activation boundary and plan approved in issue comment 6036497058. Coordinator: Codex in this conversation.
- PR creation, merge, deployment, actual-host collector qualification and new credentials retain separate authority. The operator permits scoped read-only infrastructure inspection, but no real-machine changes; 6.3 verification uses only isolated fixtures. No live targets are named or approved by this document.
