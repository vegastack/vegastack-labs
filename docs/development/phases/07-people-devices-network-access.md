# Phase 7 — People, devices, identity and network access

Status: development started 23-10-2026. This is an implementation map, not live authority or completed acceptance. Phase 6 accepted deferrals remain deferred. Nodes04/05 are excluded from all operations, including reads and indirect effects.

## Small delivery order

| Slice | Issue | Outcome | Dependency / present status |
| --- | --- | --- | --- |
| 7.1 Platform users | [#269](https://github.com/vegastack/vegastack-labs/issues/269) | Onboard, suspend, resume and offboard through existing exact plans; invalidate access/sessions | Implemented; native Linux lifecycle/migration and approved API workflows passed; landing in progress |
| 7.2 Operator devices | [#270](https://github.com/vegastack/vegastack-labs/issues/270) | Request, approve, revoke a device bound to an active human | Depends on 7.1; transport binding must be explicit in its implementation plan |
| Pilot browser access | [#264](https://github.com/vegastack/vegastack-labs/issues/264) | Authenticated real Console at the selected hostname | Cloudflare permissions and exact ingress/identity inputs pending; existing issue retained |
| 7.3 Network implementation map | [#271](https://github.com/vegastack/vegastack-labs/issues/271) | Ground remaining LAN/Mesh/edge/identity slices before implementation | Source and official documentation research; no provider changes |

These issues do not represent all Phase 7 acceptance as complete. The phase milestone stays open until the implemented scope and explicit remaining decisions are reconciled with the roadmap.

## Reuse and boundaries

Use one existing executable, server-owned SQLite, local/SSH identity adapters, grants, canonical declaration/plan/acknowledgement/run flows and generated clients. No new login framework, service, worker or approval mechanism. Onboarding a platform human does not provision a Workspace or OS account. Device revocation inside the controller does not prove deletion of an external provider registration or termination of an already established OS shell.

The existing Cloudflare Access adapter verifies external identity; the browser session and authorization layers decide controller access. A Slack approval identity does not automatically establish a browser login mapping. The selected public Console origin is `https://labs.vegastack.dev`; this does not silently rename historical private inventory suffixes.

## User lifecycle implementation

Extend the existing authorization grant batch with a bounded lifecycle action. Draft creation remains inert. Onboard creates an absent human with no implicit grants or authentication binding. Suspend denies the principal while retaining explicit grants; resume reactivates only the retained grants and never restores old sessions. Offboard is terminal, preserves history and revokes grants, external bindings and sessions. Reject self-directed lifecycle changes and loss of the final active administrator. Repeat current identity, revision and authorization checks at execution.

Existing principal tables require a distinct suspended state; do not implement resume by undoing permanent revocation. Preserve existing rows, foreign keys, terminal-state triggers, recovery preimages and audit attribution. Required evidence includes inert drafts, allowed transitions, denied unauthorized/stale/terminal transitions, session invalidation and denied subsequent mutation. Native Linux evidence for this slice includes four lifecycle/migration cases and seven approved API workflow variants, executed in a disposable local Debian ARM64 VM. A cross-build alone is not native execution evidence.

## Remaining network slices and evidence

| Slice | Work possible without account access | Prerequisites before live execution | Completion evidence |
| --- | --- | --- | --- |
| LAN/Mesh path selection | Deterministic selector against declared endpoints and synthetic marker/provider observations | Approved reservations, host identity, device state; G003/G013 where applicable | Valid LAN selection, remote fallback, wrong host/revision denial, outage/manual fallback |
| Managed-network detection | Bounded TLS marker validation and timeout behavior | Explicit marker host/port/certificate owner and rotation; no excluded host | Correct fingerprint, stale/wrong marker denial, timeout fallback; no remote reachability masquerading as LAN |
| Mesh device adapter | Pin typed provider operations and test read/reconcile failures with fixtures | Account/API scope, approved device/owner mapping, policy and enrollment scope; applicable G005/G016 evidence | Request stays quarantined, exact binding, allowed/denied flows, revoke/re-registration, failed reconciliation remains unavailable |
| Access/Tunnel ownership | Reuse existing Access verification; define exact owned resources and partial-failure behavior | Account/zone, connector placement, credential scope, origin TLS and user mapping; G012/G016 resolution | Authenticated/denied browser requests, direct-origin denial, connector failure, scoped rotation and rollback |
| Optional Workspace binding | Define immutable external-subject mapping through existing identity boundaries | Existing organization subject and owner-approved credential/read scope | Mismatched/removed subject denied; provider outage does not disable local authorized operation |
| Operator/mobile guidance | Document enrollment pending/approved/revoked and manual fallback states | Actual supported client/version and enrolled identity for any live demonstration | User can identify pending/denied state; recovery procedure matches actual implemented path |

Account-specific adapter operations must be verified against official API documentation before writing requests. This map does not invent API fields, provider credentials or an automatic account provisioning flow. Router/switch changes remain guided and separately scoped; no arbitrary subnet discovery or automatic public port forwarding.

## Verified provider facts — 23-10-2026

- Tunnel uses outbound connector connections and does not require a publicly routable origin IP. Tunnel transport and Access login are distinct responsibilities. [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/)
- Mesh client traffic is governed by Gateway network policies; the documented default device IP range is `100.96.0.0/12`, with custom ranges possible. Include-mode policy must route the actual selected Mesh range. Enrollment alone is not evidence that Mesh traffic works. [Mesh clients](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-mesh/guides/connect-client-devices/)
- Managed-network detection validates a TLS endpoint; Cloudflare documents fallback to the default profile after a five-second timeout. The endpoint must not be reachable remotely as a false location signal. Certificate fingerprint handling must follow the actual provider contract; do not confuse a whole-certificate fingerprint with SPKI. [Managed networks](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/configure/managed-networks/)

## Pilot blockers versus full qualification

Browser issue #264 still needs the Cloudflare account/zone and permissions, existing tunnel ownership or explicit connector selection, Access issuer/audience/login choice, exact origin bind/port/TLS trust, and the external subject mapped to the current human. DNS permissions alone are insufficient for those configurations. No provider or host is selected implicitly by this document.

The historical G012 multi-connector qualification contract cannot be reported as satisfied by a single local pilot. Resolve its applicability or an explicit bounded pilot exception before deployment; do not expand the pilot into unrelated hardening. Similarly, the existing G005 long-duration Mesh qualification is separate from software fixture acceptance and is not a prerequisite to develop user/device lifecycle. No test may claim full live qualification from mocked provider results.

## Verification and tracking

Issue comments carry the current plan, ledger and evidence. Only focused affected tests run during implementation; required generation and affected-branch checks remain at shipping. No redundant independent review rounds are added under the operator's simplicity instruction. Missing native runtime evidence is recorded explicitly. Public repository records contain schemas, synthetic examples and sanitized outcomes; private operational values and credentials stay outside Git.
