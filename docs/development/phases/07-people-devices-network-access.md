# Phase 7 — People, devices, identity and network access

Status: development started 23-10-2026. This is an implementation map, not live authority or completed acceptance. Phase 6 accepted deferrals remain deferred. Nodes04/05 are excluded from all operations, including reads and indirect effects.

## Small delivery order

| Slice | Issue | Outcome | Dependency / present status |
| --- | --- | --- | --- |
| 7.1 Platform users | [#269](https://github.com/vegastack/vegastack-labs/issues/269) | Onboard, suspend, resume and offboard through existing exact plans; invalidate access/sessions | Merged in [PR #273](https://github.com/vegastack/vegastack-labs/pull/273); native lifecycle/migration and approved API workflows passed |
| 7.2 Operator devices | [#270](https://github.com/vegastack/vegastack-labs/issues/270) | Request, approve, revoke a device bound to an active human | Implemented for protected local/SSH device attribution; native lifecycle and existing-connection denial checks passed; landing in progress |
| 7.4 Browser identity binding | [#272](https://github.com/vegastack/vegastack-labs/issues/272) | Link an existing verified browser identity to an existing human through approved plans; revoke only its sessions | Implemented through existing grant-batch plans; native binding/session and integrated API workflows passed; no provider changes |
| Pilot browser access | [#264](https://github.com/vegastack/vegastack-labs/issues/264) | Authenticated real Console at the selected hostname | Cloudflare permissions and exact ingress/identity inputs pending; existing issue retained |
| 7.3 Network implementation map | [#271](https://github.com/vegastack/vegastack-labs/issues/271) | Ground remaining LAN/Mesh/edge/identity slices before implementation | Research complete; findings and unresolved live inputs recorded below; no provider changes |

These issues do not represent all Phase 7 acceptance as complete. The phase milestone stays open until the implemented scope and explicit remaining decisions are reconciled with the roadmap.

## Reuse and boundaries

Use one existing executable, server-owned SQLite, local/SSH identity adapters, grants, canonical declaration/plan/acknowledgement/run flows and generated clients. No new login framework, service, worker or approval mechanism. Onboarding a platform human does not provision a Workspace or OS account. Device revocation inside the controller does not prove deletion of an external provider registration or termination of an already established OS shell.

The existing Cloudflare Access adapter verifies external identity; the browser session and authorization layers decide controller access. A Slack approval identity does not automatically establish a browser login mapping. The selected public Console origin is `https://labs.vegastack.dev`; this does not silently rename historical private inventory suffixes.

## User lifecycle implementation

Extend the existing authorization grant batch with a bounded lifecycle action. Draft creation remains inert. Onboard creates an absent human with no implicit grants or authentication binding. Suspend denies the principal while retaining explicit grants; resume reactivates only the retained grants and never restores old sessions. Offboard is terminal, preserves history and revokes grants, external bindings and sessions. Reject self-directed lifecycle changes and loss of the final active administrator. Repeat current identity, revision and authorization checks at execution.

Existing principal tables require a distinct suspended state; do not implement resume by undoing permanent revocation. Preserve existing rows, foreign keys, terminal-state triggers, recovery preimages and audit attribution. Required evidence includes inert drafts, allowed transitions, denied unauthorized/stale/terminal transitions, session invalidation and denied subsequent mutation. Native Linux evidence for this slice includes four lifecycle/migration cases and seven approved API workflow variants, executed in a disposable local Debian ARM64 VM. A cross-build alone is not native execution evidence.

## Device access implementation

`device request`, `device approve` and `device revoke` prepare inert changes for one existing active human and immutable device identity. The existing exact-plan acknowledgement/apply path owns all three state changes. Request creates pending state and grants no access; approval allows only requests already authenticated and authorized as that human/device. Revocation is terminal. Owner grants and revisions are not changed by device lifecycle.

Device identity comes from the protected server profile's optional `principalBindings[].deviceId` associated with the socket peer UID. The SSH forced-command identity must match that configured identity. The server, read authorizer and effective authorization repository check the current device and active owning human, including subsequent requests on an existing HTTP connection and repeated stream authorization. Client HTTP headers never establish device identity.

Legacy bindings without `deviceId` and browser adapters without a verified device claim retain their existing principal authorization; they are unattributed and carry no device-specific revocation promise. Approving a record does not install a key, edit an OS account or enroll a Cloudflare device. Applying that local profile binding on a live controller remains a separately scoped operation.

Native Linux evidence uses the real store and approved API workflow, plus an actual HTTP keep-alive connection that is denied after device revocation or owner suspension. This is software evidence, not live provider/host admission.

## Browser identity binding implementation

The existing `authorization grants draft --file <request.json>` accepts a single `identityBinding` change instead of grant, user or device actions. It links exact verified identity metadata to an existing active platform human. It never verifies a login by itself, creates a human, provisions an external account or grants permissions. Existing policy-author, human acknowledgement, execution authority and recovery preimage requirements still apply.

Use `action: "bind"` or `action: "revoke"`, method, issuer, immutable subject and a sorted unique audience list in the generated `BrowserIdentityBindingChange` schema. Include its schema/version, the existing human's current grant revision, current declaration/state revisions and recovery epoch, and an empty `changes` array in the enclosing grant-batch request. Obtain these through the existing authorized API/CLI reads; do not read SQLite directly. Never include JWTs, OAuth tokens or credential material. Mixed grant/lifecycle/device/binding batches are denied.

Draft, inspect and plan the declaration using the existing commands, review the exact Slack acknowledgement, then apply that exact plan. A draft changes nothing. Bind requires an absent exact identity; existing, conflicting or terminal bindings are denied. Revoke requires the same owner and an active or suspended binding. It ends only that binding's active browser sessions, leaving unrelated identities/sessions and the human's grants unchanged. Rebinding a terminal revoked identity is denied; use the documented recovery/identity process rather than rewriting database rows. For a mistaken active binding, prepare and acknowledge its exact revoke plan; no automatic restoration is performed.

Linux software fixtures cover the real approved bind/revoke path, exact identity matching, stale and unacknowledged denial, terminal state and unrelated-session preservation, alongside existing grant/user/device API variants. Actual Console login still requires the configured Access adapter to validate the real issuer, subject and audiences and the separate browser deployment prerequisites in issue #264. This software adds no provider service, browser device claim or live access.

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

## Network research result — 23-10-2026

Issue [#271](https://github.com/vegastack/vegastack-labs/issues/271) confirms that existing protected client profiles have one fixed SSH destination, while inventory address rows do not label LAN/Mesh paths or prove provider registration. Automatic selection therefore still needs an authoritative routing-data contract and an executable consumer. No standalone selector library or provider client is counted as a completed workflow. A bounded controller LAN/status slice was outlined as future planning; it is not implemented or accepted Phase 7 evidence. The immediate website prerequisite found during this research is the missing supported external-identity binding writer, tracked as #272.

Cloudflare's current [registration list API](https://developers.cloudflare.com/api/resources/zero_trust/subresources/devices/subresources/registrations/methods/list/) distinguishes registration and physical device identity, supports cursor pagination and reports virtual IPs. Its [registration revoke API](https://developers.cloudflare.com/api/resources/zero_trust/subresources/devices/subresources/registrations/methods/revoke/) is deprecated in favor of [registration deletion](https://developers.cloudflare.com/api/resources/zero_trust/subresources/devices/subresources/registrations/methods/delete/); neither local controller revocation nor provider deletion proves termination of an OS shell. Account-specific ownership, registration binding and policy scopes must be supplied before live reconciliation. No such provider action occurred.

[Managed-network TLS detection](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/configure/managed-networks/) uses a whole-certificate SHA-256 fingerprint in its documented self-signed configuration; SPKI is not interchangeable. [Tunnel credential rotation](https://developers.cloudflare.com/tunnel/reference/tunnel-tokens/) does not automatically end existing connector connections; any disconnection operation needs the full target set and protected-host exclusion checked. [Google OIDC](https://developers.google.com/identity/openid-connect/openid-connect#an-id-tokens-payload) uses stable subject identity rather than mutable email. None of these provider facts introduces another authentication service or account-provisioning requirement.
