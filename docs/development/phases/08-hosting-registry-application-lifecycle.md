# Phase 8 — Hosting, registry and application lifecycle

Status: software development started 26-10-2026 at baseline `b0624b9060de1ad89c8b5ae37ebfc981d0c1929b`. Phase 7's bounded software milestone is closed; live Console deployment remains separately blocked in [#264](https://github.com/vegastack/vegastack-labs/issues/264). This phase has not passed acceptance.

## Outcome and architecture

Build the smallest useful application-management path using the existing executable, server-owned SQLite, grants, declarations, plans, Slack acknowledgement and run executor. A maintainer will declare a service/environment, import its existing provider resources, inspect its actual observed state, deploy one immutable image through an approved plan, and receive a verified health/rollback or recovery result.

Coolify remains the typed hosting adapter. Harbor remains a Coolify-managed application workload and image registry. Neither provider becomes a platform-core requirement. Reuse the current credential-reference and backup mechanisms; add no daemon, queue, generic provider framework or signing system. Source builds, registry publication and the managed CI executor belong to Phase 9. Existing Phase 6 native/macOS/advanced-recovery deferrals remain deferred.

## Delivery map

| Delivery | Owner/status | Required result |
| --- | --- | --- |
| Exact Coolify read observations | [8.1 / #283](https://github.com/vegastack/vegastack-labs/issues/283), merged in [PR #285](https://github.com/vegastack/vegastack-labs/pull/285); focused tests/vet and exact-head check passed | Fixed GETs for an explicit existing application/server; current team and project/environment/resource binding; sanitized configuration/provider status. |
| Immutable Harbor artifact inspection | [8.2 / #284](https://github.com/vegastack/vegastack-labs/issues/284), merged in [PR #285](https://github.com/vegastack/vegastack-labs/pull/285); focused tests/vet and exact-head check passed | Exact project/repository/digest read, truthful scan state and explicit absence of signature verification. |
| Service/environment and owned-resource workflow | [8.3 / #286](https://github.com/vegastack/vegastack-labs/issues/286), implemented; Linux approved-import/provider-composition and built-Console browser proofs passed; shipping evidence in issue | Database declarations/import, scoped service reads and real Services Console records using the same generated API. No provider write occurs merely from a draft or import request. |
| Central/manual digest deployment and recovery | Subsequent batch | Exact approved target/image, actual signed-digest intake verification, independent running-digest/health observation, safe retry and migration-aware rollback or explicit recovery. No CI executor required. |
| Coolify/Harbor lifecycle and consistent recovery | Subsequent batch | Owned teams/resources/projects and robot references, platform/workload backup separation, declared consistency procedure and isolated restore/migration evidence. Preserve the existing two-system-robot deployment profile. |
| Combined operator procedure and acceptance | Final delivery owner assigned with the integrated batch | One demonstrated service workflow with success, scope denial, provider outage and health/data recovery cases, plus matching manual steps. |

Closing the two first-batch issues does not close Phase 8. The remaining delivery rows must be scoped into executable issues and implemented before phase acceptance. The broader [registry/hosting module #11](https://github.com/vegastack/vegastack-labs/issues/11) remains the requirements map.

## First batch authority and execution

On 26-10-2026, (omkarmohanta09) instructed “ok then start it” after choosing to start Phase 8 software while Cloudflare access is pending. The first batch creates the two typed observation adapters needed by the existing Phase 8 roadmap; it introduces no new product policy or live operation. Issue briefs, plans, approval references and ledgers record the exact implementation boundaries.

The coordinator serializes shared documents and shipping. Two GPT-6.1 Sol medium implementation agents own separate adapter packages; no independent reviewer agents are added. Both issues share one integration branch and PR with one final required affected proof. Test and boundary failures are corrected directly; no repeated older phase-wide acceptance suite is added.

Per adapter, expected agent time is 12 minutes with a 24-minute checkpoint and approximately 2 minutes of operator result review. Basis: two implementation/test files, 4–6 focused reads, about 10–15 agent turns and 3–5 command minutes. The adapters run in parallel. Cold public toolchain downloads and the shared final repository check are separate command waits; the previous tooling suite took about nine minutes. Actual start/end and delivery results belong in the issue ledgers.

## Adapter contracts and verification

Coolify uses the existing selected [v4.3.10 OpenAPI contract](https://github.com/coollabsio/coolify/blob/v4.3.10/openapi.json), checked 26-10-2026. The pinned current-team route is `/team`; do not substitute a newer documentation route. Exact application inspection also checks its project/environment links and declared destination identity. Configuration and a provider-reported status cannot prove the image actually running on a machine. If the API cannot establish a server relationship, it remains unknown. Server inspection never calls validation, which may change Docker or services.

Harbor uses the [v2.14.6 API specification](https://github.com/goharbor/harbor/blob/v2.14.6/api/v2.0/swagger.yaml) as its development contract, checked 26-10-2026. This is not a live installation/version choice. Artifact reads use an immutable sha256 digest and explicit project/repository scope. Index identity, scan availability and findings stay distinct. Artifact presence or a successful scan does not prove signature/provenance identity.

Both adapters accept only a configured HTTPS origin and typed targets. They use borrowed credentials from the existing credential value type, fixed GET paths, bounded bodies/timeouts and sanitized snapshots/errors. Default transports do not inherit environment proxies; redirects/retries are disabled. No raw provider response, secret, embedded provider command or arbitrary caller URL reaches a public result. Local HTTPS contract fixtures prove exact requests, identity mismatches, error/cancellation handling and redaction. No real provider is contacted by public tests.

The first batch supplies adapter foundations. It does not yet make a new CLI, API route or Console workflow available. Issue [#286](https://github.com/vegastack/vegastack-labs/issues/286) integrates those surfaces through protected server-owned bindings and current exact grants; a raw adapter is not an alternate operational entry point. Its implementation and verification are recorded below.

## Service import slice — implementation and verification

The approved second slice is [8.3 / #286](https://github.com/vegastack/vegastack-labs/issues/286), based on `36459c4a`. The operator selected GPT-6.1 Sol medium implementation agents with dependency-aware parallel ownership; no independent reviewer agents are added. Reuse the existing executable, server-owned SQLite and human-approved exact-plan executor. This batch authorizes repository development only, with no provider, fleet, credential, Slack, CI or deployment operation.

The implementation adds one initial service/environment registration, protected typed Coolify/optional Harbor bindings, current exact-scope API/CLI reads and the actual Services Console. Import preparation records an inert declaration; approved apply reobserves the exact bound resources and performs only a local registration/ownership effect. Registration is `registered`, host admission is `not-verified`, Coolify configured image/status is separate from unknown actual running digest/health, and Harbor scan state is separate from unverified signature/provenance. Services denial removes cached list/detail/observations and cancels pending reads. The matching human procedure is [Register and inspect an existing service](../../operator-services.md).

The approved import and four denied/stale branches pass real Linux SQLite/API/plan/acknowledgement/apply fixtures. Two catalog tests and six production-composition tests pass inert preparation, exact-scope reads, synthetic HTTPS/provider failures, credential closure/rotation and current-authority changes. Nine built-Console single-worker Chromium tests pass paging, keyboard/accessibility, truthful states and removal of private data after denial/session expiry, including a late response. Exact commands, screenshots and the final affected shipping result are recorded in #286. These bounded proofs do not close the remaining Phase 8 delivery rows. No live provider, host, deployment, workload admission, signature verification, service deployment/rollback or Phase 8 acceptance is claimed. Existing Phase 6 deferrals remain deferred.

Expected implementation/integration effort is 35 agent minutes, checkpoint 70 agent minutes, with about 3 minutes of operator result review. Basis: roughly 30 focused source/test files, 45–60 turns across assigned agents and 8–12 command minutes. Shared public toolchain/runtime downloads and the final browser/check command waits are separate; actual times and proof belong in the issue ledger.

## Live prerequisites and exclusions

Software development can proceed independently of Cloudflare website access. Live work still requires the named account/origin, actual provider versions, credentials/ownership, qualified target capacity and separate scoped authorization. Current code or fixtures cannot supply those facts.

Nodes04/05 remain absolutely excluded, including reads and indirect effects. No infrastructure, provider, credential, database, application, runner or public listener is changed by this development batch. Do not select placement, invent Harbor source data, claim host admission or count a SQLite restore as Harbor consistency proof. Existing basic authorization, acknowledgement, secret handling and data preservation remain mandatory.

## Acceptance and evidence

The first adapters require focused Go tests and vet against real local HTTPS peers, covering positive scope and denied wrong identities, malformed/duplicate/oversized JSON, TLS/redirect/timeout failures and secret-free results. Generated or runtime boundaries remain unchanged unless a later issue explicitly extends them. One final check runs against the exact clean, pushed integration commit before PR creation.

Full Phase 8 acceptance additionally requires the operator workflow and the remaining rows above. Actual running-digest, stateful restore, provider permission and installation/qualification evidence cannot be replaced with an adapter mock. Live website deployment and existing deferred work remain separately tracked.
