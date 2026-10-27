# Phase 9 — SCM, managed CI and application delivery

Status: implementation started on 27-10-2026. The first bounded software delivery is [9.1 / #296](https://github.com/vegastack/vegastack-labs/issues/296). Phase 9 remains open until the remaining flows and combined acceptance below are implemented and verified. Phase 8 supplies the existing service, registry, immutable deployment and recovery paths.

## Outcome and approach

A trusted application revision can build, produce verifiable image/provenance/SBOM evidence, publish to its registry scope, and reach the existing exact-plan deployment executor. Build jobs and deployment jobs have separate credentials. The existing `vsk-labs server run`, server-owned SQLite, protected credential resolver, declarations, plans, acknowledgement and executor leases remain the authority. Add no second controller, queue, privileged managed-host agent, generic CI framework or signing service.

The Labs GitHub adapter is replaceable. GitHub outages cannot disable local control reads, plans or recovery. Optional repository discovery, webhooks, rich statuses and Apps remain unselected; they are not prerequisites for the first working path.

## Delivery map

| Delivery | State | Required result |
| --- | --- | --- |
| Explicit enrollment and source/job observation | [9.1 / #296](https://github.com/vegastack/vegastack-labs/issues/296), implementing | Provider-neutral exact binding comparison and bounded GitHub GET observations of repository, workflow bytes, revision, run attempt and assigned job. A match grants no execution authority. |
| Server-owned enrollment and one-job admission | Next software slice | Current authorized enrollment in SQLite; immutable controller-owned pre-step admission bound to the actual assigned job; replay, shared-label race and cancellation denial before checkout/user steps/credential delivery. A workflow name, label or observation alone is insufficient. |
| Ephemeral Linux execution and logs | Pending | Existing constrained SSH path launches one pinned runner per job on a qualified target, with rootless build execution, isolated workspace/cache/network, no host Docker socket or privileged mode; external sanitized logs survive cleanup. Failure to clean or preserve logs blocks promotion and further use. |
| Build evidence and registry publication | Pending | Exact source revision produces an immutable image, SBOM and provenance using the existing verification contract. Publication receives only its registry scope and cannot deploy. No new signing system; maintainer identity and real credentials remain activation inputs. |
| Protected deployment and Mac fallback | Pending | Separate admitted deployment job claims only the existing authorized target/digest lease and receives its narrow credential; independent hosting observation verifies success. Supported hosted/manual Mac fallback stays explicit without claiming a self-hosted Mac qualification. |
| Combined operator acceptance | Pending | One isolated source-to-build-to-registry-to-approved-deployment demonstration, plus wrong identity/digest, untrusted job, race/replay, cancellation, outage, cleanup and credential-scope denials and matching human procedure. Required real runner/isolation evidence cannot be replaced with API fixtures. |

The broader requirements remain in [Module 4 / #10](https://github.com/vegastack/vegastack-labs/issues/10). Each next batch gets grounded issue scope and acceptance before code. The table records remaining work; it does not declare it deferred or complete.

## First delivery contract

`internal/ci` compares an explicit enrollment against a fresh observation. It binds stable repository/owner/workflow IDs, repository name, workflow path and SHA256 file digest, immutable source revision, exact branch ref and event, assigned job name, runner/group IDs and label set. This first slice supports only exact `push` or `workflow_dispatch` branch bindings. Pull-request/fork events, wildcard identity and missing/mismatched inputs are denied. Every other event remains unsupported rather than being treated as trusted.

`Match` returns only `enrollment-match`; it is an inert comparison with no credential, runner-admission or deployment authority. Observation age is limited to 60 seconds, with at most 5 seconds of positive clock skew. The caller supplies current time explicitly. No durable admission proof, alternate policy store or caller-writable execution grant is created.

`internal/adapter/githubci` reads a configured HTTPS API origin using fixed constructed routes. It checks the current run before and after observing the exact run attempt, complete bounded attempt-job membership and the actual workflow file at the pinned revision. Stable repository and head-repository IDs must agree; runner labels alone cannot prove the assignment. Provider-returned URLs are never followed. The REST contract is pinned to `2022-11-28` for this software slice.

The adapter borrows the existing `credentialref.Value`; nil explicitly selects public reads. It never discovers a credential from an environment variable. JSON, page count, workflow bytes and overall request duration are bounded, duplicate keys are rejected, redirects/retries are disabled, and returned errors contain fixed categories without provider bodies or tokens. A configured transport is a trusted composition input, never a job option.

Official contracts checked on 27-10-2026: [workflow run attempts](https://docs.github.com/en/rest/actions/workflow-runs#get-a-workflow-run-attempt), [attempt job membership](https://docs.github.com/en/rest/actions/workflow-jobs#list-jobs-for-a-workflow-run-attempt), and [repository file contents](https://docs.github.com/en/rest/repos/contents#get-repository-content). The [runner hook documentation](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/run-scripts) describes before-step hooks and nonzero-exit denial; those documented capabilities alone do not prove an immutable guard, hostile-job isolation or G-006 qualification.

## Authority and acceptance limits

The operator instructed “ok so the usage has been reset continue working to next phase” on 27-10-2026 and reiterated the simplicity and no-unnecessary-review requirements. Two GPT-6.1 Sol medium implementation owners handle the two small packages; the coordinator handles integration and one required final affected check. No independent reviewer round is added. Ordinary repository PR/merge authority follows the existing user instructions; release, provider and fleet actions remain separate.

The GitHub account for this project is `omkarmohanta09`. Verify that account through the terminal before mutations. The first issue was incorrectly created through another account's connector and was closed as superseded; #296 preserves its brief/plan/ledger under the correct author. The operator stopped the work during that correction and then explicitly resumed it. This correction is not a feature completion claim.

Public development uses pure comparison tests and local HTTPS peers; this slice needs no VM, live provider, private token, runner or Cloudflare access. Tests must prove exact routes/identities, all-field mismatch denial, stale/future observations, rerun races, pagination, malformed/oversized input, cancellation, redirect refusal and secret-free errors/results. Focused Go tests/vet and the configured exact-head affected proof are required before merging.

No API/CLI/Console CI operation is activated by this foundation. GitHub reads are not atomic; a matching observation cannot establish actual-job isolation, branch protection, trusted workflow steps or durable execution authority. The later controller must reauthorize, reobserve and enforce its own before-step boundary. G-006 stays open.

Expected first-batch agent time: 30 minutes; checkpoint: 60 minutes; operator result review: approximately 2 minutes. Basis: two packages and their tests plus three documentation files, approximately 25–40 turns and 8–12 command minutes. Download/final-check waits and the operator stop are recorded separately in the issue ledger; actual completion is reported there.

## Live prerequisites

No live host, provider, credential, Slack, CI, release, public listener or VM operation is part of this batch. Nodes04/05 remain absolutely excluded, including indirect effects. Do not dispatch to the shared `vsk-runner` selector. Actual enrollment/runner groups, pinned offered runner version, qualified host/isolation, signing identity and scoped registry/deployment credentials must be supplied and independently verified before an explicitly authorized activation.

The website at `labs.vegastack.dev` remains separately tracked by [#264](https://github.com/vegastack/vegastack-labs/issues/264). Earlier Phase 6/macOS/advanced-recovery deferrals remain deferred. Completing this first slice does not complete Phase 9 or qualify a host/provider.
