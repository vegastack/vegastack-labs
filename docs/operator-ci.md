# Managed CI: current operator procedure

## Prepare the build locally

`vsk-labs release build-go-image` packages an existing static Linux Go binary into a new local OCI layout. Supply `--binary`, `--source-uri`, `--source-revision`, `--builder-id`, `--invocation-id` and a new `--directory`; `--output json` returns the generated result envelope. The embedded Go build information must report the exact clean Git revision, Linux AMD64 or ARM64, and CGO disabled. The source and builder metadata are checked for consistency, not authenticated.

The output contains actual image bytes, a compiled Go-module SPDX inventory and binary-packaging provenance statements. Both statements are **unsigned**. This command neither compiles source nor signs, publishes or deploys it. Follow the [packaging contract](development/go-image-packaging.md) for the precise supported subset. The existing verified publisher still requires real matching Sigstore bundles and a separately protected expectation/trust policy.

## Prepare an online runner

Use the existing controller enrollment/job draft, exact plan, human acknowledgement and execution flow. The selected group must restrict repository access to the enrolled repository. A screenshot, online runner or shared label does not grant admission. Do not use the shared `vsk-runner` selector. Nodes04/05 remain excluded, including indirect assignments. Existing persistent runners are unchanged.

The first online profile requires a dedicated rootless Docker daemon with **one running container at a time**, an empty selected bridge before launch, inter-container communication disabled and IPv6 disabled. The same pinned multiarch image supports native AMD64/ARM64 selection; native ARM64 testing does not qualify an AMD64 host. The protected root helper inspects the actual daemon ancestry, current IPv4/IPv6 egress rules, covered connected routes and exact payload/network membership. It uses its inherited private channel to authorize the demoted worker's two checks, before creation and before registration delivery. Profile hashes alone cannot pass these checks.

Configure only the fixed public HTTPS/public-resolver profile through separately authorized host configuration. IPv4 private, LAN, Mesh, link-local, metadata and special-use destinations are denied, and IPv6 is denied. A protected numeric public witness must connect; each explicitly owned private witness must be reachable from the supervisor before and after being denied from the payload. No fleet scan is part of verification. The checker installs no firewall rule and adds no service. Missing policy, another active container, drift or uncertain cleanup blocks use. Full user-stack gateway/DNS and hostile-job isolation qualification remains a separate native acceptance obligation; these checks do not claim G-006 or fleet qualification.

## Keep deployment separate

External application-deployment claims, renewals and receipts require a protected `ciDeploymentJobs` binding, an explicitly `deployment`-class enrollment and a matching plan-sealed `x-executor-deployment-job` digest. The server rechecks current enrollment, observer authority and actual numeric GitHub job/source/runner facts. A build enrollment cannot acquire a deployment lease. Job admission is additional to the existing exact plan, executor identity and independent receipt verification.

The managed deployment extension links a CI plan to one companion external deployment plan at the same database revision. Read both plans and obtain each required human acknowledgement before starting them. The existing plan response includes the companion ID and digest. The job remains held while the controller checks the actual consumed job identity, both execution leases and the exact protected hosting credential version. The initial supported network scope is public HTTPS Coolify with no application environment-secret or settings change. Private LAN/Mesh provider origins require a separately implemented network profile.

The hosting credential travels on the existing private controller-to-container channel. The typed consumer runs inside the admitted container, rechecks authority before provider requests and clears its in-memory credential afterward. An external result still requires independent provider/runtime observation before completion. The [service procedure](operator-services.md) describes the existing central deployment path.

## Publish a completed build

`vsk-labs ci publication draft --config <profile> --file <request> --output json` prepares a publication plan from one protected binding. The controller checks an actually completed successful GitHub run and exact job, verifies the supplied image and real Sigstore evidence against the protected source/builder policy, and uses a separate repository-scoped publication credential. The ordinary plan, human acknowledgement and apply commands perform the write. An unsigned packaging output cannot pass this publisher.

The publication attempt is bound to its immutable plan. Cancellation, credential revocation and uncertain registry writes require investigation through the recorded result; creating another run does not authorize repeating that attempt. The final combined live demonstration remains tracked by #317.

## Verify and recover

Before a live demonstration, verify the exact repository/group, source workflow/revision, disposable target identity and capacity, host/network evidence, separate observer/registration/publication/deployment credential references and signing policy. Resolve credentials only through their authorized existing mechanism; never paste a token in chat or store it in a workflow, plan, issue or log. Prepare and approve the exact live actions before registration, provider writes or dispatch.

On denial, expiry, cancellation, outage or malformed admission, keep user steps held and terminate the owned job. Preserve fixed sanitized lifecycle evidence, verify the exact container/workspace cleanup, then remove only its owned offline idle runner registration. Unknown cleanup is a failure, not permission to start another job. Do not remove another runner or clear unrelated Docker state.

The combined acceptance owner is [#317](https://github.com/vegastack/vegastack-labs/issues/317). It remains open until actual build/sign/publication/approved external deployment and independent observation pass. Earlier Mac/advanced-recovery deferrals and the separate website work remain separate.
