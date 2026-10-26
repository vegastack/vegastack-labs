# Register, inspect and deploy an existing service

This procedure imports one existing application/environment into the controller's service catalog. It uses the existing `vsk-labs` server, SQLite, grants, declaration, exact plan, human acknowledgement and local executor. Importing records ownership in the controller; it does not create, deploy, restart, reconfigure or delete provider resources. A service is **registered**, with host admission **not-verified**.

## Prerequisites and targets

Use a currently authorized controller profile and one explicit service/environment binding. The environment ID is part of the registration; it is never inferred from the service name. The owner must be active, the host registered with its current exact identity, and the protected server binding must match the service, environment, owner and host. Registration is not a host security qualification or workload admission.

Resolve the complete target identity, aliases and indirect provider relationships from already available records before any authorized provider read. Nodes04/05 remain absolutely excluded, including reads and indirect effects. The protected profile's `networkConnectExcludedHostIds` carries these physical exclusions through identity and alias/history checks. An ambiguous target or incomplete exclusion is a stop. This guide grants no live access; actual provider configuration, credential setup and infrastructure operations need their own scoped authorization.

An infrastructure administrator supplies the protected server's bounded `serviceBindings` configuration through the existing profile mechanism. Coolify scope pins its HTTPS origin, team, project, environment, destination and existing application identity. Optional Harbor scope pins its HTTPS origin, project, repository and immutable artifact digest. Neither client nor browser selects an arbitrary provider URL or replaces these bindings. Public service responses expose the logical binding ID/digest, not raw provider configuration or credential references.

The caller needs exact current author permission `service.import.prepare` on the service. Execution needs `service.import` on the service's `execution-target` with the human branch; the responsible human needs `plan.acknowledge` on its `plan-target`. Reading needs separate exact `service.read` on the service. Current device, owner, host, state, recovery epoch, gate and recovery preconditions still apply. An agent cannot acknowledge its own plan.

Provider reads borrow active verified references through the existing credential resolver: `hosting.coolify` / `hosting-observe` / `credential.hosting.read`, and, when Harbor is configured, `registry.harbor` / `registry-observe` / `credential.registry.read`. Their target is the service ID. Keep reference values and credentials in private operational storage; never put plaintext material in a request, plan, issue, prompt or log.

## Prepare and approve the import

Prepare a private JSON file conforming to the generated [ServiceImportDraftRequest schema](../schemas/v1/service-import-draft-request.schema.json). It contains only `schema`, `schemaVersion`, `serviceId`, `bindingId`, `expectedStateRevision`, `recoveryEpoch`, `idempotencyKey` and `reasonDigest`. Obtain the current state revision and recovery epoch from authorized controller reads. Use the exact configured logical binding ID, a fresh bounded idempotency key and the digest of the approved reason. Do not invent missing state or provider identifiers.

1. Run `vsk-labs service import draft --config <protected-profile> --file <private-request.json> --output json`. The server authorizes before resolving credentials or contacting providers. Coolify must return the exact bound application; configured Harbor must return its exact artifact. Preparation binds a digest of sanitized observations into an inert declaration.
2. Inspect the returned declaration and run `vsk-labs plan --config <protected-profile> --declaration-id <returned-id> --revision <returned-revision> --output json`. Review the service/environment, owner, host identity, binding digest and local registration effect in both plan forms.
3. Request the normal human acknowledgement for the exact immutable plan through the existing Changes/Slack workflow. No separate Services approval or provider action exists.
4. After acknowledgement and current prerequisite checks, run `vsk-labs apply --config <protected-profile> --plan-id <approved-plan-id> --output json`. Inspect its run using the existing `run inspect` workflow. The executor reobserves the same protected resources before its local effect and independently verifies the stored registration and audit result.

A draft or committed declaration does not register a service. Stale state/epoch, changed binding, owner or host identity, changed provider observation, revoked authority, duplicate service/resource ownership, absent acknowledgement or failed recovery checks stop execution. Provider identity/configuration is checked at observation time; this does not provide an atomic guarantee about subsequent external state. No provider write is part of import.

## Inspect records and observations

Use `vsk-labs service list --config <protected-profile> --limit 25 --output json`. Continue with the returned `nextAfter` using `--after <service-id>`; the API accepts limits 1–100 and returns only exact currently permitted service IDs. Use `vsk-labs service show --config <protected-profile> --service-id <service-id> --output json` for the stored registration and `vsk-labs service observe --config <protected-profile> --service-id <service-id> --output json` for a fresh provider observation. These calls use the same protected API; never read SQLite directly or substitute a provider CLI.

The Console's Services page lists actual registered environments, supports bounded continuation and inspection, and refreshes registration/observations through the generated API client. The Changes page remains the approval/execution surface. Empty scope, loading, denial, malformed responses and unavailable dependencies are distinct. A retryable transient failure may retain explicitly stale data; that label means current provider availability has not been established. Current denial or expired authentication removes service list/detail/observation data, including pending reads that could otherwise return late.

Interpret each field independently:

| Observation | Meaning and limit |
| --- | --- |
| Registration / host admission | `registered` records a local import; `not-verified` establishes no host admission or security qualification. |
| Hosting state and reason | `observed`, `unavailable`, `unknown` or `not-configured`; unavailable credentials/providers are reported explicitly. |
| Coolify reported status / configured image | Provider-reported configuration/status only. Actual running digest and application health remain `unknown`. |
| Harbor artifact digest / kind | Exact registry identity when observed; image and index remain distinct. This does not prove which image is running. |
| Scan state | Findings, passed, pending, running, error, unavailable, not-scanned and unknown remain distinct. A scan does not establish signature identity. |
| Signature / provenance | Both remain `unverified`; this slice contains no signature/provenance verification. |

## Failure, retry and recovery

If preparation fails, no registration exists: resolve current authorization, exact binding and provider availability through the authorized reads, then prepare again with current state. If the plan is stale, prepare a new current declaration/plan and obtain its own acknowledgement; never reuse an old approval for changed inputs. After an uncertain execution result, inspect the existing run and service record before retrying through the same idempotent workflow. Do not bypass resource-ownership uniqueness or delete database rows.

This slice imports once; changing an existing registration, removing ownership, deploying, rolling back and migrating workload data are not implemented service operations. The existing `service plan`, `service deploy` and `service rollback` entries remain planned. A mistaken registration needs separately scoped corrective development or the existing authorized control-database recovery procedure, with its normal data-preservation/recovery prerequisites. Import failure never authorizes deleting an external application, artifact or database. A control-database recovery is not Harbor/application consistency proof.

## Development evidence boundary

Real Linux SQLite/API fixtures pass the approved import and four denied/stale execution branches. Six production-composition fixture tests pass scoped HTTPS reads, independent provider failures, credential closure/rotation and current authority changes. The built Console passes nine single-worker Chromium tests, including pagination, keyboard/accessibility, empty/denied/error/unavailable states and late-response cache removal and rejection of a response for the wrong service. Provider peers, credentials and browser records are synthetic. Exact commands, screenshots and the final affected shipping result are recorded in [#286](https://github.com/vegastack/vegastack-labs/issues/286). No real provider, host, Slack workspace, secret, CI runner or live deployment is qualified; Phase 8 acceptance and the existing Phase 6 deferrals remain open.


## Deploy one immutable image

The first deployment slice changes only the image of an existing, explicitly bound standalone Docker-image application. Existing application settings stay under the declared owner. It does not provision applications, add destinations, run migrations, configure hosts or expose services. Swarm, Compose stacks, previews, multiple containers and multi-platform image indexes are unsupported in this slice.

The host must already have current application-role admission evidence. A registered or adopted-unadmitted host cannot deploy workloads. The server resolves the accepted machine identity and pinned SSH connection from its own records; Docker reads use a separately activated runtime credential with existing access to the local socket. No host executable, sudo grant or new agent is installed. Missing admission or Docker access blocks the operation.

The protected server profile adds `serviceDeploymentBindings`. Each entry pins the existing service binding, one destination UUID and server UUID/ID, separate mutation/runtime references, exclusive controller ownership, a data policy, and a small artifact catalog. Configuration is hashed by the server into the exact plan. Artifact entries select a logical ID, full repository, immutable SHA-256 and three local paths: actual OCI image manifest bytes, its existing Sigstore bundle and its explicit trust policy. Keep those files in service-owned 0700 directories with 0600 permissions. The existing offline verifier authenticates the actual manifest bytes and checks the content digest; a signature over the printable digest is insufficient. No new signer or trust service is introduced. Automatic artifact publishing/intake remains later work.

The matching Harbor repository must contain that exact image manifest. The hosting mutation reference uses consumer `hosting.coolify.deploy`, purpose `hosting-deploy`, capability `credential.hosting.deploy`. Runtime reads use `service.runtime`, `runtime-observe`, `credential.service-runtime.read`. Existing registry observation uses `registry.harbor`, `registry-observe`, `credential.registry.read`. References target the exact service ID, must be active/current and verified for their consumer, and must be enabled in the applied profile. Never reuse a discovery credential as implicit Docker authority.

The operator needs current exact `service.deploy.prepare` author and `service.deploy` execute grants plus read access to the service and its host. The assigned human needs `plan.acknowledge` on that service's plan target. The existing maintainer/infrastructure authorization rules and current device checks apply. Every deployment uses the human branch in this slice, including development environments; no automatic approval class is added.

1. Prepare a private [deployment draft request](../schemas/v1/service-deployment-draft-request.schema.json) containing the exact service ID, configured artifact ID, `action: deploy`, current `expectedStateRevision`/`recoveryEpoch`, fresh `idempotencyKey` and approved `reasonDigest`.
2. Run `vsk-labs service deployment draft --config <protected-profile> --file <private-request.json> --output json`. This is inert. The server checks its protected artifact catalog and current authority/admission before staging a declaration.
3. Use the existing `plan` command for the returned declaration/revision. Review service, environment, host, exact `repository@sha256:...`, data policy, previous deployment revision and configuration digest in the readable and JSON plan. Request the existing exact human acknowledgement, then execute with `apply` through the same documented flow as import.
4. Read the existing run and `vsk-labs service deployment show --config <protected-profile> --service-id <service-id> --output json`. The fixed API is `POST /api/v1/services/deployment-drafts` for operator preparation and `GET /api/v1/services/{serviceID}/deployment` for scoped latest results. The Changes Console uses the same plan/run; this slice adds no separate browser deployment form. The older planned `service plan|deploy|rollback` shortcuts remain unavailable; use the implemented commands above.

The controller first confirms one exact primary destination/server and explicit zero additional destinations. It patches only the image repository and digest tag, queues one application and confirms the returned receipt belongs to it. A provider receipt or `finished` status is not deployment success. Success also requires an independent SSH observation of one matching local Docker container, the actual repository manifest digest, running state and Docker HEALTHCHECK `healthy`. No healthcheck, a changing/missing/ambiguous container, mismatching digest, expired authority or unknown state cannot count as success. The observation reads only fixed non-secret fields; it never returns environment variables, full inspect output or health logs.

Convergence reads are bounded to 45 seconds inside the existing 60-second execution lease. A slow rollout remains partial rather than gaining an invented success or a new background worker. The result is timestamped evidence from that execution, not a permanent current-health claim. The existing general provider observation still reports its independent unknown running/health fields truthfully; inspect the deployment record and its timestamp for this run's proof.

## Partial deployment and explicit rollback

The controller durably records an attempt before provider I/O. PATCH and deploy are separate operations: a later failure may leave image configuration changed or a deployment queued. Unknown transport outcomes retain partial status, sanitized provider receipt ID/stage when known, proof digests and audit attribution. Restart, duplicate apply and a new submit key cannot silently replay that attempted plan. Preserve the result and inspect the known provider receipt/current runtime through the approved operational route before preparing any corrective plan; a missing receipt is not proof that nothing happened. No automatic retry or automatic rollback occurs.

For rollback, prepare the same draft with `action: rollback` and a configured artifact ID that already has a successful verified deployment for this service in the current recovery epoch. It creates a new exact plan and requires human acknowledgement. Only protected `stateless` or `compatible` data policy permits image changes in this slice. `unknown` or `irreversible` policy blocks deployment and rollback; stateful migration/restore needs its separate recovery workflow. Image rollback does not restore database contents.

Coolify's API does not atomically freeze a destination set between preflight and execution. Exclusive controller ownership is required; an external administrator can still introduce a race by editing it concurrently. Do not claim atomic target isolation or authorize deployment when indirect protected-host impact is unresolved. Nodes04/05 remain excluded. Synthetic software tests do not qualify hosts, verify real credentials, install providers or authorize a live rollout.
