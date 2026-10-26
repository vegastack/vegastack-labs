# Register and inspect an existing service

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
