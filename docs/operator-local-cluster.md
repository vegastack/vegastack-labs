# Operate the local working cluster

Use the installed `vsk-labs` executable and your protected operator profile. Replace every placeholder below with an exact authorized ID or private path from the controller records. Keep responses and operational identifiers private. Nodes04/05 remain excluded, including reads and indirect effects. This procedure covers the existing pilot; it grants no new host enrollment, service change or maintenance authority.

## Use the Console

Overview reports the controller database, read access and change-engine state. A ready change engine still requires permissions, checks and acknowledgement for each exact operation. Use the normal Nodes and Services pages to inspect registered machines and recorded deployments; expand technical collection details only when diagnosing observation freshness. A recent local database read is not a newly completed integrity check or proof that applications are healthy.

Nodes keeps registration inspection first; expand add/preparation or advanced maintenance only for that task. Inventory drafts remain separate proposed records. Services presents its recorded deployment before optional configuration, provider and recovery detail. In Changes, enter an existing run reference to inspect its durable result without retrying execution. Backups, Audit and Gates refresh their existing records explicitly; a refresh does not initiate backup, restore, provider probing or host repair. Restore preparation remains disabled while required backup/audit status is unknown.

The obsolete Settings link is absent. Direct unavailable addresses describe an unavailable feature, not a disconnected controller; the old dashboard address opens the existing Overview. Design-state examples are labelled examples. [Console correction #404](https://github.com/vegastack/vegastack-labs/issues/404) records the exact tested source and installed verification; these instructions describe that corrected behavior and do not upgrade a running pilot by themselves.

## Check the controller and recorded state

```text
vsk-labs server status --config <protected-profile> --output json
vsk-labs status --config <protected-profile> --output json
vsk-labs doctor --config <protected-profile> --output json
```

`server status` reports control-service health. `status` reads the platform summary; `doctor` diagnoses its first failing invariant without mutation. Read the returned status, errors, state revision and recovery epoch. Keep `releaseBuildId` and `sourceRevision` from the response when identifying the installed pilot build; a newer repository checkout does not upgrade it. A healthy controller or an old observation does not establish current workload health. Missing or stale evidence is not, by itself, a reason to restart or repair anything.

For an existing registered machine:

```text
vsk-labs node inspect --config <protected-profile> --host-id <host-id> --output json
```

This reads its stored registration without contacting the machine. Registration and workload admission are separate: `adopted-unadmitted` is a valid recorded state, not a security-qualified or workload-ready host. Physical identity and role records remain authoritative; do not infer a target from a display alias.

## Prepare a new registration only when separately authorized

Follow the [node runbook](runbooks/vegastack-labs-manage-nodes.md) and [lifecycle prerequisites](platform-lifecycle.md). Resolve the exact machine identity, exclusions, current discovery evidence and access before preparing its typed request. If a discovery target is missing, the existing `node target prepare` path creates an inert target draft; it does not discover or register a machine automatically.

```text
vsk-labs node add --config <protected-profile> --file <reviewed-node-add.json> --output json
```

The request uses the generated `vegastack-labs.dev/host-adoption-request` contract. The command prepares an inert registration declaration. Review the returned declaration, then use the existing commit/plan, genuine human acknowledgement and exact apply workflow under explicit execution authorization. Preparation alone performs no registration or host configuration. Applicable baseline and role checks remain separate before workload admission; see [Linux role installation](development/linux-role-installation.md).

## Console correction coverage

Issue #404 covers the existing Console, including its legacy addresses. The following coverage is isolated browser and source evidence; it does not establish installed-site behavior or native/provider health.

| Page | Browser behavior covered | Boundary still requiring live evidence |
| --- | --- | --- |
| Overview | Summary/source states, outage and denial clearing, record links, collapsed collection details | Installed controller response and served assets |
| Nodes | Registered list and inspection, refresh, draft pagination/details, discovery/registration/action forms, admission states and stale-plan races | Real discovery, host changes and admission |
| People | Authorized list/detail, pagination, denial/revocation clearing and refresh | Actual identity-provider changes |
| Services | Registration/detail, recorded deployment/settings/recovery/provider reads, empty/stale/denied states | Fresh native/provider health or deployment |
| Backups | Status and recovery-point reads, restore-draft prerequisites, scheduling/run launchers, uncertain/denied result handling | Actual backup or restore execution |
| Providers | Configured capability reads, missing connectivity and denied/error states | Provider connectivity and changes |
| Gates | Evaluations, explicit check/evidence forms, failure families and recovery-epoch handling | Applied evidence from its real producer |
| Audit | Verification/checkpoint reads, refresh, continuity limits and denial/error states | Independent recovery qualification |
| Changes | Draft/revision/plan, approval polling, exact execution, uncertainty recovery, event reconnect, cancel/resume and existing-run lookup | Genuine human acknowledgement and live execution |
| Navigation and legacy routes | Sidebar navigation, theme/keyboard checks, desktop/mobile layouts, dashboard Overview, design examples and unavailable-page guidance | Authenticated installed-site smoke check |

All nine main pages have populated fixture checks and desktop/mobile accessibility/layout coverage. Legacy routes and error states are exercised by their owning browser tests. Tests deliberately retain malformed-response and denied-access behavior; a successful screenshot alone is not a successful operation. Advanced or deferred workflows remain bounded by their existing prerequisites.

## Import and export inventory drafts

An inventory import validates and stores an inert draft. It does not scan machines, change the source Sheet, accept inventory, register hosts or admit workloads. Use a deliberate source revision and actual UTC capture instant, not the file timestamp:

```text
vsk-labs inventory import --config <protected-profile> --file <private-candidate.json> --format typed-json --source-revision <source-revision> --captured-at <RFC3339-UTC-time> --idempotency-key <opaque-key> --output json
vsk-labs inventory export --config <protected-profile> --draft-id <draft-id> --draft-revision <draft-revision> --output json
```

The other supported import format is `labs-sheet1-csv`. Inspect all findings: both `valid` and `blocked` are draft states. An exact import retry with the same key and candidate returns the original draft; corrections require a new candidate and key. Import needs its existing draft-write authority even though it has no infrastructure effect.

Export selects one exact draft and requires the configured verified signing/export service. Missing trust or service prerequisites stay blocked. Its signature establishes draft-byte integrity, not acceptance, host authority or recovery qualification. Saving command stdout saves a client response, not a database backup or independently verified recovery point. See [inventory semantics](inventory-and-roles.md#draft-import-diff-and-export-workflow).

## Inspect a service or a failed operation

```text
vsk-labs service list --config <protected-profile> --output json
vsk-labs service show --config <protected-profile> --service-id <service-id> --output json
vsk-labs run inspect --config <protected-profile> --run-id <run-id> --output json
```

Service reads show stored registrations and delivery records within your scope. They do not refresh provider/native health or prove destination admission. For a failure, preserve the original JSON response, stable error code, request ID and any returned run ID. Use that exact run ID for `run inspect`; it reads the durable result without retrying apply. If no run was created, retain the request/plan references and diagnose that failure rather than inventing a run ID.

Treat `partial`, failed, unknown and succeeded as different outcomes. Do not repeat an uncertain write or re-run the completed manual delivery just to obtain fresh evidence. Use the owning [hosting procedure](operator-hosting.md) or [workload recovery procedure](operator-workload-recovery.md) for the next explicitly authorized action.

## Maintain the pilot controller

The installed controller is a local pilot build, not a published signed distribution. Historical maintenance retained the old binary and a consistent stopped-database copy, restarted only Labs, and verified controller health while preserving the profile, policy and unrelated services. The retained copy has not been demonstrated as an independent, restore-qualified recovery point. These historical facts do not authorize another replacement.

For a separately approved binary replacement, use the existing narrowly scoped administrator procedure:

1. Pin the controller's physical identity and current executable/configuration/database paths from protected records. Record its build, checksums, instance and recovery epoch. Select the reviewed compatible replacement and confirm independent administrator recovery access. A source build alone supplies no release-signing or compatibility guarantee.
2. Record the exact maintenance scope and recovery conditions before disruption. Do not combine a binary replacement with profile, credential, schema or other-host changes unless those changes are separately covered.
3. Stop only Labs and confirm its database writer has exited. Retain the original binary and a consistent database copy with matching protected configuration and version records. Never copy a database over a running controller or start a second writer.
4. Install the pinned binary, start the same controller using the existing configuration, and verify executable identity, `server status`, database integrity/recovery state and unaffected services. Retain the actual maintenance result, including failures.
5. If verification fails, preserve the database and logs. Restore the old binary only when its compatibility with the current database is established and the approved rollback permits it. A schema transition can make binary-only rollback unsafe. An unknown state requires a separate recovery decision, not automatic database restoration.

No general controller-upgrade command, automatic updater or new installation framework is introduced here. The [control-service installation procedure](development/linux-role-installation.md#first-control-service) owns foreground/service handoff. [Database lifecycle and recovery](platform-lifecycle.md) own backup qualification and fenced restore: `database backup` executes an exact approved backup plan and leaves qualification separate; `database verify` performs its separate verification; `database restore` prepares an inert restore change. They are not shortcuts around their authorization, recovery or native prerequisites. Same-host retained copies do not prove node-loss recovery, and neither backup restoration nor native rollback qualification is claimed by this working acceptance.
