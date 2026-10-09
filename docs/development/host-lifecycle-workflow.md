# Linux host workflow

The Nodes screen and CLI use the same server authorization, immutable plans, Slack acknowledgement and run engine. Loading a file or preparing a draft does not configure a host. A registered host is not workload-qualified.

## Role preparation and collection

1. Inspect the registered host and its current baseline and role admission evaluations. The Console reads each gate for the exact host; **Read current admission** refreshes server evaluation without connecting to the host or collecting new evidence.
2. Prepare an exact `HostActionRequest` containing the existing `LinuxRoleInput`. Include the host identity, target revision/digest, profile and package pins, role binding, account/directory selectors, resource limits, console confirmation and credential references. Never include plaintext secrets.
3. In **Hardening, roles and recheck**, choose **Role and service handoff** and load the prepared file. Review the host, profile, role, accounts and limits. The supported actions are `debian.role.apply`, `debian.role.collect`, `debian.control.handoff` and `debian.control.handoff.verify`. The server independently validates, binds current baseline evidence and renders the policy.
4. Choose **Prepare role draft**, then **Create exact plan**. Review the server plan, request the existing Slack acknowledgement, and apply that exact approved plan through the shared run controls. The equivalent CLI preparation is `vsk-labs node role prepare --config <profile> --file <request.json>`; use the returned declaration with the ordinary `plan` workflow.
5. Inspect the run result, then refresh admission. Initial role apply leaves network qualification pending until the applicable approved access probes run and a fresh role collection records the result. A successful execution does not replace missing, failed or stale gate evidence.

A changed identity, profile, declaration or recovery epoch requires current evidence and a new plan. Revoked access clears scoped forms and results. Temporary failures retain unsaved input and do not automatically resubmit a mutation. Recheck actions still use exact approved host-action plans; refreshing displayed gates does not manufacture a host observation.

## Initial control service

An administrator first prepares the supported Linux host, nonroot account, protected directories, verified executable and recovery access. `vsk-labs server prepare --file <role-input.json>` produces inert preparation guidance without opening SQLite or installing a service.

Prepare the protected server profile and setup record, including the existing Slack workspace/user mapping and secret references. Start `vsk-labs server run --config <profile> --setup <record>` in the foreground. The mapped human approves the exact setup through the existing Slack flow. A browser visitor cannot grant itself administrator rights or initialize the controller.

Once authenticated server authority exists, prepare and approve the control role installation, then the separate exact `debian.control.handoff` action. Review its foreground process identity, service UID, existing database instance, configuration/unit/executable digests and deadlines. Handoff transfers the same existing controller to the OS service manager; it does not restore or create another database. Use a fresh `debian.control.handoff.verify` plan to verify continuation afterward.

## Recovery and limits

Follow the underlying role action's bounded recovery procedure. Preserve account data, directory contents, owned-file journals and the existing database. An unresolved role installation journal blocks retries; the Console cannot clear it. An unchanged active control-role reapply verifies state without writes or restart. Different active control configuration remains refused.

This workflow consumes the implemented Linux foundation. Native acceptance and future provider capabilities remain separate requirements. macOS role installation remains unsupported. Nodes04/05 remain excluded, and development or UI availability grants no live host authorization.

## Replacement and recovery

Prepare a bounded `HostReplacementRequest` from current authorized records. In **Host replacement and recovery**, load that file and review the distinct old/new hosts and identities, target revisions and SSH key digests, exact alias owners and generations, role declarations, preserved volumes/resources and recovery epoch. Control-database replacement additionally names the verified source point, manifest and custody references; stateless replacement does not restore database payloads. The browser does not calculate authoritative bindings or edit arbitrary request bodies.

Confirm the displayed impact, then choose **Prepare replacement draft**. This acknowledgement of the preview is not execution approval. Continue through **Create exact plan**, the existing Slack acknowledgement and the exact-plan run controls. CLI equivalents are `node replacement prepare --config <profile> --file <request.json>` and `node replacement inspect --config <profile> --replacement-id <id>`.

Inspect the replacement by its exact ID after each stage. The displayed status, blockers, next action, ownership generations and epoch come from the server. Frozen aliases are not transferred aliases. A staged restore, restarted candidate, successful service or incomplete native admission must not be treated as completed replacement. Use **Backups and recovery** for existing recovery-point selection, restore verification and its safe next action. Follow the owner’s recovery-required procedure without automatic resubmission or reimaging.

Once fences, restoration when applicable, and current destination admission are verified, prepare a fresh commit request and a separate approved plan. A stale epoch, denied destination or changed binding requires current server state and a new plan; browser confirmation cannot bypass these checks. Preserve the old host’s data. The server’s committed state records alias ownership transfer, not native acceptance or future provider readiness.
