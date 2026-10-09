# Linux role preparation and installation

Issue [6.9 / #230](https://github.com/vegastack/vegastack-labs/issues/230) extends the existing executable, API and exact-plan workflow. A role installation prepares host-side identities, protected directories and resource limits. It does not install Coolify, Harbor, Mesh or managed CI runners, issue their credentials, or admit workloads.

## Prepare and inspect

`vsk-labs server prepare --file role-input.json --output json` reads one bounded `LinuxRoleInput` and returns the proposed files, their digests and administrator prerequisites. It performs no installation, database access or network operation. Human output presents the same role, paths and policy digest. This local preparation needs no baseline proof. Omit `baselineSnapshotDigest` in desired input so the server can bind its current proof when staging a role action; a supplied digest must match. Prepared files and input digests are not proof and cannot pass admission by themselves.

The finite roles are `control`, `application`, `ci`, `recovery-spare` and `reserve`. The input selects fixed account/path names, exact numeric identities, measured capacity and bounded resource limits. Unknown users, conflicting ownership, symlinks and unrelated data must be preserved. The existing control account must also support the approved SSH automation path; preparation does not change its login policy. Preparation cannot authorize a capacity increase or replace the administrator's independent identity and recovery checks.

For an initialized server, `vsk-labs node role prepare --config operator-profile.json --file role-request.json --output json` sends one typed `HostActionRequest` to the existing draft API. The input carries a finite role action and `LinuxRoleInput`; there is no arbitrary command, unit body or path root. The server renders and binds the exact policy and current baseline before producing an inert declaration. Inspect that declaration's exact plan, obtain the assigned human acknowledgement, and execute using the existing plan/run commands. A connection failure must be inspected before resubmission; a prepared draft is not an installed role.

## First control service

The administrator first establishes the independently verified public-key trust, verified executable and exact non-root `vsk-labs` account. The prepared output lists the required UID/GID and paths. Preserve existing root-owned helper state at `/etc/vsk-labs` and `/var/lib/vsk-labs`; do not recursively change ownership of either directory.

The control service has dedicated configuration at `/etc/vsk-labs/control/server.json`, data under `/var/lib/vsk-labs/control`, and runtime state at `/run/vsk-labs-control`. Run the existing foreground `server run --config ... --setup ...` procedure under that same non-root UID. Only the server initializes SQLite after the existing authenticated setup acknowledgement. Preparation neither creates a database nor supplies a second bootstrap authority.

A fresh installation uses `/var/lib/vsk-labs/control/control.db`. A legacy database at `/var/lib/vsk-labs/control.db` blocks this path rather than being moved, replaced or ignored. Moving existing data requires a separate data-preserving migration procedure; role installation does not perform one.

The approved `debian.role.apply` action installs the exact inert `vsk-labs.service` unit. It does not stop the foreground process. Its command remains the same executable's `server run` with the protected configuration and no persistent `--setup` argument.

A separately acknowledged `debian.control.handoff` action binds the foreground process identity, UID, database instance and recovery epoch, writer lock, executable/configuration/unit digests and expiry. Its bounded OS-manager job belongs to the same executable. Scheduling is pending completion, not service success. A fresh acknowledged `debian.control.handoff.verify` continuation verifies the recorded terminal result and current service state; the interrupted original run remains partial. An unchanged active control-role reapply verifies exact declared state without writing files or restarting the service; it does not authorize a live configuration transition.

On a failed or ambiguous handoff, preserve the database and configuration. Inspect the recorded pending/terminal state and verify that no writer remains before an explicitly authorized recovery using the same binary, configuration and database. Do not start a second foreground server, reuse an expired acknowledgement, kill an unrelated process or restart other services.

## Post-install checks and human fallback

Recollect every affected access/baseline control and the role observations after the change. An intent to mutate invalidates the older role evidence even if the effect becomes uncertain. The first installation consumes the current preparatory host baseline; it does not require the role to be installed before its own installer can run.

The human fallback uses these same preparation, exact-plan, acknowledgement and verification steps with the same target list and recovery prerequisites. It does not substitute raw privileged playbooks or service commands for the approved action. Application and CI roles require actual cross-user/process/filesystem isolation observations; configuration templates alone cannot prove isolation. Reserve roles must remain free of workload enrollment and credentials. Application, CI and standby slices have exact boot enablement links. Their bounded systemd-tmpfiles configuration recreates only the declared runtime directories after reboot; it contains no cleanup rule. Installation validates both unit and tmpfiles preimages before changes. Failure restores only owned file preimages and newly created enablement links, preserving accounts, directories and data. An unresolved installation journal blocks a subsequent apply before mutation and retains the original preimages; a retry cannot overwrite that recovery evidence. Inspect and resolve the interrupted operation through an explicitly approved recovery path before retrying.

Issue [#228](https://github.com/vegastack/vegastack-labs/issues/228) owns actual Debian native qualification, including reboot and effective service behavior. Missing native, storage, container or later-provider evidence remains a blocker. Synthetic tests do not qualify a host. Mac/iMac acceptance remains pending within v1, and nodes04/05 remain absolutely excluded from all operations.
