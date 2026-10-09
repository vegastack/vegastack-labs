# Debian baseline controls

Issue #226 extends the existing `vsk-labs` signed host-action path. The server owns plans, acknowledgements, execution receipts and SQLite results. There is no additional controller, daemon or result registry. Native qualification remains #228; host admission is owned by #229.

## Finite actions

| Action | Purpose |
|---|---|
| `debian.baseline.apply` | Apply only the selected reviewed baseline configuration after exact acknowledgement. |
| `debian.baseline.collect` | Observe the selected effective controls without repairing them. |
| `debian.aide.initialize` | Create a first protected control-role AIDE reference under explicit approval. |
| `debian.aide.refresh` | Replace that reference only with the exact previous digest and approved change. |
| `debian.volume.observe` | Observe an existing encrypted volume's actual mapping, mount and header. |
| `debian.volume-recovery.verify` | Test independently held recovery material against the exact current header without activation. |

Each action uses version 1.0.0 and the existing input/result size bounds. Select at most eight control measurements per action; larger collections require separately declared actions before acknowledgement. Extra actions are never invented at runtime. Source and custodian host scope is derived by the server from the sealed input and appears in the exact plan.

## What is observed

- SSH-only Fail2ban: five failures in 600 seconds, a 600 second ban, exact recovery-source exemptions, actual configured log attribution and bounded effective jail/action settings. Real ban/expiry and continued independent access must be qualified natively.
- Audit: only selected configuration watches, bounded rate/backlog/retention, actual enabled/lost/backlog state and rejection of broad argument capture. Only the owned audit key is removed/reloaded; unrelated audit rules are preserved.
- AppArmor: selected pinned profiles must be enforcing. Enabled service alone is insufficient; real allowed/denied workload probes belong to native qualification.
- AIDE: control role only, protected known-good baseline for stable owned configuration. Collection cannot refresh away unexpected drift. Logs, databases and container/build storage are excluded.
- Updates: exact installed package versions, one selected owner, signed source/key identity, actual signed package provenance supporting the seven-day soak, and separate current security metadata. A configured duration alone never proves soak. Missing provenance remains unavailable.
- Clock/resources/kernel: effective synchronization and bounded offset, declared filesystem headroom and service limits, and the finite selected kernel settings. Collection never sets the clock, deletes data or disables confinement.
- Storage: actual existing encrypted mapping and independently held recovery-key verification. See [volume verification](debian-volume-verification.md). Backup encryption or an administrator assertion cannot replace these two observations.

## Safe execution and recovery

The fixed central Ansible renderer uses pinned executable/version/collection/role inputs before the draft is sealed. Target handlers accept only finite owned formats and direct fixed commands. Unsupported OS/build/package ownership or unknown competing configuration is refused. First account/key/trust preparation remains an independent administrator task.

Configuration changes reuse the existing protected rollback record and 600 second local timer. It records only the exact changed baseline files and finite affected services; restoration does not overwrite unrelated files or restart unrelated services. Baseline confirmation follows actual effective collection; failed or uncertain observations do not grant admission. AIDE reference creation/refresh has its own explicit atomic approved operation and never silently blesses drift. No ordinary baseline action reboots or formats a host.

Human procedure: inspect the exact host/profile/current blockers → prepare the finite inert draft → review its readable/JSON plan → request and receive the configured human Slack acknowledgement → apply once → inspect the actual run and measured results. Do not retry a partial mutation automatically. Use the independent console to inspect the owned rollback state and follow the same exact previous-state restoration procedure; a manual emergency intervention requires a fresh reconciled declaration and recollection.

Results retain failed, partial, unsupported and error states. A successful collection operation may truthfully contain an unavailable control; this is not a passed control or qualified host. The server binds canonical measurements to the actual plan/run/step/lease/receipt, current identity and recovery epoch. Gate readers expose only verified completed steps. Relevant identity/profile/role/declaration or custody changes invalidate eligibility; missing qualification remains a blocker.

## Development and live boundary

Ordinary tests use temporary roots/databases, synthetic SSH/Slack peers and narrowly injected OS boundaries. The approved isolated Linux test environment is separate from fleet authority. Native package/service/kernel, ban expiry, reboot, real cryptographic key and allowed/denied packet qualification must be measured under #228's exact profile. Implementation does not pass either host gate, enable workloads or complete Phase 6.

Nodes04/05 remain absolutely excluded. Mac/iMac remain deferred within v1. No deployment, real Slack setup/message, release or existing application/database change is authorized by this document.

### Failure containment corrections

- AppArmor uses an all-profile preflight. Existing enforcing profiles are unchanged; only an absent self-contained single profile can be added with its exact absence recorded in the existing rollback record. Unknown/complain/include-dependent prior state refuses automated change. Partial additions are removed through that same timer recovery path.
- Baseline rollback distinguishes stopped services from active services. Early boot queues the exact prior state and retains `services-pending`; the existing timer must later observe restoration before reporting `restored`.
- AIDE validates the candidate database and approved scoped content again before replacing the old reference; it cannot approve its own changed configuration using an old content digest.
- Audit checks require local events, disk logging and the fixed audit log destination. Update-owner checks reject unavailable unit observations and require effective selected-owner APT settings and timer activity. Native behavior remains separately qualified by #228.

AppArmor rollback ownership is recorded separately from the planned profile list in the existing protected record: an add is pending before invoking the parser and owned only after successful completion is durably saved. A profile appearing before our add is never removed by rollback. Failed/interrupted additions and profiles loaded after reboot have ambiguous ownership and remain untouched with an explicit uncertain recovery state. Earlier durably successful additions may be removed during the same boot; this does not turn an ambiguous later addition into a completed rollback.
