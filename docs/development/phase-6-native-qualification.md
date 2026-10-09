# Debian native qualification

Status on 10-10-2026: implementation and isolated Linux software verification are in progress under issue #228. Complete native qualification, cleanup acceptance and the integrated Linux report (#234) remain pending. Mac/iMac remain deferred within v1. None of these records authorizes fleet deployment or access to protected hosts.

## Evidence boundary

The same `vsk-labs` executable runs the ordinary server inside the controller guest and a finite outer QEMU/serial coordinator. Only the server owns SQLite. The coordinator checks its exact owned QEMU processes, prepared disk and firmware pins, guest identities, executable, original scope and absolute expiry. Guest links stay inside the approved isolated container.

Native qualification has baseline, role and recovery stages. The internal collector joins real current producer plans, executions, leases and receipts with fresh native observations. It produces a draft through the existing gate path. A normal plan and human acknowledgement must apply that draft. A JSON report is an export of results; copying it, uploading a matching bundle or supplying digests cannot confer native authority. Public evidence submissions remain fixtures.

The report consistency command checks complete scenario coverage, bindings, time bounds, positive and negative observations, recovery and cleanup:

```sh
pnpm check:phase-6-native --report /absolute/path/native-report.json
```

Its `consistent` result is deliberately not an authenticity result. Applied internally collected evidence and its producer records remain necessary. Virtual tests cannot prove physical hardware, power, thermals or the live deployment profile. Simulated Slack transport exercises the actual adapter and acknowledgement service but does not establish a real workspace binding.

The initial setup supervisor measures six setup/refusal/restart attempts before one final restart. After the six observations the supervisor waits for the private coordinator to apply the exact capability profile through the ordinary API, plan, acknowledgement and run. Empty protected markers sequence this wait and grant no authority. The original deadline still bounds the wait, and final startup independently checks the applied profile. The last restart installs the protected prepared profile, changing only the three existing action-signer fields and, when configured, the four existing local-backup fields. The witness binds the initial profile to the setup receipt and the final profile to the role input; all seven actual attempts are required. An absent or invalid backup configuration cannot establish recovery readiness.

Native preparation can submit the scoped profile and import only a closed administrator-prepared private SSH slot through existing APIs; plaintext is never placed in a preparation request or report. It can submit a bounded exact grant batch through the ordinary declaration, plan, acknowledgement and run path. It reads current database status after each successful mutation; an immutable run revision is not the current state revision. Preparation creates no authority outside the existing API.

## Human procedure

1. Read the current repository exclusions and the separately approved private environment packet. Resolve every physical and guest identity from existing records before connecting. Refuse an active worker, an unknown identity or insufficient approved capacity. Never dispatch shared CI or substitute another target.
2. Review the exact source commit, executable, image, offline packages, profile and guest preparation pins. Account for prepared and writable copies of every guest disk, retained inputs and runtime overhead. At most four guests must fit six CPUs, eight GiB memory and eighty GiB storage. The current private launcher leaves runner services unchanged and refuses or stops its owned fixture when a worker appears.
3. Prepare distinct disposable controller, subject, custodian and replacement identities. The replacement needs direct isolated paths to the subject and custodian, independent of the former controller. Keep synthetic credentials in protected private files; never place them in command arguments, reports or this repository.
4. Run `vsk-labs qualification inspect` with the protected configuration and bounded request. Start the reviewed finite native run with `vsk-labs qualification native --config <protected-profile> --file <protected-scope> --output json`. Use its numbered protected preparation, action, witness and collection slots. Each operation uses the same ordinary API, plan, grants and human acknowledgement as normal operation. Neither editing a slot nor declaring a host admits workloads.
5. Complete the generated scenario catalog, including actual allowed and denied SSH, idempotence, full rollback and Fail2ban waits, reboot, kernel/service controls, independent encrypted custody, credential lifecycle, bootstrap, installed roles and distinct replacement recovery. Do not shorten timers or replace unavailable native observations with fixtures.
6. For replacement, stage the actual backup-derived candidate, approve the finite recovery-receive action and send only its exact bounded candidate and journal. The receiver verifies the physical identity, approved executable and destination configuration; only the control UID opens SQLite. Existing destination files cause refusal and are preserved. Successful receipt suspends source mutation without changing its identity or epoch. The ordinary former-writer fence and recovery canary are still required before successor authority or alias commitment. An uncertain run after source suspension remains uncertain; it is not automatically retried or hidden.
7. Select the replacement controller only after actual health, identity and restore-binding checks. Restart it while alias ownership remains frozen, then verify unchanged ownership. After the required current-epoch proof and commitment, reboot the former guest and prove its attempted return is denied. The original scope and expiry do not renew.
8. Apply each complete internally collected stage through the ordinary gate plan. Preserve the exact evidence IDs, bundle and producer references privately. Request terminal cleanup, verify owned processes have exited, preserve the small sanitized report and perform only the approved exact owned-file cleanup. Verify that runner services retain their prior state. Cleanup uncertainty keeps acceptance pending.

## Failure and recovery

Stop the dependent lane when authority, identity, capacity, executable, current approval, observation or recovery evidence is missing. Preserve candidate files and logs; never overwrite a partial receiver or automatically reset a populated database. A source restart must not promote a candidate meant for a distinct replacement. Resume only from a separately reviewed valid state using ordinary recovery operations.

The coordinator's cancellation cleanup is bounded and targets only its owned QEMU processes. It retains disks for inspection. External container, file and runner cleanup follows the approved private procedure; a successful in-process cleanup does not prove external teardown. No host-wide prune, wildcard deletion or unapproved service action is permitted.
