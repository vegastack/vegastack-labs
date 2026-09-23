# Credential lifecycle and recovery procedure

This is the human-readable equivalent of the `vsk-labs` credential lifecycle. It uses the same protected input, declaration, exact plan, independent acknowledgement, action-scoped execution, verification and recovery prerequisites as automation. It supplies no live authority and cannot close `G-007`.

## Preconditions and safe inputs

- Work from the protected local operator client against the intended `vsk-labs server run` instance. Record the current state revision, recovery epoch and target. Browser and remote-read transports cannot submit credential lifecycle requests.
- Confirm the assigned human has the exact `plan.acknowledge` grant and the executor has the exact `credential.stage`, `credential.activate`, `credential.rotate`, `credential.revoke` or `credential.recover` grant for the execution target. Lifecycle policy preauthorization is unavailable.
- Pass private import bytes only through standard input or an already-open descriptor. Never place material in JSON, arguments, environment variables, logs, prompts or SQLite. Public files contain metadata only.
- For activation or rotation, verify the declared systemd units, service UID/GID bindings, one artifact consumer, every positive consumer and every required denied reader. For recovery, first satisfy the independent-source and replacement-authority prerequisites below.

## Stage and activate

1. Run `vsk-labs credential import` with the exact public reference, consumer, purpose, target, `native-systemd` resolver, material version, current revision/epoch and unique idempotency key. Record only the returned draft ID, fingerprint and revision/epoch.
2. Submit `vsk-labs credential stage --config <profile> --file <metadata.json>`. Plan the returned declaration with `vsk-labs plan`, inspect the exact target and imported draft binding, obtain the independent human acknowledgement, and apply that immutable plan. Inspect the durable run and confirm the named version is `staged`; it must not be selected as current or delivered to a process.
3. Submit and plan `vsk-labs credential activate` for that exact staged version and complete consumer/denied-reader set. After independent acknowledgement, apply it once. Confirm the run records a restart, the name-bound credential observed by every declared consumer, every required denied reader returning denied, and the version becoming `active`.

## Rotate and revoke

1. Import and stage the successor exactly as above. Keep the existing version active.
2. Submit `vsk-labs credential rotate` naming the staged successor, exact prior active version, complete consumer sets and an overlap no greater than the supported maximum. Plan, inspect, independently acknowledge and apply the exact rotation.
3. Verify the successor is the logical current version and all required consumer evidence passed. The prior version remains explicitly `active` during the declared overlap; rotation never silently revokes it.
4. Before the overlap expires, submit a separate `vsk-labs credential revoke` for the exact prior version. Plan, independently acknowledge and apply it. Confirm the prior version is `revoked` and the successor remains current. Never revoke the only working version to repair a failed rotation.

## Clean-host recovery

1. Keep the replacement read-only. Complete the authoritative restore and fencing procedure, advance the recovery epoch there, invalidate prior plans, leases and sessions, and prove the former controller and each current mutation boundary deny the old identity. Epoch advancement alone is not a fence.
2. Have the independent administrator install the signed public manifest, qualified direct-denial set and encrypted custody handoff at the fixed protected recovery paths. The replacement recipient key comes from its protected service credential. Do not copy the former host key or place opened material in a file.
3. Import a new inert draft under the replacement host key in the already-current epoch. Submit `vsk-labs credential recover` with the exact prior epoch and public custody/fence digests. Inspect the plan's draft origin, ciphertext fingerprint, target, revision and both epochs.
4. After independent human acknowledgement, apply once. The installed recovery source must verify the signed package, freshness and complete denial set, consume its one-use receipt, open the exact protected ciphertext inode, and compare the stream with independently supplied material. A successful effect appends a `staged` version and recovery evidence only. Activate it through a separate plan after native positive and denied verification.

## Verification and failure recovery

Inspect each run with `vsk-labs run inspect` and re-read the credential reference. Preserve the import, declaration, plan, acknowledgement, sanitized run, version history, recovery record and audit chain. Check that public plan/run JSON and database files contain no private input.

If a revision, epoch, consumer, digest, inode, receipt, source, restart, positive read, denied read or fence check fails, stop. Do not retry an uncertain effect, reuse a recovery receipt, edit SQLite, overwrite ciphertext, widen the consumer set, copy a host key or call a fixture live evidence. Reinspect the durable run. Preserve the failed artifacts and last working version, correct the named prerequisite, refresh observations, and create a new declaration and plan. For recovery uncertainty, use a new challenge, independently signed manifest and one-use receipt. The control-database restore and epoch transition remain governed by the existing backup/restore procedure in [Security and operations](security-and-operations.md#verification-and-recovery-cases); this procedure does not duplicate or bypass it.
