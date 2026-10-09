# Read-only Debian volume verification

Issue #226 implements observation of an already encrypted volume and an independent recovery-key test. It does not encrypt, format, unlock, mount, unmount or reimage a disk. Native qualification remains #228; software fixtures do not admit workloads.

## Prerequisites and preparation

Use the existing exact signed host-action path and administrator preparation. Nodes04/05 are excluded, including indirect operations. Each real preparation or operation needs its own scoped authority; the development test permission does not authorize fleet use.

The subject binding names the exact host identity, protected mount, active mapper, backing major/minor numbers, LUKS UUID, selected bound keyslot, bounded header digest/length, mapping and mount digests, declaration and recovery epoch. The custodian must differ from both the subject and control host. An independent administrator binds the custodian's recovery-reference ID/version and privately prepositions the already-held key and exact header copy. No controller request carries either secret.

`PrepareVolumeRecoveryPolicy` is an inert library operation returning the finite policy bytes and their digest. The administrator supplies the separately verified cryptsetup executable digest. Its binding digest excludes only `RecoveryReferenceDigest` to avoid self-reference; the returned policy digest fills that field before the final action is acknowledged.

The fixed custodian location is `/etc/vsk-labs/volume-recovery/<reference-id>/`, containing `policy.json`, `header` and `key`. All ancestors are protected and root-owned; those files are regular, root-only, single-link files. No API-selected filename, symlink, arbitrary device or alternative key source is accepted. Preparation does not create a recovery key or export a live header.

## Exact operation and expected result

1. Inspect the current declaration, host identities, profile/tool/package pins and independent console prerequisites through the existing server API.
2. Prepare an inert `debian.volume.observe` action for the subject, with at most eight declared volume controls. Review its exact plan, obtain the configured human Slack acknowledgement and execute through the same engine as other host actions.
3. The observer reads mountinfo, sysfs and the exact block device. It requires an active, unsuspended LUKS2 mapping, one backing device, the selected data-bound keyslot, supported cipher geometry with mapping offset/size joined to header segment geometry, and identical current mount/device/header bindings before and after the read. Plaintext bypass, ambiguous stacks or changed identities are refused.
4. Prepare `debian.volume-recovery.verify` on the independent custodian. The sealed input includes the actual prior observation receipt digest, exact subject/custodian scope and recovery reference version. Review and acknowledge its new exact plan.
5. The verifier checks protected source ownership, the pinned tool, the header digest/UUID and selected keyslot, then performs a bounded cryptsetup test-passphrase operation. The key travels through a private inherited descriptor, is bounded to 8–4096 bytes and is cleared from the owned buffer. No mapping name or activation command is supplied.
6. Both operations pass cryptsetup a sealed anonymous in-memory header copy. This is necessary because cryptsetup can automatically repair inconsistent LUKS2 metadata during reads. Both status calls explicitly use that sealed header override. Recovery executes the exact verified cryptsetup bytes through a sealed executable descriptor, so replacement of the tool pathname cannot redirect the key. The child receives neither the physical device descriptor nor the custodian's original header descriptor. Kernel seals prevent writing or resizing the copy, including after reopening it. Original bindings are rechecked before a result is emitted.
7. Read the actual run/result. The server appends bounded sanitized measurements only against the matching execution receipt and verified step. Volume admission requires both current subject and independent custodian receipt chains plus the separately applicable native qualification. A passed key test alone never establishes the mounted volume's encryption.

There is no automatic retry or repair. Failure leaves existing data and mappings in place, records no successful verification and requires inspection of the named prerequisite. Changed identity, header, slot, key-reference version, declaration or epoch requires a fresh observation and acknowledged plan. Physical recovery and header replacement are separate operations outside this verifier.

## Verification limits

Focused tests cover metadata bounds and selected-slot binding, plaintext/ambiguous mapping denial, private file ownership and link refusal, changed header and failed key denial, sanitized results, geometry mismatch/overflow, executable-path replacement, and actual Linux write/truncate refusal on a sealed descriptor. Temporary-root tests substitute only the cryptographic process boundary; they do not prove that a real recovery key opens a real encrypted device. #228 must run the actual pinned tool against an already encrypted disposable fixture, prove correct/wrong key and header/slot cases, and compare header/device bytes and active mappings before/after, including an inconsistent redundant-header fixture around both status calls.

Mechanism sources checked on 09-10-2026: [Debian cryptsetup-open manual](https://manpages.debian.org/trixie/cryptsetup-bin/cryptsetup-open.8.en.html), [Debian luksDump manual](https://manpages.debian.org/trixie/cryptsetup-bin/cryptsetup-luksDump.8.en.html), and the upstream [LUKS2 disk metadata implementation](https://github.com/mbroz/cryptsetup/blob/master/lib/luks2/luks2_disk_metadata.c). Qualification pins the actual installed package; these references are not runtime qualification evidence.
