# Debian baseline native preparation

This procedure describes code shipped by #226. It grants no machine access. Nodes04/05 are excluded, including indirect effects. Actual native qualification belongs to #228.

## Initial administrator prerequisites

Use the independent console and the same exact named-host approval as host-action preparation. The OS/profile, package versions, executable, central Ansible renderer and root action policy must match the approved lock. The baseline helper cannot install itself, acquire root, create signing keys, or fetch arbitrary packages. `ansible/roles/debian_baseline/tasks/prepare.yml` is a separately authorized administrator entry point: exact `name=version` package selectors, no cache update or broad upgrade, and package service starts suppressed during preparation. The package-soak assertion is an administrator installation prerequisite; it never creates qualifying evidence.

The role prepares root-owned private `/etc/vsk-labs/baseline` and `/var/lib/vsk-labs/baseline`. The existing host-action preparation owns the rollback service/timer/boot unit. The baseline handler reuses their protected record and lock. It saves previous file bytes and finite service states; audit restoration also restores the actual previous rate/backlog/failure limits. No new service or daemon is installed by this issue beyond the selected OS controls.

- Fail2ban owns only the `sshd` jail, `70-vsk-sshd.local`, `vsk-sshd.conf` and the `f2b-vsk-sshd` chain. Its SSH-only INPUT prefix can only drop individual source addresses and return; #225 rejects any access-granting or unrelated prefix. It cannot bypass the host access chain.
- Audit owns only `70-vsk-security.rules`, its approved bounded auditd configuration, and the `vsk-security` audit key. Reload deletes only that key, then loads the protected owned file. It never runs a blanket rule flush. Immutable audit state requires an explicit separate operator procedure; no automatic reboot exists.
- AppArmor profiles are existing package-selected files. Their bytes must match the declared digest and package verification must be clean. Loading never edits unrelated profiles or enables complain mode. Read-only observations do not claim native allowed/denied workload qualification.
- AIDE initialization/refresh is a separate signed action. `ApprovedChangeDigest` is the canonical JSON digest of the map from exact scoped absolute path to its current SHA256 content digest. Refresh also requires the previous database digest. The new protected database/reference is reported as `AIDEReferenceDigest`. Unexplained drift, an existing initialization target, stale preimage or retained incomplete `aide.new.db` refuses rather than overwriting it. An interrupted database/reference pair remains visibly mismatched for console inspection.

## Signed update and package-soak provenance

The read-only update collector uses a root-owned private `apt-sources.json` under `/etc/vsk-labs/baseline`. This is a finite source configuration, not an approval record. It contains `owner`, `soakSeconds` (at least 604800) and at most eight `sources`. Each source names only safe basenames: `sourceFile` under `/etc/apt/sources.list.d`, `releaseFile` under `/var/lib/apt/lists`, `keyringFile` under `/usr/share/keyrings`, the exact signing `fingerprint`, and `kind` (`snapshot` or `security`). A snapshot also names `packagesFile` under the same APT lists directory and its exact signed `packagesReleasePath`.

The approved profile's `PackageSourceDigest` binds the canonical map of source-file/keyring and immutable snapshot-release basenames to their actual SHA256 bytes. Unknown enabled source files and active legacy source entries refuse. Every release must pass the real `gpgv` signature check and remain unchanged during verification. Parsing is limited to the authenticated clear-signed body; unsigned trailers refuse.

A snapshot must be at least seven days old and, when upstream supplies `Valid-Until`, still within that signed validity. Official stable snapshots may omit expiry; their authenticated release digest remains pinned in `PackageSourceDigest`. Its signed SHA256 entry must match the actual Packages bytes containing every locked package/version. A separate security release must be current within 24 hours and have a present, unexpired signed expiry. No expiry timestamp is invented for a stable snapshot. A configured duration alone is never evidence. Missing compatible signed provenance yields an unavailable measurement; ordinary fresh APT metadata is not silently treated as seven-day proof. No collector updates packages, sources, keys or metadata.

## Human verification and recovery

Review the exact typed plan and declared control IDs, acknowledge through the configured Slack identity, execute once, and inspect actual result rows. A successful read operation can contain failed or unavailable controls. Those rows remain unqualified until the independent native acceptance and admission requirements are satisfied.

For partial baseline configuration, leave the 600-second rollback armed and inspect the exact protected record through the independent console. Restoration touches only saved owned files and the finite services actually changed; it preserves external drift and refuses uncertain state. Do not retry or refresh a reference to hide a failure. Reconcile any separately authorized emergency intervention into a new declaration and current collection.

Software tests substitute only filesystem/process boundaries. Real jail expiry, audit events, kernel confinement, signed repository verification and reboot repetition must still be exercised on the separately approved isolated #228 environment. No such native operation is performed by writing or merging these files.
