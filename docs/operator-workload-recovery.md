# Consistent platform and workload recovery

`vsk-labs service recovery draft` prepares an inert declaration. The existing
plan, infrastructure-administrator acknowledgement and central run executor are
required before the server can stop containers, capture data or restore anything.
`vsk-labs service recovery show --config <profile> --service-id <id>` reads the
latest journaled result. Registration and public fixtures confer no live authority.
Nodes04/05 remain excluded, including indirect actions and reads.

## Exact prerequisites

The protected server `serviceRecoveryProfiles` entry binds one logical service,
policy, source/target physical identities, distinct SSH mutation references,
complete Compose component and mount inventory, immutable image digests, byte/time
limits and protected local restic repository/exchange directories. The finite
consistency procedure is `docker-stack-cold-v1`. A platform subject additionally
has `platformOwnerId`: it uses actual managed/discovery/admission records and host
read grants without inventing a Coolify application registration for Coolify itself.
Ordinary application/Harbor subjects use their actual registered service bindings.

Both hosts need current role admission. The target must be a different physical
machine, with an already created, stopped, same-version stack and empty storage.
Every component needs an explicit Docker health check and `restart: "no"` for the
cold-maintenance workflow. The server requires the exact complete project set,
image RepoDigests and mount identities; missing members and another container
holding a declared source volume block execution. Shared mounts must consistently
map to the same isolated target storage. No arbitrary shell command or hook is an
input. Mount archives reject traversal, unsupported special files and links outside
the captured mount; unsupported data layouts remain blocked.

Target networks must be Docker internal networks. Published ports may bind only
to loopback. Do not attach production clients or routes during a restore rehearsal.
The protected Harbor verifier endpoint uses that target's pinned SSH connection
to the exact verified loopback port; TLS verifies the protected registry hostname.
It cannot point to an unrelated healthy registry.
This operation does not install Docker, Compose, Harbor, Coolify, a new host agent
or host networking rules. Their installation and qualified capacity are separate
prerequisites. Stopping a platform Compose stack does not stop or reinitialize the
independent `vsk-labs` OS service or its SQLite database.

Credential consumers are `service.recovery` / `workload-recovery` /
`credential.service-recovery.mutate` and `service.recovery.repository` /
`workload-repository` / `credential.service-recovery.repository`. Source and target
mutation keys belong to their exact logical subjects and differ from read-only
runtime observation credentials. Harbor checks additionally borrow the existing
registry observation reference. Keep values in the normal protected secret store.

## Backup and isolated restore

1. Prepare a private request with schema
   `vegastack-labs.dev/service-recovery-draft-request`, schemaVersion `1.0.0`,
   serviceId, policyId, action `backup`, empty backupPointId, current
   expectedStateRevision/recoveryEpoch, idempotencyKey and reasonDigest. Run
   `vsk-labs service recovery draft --config <profile> --file <request.json>`.
2. Inspect its identical readable/JSON plan, request the normal human approval,
   and execute that exact plan through the ordinary `plan`/`run` commands. The
   server checks scope and identities, journals the attempt, stops the complete
   stack and independently verifies it is stopped before capturing every mount.
3. The server stages bounded archives privately, binds content/mode/ownership
   hashes in a distinct workload manifest, encrypts the directory with the pinned
   restic child, checks the returned snapshot and performs a full repository read.
   The object boundary grants append-only writes; restore uses a read-only lease.
   A first empty protected repository is initialized; an existing repository is
   never reinitialized after a key/configuration failure.
4. After any ordinary backup stop attempt, bounded cleanup restarts exactly the
   previously running component set, including after cancellation. Source health
   failure remains `partial`; it never becomes backup success. No source data is
   deleted. Inspect the recovery result and retain its backupPointId.
5. Prepare a new action `isolated-restore` naming that backupPointId and fresh
   state/epoch/idempotency values; obtain approval for its exact plan. The server
   restores the exact encrypted snapshot into a fresh staging directory, verifies
   every archive, proves target mounts empty, copies only those mounts, re-captures
   and compares restored content, then starts and observes component health.
6. Registry restores also authenticate an exact artifact read and actual immutable
   manifest/config/all-layer pull and prove a pull-scoped token cannot start an upload. Provider
   lifecycle checks own the two system robots' configured scope/expiry. An unavailable
   scanner remains unavailable; these checks do not turn scanning into a pass or
   fabricate all-project/robot qualification. Required unsupported checks block.

The journal distinguishes source resume, source fence, isolated restore verification,
actual source image digests, elapsed time, failure and next action. A SQLite online
snapshot, restic exit status or operator-entered receipt cannot create workload
restore evidence. Stateful service deployment reads current applied restore proof
from this journal, tied to its exact service/policy/epoch and restored image set.
The local encrypted repository does not by itself establish off-site/R2 retention,
independent key recovery or live G-008/G-015 qualification.

## Migration and recovery decisions

A rehearsal leaves source service availability unchanged. For final migration,
prepare a new exact `migration-freeze` plan: it takes the final cold snapshot and,
only on verified backup success, intentionally preserves the source stopped with
restart disabled. Failure runs the normal source cleanup. Restore its exact point
to the declared empty isolated target through another approved plan; preserve both
source and target datasets.

Routing remains the existing owned ingress workflow. Its separately acknowledged
plan moves the actual route. A `migration-cutover` recovery plan can finalize only
when current applied ingress observations match the exact declared target origin,
port, identity, ownership binding and epoch, and SSH independently proves the
source remains stopped. Missing route/fence evidence blocks; no database flag
stands in for a routing mutation. A historical applied target route permanently
crosses the possible-writer boundary even if someone later changes the route back.

Before any target route/writer admission, `rollback-before-writers` requires an
independently stopped target, an exact current source route and no historical
applied target route; only then may its approved plan start the preserved source.
After target admission, old-source image rollback is denied. The result requires
a new consistent target backup/restore or an explicitly scoped roll-forward plan;
`recovery-after-writers` reports that requirement and cannot restart the old source.
No operation writes to both stacks or automatically destroys a failed target.

The human fallback follows the same identity, full-target, approval, complete
inventory, stop verification, encryption, isolated restore/content/health and
writer-boundary prerequisites. If normal execution is unavailable, preserve both
copies and use the separately authorized emergency procedure with its required
audit and reconciliation; these instructions do not authorize raw Docker/SSH or
provider commands outside the deterministic plan path.
