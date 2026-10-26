# Phase 8 software acceptance

Status: isolated feature acceptance is complete for issues [290](https://github.com/vegastack/vegastack-labs/issues/290), [291](https://github.com/vegastack/vegastack-labs/issues/291), [292](https://github.com/vegastack/vegastack-labs/issues/292) and [293](https://github.com/vegastack/vegastack-labs/issues/293), 26-10-2026. The final exact-head shipping proof and merge are recorded on issue293; closure is contingent on that proof, not on this document alone.

## Delivered operator paths

| Outcome | Existing public path | Evidence boundary |
| --- | --- | --- |
| Declare and inspect services | `service import draft`, `service list`, `service show`, `service observe` | Existing approved registration and scoped observations; registration does not establish workload admission. |
| Configure and deploy | `service configuration show`, `service deployment draft/show`, then existing `plan` and `apply` | Protected desired settings, explicit admitted target, fresh capacity/reservation, immutable signed artifact input, exact human approval, journaled provider writes and independent runtime health/image/resource/secret-hash observations. |
| Manage owned hosting/registry resources | `hosting lifecycle draft/show`, then existing plan/approval/apply | Exact team/project/environment/destination and Harbor namespaces, durable owned resource IDs, manual retention policy and two distinct protected system robot references. Unknown attempts do not replay. Existing team creation is an administrator prerequisite because the pinned API has no team-write route. |
| Install selected platform components | Existing `node action prepare` with finite `hosting.platform.install` or `hosting.platform.verify` | Signed host-action binding, protected complete Compose/environment bytes and preloaded immutable images. Installation refuses existing application data/containers and preserves controller database/unit identity. |
| Preserve and recover stack data | `service recovery draft/show`, then existing plan/approval/apply | Complete declared stack mounts, whole-stack cold consistency, encrypted backup/check and isolated restore with independent content/runtime checks. Platform and workload subjects are separate. |
| Migrate safely | Recovery freeze/restore, separate existing ingress plan, then recovery cutover | Actual source stopped, exact current route proof and durable writer boundary. After target writers, rollback to the old source is blocked; recovery/roll-forward needs a new plan. |
| Inspect results in Console | Existing Services and Changes views using generated API | Desired/blocked/partial/unknown results stay distinct. Scope denial/session expiry removes cached private records and aborts pending reads. |

The matching human procedures are [services](../operator-services.md), [hosting](../operator-hosting.md) and [workload recovery](../operator-workload-recovery.md). Preparation alone is inert; secret values never appear in these documents, public plans, results or audit records.

## Verification

The isolated test environment is one disposable local Debian 13 ARM64 guest with 2 CPUs, 2 GiB RAM and an 8 GiB disk, using `/var/tmp` for durable filesystem tests. No inventory node or live provider participates. Synthetic HTTPS/SSH peers exercise actual protocol requests and mutable fixture state; native Restic runs perform real encrypted backup, full repository read/check and isolated restoration. They are software proofs, not vendor installation or fleet qualification.

- Combined hosting API/declaration/plan/human-acknowledgement/run tests exercise real SQLite and actual TLS-backed resource creation/verification, including unknown effect, provider failure, current authorization/device/epoch denial and no replay.
- Recovery API tests exercise six approved/denied/unknown-effect branches through the same engine. Pinned Restic, actual archives, full check, independent recapture and source cleanup demonstrate data preservation. Registry checks bind the restored target transport and validate image content and pull-only permissions.
- Service tests exercise unknown/insufficient capacity, transactional reservations, retained partial attempts, configuration/health/resource identity and protected secret binding. Existing digest verification and compatible rollback proofs remain applicable.
- Fresh built-Console, single-worker browser checks cover visible states and privacy after revocation. Exact endpoint, generated contract and CLI source-boundary checks preserve historical baselines and add only this batch's approved scope.
- Final source commit, commands/results, screenshots and shipping proof are recorded in the four issue evidence comments. Unavailable or unrun checks are never counted as passed.

## Deployment limits

No live host, provider, Slack credential, CI job, release or public listener is changed by this batch. Website [264](https://github.com/vegastack/vegastack-labs/issues/264) remains dependent on Cloudflare permissions. Live deployment still needs actual provider versions/ownership, private credentials, admitted targets/capacity and explicit scoped authority. Nodes04/05 remain excluded, including indirect effects. Prior Phase6/macOS/advanced signed-recovery deferrals remain unchanged.

Placement also requires other running containers to have known enforced CPU allocations; unknown or unlimited external allocations block the capacity claim. Placement is explicit; there is no automatic scheduler or replicas/Swarm/HA system. Existing owned resources that cannot be safely reconciled through the finite typed operation remain blocked rather than being adopted or deleted by name. Source builds, registry publication and managed CI execution belong to Phase9. No full-v1/native or vendor deployment qualification is claimed.
