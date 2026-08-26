# Implementation gates and evidence procedures

This appendix turns every remaining audit item into an executable gate. It does not claim that physical inspection, provider configuration, real-host testing or a production mutation occurred. A design can be closed in this specification while its activation evidence remains required.

The portable platform owns the gate/evidence model. Concrete serials, node candidates, provider choices and phase numbers below belong to the VegaStack Labs deployment profile. [Architecture boundary](../README.md#architecture-boundary)

Generic gate ownership, applicability and profile-version rules are defined in [portable lifecycle](platform-lifecycle.md#identity-and-configuration). The following ledger is selected only by the Labs profile. Local service initialization uses its own finite prerequisites, not post-install site evidence. Development stage numbers and deployment stage numbers are different namespaces.

## Gate semantics

Each gate has two independent states:

- **Design state** — whether this specification defines the mechanism, owner, collection method, acceptance rule, failure behavior and recovery.
- **Activation state** — whether a trusted actor has supplied current evidence and the checks passed for the exact subject, release and recovery epoch.

`design-closed` never means “deployed.” Activation is one of `evidence-required`, `implementation-required`, `conditional` or `deferred`. Only a gate evaluation bound to the current recovery epoch can admit a phase. Evidence expiry, subject replacement, failed recheck or a recovery-epoch change reopens it automatically.

Evidence submission is inert: `vsk-labs gate evidence --gate <gate-id> --file <path>` validates a bundle and creates a draft. The normal `plan --change` then `apply --plan-id` path records it. Closure is derived from the applied evidence plus deterministic checks; there is no privileged `gate close` shortcut.

## Gate ledger

| ID | Gate | Design state | Activation state | Accountable owner | Exact remaining evidence and acceptance | Phase effect |
|---|---|---|---|---|---|---|
| `G-001` | Serial/node-map integrity | design-closed | evidence-required | lead infrastructure operator | console/label photos or signed physical worksheet for `PF4F10C1` and `PG025CNM`; one-to-one serial/node uniqueness; approved Sheet correction and credential-hygiene attestation | blocks affected physical identity/hostname/role bindings; not unrelated local setup |
| `G-002` | Host discovery and qualification | design-closed | evidence-required | infrastructure operator | signed discovery bundle per host with model, serial, CPU/architecture, RAM, disks/health, battery, firmware, NIC/MAC/link, temperatures and burn-in results; all role checks pass | blocks affected host admission and capacity role |
| `G-003` | LAN facts | design-closed | evidence-required | network operator | sanitized router export/screenshots and measured record of subnet, gateway, DHCP pool, reservation range, conflicts and HX510 controls; no credentials | blocks phase-1 network apply |
| `G-004` | ES216G receipt and configuration | design-closed | evidence-required | network operator | SKU/revision/firmware, labeled port map, loop-prevention state and successful export/restore rehearsal | blocks phase-1 switch apply |
| `G-005` | Cloudflare Mesh pilot | design-closed | evidence-required | access-adapter owner | account/client/device-policy compatibility plus 30-day results meeting the reconnect, route, MTU, loss and throughput rules below | blocks phase-2 exit; prerequisite failures block pilot start |
| `G-006` | CI runner controller and admission | design-open: actual-job admission qualification | evidence-required | CI adapter owner | explicit enrolled repository/workflow list; runner group/label proof; hostile-job isolation, one-job lifecycle, cancellation cleanup and external-log preservation tests | blocks phase-4 runner enrollment |
| `G-007` | 1Password topology and recovery | design-open: physical-vault reader-set layout | evidence-required | secrets administrator | actual vault/item IDs, scoped service-account grants, offline recovery custody receipt, positive reads and all required negative reads | blocks phase-3 provider credential activation |
| `G-008` | Backup repositories and recovery | design-open: compatibility qualification | evidence-required | backup administrator | pinned restic binary digest, SSD/R2 repository IDs, capacity forecast, R2 lock proof, independent key recovery and functional clean-host restores | blocks phase-3 control acceptance |
| `G-009` | UPS and unattended recovery | design-closed | evidence-required | infrastructure operator | UPS model/rating, protected-outlet map, measured load/runtime and successful automated shutdown plus unattended boot test | blocks always-on roles in phases 1, 3 and 4 |
| `G-010` | Measured role thresholds | design-closed | evidence-required | role owner | real-host burn-in results meeting the common and role-specific thresholds below | blocks the corresponding phase-1/4 role |
| `G-011` | Independent alert delivery | design-closed | evidence-required | lead operator | named primary/secondary recipients and tested off-site delivery route that depends on neither home control nor GitHub; failure and recovery receipts | blocks phase-3 operations acceptance only |
| `G-012` | Tunnel connector placement | design-open: credential/rotation boundary approval | evidence-required | access-adapter owner | qualification of two explicitly selected application nodes from `vsk-node-03`/`vsk-node-05`/`vsk-node-07`, protected per-host secret custody, reviewed tunnel-scope rotation/containment and single-connector failure test; substitute only by plan | blocks each selected Tunnel route activation, including minimal control ingress during control acceptance and later application ingress |
| `G-013` | LAN managed-network marker | design-closed | evidence-required | access-adapter owner | a qualified selected application-node host, pinned TLS certificate fingerprint/expiry/rotation owner and safe remote-profile fallback test | blocks phase-2 managed-network activation |
| `G-014` | Coolify initial release | design-closed | evidence-required | platform administrator | revalidate selected `v4.3.10`, tag commit and installer digest; clean install/backup/restore/rollback proof on the qualified control host | blocks selected Coolify activation; not initial local vsk-labs service creation |
| `G-015` | Harbor migration inputs and target | design-closed | evidence-required | registry owner | source version/size/growth/layout/users/projects/robots/rules, chosen stable hostname, qualified target-node evidence, consistent backup and isolated restore/cutover rehearsal | blocks phase-5 Harbor migration |
| `G-016` | Provider mutation ownership | design-closed | evidence-required | adapter owner named per instance | actual Cloudflare/Coolify owners, scoped credentials, owned-resource manifests and positive/negative canary tests | blocks the first mutation by each adapter |
| `G-017` | Platform release identity and feeds | design-closed | evidence-required | platform release owner | exact repository/workflow identity, feed URLs, OIDC issuer/identity policy and successful offline bundle verification for every asset | blocks first platform release and every site installation, including initial local setup |
| `G-018` | Generated command/schema registry | design-closed | implementation-required | platform implementation owner | source repository generates commands, JSON schemas, errors and exit codes from one metadata graph; cross-platform golden and compatibility tests pass | blocks first mutating platform release |
| `G-019` | First application deployment identities | design-closed | evidence-required | project maintainer plus Coolify team owner | project/team/resource/environment map, token owner/expiry, `write`+`deploy` positive test and denied cross-team/root/read-sensitive/unclaimed/stale-lease tests | blocks that project's first digest deployment |
| `G-020` | macOS CI lane | design-closed | evidence-required | CI owner plus Mac owner | current preview recheck, measured self-hosted Mac limits and successful `macos-15-intel` hosted fallback plus protected manual Apple-silicon-only lane | blocks self-hosted Mac runner admission, not Linux CI |
| `G-021` | iMac Hermes limits | design-closed | evidence-required | Hermes role owner | single-session soak with memory pressure, responsiveness, thermal and disk evidence under the limits below | blocks iMac Hermes acceptance |
| `G-022` | Later service admission | design-closed | conditional | assigned service maintainer | owner, environments, resources, exposure, backup, health, migration, rollback and placement evidence for that service | blocks only that service's first plan |
| `G-023` | Chaabi Prod | design-closed | deferred | future application/service owner | a separately authorized post-v1 discovery and migration plan | no v1 phase is blocked; mutation is prohibited in v1 |

## Evidence bundle contract

The implementation stores gate definitions, evidence metadata, checks and evaluations in SQLite. Attachments live in a permission-restricted evidence directory and are addressed by digest; critical evidence is included in encrypted backups. Credentials, recovery codes, unredacted router exports and secret-bearing screenshots are prohibited. A photo or export containing sensitive identifiers is marked restricted and never projected to D1, notifications or routine agent context.

```json
{
  "schema": "vegastack-labs.dev/gate-evidence",
  "schemaVersion": "1.0.0",
  "gateId": "G-002",
  "subjectRefs": ["node:vsk-node-01"],
  "recoveryEpoch": 3,
  "collectedAt": "2026-08-25T12:00:00Z",
  "collector": {"actorId": "operator:<id>", "deviceId": "device:<id>", "method": "local-console"},
  "facts": [{"name": "network.link_mbps", "value": 1000, "unit": "Mb/s", "source": "os-observation"}],
  "checks": [{"id": "link.full_duplex", "status": "passed", "observed": "full", "expected": "full"}],
  "attachments": [{"logicalName": "discovery.json", "sha256": "<64-hex>", "mediaType": "application/json", "storedRef": "evidence:<opaque-id>"}],
  "approvals": [{"class": "physical-fact", "actorId": "operator:<id>", "acknowledgedAt": "2026-08-25T12:05:00Z"}]
}
```

Required invariants:

- the gate, subject, adapter/release versions, recovery epoch, collector identity and collection time are explicit;
- facts carry unit and collection method; absence is `unknown`, never an empty success;
- checks record observed and expected values, not only `passed`;
- attachments are hashed before import; the database records no arbitrary absolute client path;
- one actor cannot satisfy a two-person physical/destructive approval where the gate requires both;
- evaluation is deterministic and produces `passed`, `failed`, `expired` or `blocked`; manual override creates a separate time-bounded exception plan, never edits evidence;
- replacement/reimage, version change or evidence expiry invalidates only the affected subjects and downstream gates.

## Physical, LAN and acceptance procedures

### Inventory and discovery — `G-001` through `G-004`

1. At local console, match chassis label/firmware serial to the active Sheet row. A second operator signs the disputed `vsk-node-05` mapping. Do not infer identity from hostname, IP or an existing OS install.
2. Collect OS-neutral hardware facts plus Linux `lscpu`, `lsblk`, `smartctl`/NVMe health, firmware, battery, NIC and link observations; on macOS use `system_profiler`, `diskutil`, `pmset` and supported health APIs. Collector commands are invoked as fixed argument arrays and redact usernames, Wi-Fi names, public addresses and serials not required by the gate.
3. Import the approved map only after the Sheet has been corrected by its human owner and credential-like fields have been removed/rotated. This audit never edits the Sheet.
4. Record the HX510 facts from its local administration interface without exporting passwords or session tokens. Reservations must sit outside the dynamic pool and have no duplicate MAC/IP.
5. For the ES216G, photograph the label, hash the downloaded official firmware, label every cable/port, export configuration, reset or use a spare configuration slot where supported, restore the export and prove management plus forwarding before acceptance.

The [network-device operations plan](network-device-operations.md) supplies the feature/evidence checklist for these gates: identify the actual DHCP authority and both HX510 modes; verify firmware-specific reservation behavior; capture management protocol/access, standalone ownership, persistence and compatible recovery support. Do not infer a switch DHCP server, SNMP/CLI, spare configuration slot or firmware rollback. Discovery does not authorize a reset; any disruptive restore rehearsal needs its own approved targets, outage and local recovery. Private configuration exports may contain secrets and belong only in the protected recovery store, never evidence pasted into GitHub. Pending reservation-policy or management-security decisions block the affected implementation or apply, not unrelated development.

### Common numeric qualification — `G-005`, `G-009`, `G-010`, `G-020`, `G-021`

These are v1 default acceptance rules. A stricter role may add checks. A weaker value requires an explicit exception plan with impact and expiry.

| Check | Default acceptance |
|---|---|
| host burn-in | 8 continuous hours at expected role concurrency; no kernel panic, unexpected reboot, I/O error or vendor critical-health flag |
| CPU/thermal | no reported throttling; sustained temperature remains at least 10°C below the hardware-reported critical limit |
| memory | peak used memory at or below 85%; no OOM; swap growth below 1 GiB and returns after workload cleanup |
| disk | SMART/NVMe overall health passes; no uncorrectable/media error increase; free space is at least the greater of 20% or 50 GB after role installation |
| wired link | 1,000 Mb/s full duplex; zero carrier changes and zero error-counter increase during a 60-minute bidirectional test |
| WAN/backhaul | packet loss below 1%; p95 latency below twice the direct-router baseline; sustained throughput at least 70% of the measured direct-router baseline |
| UPS | measured steady load at or below 60% of rated continuous capacity; at least 15 minutes runtime; graceful shutdown completes with at least 5 minutes measured margin; unattended restart succeeds |
| two-job Linux CI | representative two-job workload for 2 hours while all common limits pass; cleanup leaves no runner/workspace/process and disk returns within 5% of pre-test use |
| Mac mini interactive protection | one native job; interactive latency and memory-pressure state remain acceptable to the Mac owner; job is drained immediately on pressure/throttle |
| iMac Hermes | concurrency starts and remains at one; memory used at or below 75%, no red memory-pressure state, no swap growth above 1 GiB and at least 20% disk free |

Mesh pilot acceptance requires 30 consecutive days with no unresolved route collision, no direct-origin bypass, 100 successful reconnect cycles with p95 below 60 seconds, MTU validation for every selected path, packet loss below 1% and throughput meeting the WAN/backhaul rule. ISP outages are recorded separately but do not erase failed client/route evidence.

## Selected implementation mechanisms

### CI controller, runners and logs — `G-006`, `G-020`

Acceptance binds the actual assigned job, not just the triggering event: prove trusted admission before checkout/user steps/secret delivery despite shared labels, competing jobs, cancellations and controller loss. The admission mechanism cannot be modified by a job. Group/label configuration and `--ephemeral` alone are insufficient proof. [GitHub routing](https://docs.github.com/en/actions/reference/runners/self-hosted-runners#routing-precedence-for-self-hosted-runners)

The selected controller is the GitHub CI adapter inside `vsk-labs server run`; no Kubernetes or second controller service is introduced. It mints short-lived registration tokens with the smallest selected-repository/organization credential, launches a pinned GitHub runner with `--ephemeral` over the existing constrained SSH adapter, and destroys the job container/workspace after the single job. The runner version must be both current enough for GitHub's service window and actually offered in the repository's generated setup instructions because GitHub rolls versions progressively.

- Linux group: `vegastack-labs-trusted-linux`; labels: the default `self-hosted`, `linux`, `x64` plus `vsk-ephemeral` and `vsk-build`.
- macOS group: `vegastack-labs-trusted-macos`; labels: `self-hosted`, `macOS`, `ARM64`, `vsk-ephemeral` and `vsk-apple`.
- Repositories are denied until an explicit enrollment row names owner, workflow paths, immutable action SHAs, allowed events/refs, secrets class, concurrency and cache namespace.
- The builder host captures runner diagnostic/process output outside the disposable workspace into root-owned journald. A narrow authenticated collector streams sanitized records to the control server's append-only run evidence before job completion; the control backup includes them under the six-month security/execution class. Failure to preserve the log marks the job `partial` and blocks deploy authority.
- Linux build jobs use rootless BuildKit inside the disposable environment. Deploy credentials are released only to the separate admitted job after plan authorization.
- ARM64 self-hosted macOS remains public preview as revalidated on 25-08-2026. Fallback is GitHub-hosted `macos-15-intel` for compatible build/test work plus a protected manual Mac-mini lane for Apple-silicon-only validation; no preview lane is silently treated as mandatory. [GitHub self-hosted runners](https://docs.github.com/en/actions/reference/runners/self-hosted-runners) · [GitHub monitoring](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/monitor-and-troubleshoot) · [GitHub-hosted runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners) [D-111](decisions-and-sources.md#d-111)

### 1Password layout — `G-007`

The purpose categories below are logical groups, not permission boundaries. 1Password service accounts grant access per physical vault, not per item/field; references or resolver allowlists cannot narrow a stolen provider token. Split physical vaults wherever authorized reader sets differ. The previous mixed-trust layout is superseded; the exact credential-to-vault-to-consumer matrix needs phase-5 solution review and G-007 qualification before credential activation. No broader grants or new provider are implied. [1Password service-account permissions](https://www.1password.dev/service-accounts/get-started)

| Logical purpose | Required physical separation | Machine access |
|---|---|---|
| Control plane | Separate signing/session or operational credentials if their reader sets differ | only the corresponding declared service identity |
| Cloudflare | Observation tokens separate from mutation tokens; tunnel runtime secrets separate from API administration | observation cannot retrieve mutation/admin credentials |
| Coolify | Dashboard-read, platform-admin and each team-deploy scope in distinct reader-set vaults | corresponding adapter/rotation identity only; no cross-team reads |
| Registry | Human administrator recovery separate from machine material; robot/TLS purposes partitioned by readers | CI receives only its delivered robot secret, never provider resolver/admin access |
| Backup and audit | Data-writer/repository material separate from retention/prune, lock-policy administration and independent checkpoint-signing authority | each narrow identity reads only its required vaults; data writer cannot retrieve retention/admin credentials |
| Project — `<slug>` | Separate project/consumer vaults wherever reader sets differ | that project's declared rotation/delivery identity only |
| Break glass | Human-only recovery custody, outside every machine-readable vault | no service account |

Each item uses a stable logical ID, owner, consumers, created/rotated/expiry dates and provider resource reference. Automated retrieval uses `op read` or `op run` with a service account restricted to named physical vaults; `RESTIC_PASSWORD_COMMAND` avoids a long-lived password environment variable. Actual UUIDs remain private. Grant changes that the provider cannot modify in place use an approved replacement-account rotation. Tests exercise provider credentials directly: observer-to-mutation, writer-to-retention and cross-project reads must fail even outside the vsk-labs resolver. Preserve positive reads, loss/recovery and rotation tests. [1Password secret scripts](https://developer.1password.com/docs/cli/secrets-scripts/) [D-110](decisions-and-sources.md#d-110)

### Backup engine and repository topology — `G-008`

The selected restic/R2 combination is a candidate pending the [coordination/payload compatibility contract](platform-lifecycle.md#recovery-and-retained-dependencies), not a proven design. Restic removes temporary locks; payload retention must also cover older deduplicated dependencies of retained snapshots. Qualify separate mutable coordination permissions and full retained-data protection using the pinned engine and actual destination. If this cannot be proven, return a concrete alternative for user review; no broad writer deletion, disabled locking or shortened retention. [Pinned restic lock behavior](https://raw.githubusercontent.com/restic/restic/v0.19.1/internal/restic/lock.go)

V1 selects restic repository format v2. The first implementation must pin restic `0.19.1` or a later reviewed patch by binary digest; upgrading the repository format is a separate plan. Restic supplies client-side encryption, S3-compatible storage, integrity checks and JSON-capable automation. Losing every repository key makes recovery impossible.

- `standard`: one encrypted restic repository on the central 512 GB SSD; daily snapshots; `--keep-within 7d`.
- `critical-local`: a separate encrypted SSD repository; every 6 hours; `--keep-within 14d`.
- `critical-offsite`: a separate encrypted R2 S3-compatible repository; daily; `--keep-within 14d`; bucket/prefix lock covers at least the retention window.
- Backup writers cannot delete/overwrite retained payloads or change bucket-lock policy. The candidate layout must separately qualify mutable coordination operations needed for refresh/unlock without granting payload deletion; do not claim that a broad R2 read/write token supplies this separation. A separately administered retention identity is used only for reviewed `forget`/`prune` after every retained dependency is safe; data writers never hold it. The writer/coordination and deduplicated-retention compatibility proof remains open, not settled by selecting restic.
- SQLite is first copied through the SQLite Online Backup API into a staging directory, checked, then passed to restic. Databases/applications use their native consistent export or quiesce hook. Raw live-database directories are rejected.
- After every snapshot, verify manifest and repository metadata. Run `restic check` weekly, `restic check --read-data-subset=1/4` on a rotating weekly quarter schedule, a full `restic check --read-data` monthly, and isolated functional restores quarterly. Run retention first as `forget --dry-run`; after reviewed prune, run `check` again.
- Capacity admission requires projected encrypted data plus 30% headroom for the full retention window and one prune/repack cycle. Crossing 70% warns; 80% blocks new standard targets; critical backups continue and page the owner.

[restic repository setup](https://restic.readthedocs.io/en/stable/030_preparing_a_new_repo.html) · [restic verification](https://restic.readthedocs.io/en/stable/077_troubleshooting.html) · [restic retention](https://restic.readthedocs.io/en/stable/060_forget.html) · [R2 bucket locks](https://developers.cloudflare.com/r2/buckets/bucket-locks/) [D-109](decisions-and-sources.md#d-109)

### Provider ownership — `G-012` through `G-016`, `G-019`

SQLite remains desired-state authority; v1 does not introduce Terraform/OpenTofu state. The Cloudflare adapter uses the official `cloudflare-go` v7 client pinned by the platform release, with a reviewed raw-REST fallback only for a required endpoint absent from the SDK. The Coolify adapter uses the documented `/api/v1` surface. Both implement observe/plan/apply/verify, owned-resource manifests, idempotency where supported, redaction, rate-limit handling and manual fallback. Resources created outside the adapter are observation-only until explicitly imported by plan. [Cloudflare Go SDK](https://github.com/cloudflare/cloudflare-go) · [Coolify API authorization](https://coolify.io/docs/api-reference/authorization) [D-112](decisions-and-sources.md#d-112)

The connector pair is selected from qualified application nodes 03/05/07; qualification and a one-connector-loss test are mandatory. The managed-network TLS marker uses a qualified selected application node. Node 02 remains the qualified spare and node 08 remains reserve; neither receives these roles implicitly. Marker failure selects the remote/private profile and cannot grant LAN trust. A replacement is a normal epoch-bound placement plan.

The initial Coolify selection is `v4.3.10`, official tag commit `83f1a2e50374c27125671084b445b2599815f114`. The version-specific official installer was retrieved read-only on 25-08-2026 with SHA-256 `8ef02dce49339208f5abc247bff0277c73d04538d7a36dcfd21331e314e0f2cd`; production bootstrap must retrieve to a file, verify this digest, inspect it and invoke the documented version argument—never pipe an unverified network response to a privileged shell. If the checksum/tag is no longer obtainable or a newer security release is required, reopen `G-014` and record a new reviewed version/digest instead of silently drifting. Disable automatic updates. [Coolify v4.3.10 release](https://github.com/coollabsio/coolify/releases/tag/v4.3.10) · [version-specific upgrade](https://coolify.io/docs/get-started/upgrade) [D-113](decisions-and-sources.md#d-113)

### Platform releases and generated registries — `G-017`, `G-018`

Release CI uses Sigstore keyless signing for every binary, package manifest and canonical release manifest. It publishes a Sigstore bundle containing signature, certificate and transparency evidence; the client verifies the bundle, exact OIDC issuer, exact repository/workflow identity, artifact digest and manifest schema. Cached bundles permit verification without a live GitHub API. Repository/workflow identity and feed URLs cannot be fabricated before the repository exists and remain `G-017` evidence.

The site retains the active release plus two previous verified releases—three complete binary/schema/manifest sets—locally and in the release provider. Rollback never crosses an incompatible schema without the matched pre-migration database backup. [Sigstore blob signing](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/) · [Sigstore verification](https://docs.sigstore.dev/cosign/verifying/verify/) [D-114](decisions-and-sources.md#d-114)

Command definitions, flags, risk class, request/response schema, stable error codes, exit mapping, help text and generated clients must originate from one metadata graph in the future source repository. CI fails on handwritten drift, duplicate codes, missing examples, platform-dependent canonical JSON or golden changes without an explicit compatibility review. The normative v1 error/exit registry already exists in [Automation and agents](automation-and-agents.md#exit-and-error-registry); `G-018` is an implementation acceptance gate, not an unresolved architecture choice.

## External-input forms

The following values cannot be responsibly selected from documentation. The Console/CLI must request them only when their gate becomes next, show why they are needed and accept a signed evidence bundle rather than free-form prose:

- `G-001` through `G-004`, `G-009`, `G-010`: physical/site observations and measurements;
- `G-011`: primary/secondary recipient identifiers and an independently hosted delivery endpoint;
- `G-015`: the existing Harbor instance's sanitized inventory and measured target-node evidence;
- `G-017`: release repository/workflow identity and feed URLs after the repository exists;
- `G-019`: each project's real Coolify team/resource/environment mapping and token owner;
- `G-020`, `G-021`: real Mac resource/thermal/interaction results;
- `G-022`: each later service's owner and operational contract.

Agents must not repeatedly ask for all of these. `vsk-labs gate list --ready-for-input` returns only gates whose prerequisites are met. A human may defer a capability; the system records the exact consequence and cannot convert deferral into a passed prerequisite.

## Phase admission report

Before a phase, `vsk-labs gate check --phase <n> --output json` returns every applicable gate, evaluation digest, evidence age, subject/recovery epoch and exact remediation. Phase 1 remains blocked by `G-001` through `G-004`, `G-009` and relevant `G-010` evidence. Later phases remain blocked only by the rows named above; `G-022` is per service and `G-023` never blocks v1.

Documentation completion therefore means the mechanism and acceptance rules are closed. It does not waive the evidence needed to touch real systems.
