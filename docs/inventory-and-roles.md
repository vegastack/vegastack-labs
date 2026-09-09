# Inventory and roles

[Back to README](../README.md) · [Architecture](architecture-and-networking.md) · [Decisions](decisions-and-sources.md)

This document is the concrete VegaStack Labs inventory profile, not the generic node schema. Other installations use the [typed identity and profile contract](platform-lifecycle.md#identity-and-configuration), without Sheet row order or mandatory physical serials.

The control-plane SQLite accepted inventory is the deployment source of truth. An import first creates an immutable generic draft; it does not become accepted inventory merely because it was decoded, stored, or has `valid` status. The later Phase 4 plan transition remains the only path from reviewed intent to accepted declaration. For the Labs profile, that later process reconciles a read-only Google Sheet and physical discovery; dedicated current capacity values take precedence while distinct numeric factory values remain reported evidence. Unstructured factory prose is never parsed into capacity. An infrastructure admin owns reconciliation; neither automation nor this specification writes the Sheet. Each accepted declaration increments the database state revision and emits a signed declarative snapshot. [D-014](decisions-and-sources.md#d-014) [D-100](decisions-and-sources.md#d-100)

## Generic import drafts versus accepted inventory

The portable inventory-draft input contains assets, nodes, aliases, addresses, observations, hardware facts and field provenance without Labs node names, domains, provider fields or Sheet columns. Strict local validation preserves a structurally safe candidate in full: no semantic conflict means `valid`, while duplicates, missing references, cycles, conflicting or unsupported identity, invalid capacity and other safe findings mean `blocked`. Both statuses are inert review artifacts. Neither trusts, qualifies, admits, names, configures or changes a host, and neither creates an accepted declaration.

Fatal structure, limit, cancellation or secret checks persist nothing. An exact retry using the same opaque request key and canonical candidate is a no-op returning the original draft reference; corrections use a new key and immutable draft. Operators inspect the complete ordered findings, correct the source through its own human-owned workflow and submit a new revision. They never edit SQLite or delete/rewrite a prior draft. The Phase 2 signed draft export identifies itself as `kind=draft`, includes either the complete `valid` or complete `blocked` revision, and preserves ordered safe provenance and findings. Its signature proves byte integrity only against the verifier policy supplied to that service; it does not accept the draft or confer infrastructure authority. Production trust remains deliberately unavailable until Phase 5 qualifies the real policy.

Every persisted `valid` or `blocked` draft now shares one SQLite transaction with its canonical `inventory.draft.persisted` event, exact-replay binding and required destination-neutral outbox rows. The event records the principal verified by the protected server context, the server-issued correlation ID, draft target and canonical content fingerprint; the import body has no authenticated-principal, responsible-human or agent field. This attribution records who submitted the inert draft but grants no authority, acknowledgement, qualification, admission or declaration transition. A disabled audit destination becomes `paused` without blocking the local draft, while any failure before commit leaves all business and audit layers absent.

## Offline Labs Sheet1 CSV profile

`internal/profiles/labsinventory` implements profile format `labs-sheet1-csv`, adapter version `1.0.0`, and header-contract version `1.0.0`. It consumes one explicit local UTF-8 CSV snapshot and returns Issue 2.3's provider-neutral `inventory.DecodedCandidate`. It has no file-opening, command, API, database, provider, source-write, Google, OAuth, or network path. Issue 2.8 (#36) owns the later authenticated CLI/API composition that will supply the local reader plus a trusted source revision and UTC capture time.

Start from the [header-only template](examples/labs-sheet1-import-v1-header.csv), or inspect the [populated synthetic example](examples/labs-sheet1-import-v1-example.csv). Every column is required once, with the exact case-sensitive order below; reordering, omission, duplication, or any adjacent column is a fatal header error.

| Position | CSV header | Accepted v1 value | Mapping |
|---:|---|---|---|
| 1 | `lifecycle` | exact `active`, `quarantined`, `retired`, or blank | `active` becomes core `available`; the other named states remain unchanged; blank or another token creates a blocking safe finding |
| 2 | `hardware_serial` | exact text or blank | the only source identity; blank creates a blocking finding and never falls back to hostname, row, ordinal, model, or address |
| 3 | `reported_hostname` | exact text or blank | display-alias observation only; it is never identity |
| 4 | `manufacturer` | exact text or blank | `manufacturer` text fact or missing provenance |
| 5 | `model` | exact text or blank | `model` text fact or missing provenance |
| 6 | `cpu_architecture` | exact text or blank | `cpu-architecture` text fact or missing provenance |
| 7 | `cpu_model` | exact text or blank | `cpu-model` text fact or missing provenance |
| 8 | `cpu_physical_cores` | blank or ASCII digits | nonnegative base-10 `count`; no sign, decimal, unit, range, or prose |
| 9 | `cpu_logical_threads` | blank or ASCII digits | nonnegative base-10 `count`; no inference |
| 10 | `factory_ram_gb` | blank or ASCII digits | distinct factory `memory-capacity`, multiplied by exactly 1,000,000,000 bytes |
| 11 | `factory_ssd_gb` | blank or ASCII digits | distinct factory SSD `storage-capacity` in decimal bytes |
| 12 | `factory_hdd_gb` | blank or ASCII digits | distinct factory HDD `storage-capacity` in decimal bytes |
| 13 | `current_ram_gb` | blank or ASCII digits | preferred current `memory-capacity` in decimal bytes |
| 14 | `current_ssd_gb` | blank or ASCII digits | preferred current SSD `storage-capacity` in decimal bytes |
| 15 | `current_hdd_gb` | blank or ASCII digits | preferred current HDD `storage-capacity` in decimal bytes |

The decoder reads at most 4 MiB plus one limit-detection byte, permits at most 4,097 CSV records including the header, requires 15 fields per data record, and permits at most 1,024 UTF-8 bytes per field. The expanded candidate must also fit Issue 2.3's provider-neutral primary-record, hardware-fact, identity, and provenance bounds; expansion beyond those bounds fails at this adapter as `CSV_LIMIT_EXCEEDED` rather than reaching persistence as an opaque core error. One UTF-8 BOM is allowed only at byte zero. LF and CRLF records plus standard quoted commas and newlines are accepted. The source digest covers the exact original bytes, including the BOM and line endings.

Every data row produces one physical draft asset in source order. Exact `active` rows alone produce nodes and consume proposed ordinals `vsk-node-01`, `vsk-node-02`, and so on, even when another field on that active row is missing or conflicting. Quarantined, retired, blank-lifecycle, and unsupported-lifecycle rows produce no node, alias, or ordinal. A proposed alias that exactly matches the reported hostname is one alias with both sources; cross-node collisions remain distinct records so generic validation blocks only the affected bindings.

Factory and current values remain separate facts and source observations. A valid current fact is marked preferred without deleting the factory report. An invalid nonblank current cell is recorded only as `invalid` provenance plus `INVALID_CAPACITY`; its raw token is not retained, and the factory value is not relabelled as current. Every blank remains `missing` provenance. Counts and capacities are overflow-checked, and no prose is interpreted.

Fatal byte, CSV, header, size, formula, prohibited-control/private-data, or cancellation failure returns only a stable code and safe record/column/field position; no candidate is available to persist. High-confidence private-data cells share the approved `CSV_CONTROL_PROHIBITED` unsafe-cell classification; v1 adds no unapproved public error code. Blank or unsupported lifecycle, missing serial, invalid count/capacity, and generic duplicate identity/alias conflicts remain ordered blocking findings on the complete inert candidate. Formula prefixes `=`, `+`, `-`, or `@` after leading Unicode whitespace, NUL/C0/C1 controls other than CSV record separators, bidi overrides/isolates, Unicode noncharacters, and credential-shaped cells are rejected without echoing their value.

The human-equivalent correction procedure is:

1. Copy the header-only template, fill only the 15 allowlisted columns, and export one UTF-8 CSV locally; do not add Sheet2 or adjacent notes/credential columns.
2. When Issue #36 makes the route available, supply the file together with an explicit trusted source revision and UTC capture time. Neither is inferred from its filename or filesystem timestamp.
3. Inspect every ordered safe finding. Treat proposed ordinal and reported hostname only as observations, never trusted host identity.
4. Correct the private source through its normal human-owned workflow, export a new immutable snapshot, and submit a new revision. Never edit SQLite or rewrite an earlier draft.

A successful decode or later import is not declaration, acceptance, admission, naming, configuration, qualification, or live authority. No command/API route exists in Issue #32 itself.

## Deterministic identity

Rules:

1. Managed hostnames are immutable `vsk-node-NN` identifiers.
2. Number active Sheet1 machines in their existing row order, skipping quarantined and retired assets.
3. Mac mini and iMac follow the active ThinkPads.
4. Role labels such as `control-plane` and `app-01` are aliases; moving a role never renames hardware.
5. Retired numbers are never recycled. A repaired quarantined asset receives the next unused number after qualification. [D-010](decisions-and-sources.md#d-010) [D-011](decisions-and-sources.md#d-011)

The canonical private inventory name is `vsk-node-NN.labs.vegastack.com`. Short role aliases are operator conveniences resolved by `vsk-labs`, not machine identity:

| Role alias | Initial target | Move rule |
|---|---|---|
| `control-plane` | `vsk-node-04` | only after a verified control restore and explicit infrastructure-admin apply |
| `builder-01`, `builder-02` | `vsk-node-01`, `vsk-node-06` | drain jobs, requalify replacement, then apply a revisioned alias change |
| `app-01`, `app-02`, `app-03` | `vsk-node-03`, `vsk-node-05`, `vsk-node-07` | restore/reconcile declared services before changing alias |
| `hermes-01` | `vsk-node-10` | restore the standard Hermes profile, then verify allowed/denied tools |

The Mac node numbers and initial role placements are derived architecture assignments, not independent Sheet facts. Phase 0 approves them with the serial map before any hostname is applied. [D-013](decisions-and-sources.md#d-013) [D-022](decisions-and-sources.md#d-022)

### Serial-to-node map

| Node | Hardware serial | Current CPU | Current RAM | Current storage | V1 role |
|---|---|---|---:|---|---|
| `vsk-node-01` | `PF2RM6PP` | Ryzen 5 PRO 4650U, 6C/12T | 16 GB | 239 GB SSD | Linux CI builder A |
| `vsk-node-02` | `PF24MXFG` | Core i5-10210U, 4C/8T | 16 GB | 117 GB SSD + 931 GB HDD | Qualified spare |
| `vsk-node-03` | `PG025CS7` | Core i5-10210U, 4C/8T | 16 GB | 232 GB SSD + 931 GB HDD | Coolify application node A |
| `vsk-node-04` | `PF4F4KNE` | Ryzen 5 7530U, 6C/12T | 16 GB | 474 GB SSD | Control plane |
| `vsk-node-05` | `PF4F10C1` | Ryzen 5 7530U, 6C/12T | 16 GB | 512 GB SSD | Coolify application node B |
| `vsk-node-06` | `PF2SCVVJ` | Ryzen 5 PRO 4650U, 6C/12T | 16 GB | 239 GB SSD | Linux CI builder B |
| `vsk-node-07` | `PG025CNM` | Core i5-10210U, 4C/8T | 16 GB | 466 GB SSD + 932 GB HDD | Coolify application node C |
| `vsk-node-08` | `PF2RLCAR` | Ryzen 5 PRO 4650U, 6C/12T | 16 GB | 236 GB SSD | Unassigned capacity reserve |
| `vsk-node-09` | discover during phase 0 | Apple M4, exact CPU variant unresolved | 24 GB | 512 GB SSD | macOS ARM64 CI + shared development |
| `vsk-node-10` | discover during phase 0 | Apple M1 | 8 GB | 512 GB SSD | macOS Hermes agent host |

This map follows the accepted active-row policy. On the read-only 25-08-2026 reconciliation, the workbook's hostname cell maps `vsk-node-05` to `PG025CNM`, while row-order policy maps `vsk-node-05` to `PF4F10C1` and `PG025CNM` to `vsk-node-07`. The conflict is a deployment blocker: physically verify both serial labels, decide the canonical mapping, correct the Sheet through its normal human workflow, and commit the same approved map as a new control-database revision. Do not configure either hostname until the two sources agree. Current RAM/storage values were taken from the workbook's dedicated current columns; no credential-like values from adjacent columns are reproduced here. [D-015](decisions-and-sources.md#d-015)

## Unmanaged or unavailable computer assets

| Serial | Current specification | State | Policy |
|---|---|---|---|
| `PF2RLCC9` | Ryzen 5 PRO 4650U; 16 GB; 256 GB SSD | Charging-port issue; Ethernet/architecture not recorded | Quarantine. Repair, discover and burn in before assigning the next unused node number. |
| `PF246XWQ` | Intel i5 10th gen; 8 GB; 256 GB SSD + 1 TB HDD | Does not charge; retired | Physical asset record only; never a v1 node. |

## Network, storage and power assets

| Asset | Quantity | Known facts | V1 use |
|---|---:|---|---|
| TP-Link HX510 AX3000 | 2 | Three gigabit ports per unit; current ACT 400 Mb/s service; secondary unit is near the servers | Primary/secondary EasyMesh; ES216G uplinks to secondary unit |
| TP-Link ES216G | 1 | 16×1GbE, fanless, 32 Gb/s switching, rack/desktop, easy-managed | Flat server LAN; local standalone management |
| External SSD | 1 | 512 GB; model, health and encryption capability unknown | Central standard/critical local backup repository on control plane |
| UPS | existing | Model, load, runtime and monitoring interface not supplied | Power is assumed handled; phase 0 records actual coverage |
| Vertical laptop rack | planned/existing | Exact geometry unknown | Spaced placement with unobstructed vents; no laptop-to-laptop contact |

## Observed application context

Sheet2 was also re-read on 24-08-2026. It is discovery context, not live-health proof or a v1 placement declaration. Blank source cells stay blank here rather than inheriting a server name by guess. “Active” does not authorize migration; application-by-application placement remains deferred, Chaabi Prod is outside v1, and Harbor alone is the platform-workload exception.

| Source server/group cell | Application | Sheet status | Recorded CPU/RAM |
|---|---|---|---|
| `Chaabi Prod` | Harbor | Active | 4 CPU / 8 GB |
| blank | VegaStack Website | Inactive | not recorded |
| blank | Ghost | Inactive | not recorded |
| blank | Directus | Inactive | not recorded |
| blank | Plausible | Inactive | not recorded |
| blank | Listmonk | Active | not recorded |
| blank | Beszel | Active | not recorded |
| blank | n8n | Inactive | not recorded |
| blank | `chaabi(prod)` | Active | not recorded |
| `chaabi-regent` | `Regent(stg)` | Active | 2 CPU / 4 GB |
| blank | `chaabi(dev)` | Active | not recorded |
| `Langfuse` | Langfuse | Inactive | 2 CPU / 4 GB |
| `vegastack-utils` | plunk | Active | 2 CPU / 4 GB |
| `vegastack-org-agents` | Hermes agents | Active | 2 CPU / 4 GB |

Before a later service is considered, discover its actual owner, repository/version, runtime host, data size/growth, dependencies, exposure, backup/restore and decommission status; then add a revisioned service declaration through the control API. Sheet status alone is insufficient.

## Capacity summary

The eight active ThinkPads provide:

- 42 physical CPU cores and 84 threads;
- 128 GB RAM;
- approximately 2,515 GB labelled SSD capacity;
- approximately 2,794 GB labelled HDD capacity.

The Macs add 32 GB RAM and 1,024 GB SSD capacity. These are label totals, not usable filesystem capacity or a redundancy claim. Phase-0 discovery records actual bytes, SMART/NVMe health, sustained temperature, battery condition and 1 Gb/s negotiation.

## Role rationale and limits

### Control plane — `vsk-node-04`

One of the two strongest ThinkPads hosts Coolify, the `vsk-labs` server service (launched with `server run`), the embedded Console/API, local SQLite, central plan/run coordination, backup orchestration, Beszel hub and control-plane supporting services. It hosts no user application or CI job. Its 474 GB SSD avoids coupling control-plane recovery to a spinning disk. The service has explicit CPU/memory/disk limits, and its database is backed up off-node; the control plane is rebuildable, not highly available. This node assignment and every capacity value in this document belong to the VegaStack Labs deployment profile, not to the portable platform contract. [D-020](decisions-and-sources.md#d-020) [D-050](decisions-and-sources.md#d-050) [D-099](decisions-and-sources.md#d-099) [D-103](decisions-and-sources.md#d-103)

### Linux CI — `vsk-node-01`, `vsk-node-06`

The two 6C/12T Ryzen PRO systems start as isolated builders. The four-job target is a capacity goal, not an unconditional setting: begin at one job per node, burn in, then admit a second job only when memory, disk and thermal guardrails pass. Nodes marked as Coolify build servers cannot host deployed resources. [D-051](decisions-and-sources.md#d-051) [D-052](decisions-and-sources.md#d-052)

### Applications — `vsk-node-03`, `vsk-node-05`, `vsk-node-07`

These are independent Coolify deployment servers. The two Intel nodes supply the largest local disk pools; the Ryzen 7530U node supplies the strongest CPU and a 512 GB all-SSD option. Harbor remains an ordinary Coolify-managed application on this pool, but no exact Harbor node is selected: phase 5 must compare measured capacity, failure domain, data/backup fit and recovery evidence before placement. Other application placement likewise stays deferred until service requirements and observed capacity exist. [D-004](decisions-and-sources.md#d-004) [D-021](decisions-and-sources.md#d-021) [D-023](decisions-and-sources.md#d-023)

### Recovery capacity — `vsk-node-02`, `vsk-node-08`

`vsk-node-02` is the qualified spare. It stays patched, inventoried, LAN/Mesh-reachable and free of production secrets or state; quarterly recovery tests may use it and must return it clean. `vsk-node-08` remains deliberately unassigned capacity reserve.

Failure order is deterministic: quarantine the failed node and freeze its aliases; choose the qualified spare if it satisfies the role's measured CPU/RAM/storage/architecture contract; rebuild from the pinned OS/toolchain and latest verified control-database backup/signed snapshot; restore state according to backup class; verify allowed/denied paths; then move the role alias in a reviewed apply. Use `vsk-node-08` only when the spare is unsuitable or already occupied. Never move a stateful service merely because an alias changed.

### Macs

`vsk-node-09` is always-on macOS ARM64 capacity with one CI slot and individual standard accounts for interactive Codex/Claude Code work. `vsk-node-10` is an 8 GB Hermes host, with conservative concurrency. Macs run native roles only—no Linux VM and no Coolify deployment role in v1. [D-024](decisions-and-sources.md#d-024) [D-066](decisions-and-sources.md#d-066)

## Phase-0 discovery record

`vsk-labs node discover` must capture, without guessing:

- chassis/model, serial, firmware and exact CPU/architecture;
- actual memory modules and usable filesystem capacity;
- SSD/NVMe/HDD SMART health and error history;
- battery health, swelling check and supported charge thresholds;
- idle and sustained temperatures, throttling and fan health;
- Ethernet controller, MAC, negotiated speed and error counters;
- power-loss boot behavior and time synchronization;
- current OS, secure boot/disk encryption state and installed Mesh client version.

A node is role-eligible only after a typed `G-002` evidence bundle is committed through plan/apply and its `G-010` role evaluation passes. The closure exercise selected the explicit 8-hour common and role-specific temperature/throttle, memory/swap, disk, link and capacity defaults in [Implementation gates](implementation-gates.md#common-numeric-qualification--g-005-g-009-g-010-g-020-g-021). Automation evaluates real observations against those values; it still cannot invent an observation or weaken a failed threshold without an explicit expiring exception plan. [D-108](decisions-and-sources.md#d-108) [D-115](decisions-and-sources.md#d-115)
