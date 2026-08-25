# Architecture and networking

[Back to README](../README.md) · [Control service](control-plane-service.md) · [Inventory](inventory-and-roles.md) · [Operations](security-and-operations.md) · [Decisions](decisions-and-sources.md)

## Portable platform boundary

The platform core models nodes, identities, services, artifacts, endpoints, desired state, observations, plans, approvals, runs, audit and recovery. It depends on capability interfaces, not vendor object shapes. A provider adapter declares its type, semantic version, supported operations, read/write scopes, consistency/freshness behavior, plan fidelity, idempotency, rollback limits and health. The engine rejects a declaration whose required capability is absent; it never guesses a provider from a domain name or optional field.

Every declaration and UI field carries one of four classes. **Core** is locally functional and provider-neutral. An **adapter** implements a provider contract but does not enable a feature by itself. An **optional capability** is enabled only by an explicit site policy, compatible adapter and tested degradation path; examples are repository discovery/events, managed source builds and PR feedback, rich provider status, external notifications and the one-way D1 status projection. The **VegaStack Labs deployment profile** selects concrete adapters, feature enablement and resource identifiers. Disabling an optional capability removes its screens/actions cleanly and cannot disable inventory, local plans, SQLite recovery or the manual path. [D-103](decisions-and-sources.md#d-103)

| Capability | Core contract | VegaStack Labs selected adapter |
|---|---|---|
| SCM | Git URI, immutable revision, repository identity and optional discovery/webhook capabilities | GitHub repositories; ordinary Git transport |
| CI | trusted event, job/run identity, result/provenance and optional status projection | GitHub Actions, including selected self-hosted runners |
| release/artifact | signed version manifest, immutable asset digest and update-check interface | GitHub Releases for `vegastack-labs`; Harbor for OCI images |
| registry | immutable image digest, push/pull and scan-result capabilities | Harbor as a Coolify workload |
| hosting | declared application/resource, image/source input, deploy, health and rollback capabilities | Coolify |
| identity | authenticated external subject and group/claim mapping | Google Workspace through Cloudflare Access |
| secrets | opaque reference resolution and rotation metadata; no value in core state | 1Password service accounts |
| edge/private access | named endpoints, authenticated ingress and private-route observations | Cloudflare Tunnel and Mesh |
| backup | consistent snapshot, client-side encryption, retention, verify and restore | local encrypted repository plus R2 off-site objects |
| notification | sanitized event, deduplication key, delivery state and acknowledgement | GitHub Issues selected for primary issue lifecycle; secondary route unresolved |

Core declarations reference an adapter instance and a provider-neutral resource key. Provider-specific configuration is validated by that adapter's versioned extension schema and stored behind the adapter boundary; it cannot become a required field in a core node/service/plan schema. Disabling an adapter leaves core state readable and identifies only its dependent operations as blocked. [D-103](decisions-and-sources.md#d-103) [D-104](decisions-and-sources.md#d-104)

## VegaStack Labs deployment profile

Everything from this heading through the physical, network, Coolify, CI and Harbor sections is concrete VegaStack Labs deployment configuration. It must not be copied into portable-core defaults.

### Deployment invariants

- Wired LAN is the primary local data plane.
- Cloudflare Mesh is the only bidirectional private overlay.
- Cloudflare Tunnel publishes only selected public or Access-protected services.
- Coolify manages independent Linux application servers; it is not a scheduler or storage cluster.
- CI builders, the control plane and application nodes have separate failure and trust boundaries.
- The local control database is private operational truth; GitHub is this profile's selected source/CI/release host, not live site state.
- Recovery never depends solely on the Internet or Cloudflare. [D-040](decisions-and-sources.md#d-040) [D-041](decisions-and-sources.md#d-041)

## Physical topology

```text
ACT Internet (400 Mb/s plan)
        |
primary HX510
        : current wireless EasyMesh backhaul
secondary HX510
        | one LAN port / one Cat6 uplink
ES216G port 1
        +-- ports 2-9:  active ThinkPads
        +-- port 10:    Mac mini
        +-- port 11:    iMac
        `-- ports 12-16: spare
```

The HX510 has three gigabit ports per unit, supports address reservation and optional Ethernet backhaul. The ES216G provides 16 gigabit ports, 32 Gb/s switching capacity, static link aggregation, VLANs, loop prevention, port statistics and cable tests. Neither the 400 Mb/s WAN plan nor the wireless headline rate reduces same-switch server-to-server links below gigabit. [TP-Link HX510](https://www.tp-link.com/in/service-provider/wifi-router/hx510/) · [ES216G official datasheet](https://static.tp-link.com/upload/product-overview/2025/202512/20251223/Datasheet_ES216G%28UN%291.20.pdf)

### ES216G v1 baseline

- local standalone management only;
- one reserved management address;
- unique administrator secret in 1Password;
- flat, untagged main LAN;
- port isolation off; loop prevention on;
- one HX510 uplink; static LAG and jumbo frames off;
- port descriptions mapped to immutable node IDs;
- exact regional hardware version recorded before firmware selection;
- configuration exported after every approved change. [D-033](decisions-and-sources.md#d-033) [D-035](decisions-and-sources.md#d-035)

The ISP-supplied HX510 firmware must be inspected before assuming every vendor feature is exposed. The official model supports address reservation; the deployment remains blocked until the actual UI is verified. [D-034](decisions-and-sources.md#d-034)

The physical port declaration is exact for v1:

| ES216G port | Intended endpoint | Acceptance |
|---:|---|---|
| 1 | secondary HX510 LAN port | stable gigabit uplink; no second Layer-2 path |
| 2–9 | `vsk-node-01` through `vsk-node-08`, respectively | label at both ends; negotiated gigabit and error counters recorded |
| 10 | `vsk-node-09` Mac mini | declared MAC and reservation match |
| 11 | `vsk-node-10` iMac | declared MAC and reservation match |
| 12–16 | disabled or unused spare | no unknown connected device |

Before the first change, photograph labels, export the factory/current configuration if supported, record management IP/hardware revision/firmware and prove local recovery access. For each later switch change: export current config, render the proposed port delta, obtain infrastructure-admin acknowledgement, change only one risk group, verify uplink/management/declared endpoints and increasing error counters, then export the new config. On loss of management or loop symptoms, remove the last cable/config change, isolate all but the uplink and one admin port, restore the previous export or documented baseline locally, and re-admit ports one at a time. Never depend on Mesh for switch recovery.

The secondary HX510 keeps its current wireless backhaul in v1. Phase 0 records Internet upload/download, latency/loss and sustained LAN-to-WAN traffic across that backhaul; same-switch server traffic must still negotiate at 1 Gb/s and remain independent of it. Before phase 1, approve the numeric WAN/backhaul acceptance profile from measured baseline and workload need—the transcript did not set one. Add Ethernet backhaul only if the approved gate fails. Roll back by returning to the single known wireless backhaul and proving there is no second Layer-2 path. [D-038](decisions-and-sources.md#d-038)

### Future second switch

Attach a second switch to exactly one ES216G port:

```text
secondary HX510 -- primary ES216G -- expansion switch
```

One port on each switch becomes the inter-switch link and cross-switch traffic shares 1 Gb/s. This consumes one of the five current spare ports, leaving four on the primary. Never connect the expansion switch to an HX510 as a second path while it is also connected to the primary switch. A two-link static LAG is a later option only after both ends are configured and a rollback cable plan exists. [D-036](decisions-and-sources.md#d-036)

## Addressing policy

The subnet, gateway and pool are discovery outputs; this draft does not invent them.

1. Keep the router as the DHCP authority.
2. Create a documented reservation for each active Ethernet MAC: node, switch and any infrastructure endpoint.
3. Put infrastructure reservations in a contiguous range that does not overlap the dynamic client pool.
4. Disable randomized MAC addressing on infrastructure Ethernet interfaces.
5. Store `serial -> node -> MAC -> reserved IPv4 -> Mesh IPv4` as constrained, revisioned rows in the control database.
6. Use OS-level static addressing only if the ISP firmware cannot reserve addresses; then allocate outside the DHCP pool and record the exception.
7. Disable IPv6 on managed Debian server interfaces for v1, as selected. Leave macOS IPv6/link-local behavior at its supported default and enforce inbound policy with the host firewall; a system-wide macOS IPv6 disable can break platform services.
8. Applications and agents must not use UPnP, NAT-PMP or automatic port mapping. Phase acceptance includes an external scan proving there are no unintended WAN listeners. [D-034](decisions-and-sources.md#d-034) [D-037](decisions-and-sources.md#d-037)

Reservation changes are generated from the revisioned SQLite network declaration. Because HX510 has no selected typed mutation adapter, an infrastructure admin performs its local UI action and attaches sanitized evidence; this is deliberate manual ownership, not an unresolved provider-IaC engine. Preflight rejects duplicate MAC/IP values, addresses inside an incompatible pool, unknown node serials and changes that remove the active control path. Apply one reservation, renew the target lease, verify forward inventory lookup plus SSH host identity, then continue. If the router cannot reserve reliably, stop the phase; the documented outside-pool OS-static fallback needs a local console test and must not coexist with a DHCP lease for the same address. A collision is handled from console: disconnect the duplicate, remove the conflicting lease/reservation, restore the last approved mapping and only then reconnect. [D-112](decisions-and-sources.md#d-112)

## Private connectivity: Cloudflare Mesh

Every managed node runs the appropriate Cloudflare One Client and receives its own Mesh IP. Clients and nodes can initiate TCP, UDP and ICMP connections subject to Gateway policy. No subnet gateway or jump host is required in v1. Cloudflare currently labels Mesh **beta**, and traffic traverses Cloudflare instead of taking a peer-to-peer path. [Cloudflare connectivity options](https://developers.cloudflare.com/cloudflare-one/networks/connectivity-options/) · [Mesh client devices](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-mesh/client-devices/)

### Path selection

| Situation | Path | Purpose |
|---|---|---|
| Both endpoints at the lab | reserved LAN address through ES216G | SSH, Coolify, builds, registry pulls, backups, databases |
| Authorized endpoint away | target Mesh address | private SSH/CLI and bidirectional agent/service flows |
| Public/protected web request | Cloudflare Tunnel | selected Coolify-managed services |
| Cloudflare/Internet outage | LAN SSH or physical console | recovery |

Mesh device profiles use Split Tunnels **include** mode with Cloudflare's current Mesh range `100.96.0.0/12`; add a routed private CIDR only if a later reviewed route actually requires it. Do not send ordinary Internet browsing through the client. Host firewalls treat `100.96.0.0/12` as an untrusted source range and admit only declared node/port flows. Servers retain application-layer SSH/TLS authentication; Mesh membership alone never grants shell or database access. [Cloudflare Mesh client devices](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-mesh/client-devices/) [D-042](decisions-and-sources.md#d-042)

### Enrollment, routes and profiles

The control database owns expected people, device identity, lifecycle state and allowed flows; Cloudflare owns observed registration and Mesh IP. The intended sequence is:

1. Configure Workspace IdP, enrollment rules, the default remote profile and the lab managed-network profile; neither profile grants application authority.
2. Self-enroll into quarantine. `vsk-labs` observes the registration but does not trust it until exact desktop inventory or a human mobile approval binds person, registration ID and Mesh IP.
3. Commit the approved device as a new database revision, then reconcile it into audiences/Gateway rules and host-firewall source declarations; verify an allowed and a denied flow before marking active.
4. Install server/Mac clients one pilot node at a time, recording client version, Mesh IP and reboot/reconnect evidence.
5. Keep v1 direct-participant only. Do not create CIDR/hostname routes or designate a gateway merely because Cloudflare supports routes; route creation is a separately reviewed topology change. [Cloudflare Mesh routes](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-mesh/routes/)

Cloudflare does not supply the desired human approval queue, so `vsk-labs` quarantine is an explicit design layer. Re-registration creates a new observed identity and returns to quarantine. An enrollment operation fails closed if device capacity would reach 48, identity cannot be bound exactly, or policy reconciliation fails. [D-043](decisions-and-sources.md#d-043) [D-044](decisions-and-sources.md#d-044)

### Pilot and operating guardrails

- Pilot the control plane, one builder, one app node, both Macs and one client for 30 days before fleet-wide trust.
- Verify reconnect after reboot, sleep/wake, WAN loss and client update.
- Test latency, throughput, long-lived sessions and Path MTU Discovery. Use Cloudflare's recommended 1,280-byte MTU when testing shows fragmentation rather than hiding the symptom.
- Configure Gateway network policy for only declared node/port flows.
- Do not run another private-overlay/VPN client on enrolled hosts unless a reviewed compatibility exception proves that routes do not conflict.
- Count servers, Macs, operator/user computers, phones/tablets and any external Mesh target against capacity. Warn at 40 nodes and reject automated enrollment at 48; the current documented account limit is 50. [Cloudflare limits](https://developers.cloudflare.com/cloudflare-one/account-limits/)
- A Mesh node and `cloudflared` may coexist only with Cloudflare's required Split Tunnel exclusions. [Cloudflare Mesh tips](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-mesh/tips/)

Pilot success requires the declared flow matrix and the fixed `G-005` 30-day envelope: no unresolved route collision or origin bypass, 100 reconnect cycles with p95 below 60 seconds, validated MTU on every selected path, packet loss below 1% and sustained throughput at least 70% of the measured direct-router baseline. It cannot rely on a second VPN. If Mesh causes routing, DNS, MTU or client instability: preserve evidence; remove the node from Mesh audiences; disable/uninstall only its One Client through the supported path; restore LAN-only firewall rules and direct addresses; verify local administration; then reopen the beta-risk decision before re-enrollment. Fleet rollback never disables every pilot node at once. Mesh outage does not trigger automatic Tunnel publication or router port forwarding. [Implementation gates](implementation-gates.md#common-numeric-qualification-g-005-g-009-g-010-g-020-g-021) [D-115](decisions-and-sources.md#d-115)

## Automatic LAN/remote names

The v1 scope is SSH and `vsk-labs` CLI aliases—not system-wide browser DNS. This avoids introducing a dedicated DNS service, and Cloudflare documents a port-53 conflict when a DNS server and Mesh node share a host.

Canonical inventory names are `vsk-node-NN.labs.vegastack.com`; role aliases include `control-plane`, `builder-01`, `app-01`, and `hermes-01`. The private suffix is fixed as `labs.vegastack.com`.

`vsk-labs` generates a small SSH include such as:

```sshconfig
Host control-plane
    User mk
    HostKeyAlias vsk-node-04
    ProxyCommand vsk-labs connect --node vsk-node-04 --port %p
```

The resolver algorithm is deterministic:

1. Validate a dedicated, low-dependency, LAN-only managed-network TLS marker; do not trust an SSID name alone. Cloudflare's client waits up to five seconds and then selects the default remote profile, so marker loss must degrade to the remote path rather than hang or retry indefinitely.
2. If the marker is valid and the target reservation is reachable, select the node's reserved LAN address.
3. Otherwise, require an active approved Cloudflare registration and select the node's Mesh address.
4. Pin SSH host identity to immutable node ID, regardless of selected address.
5. Fail closed if the chosen address does not match the current inventory revision; never fall through to public DNS.

This makes `ssh mk@control-plane` and `vsk-labs node inspect control-plane` automatic while leaving direct LAN/Mesh addresses available for recovery. Cloudflare managed networks support TLS-based location detection and profile changes on network transitions. [Cloudflare managed networks](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/configure/managed-networks/) [D-046](decisions-and-sources.md#d-046)

The TLS marker is a minimal HTTPS endpoint on the LAN with a pinned certificate/SPKI fingerprint and no secret response. The default host is `vsk-node-02`; the access-adapter owner owns certificate rotation. `G-013` requires that host's qualification, actual fingerprint/expiry and safe remote-profile fallback before phase 2; a planned substitute is allowed. Marker loss intentionally selects remote Mesh. `vsk-labs connect` records only the chosen path/reason and timing, never credentials. Diagnosis order is: validate target alias and SSH host-key mapping; inspect marker result; probe reserved LAN address without changing routes; inspect One Client registration/profile/Mesh IP; probe Mesh address; then report the first failed invariant. Operators can force `--path lan` or `--path mesh` for diagnosis, but only direct IP plus pinned host key is the break-glass recovery path. A wrong host key, public resolution or dual identity mismatch is a hard stop, not an automatic fallback. [Implementation gates](implementation-gates.md#provider-ownership-g-012-through-g-016-g-019)

If future requirements need system-wide private DNS, treat that as a separate reviewed design. As revalidated 2026-08-24, Cloudflare Mesh hostname routes require MASQUE and Linux client version `2026.6.822.0` or later, and private DNS topology has additional return-route constraints. [Cloudflare Mesh routes](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-mesh/routes/)

## Public and protected ingress

`cloudflared` establishes outbound-only connections; no HX510 port forwarding is allowed. Use one named tunnel with at least two connectors on different qualified application nodes. The default candidates are `vsk-node-02` and `vsk-node-08`; `G-012` admits them only after burn-in, a one-connector-loss test and evidence that they do not share one disk or power adapter. A failed candidate is replaced through an epoch-bound placement plan, not by silently weakening redundancy. [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/) [D-045](decisions-and-sources.md#d-045)

The control database owns tunnel name, connector node IDs, hostname-to-origin declarations, exposure class, Access audience and health check; Cloudflare owns connector/runtime state. The direct typed Cloudflare adapter owns declared VegaStack Labs Cloudflare objects; v1 has no Terraform/OpenTofu state. Bootstrap only after local HTTPS origin health passes: create or explicitly import the owned tunnel, issue separate connector credentials through 1Password, install a pinned `cloudflared` package on connector A, verify origin and Access allow/deny, then repeat for B. Never place a tunnel credential in Compose, the database, a plan or a shared node image. An object created outside the adapter is observation-only until a reviewed import plan establishes single ownership. [D-112](decisions-and-sources.md#d-112)

Routine upgrade drains and updates one connector, proves the other remains healthy, then reverses. Rotation adds a replacement credential/connector, verifies it, removes the old connector and revokes the old credential; do not rotate both simultaneously. Diagnosis distinguishes origin failure, Access-policy denial, DNS, connector disconnect and Cloudflare edge failure using sanitized connector/HTTP evidence. Rollback removes the new hostname/policy or restores the previous pinned connector/config while keeping the private origin reachable by LAN/Mesh. Public failure never changes an exposure class to less restrictive or opens a router port.

Every declared service chooses one exposure class:

| Class | Reachability | Default control |
|---|---|---|
| `public` | Internet through Tunnel | application authentication, rate limits and service policy |
| `protected` | Internet through Tunnel | Cloudflare Access plus explicit Google Workspace audience |
| `private` | LAN/Mesh only | Gateway network policy and application authentication |

Dashboards default to `protected`; private is reserved for protocols or services that should not be browser-published. The accepted public convention is `<service>.vegastack.com` for production-like services, `<env>--<service>.vegastack.com` for other environments, and `labs-<tool>.vegastack.com` for lab tools. Exact names belong to each later service declaration. [D-047](decisions-and-sources.md#d-047) [D-048](decisions-and-sources.md#d-048)

Every published route must pass four tests from an authorized external client and an unauthorized one: expected DNS/TLS chain, positive audience access, negative audience denial, and origin unreachable when the route is removed. A `private` service has no public DNS/Tunnel route. Unknown or omitted exposure class fails validation.

## Coolify control and application plane

```text
vsk-node-04: Coolify + vsk-labs controls
        | SSH over reserved LAN addresses
        +-- vsk-node-03: application server
        +-- vsk-node-05: application server
        `-- vsk-node-07: application server
```

Coolify is a privileged control plane and its remote servers remain ordinary Linux machines managed over SSH. V1 does not create a Docker swarm, Kubernetes cluster, distributed filesystem or automatic application failover. [Coolify server overview](https://next.coolify.io/docs/core/infrastructure/servers/overview) · [Coolify security model](https://next.coolify.io/docs/core/security-model)

The control node may run Coolify, `vsk-labs server run`, the embedded Console/API and SQLite, Ansible execution, the Beszel hub, backup scheduling and alert forwarding. It runs no user application or CI job. The `vsk-labs` service is installed as an independent `systemd` unit rather than inside Coolify, so Coolify remains diagnosable when impaired; its complete runtime/data contract is in [Control-plane service and Console](control-plane-service.md). Initial Coolify is pinned to `v4.3.10`, tag commit `83f1a2e50374c27125671084b445b2599815f114`; the verified 2026-08-25 official installer digest and safe version-specific invocation are in `G-014`. Do not pipe or execute an unverified mutable download, and disable automatic updates. The VegaStack Labs control database, Coolify database, `APP_KEY` and SSH keys are backed up under their separate recovery contracts; Coolify restore uses the same version before any reviewed upgrade. Coolify's own backup does not include workload volumes. [Implementation gates](implementation-gates.md#provider-ownership-g-012-through-g-016-g-019) [Coolify installation](https://coolify.io/docs/get-started/installation) · [Coolify backup and restore](https://coolify.io/docs/knowledge-base/how-to/backup-restore-coolify) [D-113](decisions-and-sources.md#d-113)

Coolify's supported installation path requires SSH and privileged/root control; a non-root configuration is not the v1 experiment. Its SSH key is therefore a high-impact credential stored separately in 1Password and admitted by each server only from the control plane. Server validation may install or restart Docker, so adding/revalidating a remote server is a mutating infrastructure-admin operation, not a harmless health check. [Coolify server overview](https://next.coolify.io/docs/core/infrastructure/servers/overview)

### Coolify lifecycle

| Operation | Safe order, verification and recovery |
|---|---|
| Bootstrap control | Close inventory/LAN/secret/backup prerequisites; install clean Debian; apply SSH/firewall/time/base packages; retrieve the official installer through a reviewed, recorded artifact/hash path; install the selected Coolify version; bind management to protected/private paths; configure backup; create least-privilege teams; verify login, database, queue, local Docker and a disposable test resource before adding servers. If any check fails, preserve logs and reimage from the clean baseline rather than hand-patching unknown state. |
| Add app server | Verify serial, reservation, host key, supported OS, storage and clean Docker state; render the exact validation effects; approve privileged SSH; add one server; run Coolify validation; deploy/remove a disposable resource; verify firewall denials and backup declaration before admitting workloads. Remove the server from scheduling and restore its pre-Coolify Docker state if validation leaves it inconsistent. |
| Rebuild control | Freeze applies and exports; provision the qualified spare or repaired node at the canonical alias; restore the verified VegaStack Labs control database with the matching pinned `vegastack-labs` platform release; install the **same** Coolify version; restore Coolify database plus matching `APP_KEY` and `/data/coolify/ssh/keys`; verify roles, plans, teams, servers and resources before enabling execution. A database without its matching key material/release is not a successful restore. |
| Upgrade | During the maintenance window, capture and verify a fresh control backup, read release/upgrade notes, canary read-only provider/remote checks, choose the exact target version and disable blind auto-update; upgrade control only; verify login, queues, SSH validation, test deploy and backup. On failure, stop mutation and restore the prior version plus its matched backup rather than mixing binaries/schema state. [Coolify upgrade](https://coolify.io/docs/get-started/upgrade/) |
| Lose app node | Stop scheduling, quarantine the host, select qualified capacity, restore application declarations/images and each workload's independent data backup, verify health and access, then change placement. Coolify UI state alone cannot recover workload volumes. |

The control database owns placement/policy and application repositories own Compose/build/health/migrations; Coolify is the reconciled runtime, while its database is still required to recover its own control state. Any console hotfix is break-glass drift and must be exported, audited and reconciled as a new declaration revision.

### Coolify source-provider boundary

The selected VegaStack Labs deployment path gives Coolify a prebuilt Harbor image digest and calls its scoped resource API. Coolify therefore does **not** need source-repository access, a deploy key or a GitHub App for the normal image deployment path. If a later service deliberately uses Coolify source builds, select the smallest supported mechanism per repository:

| Need | Smallest Coolify mechanism | GitHub App classification |
|---|---|---|
| public repository source | public HTTPS URL | not required |
| one private repository, read-only checkout | repository-scoped SSH deploy key | not required |
| integrated repository picker plus managed push/PR webhooks across selected repositories | Coolify's GitHub App source integration | optional supported adapter |
| automated Coolify comment on a pull request | Coolify's GitHub App, with its documented PR permission | required only for that optional comment feature |
| protected CI deploys a prebuilt image | Coolify team-scoped API token with only the documented `write` and `deploy` permissions, plus a registry pull credential; VegaStack Labs CI updates the exact digest and calls Coolify under a `vsk-labs` plan/run authorization | not required |

Install no Coolify GitHub App by default for v1. If the optional integration is later approved, its owner, selected-repository installation boundary, generated permissions, webhook secret/private key storage, rotation, negative tests, outage behavior and uninstall/offboarding procedure must be recorded before installation. A GitHub outage stops new source events/builds; it must not stop the running application, local control state or manual digest deployment. [Coolify GitHub source overview](https://next.coolify.io/docs/applications/sources/github/overview) · [Coolify deploy key](https://coolify.io/docs/applications/ci-cd/github/deploy-key) · [Coolify GitHub App](https://next.coolify.io/docs/applications/sources/github/app) [D-104](decisions-and-sources.md#d-104)

The exact OS/architecture contract is the [support matrix](automation-and-agents.md#os-and-architecture-support-matrix): Debian 13 `amd64` for the VegaStack Labs server and Linux nodes, Ubuntu Server 26.04 LTS `amd64` for a reusable managed-node role only after its mandatory lane passes, and current/previous macOS on Apple `arm64` for native Mac roles. Coolify remains Linux-only. Discovery may report other systems, but every mutating command blocks outside the tested matrix. [Ubuntu 26.04 release notes](https://documentation.ubuntu.com/release-notes/26.04/) [D-025](decisions-and-sources.md#d-025) [D-107](decisions-and-sources.md#d-107)

## CI, image and deployment flow

```text
GitHub Actions workflow (VegaStack Labs CI adapter)
   |
ephemeral job on vsk-node-01 or vsk-node-06
   |
build + test + sign image
   |
Harbor on the phase-5-selected Coolify app node (local primary, R2 backup)
   |
CI submits immutable digest/change evidence to vsk-labs plan/run
   |
risk policy auto-authorizes exact low-risk class OR maintainer acknowledges production-like plan
   |
protected CI executor claims lease -> updates digest and calls Coolify
   |
application node pulls and verifies the exact digest
```

- Start each Linux builder at one job. Admit two per node only after sustained thermal, RAM and disk tests.
- Each Linux job receives a new unprivileged one-job runner container, a clean workspace and rootless BuildKit. Build/test jobs receive no Docker socket, privileged container, host namespace, fleet/node-admin, secret-provider, control-plane-admin or Coolify credential. A separate protected deploy job may receive only its mapped Harbor identity, project-scoped `vsk-labs` submit/claim identity and its Coolify team token after event/ref/environment admission; it never receives fleet/control credentials. Runner-controller registration material stays outside the job, logs are exported, and the container/workspace is destroyed after completion.
- Builders are a separate trust zone: host firewall policy prevents them initiating connections to control, application or database ports except the exact registry/CI flows declared for a job. Caches are content-addressed and separated by repository/trust class.
- Untrusted or fork pull requests run on GitHub-hosted runners. Home runners accept only protected pushes, releases or manually approved trusted events; each organization repository is explicitly enrolled in the runner group and declares a trust policy before use. GitHub recommends ephemeral autoscaling and warns that self-hosted runners can be persistently compromised by untrusted workflow code. [GitHub self-hosted runners](https://docs.github.com/en/actions/reference/runners/self-hosted-runners) · [GitHub secure use](https://docs.github.com/en/actions/reference/security/secure-use)
- Mac mini exposes exactly one native macOS ARM64 job, at lower scheduling priority with explicit CPU/memory limits, and remains usable for interactive development. It follows the same trusted-event and cleanup rules; it does not accept arbitrary fork code.
- A node enabled as a Coolify build server cannot host deployed resources; the default v1 path builds in CI and deploys prebuilt images. [Coolify build servers](https://coolify.io/docs/knowledge-base/server/build-server)
- CI builds, tests, signs and attests the image, pushes it to Harbor and submits the immutable SHA-256 digest plus provenance/scan evidence as an inert service change. The control server creates an epoch-bound plan/run authorization. An exact policy may auto-authorize the declared low-risk environment class; a production-like class waits for its assigned maintainer's acknowledgement and explicit apply. The enrolled protected CI job then claims a one-time execution lease, updates only the mapped Coolify resource to that digest and directly calls Coolify. This is the accepted CI execution adapter, not general CI authority. Coolify supports digest-pinned image references and team-scoped API tokens; changing an image reference needs `write`, while triggering it needs `deploy`. [Coolify Docker Image](https://next.coolify.io/docs/applications/deployments/docker-image) · [Coolify API authorization](https://coolify.io/docs/api-reference/authorization) · [Coolify deploy API](https://coolify.io/docs/api-reference/api/deployments/deploy-by-tag-or-uuid)

### CI trust and admission matrix

| Event/code source | Home Linux/Mac runner | Secret/deploy authority |
|---|---|---|
| fork pull request or untrusted external contribution | never; GitHub-hosted only | none |
| internal pull request before explicit trust decision | GitHub-hosted by default | read-only test token at most |
| protected-branch push produced by required review/checks | allowed for explicitly enrolled repository/workflow | build job has no deploy token; separate admitted job may claim and execute only a preauthorized low-risk environment plan |
| signed/reviewed release or protected manual dispatch | allowed for explicitly enrolled repository/workflow | mapped registry publish; deploy job receives its team token only after plan authorization, with maintainer acknowledgement for production-like policy |
| `pull_request_target`, reusable workflow from mutable ref, or workflow that checks out attacker-controlled code in privileged context | prohibited on home runners | none |

Repository enrollment records owner, runner labels, allowed workflow file paths/events, trust class, required reviewers, maximum job/concurrency class, cache namespace, registry projects and secret references. Workflow actions are pinned to full commit SHAs; default `GITHUB_TOKEN` permissions are read-only and elevated per job. A controller accepts a job only when repository, workflow commit, event/ref and protection evidence match the declaration. [D-057](decisions-and-sources.md#d-057)

The controller design is closed: the GitHub CI adapter inside `vsk-labs server run` mints short-lived registration tokens, launches the pinned runner with `--ephemeral` over constrained SSH and destroys its container/workspace after one job. Linux uses group `vegastack-labs-trusted-linux` with default `self-hosted,linux,x64` plus `vsk-ephemeral,vsk-build`; macOS uses `vegastack-labs-trusted-macos` with `self-hosted,macOS,ARM64` plus `vsk-ephemeral,vsk-apple`. Root-owned host journald captures diagnostics outside the job and a narrow authenticated collector preserves sanitized logs on control before completion. Phase 4 still requires exact repository/workflow enrollment and tests proving cancellation cleanup, log preservation and that a hostile job cannot reach another job, Docker socket, host namespaces, control/app/database ports, 1Password or controller credentials. GitHub requires runner software to remain within its supported update window. Self-hosted macOS ARM64 is still public preview on 2026-08-25; fallback is GitHub-hosted `macos-15-intel` for compatible work plus a protected manual Mac-mini lane for Apple-silicon-only tests. [Implementation gates](implementation-gates.md#ci-controller-runners-and-logs-g-006-g-020) [D-053](decisions-and-sources.md#d-053) [D-111](decisions-and-sources.md#d-111)

Capacity qualification starts at one job per Linux node and one lower-priority job on the Mac. Apply the fixed 8-hour common profile and 2-hour two-job profile from `G-010`: no throttle/errors, memory at or below 85%, bounded swap, healthy disks with the greater of 20% or 50 GB free, and complete cleanup. Increase one Linux node to two jobs, verify the representative mix, then repeat on the other node. Any limit breach returns that node to one job and creates failed evidence; “four jobs” is a target, never a reason to ignore hardware. [Implementation gates](implementation-gates.md#common-numeric-qualification-g-005-g-009-g-010-g-020-g-021) [D-052](decisions-and-sources.md#d-052) [D-054](decisions-and-sources.md#d-054) [D-115](decisions-and-sources.md#d-115)

### Signed digest promotion

The application repository owns source/build/tests/health/migrations; the protected workflow produces image digest, SBOM, signature and provenance. Before promotion, CI independently resolves the Harbor digest, verifies the selected signing identity/provenance policy and records the scan result. Scanning is report-only in v1, but a missing/failed signature, provenance or digest match always blocks deployment. CI submits this evidence as an inert change. The control database maps the digest to one Coolify resource/environment, dynamic environment risk class and backup/rollback policy. Eligible low-risk classes may auto-apply under that exact preauthorized policy; production-like classes wait for maintainer acknowledgement. The protected CI executor claims the bound lease, uses its Coolify team's expiring `write`+`deploy` token to update the exact digest and trigger the resource, then reports the deployment UUID/health while the control server independently observes the running digest. A Coolify token is team-scoped, not resource-scoped, so each project trust boundary gets its own Coolify team/token and accepts residual blast radius across resources in that team; no `root` or `read:sensitive` permission is allowed. On failure, stop rollout and create/execute a recovery plan for the previous healthy digest only when its data/migration contract says rollback is safe; otherwise follow the application's manual recovery runbook. This CI-to-Coolify path is the accepted VegaStack Labs deployment profile; AWS, Hetzner and client-infrastructure targets remain application-repository workflow concerns outside v1 unless a future hosting adapter is explicitly onboarded. The signing identity, Coolify automation-token owner, exact team map and positive/negative permission test remain phase-5 inputs. [GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations) · [Coolify API tokens](https://next.coolify.io/docs/core/security/credentials/api-tokens) [D-055](decisions-and-sources.md#d-055)

## Harbor workload contract

Harbor is deployed from a version-controlled Compose definition through Coolify on an application node selected only after the phase-5 capacity, storage, failure-domain, backup and restore gate. No exact node is fixed yet. It remains an application workload—not a dedicated infrastructure node—and follows the same resource, health, backup and recovery declaration as any other stateful service. [Coolify Docker Compose](https://coolify.io/docs/knowledge-base/docker/compose) [D-004](decisions-and-sources.md#d-004) [D-023](decisions-and-sources.md#d-023)

- Keep the current local human-authentication mode for v1; disable self-registration. SSO/Access for human login is a later migration because Harbor cannot switch a populated local-user database directly to OIDC. Harbor authentication remains authoritative even when its UI/registry is reached through Tunnel. [Harbor database authentication](https://goharbor.io/docs/edge/administration/configure-authentication/db-auth/) · [Harbor OIDC](https://goharbor.io/docs/main/administration/configure-authentication/oidc-auth/)
- Give the registry one stable hostname. On the LAN it resolves directly to the HTTPS origin; externally it reaches the same service through Cloudflare Tunnel. Use a trusted origin certificate and never run the registry over plaintext HTTP. [Harbor HTTPS](https://goharbor.io/docs/main/install-config/configure-https/)
- Public browser access and pulls may use Tunnel with Harbor authentication, rate limiting and WAF controls. Do not assume large image pushes work through the proxied public hostname: current Free/Pro request bodies are limited to 100 MB. Remote CI/operators push through Mesh/private routing unless multipart/chunk behavior is validated end to end. [Cloudflare 413 limits](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/4xx-client-error/error-413/)
- V1 deliberately uses two expiring system robot accounts across enrolled namespaces: shared CI push/pull and shared deployment pull-only. Record the accepted cross-project blast radius, store tokens only in 1Password, rotate yearly with the normal staged procedure, and prefer per-project robots as later hardening. Harbor supports system robots across selected projects and project-scoped robots for narrower access. [Harbor system robots](https://goharbor.io/docs/2.12.0/administration/robot-accounts/) · [Harbor project robots](https://goharbor.io/docs/main/working-with-projects/project-configuration/create-robot-accounts/)
- Local storage is primary and encrypted R2 is backup, not a live object-storage backend. Clean migration is required; existing size, version, growth, project list and a tested data-consistent adapter remain discovery inputs.

### Harbor lifecycle

The application repository owns the pinned Harbor/Compose definition and health contract; the control database owns node placement, stable hostname, exposure, projects/namespaces, resource/quota policy, `critical` backup class and secret references. Harbor owns runtime users, robots, repository metadata and audit events, which are reconciled/exported without copying tokens.

1. **Discover/migrate-plan:** record current and target versions, architecture, image/blob bytes and growth, database size, projects/public flags, users, robots, scanners, retention/replication rules, TLS names and exact persistent volumes. Confirm the target version's supported upgrade path; no in-place experiment is allowed on the only copy.
2. **Bootstrap:** reserve storage with measured headroom; issue a trusted certificate for the stable origin name; deploy the pinned Compose through Coolify; verify all component health over HTTPS; disable self-registration before adding users; create declared projects/quotas/retention; configure the scanner; create the two scoped robots and test their positive and negative permissions. If bootstrap fails before data import, remove the disposable deployment and volumes after preserving sanitized logs.
3. **Backup:** the adapter must capture the Harbor configuration/certificates/secret references, registry blob storage, PostgreSQL-consistent dump/state, and every other persistent volume named by the deployed Compose version (including Redis/job-service state where persistent). It records component versions, digest/size/count manifest and consistency method, encrypts locally, copies to the locked R2 repository and verifies repository integrity. A raw copy of a live database is invalid. The exact adapter remains a phase-5 blocker.
4. **Restore test:** deploy the same pinned version to isolated storage/name; restore secrets/certificates and consistent state; prove login, catalog/tag/digest, public/private behavior, robot push/pull denials, scanner and a sample client pull; record timings against the critical recovery objective; destroy the isolated copy only after evidence is retained.
5. **Clean cutover:** freeze pushes and retention/GC, take/verify a final backup, import to the clean target, run the restore acceptance tests, then move the stable origin/Tunnel route. Keep the source read-only and rollback-ready for the approved window. Roll back DNS/route to the untouched source if validation fails; never write to both. Resume writers and start the rollback clock only after digest/count reconciliation passes.
6. **Upgrade/rotation:** take a verified backup and read official release notes; rehearse on restored data; upgrade one supported step; verify the restore checklist. Rotate one robot by creating/testing its replacement before revoking the old token. Run garbage collection/retention only with a recovery point and the version-specific safe procedure.

Harbor audit logs are collected for the selected six-month security/execution class. Vulnerability scanning is visible and report-only initially; the record must distinguish “scan passed”, “findings present”, “scanner unavailable” and “image not scanned”—never collapse the latter three into success. [Harbor vulnerability scanning](https://goharbor.io/docs/main/administration/vulnerability-scanning/)

All application-specific exact placement, including Harbor's target node, is deferred; Harbor is only the in-scope platform-workload exception. [D-004](decisions-and-sources.md#d-004) [D-055](decisions-and-sources.md#d-055) [D-056](decisions-and-sources.md#d-056) [D-058](decisions-and-sources.md#d-058) [D-059](decisions-and-sources.md#d-059)
