# Network device capabilities and operations

Status: researched implementation-planning input, 26-08-2026. Covers the selected ES216G and two HX510 units. The product name does not establish the delivered hardware revision, installed firmware, current mode or ISP-exposed controls. No device was accessed or changed. Detailed new settings and issue bodies still require approval.

The existing choices remain: router-owned DHCP reservations, standalone switch management, one flat wired LAN, one switch uplink, host firewalls, Cloudflare Mesh/Tunnel and no automatic router port mapping. Complete and verify v1 before the first lab onboarding rehearsal. [Architecture and addressing](architecture-and-networking.md#addressing-policy) · [Delivery path](development/roadmap.md#delivery-path-from-development-to-the-lab) · [Phase 0](development/phases/00-development-foundation.md)

## Which device assigns addresses?

**The ES216G cannot supply the planned DHCP server.** Its documented DHCP client obtains its own management address; manual IP settings also affect that address only. TP-Link's comparison distinguishes the Agile/Easy Managed range from ranges providing DHCP server/relay and routed interfaces. “Managed L2” does not imply those services. Installing an Omada controller would not add a DHCP server to this switch. [ES216G datasheet](https://static.tp-link.com/upload/product-overview/2025/202512/20251223/Datasheet_ES216G%28UN%291.20.pdf) · [Switch-range comparison](https://www.omadanetworks.com/us/business-networking/all-omada-switch/)

The HX510 product specification advertises address reservation. The BBA Mesh guide linked by its support page describes DHCP server settings and MAC-to-IP reservations, but explicitly warns that features vary by model, software, region and ISP. Inspect the actual DHCP authority rather than assuming the nearest mesh unit is the router. The expected deployment has the primary HX510 as gateway/DHCP owner and the secondary as its mesh satellite; if the units are actually access points behind another gateway, resolve the declaration before changing anything. Never start a competing DHCP server on the secondary HX510 or a lab host. [HX510 India specification](https://www.tp-link.com/in/service-provider/wifi-router/hx510/) · [BBA Mesh guide, sections 6.1.2–6.1.3](https://static.tp-link.com/upload/manual/2026/202607/20260714/BBA%20Mesh_UG_REV1.0.1.pdf)

Moving DHCP off the router would require a separate DHCP service or suitable gateway, with its own availability, recovery and migration design. It is not necessary for the selected fleet and is not added by this research. The switch itself is not a host on which our Ansible roles can install a DHCP service.

## Capabilities and intended use

### ES216G

The precise numeric specification below comes from the UN V1.20 datasheet. The older Easy Managed user guide supplies configuration guidance, not proof that every revision has identical controls. In particular, its four-member LAG example/limit differs from the newer eight-member specification. Pin and inspect the delivered variant before implementing any version-sensitive behavior.

| Feature | Documented capability | Lab treatment |
|---|---|---|
| Ports and capacity | 16 gigabit copper ports; 32 Gb/s switching; 23.8 Mpps; fanless. | Use the existing port map. A single port/uplink remains 1 Gb/s; aggregate switching capacity is not per-host or Internet bandwidth. ES216G does not power the laptops/Macs over Ethernet. |
| Address management | DHCP client or manual management IP. | Reserve the switch's management address at the DHCP authority. Each host gets its own reservation. |
| Loop protection | Loopback detection/prevention. | Keep the approved single-uplink tree. Qualify recovery without intentionally looping the live LAN; do not infer STP/RSTP redundancy. |
| VLANs/isolation | Port/MTU/802.1Q VLANs; up to 32 groups, 4K VID space. | Keep the approved flat untagged LAN and port isolation off. “MTU VLAN” is a VLAN feature, not the packet-size setting. No VLAN redesign or routed segmentation is implied. |
| Link aggregation | Static LAG; V1.20 lists four groups, up to eight members. | Off in v1. Static aggregation is not LACP and does not justify a second cable to the router. |
| Multicast | IGMP v1/v2/v3 snooping and fast leave. | Record effective settings; qualify discovery/multicast across the HX510 link and Macs before changes. Do not assume the switch is a querier or enable fast leave on a link carrying multiple clients. |
| QoS and flooding | Port/802.1p/DSCP priority, eight queues, WRR, rate limits and storm control. | No arbitrary priorities or thresholds. Measure first; define exact limits and recovery if needed. Do not throttle the sole management/uplink path as an experiment. |
| Discovery and diagnostics | LLDP, counters, port mirroring and cable diagnostics. | Use available observations; LLDP is not identity proof. Packet capture requires explicit targets, duration and private handling. Treat cable testing as potentially disruptive until qualified. |
| Frame size | V1.20 advertises 15 KB jumbo frames. | Keep the existing standard-MTU policy; all-path support must precede any later increase. |
| Management | Web GUI; optional Omada controller management. | Keep standalone. No new controller, cloud adoption or undocumented API/SSH automation. |

Source for listed features: [ES216G UN V1.20 datasheet](https://static.tp-link.com/upload/product-overview/2025/202512/20251223/Datasheet_ES216G%28UN%291.20.pdf). The manufacturer comparison does not list ACL, LACP, 802.1X, SNMP or CLI for this range. Do not promise SNMP polling, switch SSH playbooks, DHCP snooping, authenticated device admission or inter-VLAN routing from the retailer's category label. The router's WAN firewall does not inspect ordinary same-LAN host traffic; the approved host/role security controls remain necessary. [Range comparison](https://www.omadanetworks.com/us/business-networking/all-omada-switch/)

The older guide documents port state/speed/duplex, configuration backup/restore, reboot and firmware upload. It also warns that ingress rate limiting and storm control conflict on a port, and restore overwrites settings and reboots. A configuration backup is not firmware rollback. [Easy Managed guide, Switching, QoS and System Tools](https://static.tp-link.com/upload/manual/2024/202408/20240813/1910013715_Omada%20Easy%20Managed%20Switch_UG.pdf)

Omada adoption is a configuration-ownership migration: the installation guide says changing from standalone to controller mode requires reconfiguration. QoS/priority availability is mode-specific in the datasheet. Do not adopt the switch merely to obtain a dashboard or assume standalone settings survive. [ES216G installation guide, chapter 4](https://static.tp-link.com/upload/manual/2024/202410/20241022/7106511600_ES220GMP%2CES228GMP%2CES216G%2CES224G%28UN%29_IG.pdf)

### HX510

| Feature group | Published capability or guide coverage | Lab treatment |
|---|---|---|
| Topology and transport | Three gigabit ports per unit; router/AP modes; EasyMesh and optional Ethernet backhaul. | Verify actual roles and uplink ports. Keep the selected wireless backhaul initially. Measure same-switch LAN and backhaul/WAN separately; do not equate AX3000 radio rates with throughput. |
| Addressing | Address reservations; guide covers IPv4 DHCP/pool/lease and IPv6 advertisements/DHCPv6. | Verify the actual server, pool, reservations and observed client MACs. Preserve existing Debian versus Mac IPv6 policy; do not disable IPv6 globally on the home router. |
| Wireless | WPA2/WPA3, multiple SSIDs, scheduling and client steering. | Inventory settings and test wired reachability through the satellite. Do not change household SSIDs, credentials, guest access or radio settings as a side effect of server onboarding. |
| WAN and security | Dynamic/static/PPPoE WAN, SPI firewall; guide covers forwarding, UPnP, DMZ and filtering. | Preserve ISP connectivity. No new forwards, DMZ host or automatic port mapping. Inventory existing exposure; unrelated household entries need a separate decision before removal. |
| Administration | Local web/Aginet and ISP cloud management; generic guide covers local HTTPS/restrictions, remote admin, TR-069, logs, diagnostics, SNMP and backup/restore. | Treat each actual UI capability as unverified. Prefer restricted local HTTPS if supported; verify HTTP is not still exposed. No default-community SNMP, write access, WAN SNMP or new remote admin. Do not disable ISP provisioning or flash generic firmware without an ISP-compatible recovery plan. |

[HX510 India product/specification](https://www.tp-link.com/in/service-provider/wifi-router/hx510/) · [HX510 support](https://www.tp-link.com/us/support/download/hx510/v1/) · [BBA Mesh guide, chapters 6, 11, 14 and 16](https://static.tp-link.com/upload/manual/2026/202607/20260714/BBA%20Mesh_UG_REV1.0.1.pdf). The generic guide is an inspection checklist, not a claim that ACT firmware provides every feature. Aginet/EasyMesh and Omada are different management systems; the HX510 is not automatically an Omada gateway.

## Address allocation and first setup

Follow the existing [discovery/assignment procedure](architecture-and-networking.md#first-address-discovery-and-assignment), with these implementation requirements:

1. Capture both HX510 units' mode, revision/firmware and link relationship; identify the observed DHCP server, gateway, DNS and lease behavior. Inspect only approved devices. Record unexpected DHCP offers as a blocking conflict, not permission to reconfigure another device.
2. Match the switch label, current management MAC/IP and each host's verified serial/wired MAC. Compare host and router observations; a MAC, port label or DHCP hostname alone is not trusted host identity.
3. Render a private proposal covering usable subnet bounds, dynamic allocation, occupied/static/reserved addresses, switch/router management addresses and each inventory node. Reject duplicate addresses/MACs, network/broadcast/gateway misuse, incompatible pools and loss of the active management path. No example address becomes a default.
4. The approved policy currently calls for a distinct infrastructure range outside the ordinary dynamic pool. The HX510 guide does not establish whether the actual firmware permits reservations outside its configured pool. A proposed alternative is verified exclusive reservations inside that pool if required by firmware; this clarification is **not yet approved**. Do not assume support, silently relax the rule or switch all hosts to static addressing. Use the existing reviewed static fallback only with its explicit prerequisites.
5. Apply one approved UI/device change at a time, reconnect independently, verify the target identity, then test lease renewal/reboot persistence before proceeding. Export configurations before and after, privately. Record whether firmware requires a separate save/commit for persistence.
6. Keep a recovery copy of the address/port map and device procedure in an independent approved recovery location accessible through the local-console/operator recovery path even when the router/control host is unavailable. A separate pre-existing workstation is not required; a copy only on control is not independent recovery. Normal clients still do not become alternate controllers. A router/DHCP outage is different from an Internet outage: new or cold-booted clients may be unable to obtain addresses. Prove the chosen console/local recovery path rather than promising indefinite operation from cached leases.

The documented factory fallback in the matched ES216G installation guide is `192.168.0.1`; that is a recovery fact, not our chosen LAN or management address. Use it only under a verified, isolated local procedure when DHCP discovery fails and the delivered manual matches. Do not attach a device with a conflicting factory address to the active LAN. [Installation guide](https://static.tp-link.com/upload/manual/2024/202410/20241022/7106511600_ES220GMP%2CES228GMP%2CES216G%2CES224G%28UN%29_IG.pdf)

## Operations to implement

The following are workflow requirements, not invented public command names or implemented adapters. `vsk-labs` owns declaration/plan/authorization, target limits and evidence; central Ansible owns supported host configuration. Where no tested device adapter exists, an authorized local admin performs the plan-declared UI step. A manual step stays pending until the relevant evidence is supplied and validated; clicking “done” is not proof of every postcondition.

| Operation | Required plan and actor | Verification and recovery |
|---|---|---|
| Inspect and reconcile | Read-only scoped collector or guided device UI; compare declared/observed version, mode, IP, ports and topology. | Record source/time/capability; distinguish unavailable/stale telemetry from healthy state. No automatic discovery of arbitrary subnets. |
| Initial network setup | Admin performs bounded switch/router steps through the local-setup/foundation workflow; retain known access and private exports. | Verify a single intended DHCP authority, management access, declared links, addressing persistence and LAN recovery. Stop at a conflict or missing feature. |
| Add/adopt a host | Verify inventory identity/data, draft reservation and port assignment, approve host hardening and role plans. | Fresh SSH identity, lease/address checks, allowed/denied flows, reboot and role admission. Unknown installations are not erased or admitted automatically. |
| Move/replace a host or NIC | Explicit old/new identity, MAC/IP/port delta and workloads to drain; preserve immutable node-ID rules. | Disconnect/fence the old device before reusing an address. Verify the replacement and remove obsolete grants; never conceal a changed SSH key. |
| Suspend/offboard | Revoke access/workload credentials via their existing owners; coordinate host shutdown and a declared physical/port action if required. | A removed reservation does not disconnect a host. Prove denied access and intended isolation; retain historical inventory and retire addressing only after checking reuse safety. |
| Diagnose loss/slowness | Separate host NIC/cable, switch forwarding, DHCP/DNS, HX510 backhaul, WAN and Mesh/Tunnel checks. | Collect bounded counters and qualified probes first. Cable tests, mirroring, counter resets or port changes need their risk/approval classification; avoid rebooting devices as the first diagnostic. |
| Change network/security settings | Admin-reviewed exact device/port delta, recovery session and effects on the control path. | Verify both permitted and denied behavior, then persistence. Revert the recorded delta or recover locally; a lost connection is not a completed change. |
| Rotate device administrator access | Secret references, custodian and controlled replacement sequence; no secrets in plan text. | Prove new login and old-login denial while retaining physical recovery. Do not assume multi-user/RBAC support on an Easy Managed device. |
| Firmware maintenance | Exact regional hardware/release match, supported upgrade route, trusted download/digest, private config backup, power/recovery and outage plan. | Recheck management, config, ports, DHCP, backhaul and flows. Never assume dual-image or downgrade support; if rollback is unsupported, state the replacement/manual recovery route before approval. |
| Backup/restore/reset or failed device | Separate configuration restore from firmware recovery; exact target, compatible export, credentials and local operator. | Restore and verify actual behavior. Factory reset is destructive and last-resort, not a connectivity fix. Hold dependent work until current evidence is re-established. |
| Power, outage and drift | Coordinate existing UPS/host shutdown policy; detect version/config/link changes and distinguish WAN, router, switch and control loss. | Test recovery and stale-evidence handling without adding automatic device reboot/reset/repair. Network equipment and ISP-driven changes have their own observed versions. |
| Future topology expansion | Explicit design/approval for a second switch, LAG, VLAN, DHCP migration or Omada adoption; excluded from ordinary onboarding. | Require compatible endpoints, full access/flow tests and a cable/config rollback plan. No second control system or untested routing capability appears implicitly. |

## Security and telemetry limits

- The current flat LAN is not isolation from a compromised local device. Host firewalls do not secure the switch's own web UI or prevent another machine from issuing DHCP offers. No unavailable ACL, DHCP-snooping or 802.1X control may be reported as active.
- Inspect management protocol support. If the switch only offers HTTP, do not claim credential encryption or put that login behind a public tunnel. A locally isolated administration procedure or explicit risk decision must be settled before the affected issue is ready; do not add a VLAN redesign silently.
- Disable unused cloud/controller enrollment where the delivered firmware supports it and verify the standalone baseline. Preserve required ISP control separately; an agent must not confuse ISP TR-069 with user-enabled remote administration.
- Router/switch exports can contain credentials and private topology. Store them as restricted, encrypted recovery artifacts; only sanitized evidence reaches audit summaries. Packet captures and mirrored traffic need equally narrow handling and cleanup.
- Do not build a mandatory SNMP exporter for the ES216G. Combine supported host/endpoint probes with guided device counters/configuration evidence. Missing telemetry remains explicit. A future supported API/controller adapter requires its own approval, real-device qualification, credential boundary and ownership migration.

## Development placement and readiness

| Existing phase | Required implementation contribution |
|---|---|
| **0, issues 0.3–0.4** | Pin the bounded local-setup/foundation and manual-operation contract, reservation-pool question when relevant, device management security and version-specific baseline. Keep this feature/operation map as the shared source rather than copying it into every issue. |
| **1–2** | Generate capability/input/result contracts and store private desired/observed network identities through the common API. Exact resource types and schemas belong to their approved solution; no provider-specific core fields. |
| **4–5** | Plan-declared manual steps, responsible-human acknowledgement, exact effects, resumable/pending/failed verification, stale evidence and protected configuration backup references. No alternate audit/approval store. |
| **6–7** | Workstation LAN/host bootstrap, reservation guidance, Ansible profiles and access integration. Test lockout recovery and single authoritative handoff. |
| **10–11** | Diagnostics, maintenance, replacement/offboarding/recovery runbooks, truthful telemetry and integrated acceptance. Test manual workflow software with fixtures; actual G-003/G-004 site acceptance still needs the delivered hardware. Any claimed automated device adapter needs real compatible-device tests. |

The hardware-input checklist is short: ES216G label/version and firmware; both HX510 labels, firmware and mode; sanitized LAN/DHCP/reservation and management-security screens; current uplink map; config export/recovery availability. Obtain these through scoped inspection or the operator, never request passwords or full secret-bearing exports in chat. No exact IP, firmware release, unsupported capability or device recovery procedure is invented to make an issue ready.
