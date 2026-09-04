# Decisions and sources

[Back to README](../README.md) · [Architecture](architecture-and-networking.md) · [Inventory](inventory-and-roles.md) · [Operations](security-and-operations.md) · [Automation](automation-and-agents.md)

## Evidence method

Authoritative transcript:

`/Users/kmanojkumar/.codex/sessions/2026/08/24/rollout-2026-08-24T12-40-40-01a0329b-68d8-7633-95e7-a7757675f5e6.jsonl`

The handoff designates physical records **1–2,074** (ordinals `0..2073`) as the authoritative snapshot. The file currently contains **2,144 valid contiguous records** (ordinals `0..2143`), so the audit parsed the entire file but tagged records 2,075–2,144 as a supplemental appended region. That tail contains the implementation handoff at record 2,110 plus task activity; it was never silently folded into the original count. The parser paired all 178 questionnaire answers and indexed five compaction boundaries. A compacted record is replacement model context: retained prior messages were recorded for lineage but not double-counted as new decisions. Later explicit user decisions override earlier statements.

Evidence notation:

- `TR-n`: transcript JSONL record whose zero-based `ordinal` is `n`; its physical one-based JSONL record number is `n + 1`. The machine register stores both values.
- `Q-n/id`: user answer at physical JSONL record number `n`, keyed by the `request_user_input` question `id`; the machine register also stores its question record, both ordinals and turn key.
- `GS1` / `GS2`: live Google workbook Sheet1 / Sheet2, re-read 25-08-2026 without editing.
- `SRC-*`: primary official documentation in [Source register](#source-register).

### Adversarial Q&A reconciliation

All 178 answered question IDs were classified as a current decision, a clarification feeding a later decision, or superseded. The highest-risk conflicts were resolved as follows:

| Earlier answer/conclusion | Authoritative final disposition |
|---|---|
| Early private-network alternatives | Cloudflare Mesh is the sole bidirectional private overlay; Tunnel is only selected ingress. [D-040](#d-040) |
| Early SOPS+age site choice | This site uses 1Password CLI/Teams service account; SOPS+age is only an optional public-engine provider. [D-071](#d-071) |
| Early Prometheus/Grafana proposal | Beszel alone is the v1 monitoring baseline. [D-084](#d-084) |
| Early 30-day update delay | Uniform routine soak is seven days. [D-086](#d-086) |
| Earlier longer backup retention | Final defaults are 7 days standard and 14 days critical. [D-080](#d-080) |
| Earlier provisional node/role maps | The final three-app/two-builder/spare/reserve mapping follows Q-1615 and the serial policy. [D-022](#d-022) |
| Earlier request to migrate active applications | Application-by-application placement is deferred; Chaabi Prod is outside v1. Harbor alone remains an explicit platform-workload exception. [D-004](#d-004) |
| Selected high-autonomy AI mode | Available only inside individual interactive standard-user profiles; never confers infrastructure authority or applies to privileged/service identities. [D-075](#d-075) |
| Private `vsk-labs-infra` repository as site authority | Superseded after the transcript: local SQLite is the private operational source of truth; GitHub remains code storage, with encrypted backups and signed exports for recovery. [D-100](#d-100) |

Unresolved items below are facts or implementation selections that the transcript genuinely did not close; they are not reopened decisions.

The audit's machine register contains one row for every 178 questionnaire answer and all 14 raw user messages, including physical record/ordinal, turn/question key, authority class, effective status and supersession pointer. Assistant recommendations and external facts are separate collections. The sanitized deliverable register also maps normalized mandates to destination/status and includes the GitHub, support and layer matrices; it never includes Sheet credential-like values. See [`audit-register.json`](audit-register.json). This document is the human-readable normative result.

## Decision log

### Scope and platform

| ID | Decision | Evidence |
|---|---|---|
| <a id="d-001"></a> [D-001](#d-001) | The display name is VegaStack Labs, the platform/repository slug is `vegastack-labs`, and the CLI/executable is `vsk-labs`. | TR-639; Q-1199/repository_names; direct user naming revision 25-08-2026 |
| <a id="d-002"></a> [D-002](#d-002) | Mixed personal/business, noncritical workloads; planned downtime/manual recovery acceptable. | Q-70/usage_class; Q-110/business_scope_resolution; Q-110/data_criticality |
| <a id="d-003"></a> [D-003](#d-003) | V1 covers fleet foundation, networking, CI, Coolify, identity, security, backup, observability and deterministic operations. | TR-8; TR-639; TR-2109; Q-579/device_scope |
| <a id="d-004"></a> [D-004](#d-004) | Application-by-application placement is deferred; Chaabi Prod migration is outside v1; Harbor is the explicit platform-workload exception. | TR-1929; TR-2109; Q-1579/chaabi_prod_scope; Q-1579/v1_application_scope |
| <a id="d-005"></a> [D-005](#d-005) | Review the compact documentation set before deployment. | TR-2109; Q-1199/documentation_shape |
| <a id="d-006"></a> [D-006](#d-006) | Active ThinkPads arrive as clean Debian 13.6 systems. | TR-8; Q-1453/thinkpad_rebuild_policy; SRC-DEB-01 |
| <a id="d-007"></a> [D-007](#d-007) | Build the clean `vegastack-labs` platform from scratch; use `mac-dev-env-setup` only to mine proven UX/workflow requirements, not for compatibility or unsafe legacy mechanisms. | Q-579/repository_strategy; Q-597/current_mac_usage; assistant TR-576/TR-585; direct user naming revision 25-08-2026 |
| <a id="d-008"></a> [D-008](#d-008) | Core management is agentless Ansible/SSH/provider APIs; no custom privileged node daemon. Phones are guided clients, not managed servers. | assistant TR-576/TR-585; Q-861/mobile_mesh_policy |

### Inventory and roles

| ID | Decision | Evidence |
|---|---|---|
| <a id="d-010"></a> [D-010](#d-010) | Immutable `vsk-node-NN`; roles are movable aliases. | Q-1579/node_naming_scheme; assistant TR-1587 |
| <a id="d-011"></a> [D-011](#d-011) | Number active Sheet1 rows in order, skipping unavailable assets; never recycle. | Q-1590/asset_numbering; assistant TR-1596 |
| <a id="d-012"></a> [D-012](#d-012) | Eight working ThinkPads; PF2RLCC9 quarantined; PF246XWQ retired. | GS1; Q-1590/faulty_node_policy |
| <a id="d-013"></a> [D-013](#d-013) | Mac mini is node 09 and iMac node 10. | assistant TR-1596; TR-1467 |
| <a id="d-014"></a> [D-014](#d-014) | Dedicated current RAM/storage columns override factory specification text. | TR-1467; GS1; assistant TR-1576 |
| <a id="d-015"></a> [D-015](#d-015) | Resolve the post-transcript live-sheet hostname conflict and remove/rotate plaintext credential-like fields before apply. | GS1 current read |
| <a id="d-020"></a> [D-020](#d-020) | One dedicated ThinkPad runs control systems only—no user app or CI job. | Q-101/control_plane_host; Q-627/control_host_scope; Q-722/control_plane_duties; Q-739/control_plane_duties_revised |
| <a id="d-021"></a> [D-021](#d-021) | Coolify application nodes are independent servers. | Q-897/coolify_compute_model |
| <a id="d-022"></a> [D-022](#d-022) | Three app nodes, two Linux builders, one qualified spare and unassigned recovery headroom. | Q-1617/app_node_count; Q-1617/linux_ci_concurrency; Q-1617/spare_capacity |
| <a id="d-023"></a> [D-023](#d-023) | Harbor is a Coolify-managed application workload on an app node, not dedicated infrastructure. | TR-1929; TR-2109 |
| <a id="d-024"></a> [D-024](#d-024) | Mac mini is macOS ARM64 CI/shared development; iMac is v1 Hermes host; no Coolify roles. | Q-70/apple_role; Q-1975/mac_v1_role; Q-1097/mac_role_boundary; TR-2109 |
| <a id="d-025"></a> [D-025](#d-025) | Tested mutation matrix: site Debian 13.x; public Linux roles Debian 13.x plus explicitly tested Ubuntu LTS; current/previous macOS for native roles; Coolify Linux only. | Q-1097/supported_os_matrix; SRC-DEB-01; SRC-CO-01 |

### Network and access paths

| ID | Decision | Evidence |
|---|---|---|
| <a id="d-030"></a> [D-030](#d-030) | Wire every always-on machine. | Q-70/wired_readiness |
| <a id="d-031"></a> [D-031](#d-031) | Use the 16-port TP-Link ES216G. | TR-1929; Q-1115/switch_class; Q-1590/switch_port_count; SRC-TP-02 |
| <a id="d-032"></a> [D-032](#d-032) | One ES216G uplink to the secondary HX510; all servers/Macs attach to the switch. | Q-1362/switch_router_topology; assistant TR-1685 |
| <a id="d-033"></a> [D-033](#d-033) | Flat untagged main LAN for v1; guest Wi-Fi separate; port isolation off. | Q-110/lan_segmentation; Q-785/lan_segmentation; assistant TR-1685 |
| <a id="d-034"></a> [D-034](#d-034) | DHCP reservations for all always-on infrastructure; verify ISP firmware first. | Q-861/lan_addressing; Q-886/lan_addressing_final; Q-1975/lan_addressing; SRC-TP-01 |
| <a id="d-035"></a> [D-035](#d-035) | ES216G local standalone management, one uplink, loop prevention on, initial LAG/jumbo off, config backup. | Q-1681/switch_management_mode; assistant TR-1685 |
| <a id="d-036"></a> [D-036](#d-036) | Future expansion switch uses one tree link; no loop; optional later static LAG only after both ends are configured. | TR-1918; assistant TR-1923; SRC-TP-02 |
| <a id="d-037"></a> [D-037](#d-037) | Disable IPv6 on managed Debian server interfaces; minimal router changes. | Q-1362/lan_ipv6_policy; Q-1362/router_hardening_policy |
| <a id="d-038"></a> [D-038](#d-038) | Keep the secondary HX510 wireless backhaul initially; measure it and move to Ethernet backhaul only if it is inadequate. Same-switch server traffic stays local. | assistant TR-1685 |
| <a id="d-040"></a> [D-040](#d-040) | Cloudflare Mesh is the sole bidirectional private overlay; direct participants; no v1 gateway/jump requirement. | Q-101/tailscale_plan; TR-146; assistant TR-177/TR-198/TR-209; TR-2109; SRC-CF-01 |
| <a id="d-041"></a> [D-041](#d-041) | LAN addresses locally, Mesh addresses remotely, LAN/console for recovery. | assistant TR-177/TR-198/TR-209 |
| <a id="d-042"></a> [D-042](#d-042) | Cloudflare One Client carries private routes only; personal devices may disconnect it. | Q-838/cloudflare_client_traffic; Q-838/personal_mesh_disconnect |
| <a id="d-043"></a> [D-043](#d-043) | Self-enroll to quarantine; exact inventory may auto-approve desktop; mobile registration ID/Mesh IP requires human approval and re-registration returns to quarantine. | Q-785/mesh_device_enrollment; Q-838/device_inventory_enforcement; Q-886/device_approval_model; Q-886/device_enrollment_window; Q-861/mobile_mesh_policy; SRC-CF-06 |
| <a id="d-044"></a> [D-044](#d-044) | Mesh capacity warning at 40, enrollment block at 48 against current limit 50; preserve the selected no-added-recurring-cost boundary. | Q-1392/cloudflare_cost_boundary; Q-1392/mesh_capacity_policy; SRC-CF-05 |
| <a id="d-045"></a> [D-045](#d-045) | Tunnel publishes selected services through two shared connectors; no inbound router forwarding. | TR-8; Q-897/cloudflare_tunnel_topology; SRC-CF-04 |
| <a id="d-046"></a> [D-046](#d-046) | Automatic LAN/Mesh selection applies to SSH and CLI aliases; direct IPs are recovery inputs; canonical private inventory names use the `labs.vegastack.com` suffix. | TR-215; Q-785/internal_naming_scope; Q-1975/hostname_resolution; assistant TR-2040; user review 24-08-2026 |
| <a id="d-047"></a> [D-047](#d-047) | Service exposure classes: public/protected/private; dashboards default protected; audience explicit. | Q-897/service_exposure_classes; Q-1078/private_web_routing; Q-1097/private_web_policy_revised; Q-1106/protected_service_audience |
| <a id="d-048"></a> [D-048](#d-048) | Public names are `<service>.vegastack.com`, `<env>--<service>.vegastack.com`, and `labs-<tool>.vegastack.com`. | Q-1078/public_hostname_convention |

### Coolify, CI and Harbor

| ID | Decision | Evidence |
|---|---|---|
| <a id="d-049"></a> [D-049](#d-049) | Stateful v1 applications are single-node with backup/restore, not automatically failed over. | Q-923/stateful_availability |
| <a id="d-050"></a> [D-050](#d-050) | Rebuildable single Coolify/control node; remote Linux servers over SSH. | Q-1143/control_plane_redundancy; assistant TR-633; SRC-CO-02/SRC-CO-05 |
| <a id="d-051"></a> [D-051](#d-051) | A Coolify build-server role cannot host applications. | assistant TR-67; SRC-CO-03 |
| <a id="d-052"></a> [D-052](#d-052) | Four Linux jobs target; capacity-calculated after thermal burn-in. | Q-1617/linux_ci_concurrency; Q-1344/builder_job_concurrency; assistant TR-1625 |
| <a id="d-053"></a> [D-053](#d-053) | Linux jobs use one-job ephemeral unprivileged containers with rootless builds, no Docker socket/privileged mode/fleet-admin credentials, isolated cache/workspace and restricted east-west network. | Q-914/runner_lifecycle; assistant TR-911/TR-920; SRC-GH-02 |
| <a id="d-054"></a> [D-054](#d-054) | Mac mini reserves one lower-priority/resource-capped native macOS job and otherwise serves interactive development. | Q-914/initial_build_targets; Q-1344/mac_mini_runner_availability |
| <a id="d-055"></a> [D-055](#d-055) | CI builds/signs images, pushes Harbor, submits the exact digest/evidence to the plan engine, then directly calls Coolify as the enrolled external executor using a project/team-scoped `write`+`deploy` token. Environment policy is risk-based: an exact low-risk class may auto-deploy; production-like deployment requires the assigned maintainer. This is the VegaStack Labs deployment path; AWS, Hetzner and client-infrastructure targets remain application-repository workflow concerns outside v1 unless a future hosting adapter is onboarded. Harbor scans report initially. | Q-282/deployment_trigger; Q-923/deployment_trigger; Q-1143/deployment_rollback_policy; Q-1161/production_deploy_approval; Q-1264/application_build_path; Q-1264/ghcr_image_visibility; Q-1264/deployment_trigger_path; Q-1312/vsk_github_secret_management; Q-1335/coolify_ci_isolation; Q-1335/image_signing_policy; Q-1335/harbor_vulnerability_gate; SRC-CO-13 |
| <a id="d-056"></a> [D-056](#d-056) | Harbor public+private, local primary+R2 backup, clean migration with accepted downtime/rollback window; human SSO deferred. | Q-1293/harbor_access_pattern; Q-1293/harbor_storage_model; Q-1293/harbor_migration_goal; Q-1312/harbor_auth_migration_policy; Q-1453/harbor_downtime; Q-1453/harbor_rollback_window |
| <a id="d-057"></a> [D-057](#d-057) | All organization repositories are eligible by explicit enrollment, but home runners accept only trusted protected/release/manual events; untrusted/fork PRs use GitHub-hosted runners. | Q-1344/home_runner_repository_policy; Q-914/ci_trust_boundary; assistant TR-1341/TR-1350; SRC-GH-02 |
| <a id="d-058"></a> [D-058](#d-058) | App repos own build/Compose, migrations and health; private infra owns environment policy class, placement, domains/exposure, secret refs, resources and backups; Coolify is derived. | Q-923/environment_model; Q-1078/service_placement_mode; Q-1106/app_infra_ownership; Q-1106/service_resource_policy |
| <a id="d-059"></a> [D-059](#d-059) | Harbor keeps local human auth/self-registration off; one LAN-direct/Tunnel hostname; exactly two yearly-rotated scoped system robots (CI push/pull, deploy pull); remote large pushes use Mesh/private; local primary plus R2 backup. | Q-1293/harbor_access_pattern; Q-1312/harbor_auth_migration_policy; Q-1312/harbor_robot_scope; assistant TR-1319/TR-1328; SRC-HBR-01/SRC-HBR-02/SRC-CF-10 |

### Identity, secrets and Macs

| ID | Decision | Evidence |
|---|---|---|
| <a id="d-060"></a> [D-060](#d-060) | Google Workspace is prerequisite IdP for protected apps and Mesh enrollment. | Q-265/cloudflare_idp; Q-1181/protected_identity_eligibility; Q-2043/cloudflare_identity; SRC-CF-07 |
| <a id="d-061"></a> [D-061](#d-061) | The original private-Git declaration mechanism is superseded by D-100; the requirement that platform-declared people/devices/roles generate Cloudflare audiences remains, now from the control database. Workspace licensing/provisioning remains outside v1. | Q-761/identity_source; Q-1181/cloudflare_access_group_authority; Q-1181/google_workspace_provisioning_scope; post-transcript user decision 25-08-2026 |
| <a id="d-062"></a> [D-062](#d-062) | Broad groups are `vegastack-labs-admins` and `vegastack-labs-users`; admins may also be users. | Q-265/admin_scope; Q-282/second_operator_identity; Q-618/access_tiers; TR-639 |
| <a id="d-063"></a> [D-063](#d-063) | Admin invite, user self-enrollment and validated declaration/plan is the onboarding flow; the original private-repository PR mechanism is superseded by D-100. | Q-1154/human_onboarding_flow; Q-618/client_enrollment; post-transcript user decision 25-08-2026 |
| <a id="d-064"></a> [D-064](#d-064) | Admins get Debian personal accounts; users only where assigned; shell is an explicit grant. | Q-265/server_account_model; Q-739/linux_admin_accounts; Q-746/node_account_scope; Q-1154/user_shell_grant_model |
| <a id="d-065"></a> [D-065](#d-065) | SSH keys are per person per device; routine elevation is scoped no-prompt. | Q-739/admin_elevation; Q-746/ssh_key_model; Q-761/ssh_key_model_final |
| <a id="d-066"></a> [D-066](#d-066) | Mac mini team accounts are individual standard macOS accounts. | Q-2043/mac_dev_privilege; Q-1975/mac_v1_role |
| <a id="d-067"></a> [D-067](#d-067) | Macs expose SSH+Screen Sharing over LAN/Mesh, disable system sleep, allow display sleep and remain always on. | Q-1353/mac_remote_access; Q-1353/mac_uptime_roles |
| <a id="d-068"></a> [D-068](#d-068) | Routine offboarding reviewed; immediate reversible suspension available. | Q-761/offboarding_model; Q-770/emergency_suspension |
| <a id="d-069"></a> [D-069](#d-069) | Work Apple ID only on designated owner/admin with recovery/Activation Lock recorded; iMac has maintenance admin plus standard Hermes manager, not team dev accounts. | Q-1353/mac_apple_id_policy; assistant TR-1361; Q-1975/mac_v1_role |
| <a id="d-070"></a> [D-070](#d-070) | Host firewall default deny with declared exceptions. | Q-861/host_firewall_policy |
| <a id="d-071"></a> [D-071](#d-071) | Site secret provider is 1Password CLI/Teams service account; fail closed; public engine may separately support SOPS+age; vault scope follows least privilege. | Q-588/secrets_backend; Q-1032/secret_source_of_truth; Q-1055/site_secret_provider; Q-1055/onepassword_outage_behavior; Q-1172/onepassword_account_state; Q-1172/onepassword_vault_granularity |
| <a id="d-072"></a> [D-072](#d-072) | 365-day rotation with 30/7-day reminders; admin approves staged distribute/test/revoke with failure rollback; lead admin holds sealed recovery material. | Q-934/recovery_key_custody; Q-1032/secret_rotation_policy; Q-1055/rotation_execution_mode |
| <a id="d-073"></a> [D-073](#d-073) | Agents never reveal plaintext by default; authorized maintainer/human reveal is 1Password-native. | Q-1161/maintainer_secret_access; Q-1172/secret_reveal_ux; Q-1214/agent_secret_boundary |
| <a id="d-074"></a> [D-074](#d-074) | No mandatory Linux full-disk encryption in v1; trusted physical-site assumption and theft residual accepted. | Q-1032/control_plane_disk_encryption; assistant TR-1038 |
| <a id="d-075"></a> [D-075](#d-075) | High-autonomy Codex/Claude profiles are available to individual interactive standard users only; never root/service/CI/fleet-credential accounts. Vendor AI auth/licensing is separate from fleet attribution and is not shared by automation. | Q-618/unsafe_ai_mode; Q-101/ai_identity_model; assistant TR-98/TR-107/TR-609/TR-624 |

### Backup, observability and maintenance

| ID | Decision | Evidence |
|---|---|---|
| <a id="d-080"></a> [D-080](#d-080) | Explicit backup class; 512 GB SSD on control plane; standard local 7 days; critical local+R2 14 days; declared Mac work included. | Q-934/backup_class_model; Q-951/backup_ssd_location; Q-951/backup_retention; Q-962/backup_retention_simple; Q-1375/mac_backup_scope |
| <a id="d-081"></a> [D-081](#d-081) | Systemd timers; stateful data uses typed adapter or declared consistency hook. | Q-962/backup_scheduler; Q-1375/stateful_backup_contract |
| <a id="d-082"></a> [D-082](#d-082) | Monthly checks and quarterly functional restores covering representative critical and standard data. | Q-951/restore_testing; Q-1375/restore_verification_depth |
| <a id="d-083"></a> [D-083](#d-083) | The VegaStack Labs notification profile opens one sanitized, deduplicated GitHub issue and closes it on verified success; an external Worker checks a narrow R2 heartbeat every 5 min and alerts at 15 min stale. The App-key mechanism was an assistant proposal and is superseded by D-104's smallest-credential classification. | Q-962/backup_failure_alerts; Q-998/backup_alert_channel; Q-998/incident_issue_lifecycle; Q-998/external_heartbeat; assistant TR-990/TR-1005; current audit correction 25-08-2026 |
| <a id="d-084"></a> [D-084](#d-084) | Beszel only, no Docker socket, rebuilt declaratively; earlier broader observability/Prometheus inputs are superseded. | Q-1015/observability_profile; Q-1392/prometheus_retention; Q-1444/monitoring_stack; Q-1444/beszel_docker_access; Q-1444/beszel_migration |
| <a id="d-085"></a> [D-085](#d-085) | Local logs 30 days; encrypted audit in R2 six months; critical first failure, warnings after two failures, low-risk notices daily digest. | Q-1015/operational_log_retention; Q-1015/alert_sensitivity |
| <a id="d-086"></a> [D-086](#d-086) | Sunday 02:00 AM–05:00 AM IST; routine seven-day soak; canary/batched updates, connectors one at a time and control last; controlled monthly platform upgrades. | Q-1132/os_update_policy; Q-1132/maintenance_window; Q-1132/platform_update_policy; Q-1143/update_soak_policy |
| <a id="d-087"></a> [D-087](#d-087) | UPS assumed; spaced vertical rack; thermal/battery qualification before load. | Q-1115/ups_policy; Q-1115/laptop_rack_policy; assistant TR-1625 |
| <a id="d-088"></a> [D-088](#d-088) | Balanced critical recovery targets: node failure RPO <=6 h/RTO <=4 h; total-site loss RPO <=24 h/RTO <=24 h. | Q-934/critical_recovery_objective |

### Automation and agents

| ID | Decision | Evidence |
|---|---|---|
| <a id="d-090"></a> [D-090](#d-090) | New MIT public `vegastack-labs` Go+Ansible platform engine, opinionated modules and no v1 plugin API. The original private `vsk-labs-infra` storage split is superseded by D-100. | Q-588/cli_runtime; Q-588/config_split; Q-597/public_repo_strategy; Q-597/v1_extensibility; Q-1199/repository_names; Q-1199/public_engine_license; Q-2043/source_repository; post-transcript user decision and direct naming revision 25-08-2026 |
| <a id="d-091"></a> [D-091](#d-091) | Natural language, Console and interactive/JSON CLI converge on one deterministic engine; manual path retained. The earlier Git transport is superseded by D-100. | TR-639; assistant TR-702; post-transcript user decision 25-08-2026 |
| <a id="d-092"></a> [D-092](#d-092) | Validated declaration+checks, authorized self-approval permitted, committing intent remains inert, and the human/manual infrastructure path requires explicit apply. D-055 preserves the accepted exact preauthorized low-risk CI deployment branch; production-like deployment remains human-approved. The earlier PR/merge transport is superseded by D-100. | Q-627/infra_change_flow; Q-722/change_flow; Q-770/approval_policy; Q-923/deployment_trigger; Q-1192/declarative_change_ux; Q-1192/private_repo_merge_policy; post-transcript user decision 25-08-2026 |
| <a id="d-093"></a> [D-093](#d-093) | Remote operators invoke central apply over SSH; drift report-only. | Q-579/control_model; Q-627/drift_policy; Q-722/cli_location; Q-1192/central_apply_transport |
| <a id="d-094"></a> [D-094](#d-094) | Agent execution needs human acknowledgement and records both human and agent. | Q-770/interactive_agent_authority; Q-746/agent_identity |
| <a id="d-095"></a> [D-095](#d-095) | Maintainer self-control within assigned project; infra admin boundary for fleet/network/identity/secrets/control plane. | Q-282/coolify_team_access; Q-1154/service_maintainer_permissions; Q-1161/production_deploy_approval; Q-1161/maintainer_approval_boundary |
| <a id="d-096"></a> [D-096](#d-096) | `AGENTS.md` canonical; Claude import; focused lifecycle skills; Hermes v1 identity contract only. | assistant TR-702; Q-1214/agent_skill_pack_shape; Q-1214/hermes_v1_scope; SRC-AG-01/SRC-AG-02 |
| <a id="d-097"></a> [D-097](#d-097) | Native macOS/Linux/Windows CLI; stable versioned JSON is the automation interface. | Q-1231/windows_client_support; Q-1231/cli_distribution; Q-1231/cli_control_version_policy |
| <a id="d-098"></a> [D-098](#d-098) | Immutable attested releases with checksums/SBOM/provenance; site pins one exact toolchain; managed Homebrew/APT/WinGet installs notify but never silently self-overwrite. | assistant TR-1220/TR-1228/TR-1241; SRC-GH-03 |

### Post-transcript control-plane decisions and audit designs

This section contains explicit post-transcript user decisions and clearly labeled audit-derived implementation designs. Only rows whose evidence says they are explicit user directions can supersede an earlier user decision; official facts constrain feasibility, and assistant-derived rows remain reviewable designs.

| ID | Decision | Evidence |
|---|---|---|
| <a id="d-099"></a> [D-099](#d-099) | V1 includes the functional VegaStack Labs Console/API on `vsk-node-04`; it is an Access-protected system service sharing the CLI engine, not a Coolify workload or generic web shell. | direct user review 25-08-2026: requested dashboard, stack, backend APIs and full functionality; direct user naming revision 25-08-2026 |
| <a id="d-100"></a> [D-100](#d-100) | Local SQLite is the private operational source of truth for inventory, policy, declarations, plans and audit state. GitHub stores code, not private runtime data. Encrypted database backups and signed declarative exports provide recovery/history. | direct user review 25-08-2026: preferred functional local storage instead of reliance on a GitHub private repository |
| <a id="d-101"></a> [D-101](#d-101) | The `vegastack-labs` platform is delivered through one CLI/executable named `vsk-labs`. Historical design: control-plane nomination/bootstrap was plan-first, idempotent and initiated from a trusted operator workstation (the mandatory workstation clause is superseded by D-118); after verification, the server process runs as `vsk-labs server run` under the OS service manager. Physical, identity, recovery-custody and destructive approval gates remain human. | direct user review/delegation 25-08-2026 plus derived safe-bootstrap design; direct user naming revision 25-08-2026 |
| <a id="d-102"></a> [D-102](#d-102) | The Console uses the VegaStack Design System component/runtime contract from `design.vegastack.com`, including its provider-first setup, owned copy-in components, accessibility and drift/release gates. | assistant-derived Console implementation choice; SRC-VDS-01 confirms feasibility; the user mandate is the clean functional Console/API in D-099, not this design system |
| <a id="d-103"></a> [D-103](#d-103) | Separate four explicit classes: portable provider-neutral platform core, typed provider adapters, optional capabilities and the concrete VegaStack Labs deployment profile. Current hardware, domains, providers and optional feature choices are never unconditional core/schema/UX requirements. | direct user delegation and naming revision 25-08-2026 |
| <a id="d-104"></a> [D-104](#d-104) | GitHub is the selected VegaStack Labs source/Actions/release provider and is replaceable. No VegaStack-owned GitHub App is required for the platform core or the normal v1 image-deployment path; use the smallest per-function mechanism and document any optional App lifecycle. | direct user delegation and naming revision 25-08-2026; transcript App mentions are assistant-only; SRC-GH-04..SRC-GH-13; SRC-CO-10..SRC-CO-13 |
| <a id="d-105"></a> [D-105](#d-105) | SQLite is authoritative operational state and encrypted/retention-locked R2 is disaster recovery. D1 may only be an optional one-way sanitized last-known-status projection; it never writes back or becomes a control/approval/recovery dependency. | direct user delegation 25-08-2026; SRC-SQL-01..SRC-SQL-05; SRC-D1-01..SRC-D1-04; SRC-R2-01..SRC-R2-04 |
| <a id="d-106"></a> [D-106](#d-106) | Audit events are application-append-only and hash-chained with signed off-site checkpoints. This is tamper-evident, not immutable against root compromise or pre-export suppression. | direct audit mandate 25-08-2026; derived threat-model control |
| <a id="d-107"></a> [D-107](#d-107) | V1 support is an explicit role/OS/architecture matrix: Debian 13 `amd64` server; Linux `amd64` and macOS Apple `arm64` managed roles as listed; Windows/Linux/macOS operator clients; browser and runner combinations separately gated. Unsupported combinations fail before mutation. | direct user delegation 25-08-2026; SRC-GO-01; SRC-DEB-01..SRC-DEB-03; SRC-UBU-01; SRC-MAC-01..SRC-MAC-03; SRC-WIN-01..SRC-WIN-03 |
| <a id="d-108"></a> [D-108](#d-108) | Every remaining implementation item is a versioned gate with separate design and activation states, typed evidence, deterministic evaluation, expiry and recovery-epoch binding. Evidence submission follows draft/plan/apply; no manual “close” shortcut exists. | direct user instruction 25-08-2026 to act comprehensively on the gap report; assistant-derived implementation design |
| <a id="d-109"></a> [D-109](#d-109) | The VegaStack Labs deployment profile selects restic repository format v2: separate encrypted standard/critical SSD repositories and an encrypted critical R2 S3 repository, with distinct data-writer/retention authority, `keep-within` retention, integrity schedules and functional restores. | direct user instruction 25-08-2026; assistant-derived mechanism; SRC-BKP-01..SRC-BKP-03; SRC-R2-02 |
| <a id="d-110"></a> [D-110](#d-110) | The VegaStack Labs 1Password profile uses purpose-separated Control Plane, Cloudflare, Coolify, Registry, Backup, per-project and human-only Break Glass vaults; service accounts are limited to named vaults and never become universal. | direct user instruction and naming revision 25-08-2026; assistant-derived least-privilege design; SRC-SEC-01; SRC-1P-02 |
| <a id="d-111"></a> [D-111](#d-111) | The GitHub CI adapter inside `vsk-labs server run` controls one-job ephemeral runners; fixed Linux/macOS groups and labels, explicit repository/workflow enrollment, out-of-workspace journald capture and authenticated control-server log preservation are mandatory. macOS ARM64 self-hosting remains preview-sensitive with a hosted Intel plus protected-manual fallback. | direct user instruction 25-08-2026; assistant-derived smallest-controller design; SRC-GH-02; SRC-GH-14; SRC-GH-15 |
| <a id="d-112"></a> [D-112](#d-112) | SQLite remains provider desired-state authority. V1 uses direct typed Cloudflare and Coolify adapters—the official Cloudflare Go SDK plus documented REST where required, and Coolify `/api/v1`—instead of introducing Terraform/OpenTofu state. | direct user instruction 25-08-2026; assistant-derived simplicity/authority design; SRC-CF-11; SRC-CO-13 |
| <a id="d-113"></a> [D-113](#d-113) | Initial Coolify selection is `v4.3.10` at tag commit `83f1a2e50374c27125671084b445b2599815f114`; the 25-08-2026 official installer SHA-256 is `8ef02dce49339208f5abc247bff0277c73d04538d7a36dcfd21331e314e0f2cd`. Bootstrap downloads to a file, verifies and inspects it, passes the exact version, and disables automatic updates. | direct user instruction 25-08-2026; read-only official release/CDN evidence; SRC-CO-14; SRC-CO-15 |
| <a id="d-114"></a> [D-114](#d-114) | Platform releases use Sigstore keyless blob signing with a stored verification bundle and exact OIDC/repository/workflow identity. The site retains the active plus two prior verified releases as the immediate rollback cache; retained recovery dependencies may require a longer archive. Exact repository/workflow/OIDC identity and feed URLs remain G-017 evidence until pinned and successfully verified; repository existence alone is insufficient. | direct user instruction and naming revision 25-08-2026; assistant-derived release design; SRC-SIG-01; SRC-SIG-02 |
| <a id="d-115"></a> [D-115](#d-115) | V1 uses the numeric host, link, WAN, UPS, runner and Mac qualification defaults in the implementation-gates appendix. Real evidence remains mandatory; a weaker threshold requires an explicit expiring exception plan. | direct user instruction 25-08-2026; assistant-derived noncritical-site acceptance profile |
| <a id="d-116"></a> [D-116](#d-116) | Every machine onboarded or added as a managed lab host requires basic OS-appropriate hardening and reliable verification. Ansible must perform the host security/tool and role configuration required for admission through the approved `vsk-labs` workflow. Debian, Ubuntu and macOS are intended roles; researching other distributions does not implicitly support untested versions/architectures. Exact tool policies, baseline settings and drift cadence remain phase-planning choices. See [host onboarding and hardening](host-onboarding-and-hardening.md). | direct user instruction 26-08-2026 alongside roadmap approval, followed by explicit Ansible/tooling clarification and cross-distribution research request; implementation recommendations remain labeled proposals |
| <a id="d-117"></a> [D-117](#d-117) | Complete and verify the full v1 platform before the first lab onboarding rehearsal; do not reduce scope or use the inventory fleet as an early pilot. Development still requires isolated, explicitly scoped real-OS/provider test environments. After software acceptance, follow the existing deployment gates and inventory, including the actual 30-day Mesh pilot before control-plane deployment acceptance. Software completion grants no live authority. | direct user clarification 26-08-2026: selected “After complete v1” when asked when to target the first Debian onboarding rehearsal |

### Current lifecycle and OSS clarifications

The following direct user confirmations on 26-08-2026 and 04-09-2026 supersede only the conflicts named in their rows. They do not claim runtime implementation, site qualification, live authority or changes to the historical generated audit register.

| ID | Confirmed requirement | Basis |
|---|---|---|
| <a id="d-118"></a> [D-118](#d-118) | The OSS product configures a selected supported control host through a guided local setup; node 04 is only the Labs assignment. Operators and nodes may be added later through separate workflows. Basic SSH management requires no third-party account, with supported local authentication and protected credential resolution. | User requested local control-first setup, corrected hard-coded site assumptions and explicitly agreed to account-free basic SSH management. |
| <a id="d-119"></a> [D-119](#d-119) | Use qualified application nodes for connectors/marker, preserving spare 02 and reserve 08. Adopt SSH-only Fail2ban, bounded auditd and AIDE on control; daily/after-change failed or stale checks block new work without silently stopping existing workloads. Native security-data updates are separate from OS/package soak. Exact mechanisms/settings remain qualified in their owning issues. | User selected the recommended placement, tools, drift and update-data policies. |
| <a id="d-120"></a> [D-120](#d-120) | Approved offboarding may include bounded isolation and must retain unresolved revocations. Allow explicitly reviewed older-backup recovery with preserved audit history/lost interval and revalidated grants. Retain recovery dependencies for retained points. Preserve backup safety over an incompatible restic/R2 implementation; compatibility remains open. Harbor stays an ordinary Coolify app with no extra privileges. Physical media disposition is excluded. | User confirmations and explicit scope corrections during the independent workflow review. |
| <a id="d-121"></a> [D-121](#d-121) | Reconcile all current requirements and perform an independent audit in a fresh Codex task before claiming readiness for the next implementation-planning step. No source/runtime implementation, issue publication, repository administration or live operation is authorized by that request. | User requested meticulous end-to-end requirements updates and a fresh-task audit. |
| <a id="d-122"></a> [D-122](#d-122) | V1 uses Slack as the only normal human-acknowledgement adapter for bootstrap and mutation. Socket Mode runs inside `vsk-labs server run`; app-level `connections:write` and bot `chat:write` are the minimum declared scopes. A verified configured workspace/user action binds the exact plan or installation manifest, local human, targets, reason, risk, expiry/nonce, state revision and recovery epoch; Slack is neither operational-state, audit nor execution authority. Private approver mappings are inert desired state and contain no token/signing secret. Missing/unavailable Slack blocks normal bootstrap/apply. Account-free human approval is deferred beyond v1 as an accepted limitation; separately authorized break-glass recovery is not a routine fallback. | Direct user selection for issue #16 on 04-09-2026; SRC-SL-01..SRC-SL-05. |

[Portable lifecycle](platform-lifecycle.md) is the current generic contract. D-118 supersedes mandatory external-workstation bootstrap and universal physical-serial/provider assumptions. D-122 supersedes only D-118's claim that human-approved bootstrap/apply is account-free; D-118's selected-host setup, account-free read/preparation, local authentication, credential resolution and recovery responsibilities remain. D-119 supersedes old connector/marker defaults on 02/08. D-120 supersedes any unconditional claim that restic/R2 no-delete writer compatibility is closed. Original historical decisions/source evidence remain readable; the current requirements and qualified applicability determine new plans.

### Fresh-audit corrections and pending solution choices

On 27-08-2026 the independent requirements audit identified provider-granularity, acknowledgement and stale-sequence conflicts. Corrected requirements require physical 1Password vault partitioning by reader set, truthful tunnel-scoped credential semantics, a separately protected human approval action, preservation of existing control state during Coolify install, and consistent current ledgers. D-122 subsequently settled the 0.3 human-proof choice as Slack-only for v1 and accepted its account/network dependency; runtime and real-workspace qualification remain downstream. Exact G-007 layout and G-012 shared-credential/compromise-interruption acceptance remain explicit solution reviews; their affected execution issues cannot be ready until settled. No topology expansion, weaker security or additional cost is authorized. The user was offered the tunnel-boundary choice but no answer was received; do not interpret silence as approval.

D-116 and D-117 postdate the historical audit snapshot. They are recorded here, but the unchanged generated audit register is not evidence that the new requirements are designed, implemented or verified.

## GitHub dependency matrix

Classification is per function: **NOT REQUIRED** means a smaller supported mechanism exists; **OPTIONAL** means an App can be a least-privilege/durable adapter choice; **ONE SUPPORTED ADAPTER** means it is a provider integration rather than core; **REQUIRED FOR OPTIONAL FEATURE** means that narrow feature technically needs the App but v1 does not need the feature. GitHub Actions' built-in `GITHUB_TOKEN` is internally an installation token of GitHub's own Actions App; VegaStack neither registers nor owns that App. [D-104](#d-104)

| Function | Classification | Smallest supported mechanism | Credential / scope | GitHub outage behavior | Provider-neutral fallback |
|---|---|---|---|---|---|
| source hosting and public ordinary Git operations | NOT REQUIRED | any Git remote; unauthenticated public HTTPS clone/fetch | none | existing checkout works; new fetch fails | configured Git URI/revision; alternate Git host |
| private human Git operations | NOT REQUIRED | personal SSH key or fine-grained PAT | selected repositories; `Contents` only as required | local work continues; fetch/push waits | standard SSH/HTTPS Git credential |
| GitHub Actions CI | NOT REQUIRED for a VegaStack-owned App | per-job built-in `GITHUB_TOKEN` | default read-only; elevate only named job/environment | no new Actions jobs; installed control/running apps unaffected | CI adapter plus documented local/manual build |
| manage enrolled GitHub Environment secrets | OPTIONAL; App not required | fine-grained PAT is supported for scoped v1 automation; purpose-specific App is preferable only if a durable organization machine identity is selected | selected repositories; `Environments: write`; never Contents/Actions/Secrets read; encrypt to GitHub's public key | no new secret install/rotation; existing workflows and local source value remain subject to their own availability | CI/secrets adapter or reviewed manual environment-secret rotation |
| manage GitHub Environment protection/reviewer policy | OPTIONAL; App not required | reviewed manual configuration or fine-grained PAT | selected repositories; `Administration: write` only if automated | protection changes wait; existing policy remains | CI environment-policy adapter/manual provider UI with audit import |
| Coolify deploys a prebuilt Harbor image | NOT REQUIRED | protected CI uses a Coolify team-scoped `write`+`deploy` token and registry pull robot after `vsk-labs` plan authorization | one Coolify project trust boundary/team; no `root`/`read:sensitive`; exact digest/resource in plan | no new CI deployment; running image and local plan history remain | hosting execution adapter/manual approved digest plan |
| Coolify fetches one private repository | NOT REQUIRED | repository-scoped read-only SSH deploy key | one repository, read-only | source rebuild waits; current workload continues | deploy key on another Git host or prebuilt image |
| Coolify repository picker and managed push/PR events | ONE SUPPORTED ADAPTER / OPTIONAL | Coolify GitHub App source integration | selected repositories; review Coolify's generated manifest | automatic source events stop; running workload continues | deploy key plus webhook, or CI→Coolify/VegaStack Labs change submission |
| automated Coolify PR comments | REQUIRED FOR OPTIONAL FEATURE | Coolify GitHub App | selected repository plus documented pull-request write permission | comment absent; preview/status can exist elsewhere | omit v1 feature; show result in CI/Console |
| repository/organization webhook | NOT REQUIRED | repository/org webhook with random secret and signature verification | admin creates hook; no runtime token after setup | events stale/queued; polling/manual reconcile | generic signed webhook or polling adapter |
| deployment event/webhook | NOT REQUIRED | Coolify webhook/API or GitHub repository webhook/deployment API as chosen | smallest deployment/status scope for exact resource/repository | event/status projection stale; running app unchanged | hosting event adapter plus manual reconcile |
| configured/public repository discovery | NOT REQUIRED | explicit URI or unauthenticated public REST | none | discovery unavailable; configured entries remain | explicit SCM registration |
| private multi-repository discovery | OPTIONAL | fine-grained PAT or read-only App installation token | selected repos; `Metadata: read` | inventory marked stale; no destructive reconcile | explicit registration; SCM adapter |
| workflow/job/runner observation | OPTIONAL | unauthenticated public reads or fine-grained read token | `Actions: read`; runner read only if displayed | Console shows last-known timestamp/stale | CI adapter/manual provider deep link |
| ordinary commit status reporting | NOT REQUIRED | workflow `GITHUB_TOKEN` or fine-grained token | `Commit statuses: write` on selected repository | GitHub projection stale; local CI result remains | provider status adapter |
| external rich Check Run writes/annotations | REQUIRED FOR OPTIONAL FEATURE under GitHub's explicit normative note | dedicated GitHub App | selected repository, `Checks: write`; no broader scope | rich check UI stale; build result remains | use commit statuses/Console; see version-sensitive contradiction below |
| build artifact publication | NOT REQUIRED | Actions artifact or registry/object-store credential | artifact or registry write only | publication retries; local result retained | artifact/OCI registry adapter |
| public release download/update check | NOT REQUIRED | unauthenticated signed public release asset/feed | none; independently verify signature/digest | update check fails closed; installed binary continues | signed release adapter/offline package |
| private release download/update check | OPTIONAL | fine-grained `Contents: read` token or read-only App | selected release repository only | no update; installed binary continues | private object/package store or cached signed asset |
| create GitHub release from Actions | NOT REQUIRED | release job's `GITHUB_TOKEN` | `Contents: write` only for protected release job | publication waits | release adapter/manual signed publication |
| external Worker creates/updates alert issue | OPTIONAL; App preferred only for durable org machine identity | fine-grained PAT with `Issues: write` is sufficient | one alert repository; no Contents/Actions/Checks/Deployments | retry/dead-letter; local/outbox alert remains | notification adapter and required independent secondary route |
| application deployment | NOT REQUIRED | provider-neutral plan/run plus a declared hosting executor; VegaStack Labs' accepted executor is protected CI calling Coolify with an exact digest | project/team Coolify `write`+`deploy` token in admitted environment; no GitHub App | builds/deploy executor stop; current deployment/control remains | alternate CI executor or centrally/manual claimed hosting plan |
| Codex/Claude/Hermes workflows | NOT REQUIRED | authenticated `vsk-labs` CLI/API and ordinary operator SCM credential for code work | no generic provider token in prompts/agent profile | source-host work waits; local inspect/plan/recovery remains | deterministic platform API and manual runbook |
| audit attribution | NOT REQUIRED | local authenticated human, device, agent/session principal, plan/run/correlation IDs | provider run/actor/credential class is optional evidence | local audit remains complete | core identity/audit model |
| durable organization automation authentication | OPTIONAL / RECOMMENDED when selected | separate purpose-specific App, or transitional fine-grained PAT | selected repositories and minimum named permissions | adapter suspends/queues; never fall back broader | provider-neutral adapter/local/manual path |

The current GitHub Check Runs page is internally inconsistent: its explicit notes say create/write is App-only, while its generated token list also names fine-grained PATs. Until GitHub resolves that contradiction and a pinned API-version capability test proves otherwise, the explicit App-only rule governs. V1 avoids the ambiguity by using Actions' native checks or ordinary commit statuses; external rich Check Run writes are not a release requirement. [GitHub Check Runs](https://docs.github.com/en/rest/checks/runs) · [GitHub commit statuses](https://docs.github.com/en/rest/commits/statuses)

### Optional GitHub App lifecycle

Do not create one omnibus App. If an optional App is approved, its declaration must contain every field below and pass positive/negative tests before installation:

| Integration / owner | Installation boundary and permission | Secret and token lifecycle | Verification | Failure, fallback, rotation and offboarding |
|---|---|---|---|---|
| Coolify source App / VegaStack Labs Coolify operator | VegaStack organization; selected source-build repositories only; exactly the current Coolify-generated permissions, with PR write only if comments are selected | App ID/client data, webhook secret and private key live only in protected Coolify secret storage; back up with Coolify; never put key/token in SQLite; installation tokens remain short-lived | selected push/PR event and signature; unselected repository denied; direct-origin and permission-negative tests | current workloads continue; use deploy key/external CI/manual digest; add/verify replacement key before revoking old; uninstall, erase stored key/webhook secret and verify delivery stops at offboarding |
| optional Issues notifier App / notification-adapter owner | one alert repository; `Issues: write` plus implicit Metadata only | private key in selected secrets/Worker secret store; mint repository-scoped installation tokens (maximum one hour); never persist token in DB/audit | create/update/dedup/close; denial outside repository; expiry and suspension tests | local dead-letter plus independent secondary route; overlap/verify new key then revoke old; suspend for incident, uninstall/delete key/config and safely drain/sanitize queue at offboarding |
| optional read observer App / SCM-CI adapter owner | selected repositories; `Metadata: read`, `Actions: read`; runner read only if screen requires it | separate read-only App/key from notifier/deploy identities; short-lived installation token | compare sampled data, prove all mutations denied and stale timestamp shown | retain last-known status/manual refresh; rotate keys with overlap; uninstall/revoke and delete cached credential at offboarding |
| optional environment-automation App / SCM-CI configuration-adapter owner | selected enrolled repositories; `Environments: write`; add `Administration: write` only if the approved adapter also owns protection rules | private key in the selected secrets adapter; mint short-lived installation tokens; target Coolify/Harbor values are encrypted to GitHub and never stored in SQLite/logs | create/rotate a canary environment secret, prove value cannot be read back, unselected repo denied and protection policy unchanged without Administration permission | reviewed manual rotation or scoped fine-grained PAT; overlap/verify new key then revoke old; uninstall/delete key and reassign or remove managed secrets/policy ownership at offboarding |

Installation approval belongs to the GitHub organization owner and the VegaStack Labs adapter owner jointly. Quarterly access review verifies selected repositories, permissions, key age, active installations, token failures and owner/offboarding state. Suspension is the immediate reversible response; uninstall plus key deletion is permanent removal. [GitHub installation tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation) · [Reviewing installed Apps](https://docs.github.com/en/apps/using-github-apps/reviewing-and-modifying-installed-github-apps)

## Assistant-derived design register

These implementation choices satisfy user constraints but were synthesized by the assistant or imposed by an official vendor constraint. They are intentionally **not** represented as independent user answers. They remain reviewable design choices; changing one does not reopen the underlying user decision.

| Decision | Derived element | Current disposition |
|---|---|---|
| [D-007](#d-007) | clean-room legacy compatibility boundary | Retained; acceptance requirements are explicit in Automation. |
| [D-008](#d-008) | agentless core and no custom privileged daemon | Retained as the smallest central-control design; labeled derived. |
| [D-013](#d-013) | Mac mini/iMac node numbers | Retained as initial assignment; phase-0 serial approval gates apply. |
| [D-032](#d-032) | exact switch attachment/port layout | Retained with physical acceptance and recovery procedure. |
| [D-035](#d-035) | safe switch defaults/export procedure | Retained and implementation-expanded. |
| [D-038](#d-038) | measure wireless backhaul before cabling it | Retained; numeric acceptance profile remains an explicit input. |
| [D-041](#d-041) | LAN-first/Mesh-remote recovery contract | Retained; user affirmed the automatic UX at TR-216. |
| [D-050](#d-050) | exact rebuild pattern around single Coolify control | Retained with same-version restore sequence. |
| [D-051](#d-051) | Coolify build server cannot host applications | Retained official vendor constraint. |
| [D-053](#d-053) | rootless ephemeral runner isolation | Retained security design; controller/log sink stay gated inputs. |
| [D-057](#d-057) | trusted-event boundary for home runners | Retained security design with explicit event matrix. |
| [D-059](#d-059) | exact two-system-robot split | Retained derived v1 design with blast radius recorded. |
| [D-069](#d-069) | exact Mac maintenance/Hermes account shape | Retained and implementation-expanded. |
| [D-084](#d-084) | no Docker socket and rebuild semantics for Beszel | Retained least-privilege design. |
| [D-091](#d-091) | one deterministic engine plus manual parity | Retained and schema/execution-expanded. |
| [D-096](#d-096) | cross-agent instruction/skill compatibility pattern | Retained with tool-specific acceptance tests. |
| [D-098](#d-098) | release checksums/SBOM/provenance hardening | Retained; signing/repository inputs remain gated. |
| [D-099](#d-099) | single Go service with an embedded static web bundle, outside Coolify | Retained as the smallest recoverable runtime; the web/API requirement is the user's decision. |
| [D-101](#d-101) | two-stage trusted-workstation bootstrap and explicit human gates | Workstation-first clause superseded by D-118. Retain explicit human nomination, finite local installation approval and server-owned handoff; see the portable lifecycle. |
| [D-102](#d-102) | VegaStack Design System selection, exact component-to-screen mapping and static-build integration | Retained as an assistant-derived implementation design; D-099 is the underlying user Console/API mandate. |
| [D-103](#d-103) | capability-based adapter/resource extension model plus an explicit optional-capability class | Retained as the enforceable four-way platform/adapter/capability/profile boundary. |
| [D-104](#d-104) | optional App lifecycle split by integration | Retained as least-privilege design; no App is installed by this specification. |
| [D-105](#d-105) | one-way outbox semantics for any D1 status projection | Retained to prevent a second control authority; projection itself remains optional. |
| [D-106](#d-106) | hash-chain plus signed off-site audit checkpoints | Retained as tamper evidence; limitations are explicit. |
| [D-107](#d-107) | intentionally narrow initial OS/architecture combinations | Retained; “Go can compile it” is not support evidence. |
| [D-108](#d-108) | typed implementation-gate/evidence lifecycle | Added to make design completion and real-world activation impossible to conflate. |
| [D-109](#d-109) | restic repository topology, retention authority and verification cadence | Conditional candidate under D-120; G-008 writer/coordination/retained-dependency compatibility is design-open, followed by actual activation evidence. |
| [D-110](#d-110) | exact purpose-separated 1Password layout | Logical purposes retained; mixed-reader physical vault layout superseded by provider permission evidence. G-007 requires reviewed reader-set partitions and direct-provider denial tests. |
| [D-111](#d-111) | built-in ephemeral runner controller, labels and external log preservation | Controller placement/lifecycle selected; actual-job admission guard remains design-open under G-006. No Kubernetes or second controller. |
| [D-112](#d-112) | direct typed provider adapters rather than Terraform/OpenTofu state | Selected to preserve SQLite authority and avoid a second state engine. |
| [D-113](#d-113) | exact initial Coolify release/tag/installer digest | Current official evidence pinned; real-host install/restore evidence still gates activation. |
| [D-114](#d-114) | Sigstore bundle identity and three-version local rollback set | Selected; the future repository/workflow/feed identity cannot be fabricated. |
| [D-115](#d-115) | numeric qualification defaults | Selected as explicit defaults; actual host/site results remain gates. |

## Coverage and audit appendix

The pre-edit adversarial matrix classified 34 decisions as complete, 47 as partially captured and two assistant-derived items as unsupported provenance; it also found one stale cross-cutting naming item. The edited result maps every normalized transcript decision plus the current post-transcript architecture decisions. **Complete** means the mandate and lifecycle are represented, not that deployment occurred. **Input-gated** means the docs specify the owner, declaration and acceptance path but preserve a genuine undecided/discovery input.

| Decision | Primary implementation section | Final documentation state |
|---|---|---|
| [D-001](#d-001) | [README](../README.md#vegastack-labs) | Complete |
| [D-002](#d-002) | [README](../README.md#boundaries) | Complete |
| [D-003](#d-003) | [README](../README.md#vegastack-labs-deployment-profile-objectives) | Complete |
| [D-004](#d-004) | [README](../README.md#boundaries) | Complete |
| [D-005](#d-005) | [README](../README.md#vegastack-labs) | Complete |
| [D-006](#d-006) | [README](../README.md#vegastack-labs-deployment-profile-objectives) | Complete |
| [D-007](#d-007) | [Automation](automation-and-agents.md#required-declarations-and-schemas) | Complete: derived design labeled |
| [D-008](#d-008) | [Automation](automation-and-agents.md#engine-responsibilities) | Complete: derived design labeled |
| [D-010](#d-010) | [Inventory](inventory-and-roles.md#deterministic-identity) | Complete |
| [D-011](#d-011) | [Inventory](inventory-and-roles.md#deterministic-identity) | Complete |
| [D-012](#d-012) | [Inventory](inventory-and-roles.md#serial-to-node-map) | Complete |
| [D-013](#d-013) | [Inventory](inventory-and-roles.md#deterministic-identity) | Complete: derived design labeled |
| [D-014](#d-014) | [Inventory](inventory-and-roles.md#inventory-and-roles) | Complete |
| [D-015](#d-015) | [Inventory](inventory-and-roles.md#serial-to-node-map) | Complete: input-gated |
| [D-020](#d-020) | [Inventory](inventory-and-roles.md#control-plane--vsk-node-04) | Complete |
| [D-021](#d-021) | [Inventory](inventory-and-roles.md#applications--vsk-node-03-vsk-node-05-vsk-node-07) | Complete |
| [D-022](#d-022) | [Inventory](inventory-and-roles.md#deterministic-identity) | Complete |
| [D-023](#d-023) | [README](../README.md#boundaries) | Complete |
| [D-024](#d-024) | [Inventory](inventory-and-roles.md#macs) | Complete |
| [D-025](#d-025) | [Architecture](architecture-and-networking.md#coolify-lifecycle) | Complete: input-gated |
| [D-030](#d-030) | [Architecture](architecture-and-networking.md#physical-topology) | Complete |
| [D-031](#d-031) | [Architecture](architecture-and-networking.md#physical-topology) | Complete |
| [D-032](#d-032) | [README](../README.md#v1-shape) | Complete: derived design labeled |
| [D-033](#d-033) | [Architecture](architecture-and-networking.md#es216g-v1-baseline) | Complete |
| [D-034](#d-034) | [Architecture](architecture-and-networking.md#es216g-v1-baseline) | Complete: input-gated |
| [D-035](#d-035) | [Architecture](architecture-and-networking.md#es216g-v1-baseline) | Complete: derived design labeled |
| [D-036](#d-036) | [Architecture](architecture-and-networking.md#future-second-switch) | Complete |
| [D-037](#d-037) | [Architecture](architecture-and-networking.md#addressing-policy) | Complete |
| [D-038](#d-038) | [Architecture](architecture-and-networking.md#es216g-v1-baseline) | Complete: derived design labeled, input-gated |
| [D-040](#d-040) | [README](../README.md#v1-shape) | Complete: input-gated |
| [D-041](#d-041) | [README](../README.md#v1-shape) | Complete: derived design labeled |
| [D-042](#d-042) | [Architecture](architecture-and-networking.md#path-selection) | Complete |
| [D-043](#d-043) | [Architecture](architecture-and-networking.md#enrollment-routes-and-profiles) | Complete: input-gated |
| [D-044](#d-044) | [Architecture](architecture-and-networking.md#enrollment-routes-and-profiles) | Complete |
| [D-045](#d-045) | [Architecture](architecture-and-networking.md#public-and-protected-ingress) | Complete: input-gated |
| [D-046](#d-046) | [Architecture](architecture-and-networking.md#automatic-lanremote-names) | Complete: input-gated |
| [D-047](#d-047) | [Architecture](architecture-and-networking.md#public-and-protected-ingress) | Complete |
| [D-048](#d-048) | [Architecture](architecture-and-networking.md#public-and-protected-ingress) | Complete |
| [D-049](#d-049) | [Architecture](architecture-and-networking.md#coolify-control-and-application-plane) | Complete |
| [D-050](#d-050) | [Inventory](inventory-and-roles.md#control-plane--vsk-node-04) | Complete: derived design labeled |
| [D-051](#d-051) | [Inventory](inventory-and-roles.md#linux-ci--vsk-node-01-vsk-node-06) | Complete: derived design labeled |
| [D-052](#d-052) | [Architecture](architecture-and-networking.md#ci-trust-and-admission-matrix) | Complete: input-gated |
| [D-053](#d-053) | [Architecture](architecture-and-networking.md#ci-trust-and-admission-matrix) | Complete: derived design labeled, input-gated |
| [D-054](#d-054) | [Architecture](architecture-and-networking.md#ci-trust-and-admission-matrix) | Complete: input-gated |
| [D-055](#d-055) | [Architecture](architecture-and-networking.md#signed-digest-promotion) | Complete: input-gated |
| [D-056](#d-056) | [Architecture](architecture-and-networking.md#harbor-lifecycle) | Complete: input-gated |
| [D-057](#d-057) | [Architecture](architecture-and-networking.md#ci-trust-and-admission-matrix) | Complete: derived design labeled |
| [D-058](#d-058) | [Architecture](architecture-and-networking.md#harbor-lifecycle) | Complete |
| [D-059](#d-059) | [Architecture](architecture-and-networking.md#harbor-lifecycle) | Complete: derived design labeled, input-gated |
| [D-060](#d-060) | [Operations](security-and-operations.md#sources-of-truth) | Complete: input-gated |
| [D-061](#d-061) | [Operations](security-and-operations.md#sources-of-truth) | Complete |
| [D-062](#d-062) | [Operations](security-and-operations.md#roles) | Complete |
| [D-063](#d-063) | [Operations](security-and-operations.md#onboarding) | Complete |
| [D-064](#d-064) | [Operations](security-and-operations.md#roles) | Complete |
| [D-065](#d-065) | [Operations](security-and-operations.md#security-model) | Complete |
| [D-066](#d-066) | [Inventory](inventory-and-roles.md#macs) | Complete |
| [D-067](#d-067) | [Operations](security-and-operations.md#mac-mini-m4) | Complete |
| [D-068](#d-068) | [Operations](security-and-operations.md#offboarding-and-emergency-suspension) | Complete |
| [D-069](#d-069) | [Operations](security-and-operations.md#imac-m1) | Complete: derived design labeled |
| [D-070](#d-070) | [Operations](security-and-operations.md#security-model) | Complete |
| [D-071](#d-071) | [Operations](security-and-operations.md#secrets) | Complete: input-gated |
| [D-072](#d-072) | [Operations](security-and-operations.md#secrets) | Complete: input-gated |
| [D-073](#d-073) | [Automation](automation-and-agents.md#audit-record) | Complete |
| [D-074](#d-074) | [Operations](security-and-operations.md#immediate-credential-hygiene-item) | Complete |
| [D-075](#d-075) | [README](../README.md#boundaries) | Complete |
| [D-080](#d-080) | [Operations](security-and-operations.md#classes) | Complete: input-gated |
| [D-081](#d-081) | [Operations](security-and-operations.md#classes) | Complete: input-gated |
| [D-082](#d-082) | [Operations](security-and-operations.md#verification-and-recovery-cases) | Complete: input-gated |
| [D-083](#d-083) | [Operations](security-and-operations.md#failure-alerts) | Complete: input-gated |
| [D-084](#d-084) | [Operations](security-and-operations.md#observability-and-audit) | Complete: derived design labeled |
| [D-085](#d-085) | [Automation](automation-and-agents.md#audit-record) | Complete: input-gated |
| [D-086](#d-086) | [Operations](security-and-operations.md#updates-and-maintenance) | Complete |
| [D-087](#d-087) | [Operations](security-and-operations.md#power-battery-and-thermal-operations) | Complete: input-gated |
| [D-088](#d-088) | [Operations](security-and-operations.md#recovery-objectives) | Complete |
| [D-090](#d-090) | [Automation](automation-and-agents.md#platform-contract) | Complete: input-gated |
| [D-091](#d-091) | [Automation](automation-and-agents.md#platform-contract) | Complete: derived design labeled |
| [D-092](#d-092) | [README](../README.md#boundaries) | Complete |
| [D-093](#d-093) | [Automation](automation-and-agents.md#normal-change-flow) | Complete |
| [D-094](#d-094) | [README](../README.md#boundaries) | Complete |
| [D-095](#d-095) | [Automation](automation-and-agents.md#approval-and-execution-boundaries) | Complete |
| [D-096](#d-096) | [Automation](automation-and-agents.md#focused-lifecycle-skills) | Complete: derived design labeled |
| [D-097](#d-097) | [Automation](automation-and-agents.md#command-surface) | Complete: input-gated |
| [D-098](#d-098) | [README](../README.md#vegastack-labs-deployment-profile-objectives) | Complete: derived design labeled, input-gated |
| [D-099](#d-099) | [Control service](control-plane-service.md#vegastack-labs-debian-runtime-architecture) | Complete: post-transcript decision, derived runtime labeled |
| [D-100](#d-100) | [Control service](control-plane-service.md#source-of-truth-model) | Complete: supersedes private-Git site storage |
| [D-101](#d-101) | [Control service](control-plane-service.md#control-plane-nomination-and-bootstrap) | Superseded in part by D-118: local-first bootstrap; human-proof mechanism and precise handoff still issue-owned |
| [D-102](#d-102) | [Control service](control-plane-service.md#web-application-and-vegastack-design-system) | Complete: assistant-derived design labeled; official contract linked |
| [D-103](#d-103) | [README](../README.md#architecture-boundary) and [Architecture](architecture-and-networking.md#portable-platform-boundary) | Complete: layer/capability rules explicit |
| [D-104](#d-104) | [GitHub dependency matrix](#github-dependency-matrix) | Complete: each function and optional App lifecycle classified |
| [D-105](#d-105) | [Control service](control-plane-service.md#sqlite-d1-and-r2-decision) | Complete: D1 projection optional; no synchronization/control role |
| [D-106](#d-106) | [Operations](security-and-operations.md#observability-and-audit) | Complete: tamper-evidence boundary explicit |
| [D-107](#d-107) | [Automation](automation-and-agents.md#os-and-architecture-support-matrix) | Complete: unsupported combinations explicit; some lanes input-gated |
| [D-108](#d-108) | [Implementation gates](implementation-gates.md#gate-semantics) | Complete: design and activation states are distinct |
| [D-109](#d-109) | [Implementation gates](implementation-gates.md#backup-engine-and-repository-topology--g-008) | Conditional candidate: G-008 compatibility qualification plus real storage/recovery evidence |
| [D-110](#d-110) | [Implementation gates](implementation-gates.md#1password-layout--g-007) | Logical purposes retained: reviewed physical reader-set layout and provider denial proof required |
| [D-111](#d-111) | [Implementation gates](implementation-gates.md#ci-controller-runners-and-logs--g-006-g-020) | Controller lifecycle retained: actual assigned-job guard and real isolation proof required |
| [D-112](#d-112) | [Implementation gates](implementation-gates.md#provider-ownership--g-012-through-g-016-g-019) | Adapter ownership retained: G-012 credential boundary approval plus scoped provider evidence required |
| [D-113](#d-113) | [Implementation gates](implementation-gates.md#provider-ownership--g-012-through-g-016-g-019) | Complete: release/tag/installer digest pinned; activation evidence required |
| [D-114](#d-114) | [Implementation gates](implementation-gates.md#platform-releases-and-generated-registries--g-017-g-018) | Requirement represented: pinned and successfully verified identity/feed evidence required; existence is insufficient |
| [D-115](#d-115) | [Implementation gates](implementation-gates.md#common-numeric-qualification--g-005-g-009-g-010-g-020-g-021) | Complete: measured evidence required |

## Implementation-readiness ledger

This is a subsystem ownership summary. The portable lifecycle owns generic setup, account-free read/preparation/recovery and Slack-only v1 acknowledgement behavior; the gate ledger owns current per-gate design/activation state. Labs values below apply only to that profile. No summary row makes a design issue executable or grants authority; exact phase/issue readiness follows the development roadmap.

| Subsystem | Source of truth | Owner | Prerequisites | Intended state / sequence | Automation boundary | Approval | Verification | Diagnosis | Rollback / recovery | Remaining blocker and phase gate |
|---|---|---|---|---|---|---|---|---|---|---|
| platform core, API and SQLite | local SQLite plus pinned `vegastack-labs` schemas/migrations | platform maintainer; deployment admin for site state | signed release and trusted supported host for finite local setup; qualification/recovery only as required by the next capability | finite local manifest → one server/SQLite/local API → scoped preparation → qualified optional Console/adapters → acceptance | server alone writes DB; finite pre-database exception only; normal changes use plan/apply | infra admin for bootstrap/migration/apply | schema/foreign-key/integrity, API/CLI digest parity, power/disk/concurrency tests | stable error registry, health/safe-mode and run ledger | pre-migration online backup, previous executable/schema, clean-node restore and writer fencing | implement `G-017` repository/workflow/feed identity and `G-018` generated registry; qualified host/backup evidence; phase 3/first release |
| hardware/inventory and host roles | SQLite typed identity/provenance; Labs physical evidence and read-only Sheet import | infrastructure admin | verify applicable typed identity; Labs serial conflicts block affected bindings; discovery/burn-in and approved OS/reimage decision | quarantine → discover → qualify → plan role → apply one node → idempotence | agentless SSH/Ansible to exact node; no custom privileged agent | infra admin | serial/host key/capacity/ports/allowed-denied/idempotence | console, facts, service/firewall/package evidence | quarantine, separately approved adoption/reimage, movable alias/qualified spare | serial/credential Sheet remediation and measured thresholds; phases 0–1 |
| network, identity and edge | SQLite intent; adapters own observed Workspace/Cloudflare/HX510/ES216G state | infrastructure admin; Workspace admin for account prerequisite | `G-003`–`G-005`, `G-012`, `G-013` and `G-016` evidence; approved identities/devices | LAN/base → quarantine enrollment → audiences/flows → Tunnel routes | direct typed Cloudflare adapter; router/switch manual action until supported; no direct provider browser calls | infra admin; account action by Workspace admin | allowed/denied, JWT/audience/origin bypass, reconnect/MTU, config export | distinguish LAN, DNS, Access, Mesh, Tunnel, origin and identity failures | LAN/console; prior switch export/policy/connector; revoke device/session | physical LAN/Mesh evidence, default-candidate qualification and actual adapter owner/permission canary; phases 1–2/5 |
| SCM, CI and release | application/platform source plus immutable revision; CI provider observations; signed release manifest | repository/platform maintainers; CI adapter owner | trusted-event policy; `G-006`, `G-017`, `G-018`, `G-020`; enrolled environments and scoped secret-delivery owner | build/test → Sigstore bundle/attest → publish Harbor/release → submit digest plan → risk authorization → claim external-executor lease | built-in ephemeral controller with fixed groups/labels/log sink; build jobs hold no deploy token; admitted deploy job gets only project/team Coolify token; no VegaStack App by default | exact low-risk policy may auto-run; production-like assigned-maintainer acknowledgement/apply | provenance/digest/SBOM, hostile-runner isolation, preserved logs, environment admission, old/new token denials and status timestamps | workflow/run/log/plan/claim/deployment IDs and last-known adapter state | `macos-15-intel`/manual Mac, cached signed release, alternate SCM/CI/hosting executor | G-006 actual-job admission mechanism plus exact enrollment, real isolation, release identity/feed and generated registry; development phase 9 and deployment phase 4/first release |
| registry and application hosting | app source contract; SQLite placement/policy; Harbor digest; Coolify runtime observation | project maintainer; infra admin for platform; protected CI executor for accepted app path | pinned Coolify `v4.3.10`; `G-015` Harbor evidence; `G-019` project/team token; registry robots and backup/health/migration/rollback declaration | CI publishes digest → draft/plan → auto policy or maintainer ack/apply → CI claims lease and calls Coolify → independent health/digest observation | external executor can mutate only exact plan target/digest; token has team-wide residual blast radius but never `root`/`read:sensitive`; Harbor stores images only | low-risk class by approved policy; production-like maintainer; infra for platform/migration | signature/digest/scan, executor claim, deployment UUID/running digest, health/migration and denied cross-team/extra-permission scope | separate CI claim, Coolify auth/team, registry, hosting, origin, data and credential failure evidence | prior safe digest only if migration permits; centrally/manual claimed plan; workload restore or clean platform rebuild | real-host Coolify restore, Harbor source/target data and per-project identity/scope proof; phases 3/5/later apps |
| secrets | selected adapter; VegaStack Labs values in 1Password, references in SQLite | vault owner and consuming adapter owner | qualified local resolver for account-free use; Labs reviewed physical reader-set vault partitions, G-007 grants and independent recovery custody | declare reference → validate metadata → resolve only in authorized execution/observation → rotate/test/revoke; planning alone never fetches candidate workload secrets | no value in plan/DB/log/browser/agent; no cross-provider fallback or universal service account | admin for provider/layout/rotation; consumer owner verifies | access-denial, fingerprint, every consumer health and revocation | distinguish unavailable, denied, missing, expired and target rejection | routine availability-preserving rotation only; approved compromise containment takes precedence; independent sealed recovery | local native resolver qualification; Labs physical vault matrix solution review, direct-provider denials and recovery proof; development phase 5 before affected activation |
| backup, restore and audit | SQLite declarations/run ledger; selected backup manifests and independent audit checkpoints; Labs restic/R2 is a conditional candidate | backup/audit owner distinct from workload; recovery-key custodian | account-free independent recovery path; Labs G-008 coordination/payload compatibility and retained dependency proof before actual repositories, keys, R2 locks/capacity and consistency qualification | consistent snapshot → verify → restic encrypt → verify preconfigured lock coverage → upload → check → functional restore drill | fixed schedules pre-authorized; no restore/delete/retention change without plan; data/export writer cannot change bucket lock | policy change/restore/cutover by infra admin; scheduled fixed run needs no per-run ack | manifest/hash/object/lock, weekly/monthly checks and quarterly functional restore | backup age, source adapter, repository, key, capacity, audit chain/checkpoint | earlier verified point, isolated clean-node restore, signed snapshot last resort | G-008 design compatibility followed by actual repository/binary/lock/key/capacity and clean-host proof; development phase 5, deployment phase 3 acceptance |
| observability and notifications | SQLite alert policy/outbox; Beszel/provider observations; destination delivery state | operations owner; notification-adapter owner | Beszel version, recipients, independent secondary route, issue credential class | observe → dedupe/classify → local outbox → selected destinations → close on verified recovery | read-only monitoring; sanitized payload; alert destination has no control authority | policy/route/credential install by infra admin | induced alert/recovery, stale heartbeat, expired credential, denied extra scope | source vs Worker vs R2 vs GitHub/secondary-route failure | local queue/manual route; replace adapter; running/control state unaffected | primary/secondary people and non-GitHub secondary delivery; phase 3 |
| operator, Console and agent UX | versioned API/schema/command metadata; root `AGENTS.md` canonical | platform/UX maintainers; deployment policy admin | platform packages, VDS build, generated clients/skills, auth/session binding and configured Slack adapter for normal mutation | install/login → inspect/draft/plan → Slack review/ack → apply → verify/recover | agents read/plan by default; Socket Mode stays inside server; server reauthorizes; no prose scraping/direct provider | configured Slack human with exact local grant; agent cannot self-acknowledge | OS matrix, JSON goldens, accessibility, workspace/user/replay/outage/stale/error/recovery and agent instruction tests | stable exit/error plus run/correlation ID and actionable `doctor` | previous signed executable, CLI/manual runbook, local/LAN recovery; explicit break-glass only under recovery authority | #7 request/proof + Slack orchestration; #9 identity mapping; #12 secret delivery; #15 presentation; #14 notifications cannot authorize; real Slack proof and first release |

## Assumptions

- Physical access to the site is trusted for v1, and the accepted disk-encryption residual is understood.
- The existing UPS protects every always-on node, network device and backup SSD; runtime still requires measurement.
- The main and guest networks are actually isolated by the deployed ISP firmware.
- All eight working ThinkPads can negotiate stable wired gigabit after clean installation.
- The current 400 Mb/s ACT plan and secondary-HX510 wireless backhaul are candidates for v1, subject to upload/backhaul qualification; wired backhaul is the fallback.
- A recoverable work Apple ID is available for the designated Mac owner/admin; team, CI and service accounts never share it.
- Workloads remain noncritical and stateful v1 services accept single-node operation plus backups.

## Activation evidence, implementation gates and deferrals

The normative [gate ledger](implementation-gates.md#gate-ledger) owns per-gate design and activation state. All 23 IDs remain traceable; a recorded requirement is not evidence that its mechanism is settled or applied.

| Readiness class | Gate IDs / work | Meaning |
|---|---|---|
| Material design/qualification open | G-006 actual-job admission; G-007 physical vault reader-set layout; G-008 backup coordination/retained-payload compatibility; G-012 tunnel credential/containment approval | Resolve the named solution before its implementation issue is ready, then obtain actual provider/site evidence. A gate alone does not solve the design. |
| External evidence required | Other applicable G-001–G-017 and G-019–G-021, individually scoped | Physical, provider, identity or real-host facts are still required; use the current ledger and operation-specific prerequisites, not a blanket pre-bootstrap checklist. |
| Implementation required | G-018 and the owning phase contracts | Generate and test the registry and applicable protocols; exact implementation choices remain issue-owned. |
| Per-service conditional | G-022 | Evaluated only for a proposed service; it does not select general application placement. |
| Deferred outside v1 | G-023 | Cannot block v1 and cannot be mutated by v1. |

Generic local setup, Slack-only v1 human acknowledgement, native credentials, privilege/OS controls and public build/checks have explicit design/qualification ownership in the [development readiness table](development/roadmap.md#implementation-readiness). The Slack prerequisite is resolved by profile/capability and does not acquire a new Labs gate ID merely by being a generic v1 requirement. Ask only for ready missing decisions/evidence; never re-ask confirmed outcomes or label missing proof passed.

The suffix `labs.vegastack.com` and profile aliases `control-plane`, `builder-01`, `app-01` and `hermes-01` remain selected Labs values, not core constants or requirements for another installation.

## Source register

Original infrastructure facts were revalidated against primary official documentation on 24-08-2026. This adversarial revision revalidated GitHub/GitHub Apps/Actions/API authentication, Coolify source modes, D1/R2/SQLite, Go and client/server platform contracts, Codex/Claude/Hermes behavior and the VegaStack Design System on 25-08-2026. Links below are primary vendor/project sources; version-sensitive interfaces must be rechecked at their stated gate.

### Validation status and sensitivity

| Subsystem | Confirmed official fact | Design choice / unresolved boundary | Recheck gate |
|---|---|---|---|
| Cloudflare | Mesh is beta; direct node TCP/UDP/ICMP uses `100.96.0.0/12`; current account limit is 50 nodes/1,000 routes; Tunnel is outbound-only; managed-network TLS detection and Mesh/`cloudflared` coexistence constraints are documented. | Mesh-only private overlay, include profile, 40 warning/48 block and selected qualified application-node connectors under D-119 are site choices; qualification, pilot and version evidence remain gated. | Before phase 2 and every client/Tunnel upgrade. |
| Coolify | Current docs require a fresh supported Linux server, privileged SSH, separate workload data backup, same-version recovery inputs and prohibit applications on a build server. | Initial `v4.3.10` tag/installer digest and direct API ownership are selected; real-host restore and token-permission evidence remain gated. | Before phase 3 install/restore/upgrade. |
| Debian | Debian 13.6 is current stable as of 24-08-2026; routine security repositories and release-note caveats still apply. | Site selects clean 13.x baseline and seven-day soak. | Before image build, point/major upgrade and if stable release changes. |
| TP-Link | HX510 official model supports three gigabit ports, reservations/Ethernet backhaul; ES216G V1.20 data sheet confirms 16×1GbE, 32 Gb/s and listed L2 features. | Local standalone settings/port plan are site choices; ISP UI, regional hardware and firmware remain discovery facts. | On hardware receipt and before firmware change. |
| Harbor | Official docs confirm production HTTPS, local/OIDC migration limitations, robots, audit and scanning behavior. | Target version, exact persistent data set/adapter, hostname and clean migration inputs remain gated. | Before phase 5 and each upgrade. |
| GitHub | Git/SSH, Actions `GITHUB_TOKEN`, webhooks, deploy keys, fine-grained tokens and Apps are distinct mechanisms. No VegaStack-owned App is generally required; external rich Check Run writes and Coolify PR comments are the narrow optional App-only cases. macOS ARM64 self-hosted runner support is preview-sensitive. | Controller/groups/labels/log sink and Intel/manual Mac fallback are selected; exact repo enrollment, real-host proof and release identity remain gated; current Check Runs docs contain a PAT/App contradiction. | Before phase 4, every API-version change and any App installation. |
| Slack | Socket Mode uses an app-level token with `connections:write`; interactive payloads carry the action context that the app must acknowledge and validate; `chat:write` permits bot messages. Slack documents request verification for HTTP-delivered interactions, while v1 selects Socket Mode and its authenticated envelope path. | Slack-only normal v1 acknowledgement, exact local-human mapping, fail-closed outage behavior and separate-device threat assumption are selected. Runtime SDK/version, real workspace/app/session and revocation proof remain gated. | Before implementing #7/#9/#12/#15 and before every Slack API/SDK or scope change. |
| 1Password | Service accounts are non-person scoped automation identities. | Purpose-separated vault topology is selected; actual UUIDs/grants, negative tests and offline recovery evidence remain site inputs. | Before phase 3 and rotation. |
| Google Workspace | Cloudflare supports Workspace identity/group data; Directory/Reports APIs expose user lifecycle/admin audit, currently with a 180-day maximum admin-report query window. | Workspace lifecycle stays human-admin prerequisite; the control database owns VegaStack Labs roles. | Before onboarding/offboarding and quarterly review. |
| Codex/Claude/Hermes | Current official docs support layered `AGENTS.md`/skills, Claude `CLAUDE.md` import plus permissions/hooks, and Hermes Blank Slate, per-profile config/tools/doctor and Codex subscription device-code auth. | Repository contract, high-autonomy boundary and read/plan-only Hermes profile are site designs. | In CI on contract changes and before agent upgrades. |
| SQLite / D1 / R2 | SQLite documents ACID, one-writer/same-host/WAL constraints, corruption hazards and online backup. D1 writes at a primary, async read replicas can lag, and its local mode is a standalone local-only environment rather than offline access to production; Time Travel/import semantics also differ. R2 documents encryption, scoped tokens, durability and bucket/prefix retention locks; its S3 API does not implement per-object Object Lock headers. | SQLite is sole authority; selected restic v2 repositories provide client-side-encrypted local/off-site recovery; D1 projection is optional one-way status only. Actual R2/SSD resource IDs, credential grants and restore proof remain `G-008` evidence. | Before initial build, every DB/library/API change and every restore/retention change. |
| Go and supported platforms | Go publishes build targets; Debian/Ubuntu, Apple and Microsoft publish lifecycle, service, signing, credential and packaging behavior. Compilation alone does not establish support. | Exact release matrix intentionally rejects untested server/node/client/runner combinations. | Every release and before adding an OS/architecture. |
| VegaStack Design | Official site documents Next 16/React 19/Tailwind v4, Base UI, provider-first setup, dashboard block, owned registry components, accessibility and component-drift gates. | Static bundle embedded into Go, screen mapping and no production Node server are VegaStack Labs deployment choices. | Before frontend scaffold and every design-system update. |

“Confirmed” is a current documented fact, not a promise that a beta/versionless interface will remain unchanged. Implementation must pin versions where available and retain the stated manual recovery path.

### Project sources

| ID | Source |
|---|---|
| SRC-TR-01 | Complete rollout transcript path listed above |
| SRC-PR-01 | Project instructions: `/Users/kmanojkumar/.codex/.chatgpt-projects/g-p-6a8bed40e41c81918ee5d434285f8ca0/AGENTS.md` |
| SRC-GS-01 | [Google inventory/application workbook](https://docs.google.com/spreadsheets/d/1l1_oZ54OQ8dObDi4DeS4soNznkgEhQ9N3GvcVIMd_qw/edit?gid=0#gid=0), read-only |

### Cloudflare

| ID | Official source | Used for |
|---|---|---|
| SRC-CF-01 | [Connectivity options / Mesh beta](https://developers.cloudflare.com/cloudflare-one/networks/connectivity-options/) | bidirectional Mesh, platform/status and traffic model |
| SRC-CF-02 | [Mesh routes](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-mesh/routes/) | CIDR/hostname routes, DNS and client prerequisites |
| SRC-CF-03 | [Mesh tips](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-mesh/tips/) | coexistence, routing conflict, MTU and update behavior |
| SRC-CF-04 | [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/) | outbound-only public/private connector |
| SRC-CF-05 | [Cloudflare One account limits](https://developers.cloudflare.com/cloudflare-one/account-limits/) | 50 Mesh-node limit |
| SRC-CF-06 | [Device serial numbers](https://developers.cloudflare.com/cloudflare-one/reusable-components/posture-checks/client-checks/corp-device/) and [device registration](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/device-registration/) | desktop/mobile device approval facts |
| SRC-CF-07 | [Google Workspace integration](https://developers.cloudflare.com/cloudflare-one/integrations/identity-providers/google-workspace/) | Access/enrollment identity and group information |
| SRC-CF-08 | [Managed networks](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/configure/managed-networks/) | TLS-based LAN detection and profile switching |
| SRC-CF-09 | [R2 bucket locks](https://developers.cloudflare.com/r2/buckets/bucket-locks/) | retention protection |
| SRC-CF-10 | [Request-size / 413 limits](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/4xx-client-error/error-413/) | proxied upload-size constraint for Harbor |
| SRC-CF-11 | [Official Cloudflare Go SDK](https://github.com/cloudflare/cloudflare-go) and [v7.8.0 release](https://github.com/cloudflare/cloudflare-go/releases/tag/v7.8.0) | direct typed provider adapter and pinned-SDK review boundary |

### D1 and R2

| ID | Official source | Used for |
|---|---|---|
| SRC-D1-01 | [D1 read replication](https://developers.cloudflare.com/d1/best-practices/read-replication/) | primary writes, asynchronous replicas, Sessions consistency |
| SRC-D1-02 | [D1 local development](https://developers.cloudflare.com/d1/best-practices/local-development/) | standalone local-only environment versus remote production authority |
| SRC-D1-03 | [D1 Time Travel](https://developers.cloudflare.com/d1/reference/time-travel/) | point-in-time recovery behavior and retention |
| SRC-D1-04 | [D1 import/export](https://developers.cloudflare.com/d1/best-practices/import-export-data/) and [limits](https://developers.cloudflare.com/d1/platform/limits/) | raw SQLite boundary, tooling/size/concurrency constraints |
| SRC-R2-01 | [R2 data security](https://developers.cloudflare.com/r2/reference/data-security/) | provider-side encryption and transport protection |
| SRC-R2-02 | [R2 bucket locks](https://developers.cloudflare.com/r2/buckets/bucket-locks/), [lifecycle rules](https://developers.cloudflare.com/r2/buckets/object-lifecycles/) and [S3 API compatibility](https://developers.cloudflare.com/r2/api/s3/api/) | bucket/prefix retention protection, lifecycle precedence and absence of per-object S3 Object Lock headers |
| SRC-R2-03 | [R2 API tokens](https://developers.cloudflare.com/r2/api/tokens/) | bucket-scoped credential design and lifecycle |
| SRC-R2-04 | [R2 durability](https://developers.cloudflare.com/r2/reference/durability/) | durability/availability boundary; backup still needs verification/independence |

### Backup engine

| ID | Official source | Used for |
|---|---|---|
| SRC-BKP-01 | [restic repository setup](https://restic.readthedocs.io/en/stable/030_preparing_a_new_repo.html) | repository v2, client-side encryption, keys and S3-compatible R2 access |
| SRC-BKP-02 | [restic verification and repair guidance](https://restic.readthedocs.io/en/stable/077_troubleshooting.html) | metadata/full-data checks and safe corruption response |
| SRC-BKP-03 | [restic retention](https://restic.readthedocs.io/en/stable/060_forget.html) | `keep-within`, append-only threat boundary, prune authority and post-prune checks |

### Coolify

| ID | Official source | Used for |
|---|---|---|
| SRC-CO-01 | [Installation requirements](https://coolify.io/docs/get-started/installation) | Linux/architecture/minimum support |
| SRC-CO-02 | [Server overview](https://next.coolify.io/docs/core/infrastructure/servers/overview) | localhost, deployment and build roles |
| SRC-CO-03 | [Build servers](https://coolify.io/docs/knowledge-base/server/build-server) | no applications on marked build server |
| SRC-CO-04 | [Docker Compose](https://coolify.io/docs/knowledge-base/docker/compose) | Compose as application source of truth |
| SRC-CO-05 | [Security model](https://next.coolify.io/docs/core/security-model) | privileged control plane and operator responsibility |
| SRC-CO-06 | [Backup/restore](https://coolify.io/docs/knowledge-base/how-to/backup-restore-coolify) | `APP_KEY`, SSH keys, application-data boundary |
| SRC-CO-07 | [Self-hosted updates](https://coolify.io/docs/knowledge-base/self-update) | controlled update settings |
| SRC-CO-08 | [Docker Image deployment](https://next.coolify.io/docs/applications/deployments/docker-image) and [deploy API](https://coolify.io/docs/api-reference/api/deployments/deploy-by-tag-or-uuid) | immutable digest and exact-resource trigger |
| SRC-CO-09 | [Installation](https://coolify.io/docs/get-started/installation) and [upgrade](https://coolify.io/docs/get-started/upgrade/) | fresh host, supported OS/architecture, exact-version upgrade |
| SRC-CO-10 | [GitHub source overview](https://next.coolify.io/docs/applications/sources/github/overview), [GitHub App](https://next.coolify.io/docs/applications/sources/github/app) and [deploy key](https://coolify.io/docs/applications/ci-cd/github/deploy-key) | public/deploy-key/App alternatives and selected-repository permissions |
| SRC-CO-11 | [Other providers](https://coolify.io/docs/applications/ci-cd/other-providers) and [GitHub Actions](https://next.coolify.io/docs/applications/sources/github/actions) | provider-neutral webhook/external-CI deployment path |
| SRC-CO-12 | [Preview deployments](https://next.coolify.io/docs/applications/sources/github/preview-deploy) | App requirement for optional automated PR comments |
| SRC-CO-13 | [API authorization](https://coolify.io/docs/api-reference/authorization), [API tokens](https://next.coolify.io/docs/core/security/credentials/api-tokens) and [team roles](https://next.coolify.io/docs/core/team/roles-and-permissions) | team binding, `write`/`deploy` permissions, token-owner dependency, rotation and residual team-wide scope |
| SRC-CO-14 | [Coolify v4.3.10 release](https://github.com/coollabsio/coolify/releases/tag/v4.3.10) | initial tag, release commit and release-date evidence |
| SRC-CO-15 | [Version-specific Coolify upgrade](https://coolify.io/docs/get-started/upgrade) | exact-version installer argument, manual updates and backup-first behavior |

### Harbor

| ID | Official source | Used for |
|---|---|---|
| SRC-HBR-01 | [Database authentication](https://goharbor.io/docs/edge/administration/configure-authentication/db-auth/) and [OIDC authentication](https://goharbor.io/docs/main/administration/configure-authentication/oidc-auth/) | self-registration and populated-database auth migration limits |
| SRC-HBR-02 | [System robot accounts](https://goharbor.io/docs/2.12.0/administration/robot-accounts/) and [project robots](https://goharbor.io/docs/main/working-with-projects/project-configuration/create-robot-accounts/) | cross-project versus project-scoped automation credentials |
| SRC-HBR-03 | [HTTPS configuration](https://goharbor.io/docs/main/install-config/configure-https/) | production TLS requirement |
| SRC-HBR-04 | [Audit log](https://goharbor.io/docs/main/administration/audit-log/) | Harbor operation traceability |
| SRC-HBR-05 | [Vulnerability scanning](https://goharbor.io/docs/main/administration/vulnerability-scanning/) | scanner/result semantics |

### Debian

| ID | Official source | Used for |
|---|---|---|
| SRC-DEB-01 | [Debian releases](https://www.debian.org/releases/) | Debian 13.6 current stable, release date and lifecycle |
| SRC-DEB-02 | [Debian 13 errata](https://www.debian.org/releases/stable/errata) | point releases and security repository |
| SRC-DEB-03 | [Debian 13 release notes](https://www.debian.org/releases/stable/release-notes/) | deployment/upgrade caveats |

### Platform and distribution

| ID | Official source | Used for |
|---|---|---|
| SRC-GO-01 | [Go build environment](https://go.dev/doc/install/source#environment) | available GOOS/GOARCH targets; compilation is not support acceptance |
| SRC-UBU-01 | [Ubuntu 26.04 LTS release notes](https://documentation.ubuntu.com/release-notes/26.04/) and [release lifecycle](https://ubuntu.com/about/release-cycle) | exact optional managed-node LTS and support lifetime |
| SRC-MAC-01 | [Apple Keychain Services](https://developer.apple.com/documentation/security/keychain-services) | macOS credential storage |
| SRC-MAC-02 | [Notarizing macOS software](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution) | signed/notarized client distribution |
| SRC-MAC-03 | [Creating launchd jobs](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) | macOS persistent-job lifecycle where supported |
| SRC-WIN-01 | [Windows DPAPI `CryptProtectData`](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata) | user/machine-bound credential protection |
| SRC-WIN-02 | [Windows code-signing options](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options) | Authenticode/package trust |
| SRC-WIN-03 | [WinGet manifest schema](https://learn.microsoft.com/en-us/windows/package-manager/package/manifest) | Windows package/update metadata |
| SRC-ANS-01 | [Ansible check/diff mode](https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_checkmode.html) and [connection details](https://docs.ansible.com/ansible/latest/inventory_guide/connection_details.html) | agentless SSH execution, plan preview limits and verification |

### TP-Link

| ID | Official source | Used for |
|---|---|---|
| SRC-TP-01 | [HX510 India product/specifications](https://www.tp-link.com/in/service-provider/wifi-router/hx510/) | ports, address reservation, EasyMesh and Ethernet backhaul |
| SRC-TP-02 | [ES216G V1.20 datasheet](https://static.tp-link.com/upload/product-overview/2025/202512/20251223/Datasheet_ES216G%28UN%291.20.pdf) | ports, switching, L2 features, power and thermals |
| SRC-TP-03 | [ES216G official support](https://support.omadanetworks.com/en/product/es216g/) | hardware-version/firmware matching |
| SRC-TP-04 | [Omada device IP discovery](https://support.omadanetworks.com/uk/document/107618/) | DHCP lease lookup, same-subnet management and matching the device MAC label; checked 26-08-2026 |
| SRC-TP-05 | [Omada switch-range comparison](https://www.omadanetworks.com/us/business-networking/all-omada-switch/) | Easy Managed/Agile versus DHCP server/relay, routing, ACL, LACP, 802.1X, SNMP and CLI capabilities; checked 26-08-2026 |
| SRC-TP-06 | [Easy Managed switch user guide](https://static.tp-link.com/upload/manual/2024/202408/20240813/1910013715_Omada%20Easy%20Managed%20Switch_UG.pdf) | management DHCP client, ports, rate/storm interactions, configuration restore and maintenance; older shared guide requires variant checks |
| SRC-TP-07 | [ES216G installation guide](https://static.tp-link.com/upload/manual/2024/202410/20241022/7106511600_ES220GMP%2CES228GMP%2CES216G%2CES224G%28UN%29_IG.pdf) | standalone access/recovery and reconfiguration when moving to controller management |
| SRC-TP-08 | [HX510 support](https://www.tp-link.com/us/support/download/hx510/v1/) and linked [BBA Mesh guide](https://static.tp-link.com/upload/manual/2026/202607/20260714/BBA%20Mesh_UG_REV1.0.1.pdf) | DHCP/reservations, local/remote administration and recovery; guide explicitly varies by model/software/region/ISP, so not ACT activation evidence |

The [network-device operations research](network-device-operations.md) applies these sources without expanding the approved topology or device-adapter scope. The outside-pool reservation alternative and firmware-specific security settings remain planning choices, not newly approved decisions. No current source lookup revalidates the historical audit register.

### Agent and operations tooling

| ID | Official source | Used for |
|---|---|---|
| SRC-AG-01 | [OpenAI AGENTS.md](https://developers.openai.com/codex/guides/agents-md) and [skills](https://developers.openai.com/codex/skills/) | layered Codex instructions and focused repository skills |
| SRC-AG-02 | [Claude Code memory](https://code.claude.com/docs/en/memory), [permissions](https://code.claude.com/docs/en/permissions) and [hooks](https://code.claude.com/docs/en/hooks) | `CLAUDE.md` import and deterministic defense-in-depth controls |
| SRC-AG-03 | [Hermes quickstart](https://hermes-agent.nousresearch.com/docs/getting-started/quickstart), [configuration](https://hermes-agent.nousresearch.com/docs/user-guide/configuration), [skills/trust](https://hermes-agent.nousresearch.com/docs/user-guide/features/skills/) and [CLI](https://hermes-agent.nousresearch.com/docs/user-guide/cli) | Blank Slate, project context/skill discovery and trust, configuration, diagnostics and noninteractive behavior |
| SRC-SEC-01 | [1Password service accounts](https://www.1password.dev/service-accounts) | non-person automation identity and scoped access |
| SRC-1P-02 | [1Password secrets in scripts](https://developer.1password.com/docs/cli/secrets-scripts/) | `op read`/`op run`, service-account least privilege and avoiding stored plaintext |
| SRC-GW-01 | [Google Directory user lifecycle](https://developers.google.com/workspace/admin/directory/v1/guides/manage-users) and [Admin activity report](https://developers.google.com/workspace/admin/reports/v1/guides/manage-audit-admin) | suspension prerequisite, native audit attribution and report window |
| SRC-GH-01 | [GitHub App permissions](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app) and [best practices](https://docs.github.com/en/apps/creating-github-apps/about-creating-github-apps/best-practices-for-creating-a-github-app) | least-privilege automation and short-lived tokens |
| SRC-GH-02 | [Self-hosted runner reference](https://docs.github.com/en/actions/reference/runners/self-hosted-runners) and [secure use](https://docs.github.com/en/actions/reference/security/secure-use) | ephemeral runner and untrusted-workflow boundaries |
| SRC-GH-03 | [Artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations) | build provenance and verification |
| SRC-GH-04 | [Deciding when to build a GitHub App](https://docs.github.com/en/apps/creating-github-apps/about-creating-github-apps/deciding-when-to-build-a-github-app) | Actions versus App boundary and durable-automation guidance |
| SRC-GH-05 | [Authenticate with `GITHUB_TOKEN`](https://docs.github.com/en/actions/tutorials/authenticate-with-github_token) and [token security model](https://docs.github.com/en/actions/concepts/security/github_token) | per-job token, permissions and GitHub-owned Actions App nuance |
| SRC-GH-06 | [Git over SSH](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/about-ssh) and [deploy keys](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys) | ordinary Git/private one-repository access without an App |
| SRC-GH-07 | [Creating webhooks](https://docs.github.com/en/webhooks/using-webhooks/creating-webhooks) and [repository webhook API](https://docs.github.com/en/rest/repos/webhooks) | repository/org webhook versus App webhook and token alternatives |
| SRC-GH-08 | [Repository API](https://docs.github.com/en/rest/repos/repos), [workflow runs](https://docs.github.com/en/rest/actions/workflow-runs) and [self-hosted runners](https://docs.github.com/en/rest/actions/self-hosted-runners) | public/private discovery and CI/runner observation permissions |
| SRC-GH-09 | [Commit statuses](https://docs.github.com/en/rest/commits/statuses) and [Check Runs](https://docs.github.com/en/rest/checks/runs) | status fallback, explicit App-only Checks note and current token-list contradiction |
| SRC-GH-10 | [Releases](https://docs.github.com/en/rest/releases/releases) and [release assets](https://docs.github.com/en/rest/releases/assets) | public/private update/download and publication credentials |
| SRC-GH-11 | [Issues](https://docs.github.com/en/rest/issues/issues) and [Deployments](https://docs.github.com/en/rest/deployments/deployments) | optional notification/deployment status mechanisms and scopes |
| SRC-GH-12 | [Installation authentication](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation) and [reviewing installations](https://docs.github.com/en/apps/using-github-apps/reviewing-and-modifying-installed-github-apps) | one-hour tokens, repository narrowing, suspend/uninstall lifecycle |
| SRC-GH-13 | [Actions Secrets API](https://docs.github.com/en/rest/actions/secrets) and [deployment environments](https://docs.github.com/en/rest/deployments/environments) | fine-grained PAT/App alternatives and exact `Environments`/`Administration` permissions for VegaStack Labs' scoped environment automation |
| SRC-GH-14 | [Monitoring self-hosted runners](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/monitor-and-troubleshoot) | external preservation of ephemeral-runner diagnostics |
| SRC-GH-15 | [GitHub-hosted runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners) | current macOS ARM64 preview status and stable Intel fallback label |

### Slack acknowledgement adapter

| ID | Official source | Used for |
|---|---|---|
| SRC-SL-01 | [Verifying requests from Slack](https://docs.slack.dev/authentication/verifying-requests-from-slack) | authenticated-request and replay/freshness principles; HTTP signing-secret flow is not substituted for the selected Socket Mode envelope |
| SRC-SL-02 | [Handling user interaction](https://docs.slack.dev/interactivity/handling-user-interaction/) | interactive action payload, acknowledgement timing and response behavior |
| SRC-SL-03 | [Using Socket Mode](https://docs.slack.dev/apis/events-api/using-socket-mode/) | WebSocket interaction delivery without a public webhook and envelope acknowledgement |
| SRC-SL-04 | [`connections:write`](https://docs.slack.dev/reference/scopes/connections.write/) | minimum app-level scope for Socket Mode connection establishment |
| SRC-SL-05 | [`chat:write`](https://api.slack.com/scopes/chat%3Awrite) | minimum bot scope for presenting approval requests |

### Release signing

| ID | Official source | Used for |
|---|---|---|
| SRC-SIG-01 | [Sigstore blob signing](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/) | keyless blob signing and stored verification bundles |
| SRC-SIG-02 | [Sigstore signature verification](https://docs.sigstore.dev/cosign/verifying/verify/) | issuer/identity policy, digest verification and offline-capable bundle direction |

### Control service and interface

| ID | Official source | Used for |
|---|---|---|
| SRC-SQL-01 | [SQLite write-ahead logging](https://sqlite.org/wal.html) | journal/concurrency constraints, fixed-version gate and v1 rollback-journal choice |
| SRC-SQL-02 | [SQLite online backup API](https://sqlite.org/backup.html) | consistent live database backup and restore contract |
| SRC-SQL-03 | [SQLite pragma reference](https://sqlite.org/pragma.html) | foreign keys, synchronous mode, integrity and operational checks |
| SRC-SQL-04 | [Appropriate uses for SQLite](https://www.sqlite.org/whentouse.html) and [transactions](https://sqlite.org/transactional.html) | small device-local workload fit and ACID behavior |
| SRC-SQL-05 | [How databases become corrupt](https://www.sqlite.org/howtocorrupt.html) | live-copy, filesystem/locking, journal and durability hazards |
| SRC-VDS-01 | [VegaStack Design System](https://design.vegastack.com/), [quickstart](https://design.vegastack.com/docs/guides/quickstart) | runtime/components, provider setup, dashboard starter, accessibility and drift/release gates |
