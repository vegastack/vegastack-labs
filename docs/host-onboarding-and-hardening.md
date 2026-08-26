# Host onboarding and hardening

Status: confirmed outcomes with profile qualification pending, 26-08-2026. The user requires basic hardening on every added managed host and has clarified that Ansible should perform the configuration needed for lab admission. The user has selected SSH-only Fail2ban, bounded auditd and AIDE for the control role, daily/after-change evidence checks that block new work without silently stopping existing workloads, and separate native security-data updates. Exact tested per-profile settings/elevation and the remaining Mac enforcement design still need phase solution/issue readiness proof; these selections are not implemented roles, expanded support or live authority. [D-116](decisions-and-sources.md#d-116) · [D-119](decisions-and-sources.md#d-119)

[Security policy](security-and-operations.md) · [Automation and support matrix](automation-and-agents.md#os-and-architecture-support-matrix) · [Development roadmap](development/roadmap.md)

## Outcome and scope

Provide one onboarding workflow: supply the machine's identity, supported OS/version, intended role and approved bootstrap access; `vsk-labs` constructs the plan; Ansible installs and configures the applicable baseline and role; independent checks determine whether the host may receive workloads. Replacements and reimages repeat the same process. Hardening alone does not prove capacity, backups or the other role-admission gates.

The portable contract specifies security outcomes. Each tested OS/release/architecture profile supplies package names, service managers, configuration formats and verification. Role overlays add control-plane, application, CI, Mac developer or Hermes requirements. No best-effort fallback runs a Debian recipe on an unknown Linux or a Linux recipe on a Mac.

The existing v1 support matrix remains unchanged. Research into other distributions establishes an extension path, not support. Initial OS installation, console identity verification, initial network/SSH access and recovery custody remain bootstrap prerequisites; Ansible cannot configure an unreachable bare machine. Normal modules also require a compatible Python on the managed host, but Ansible itself need not be installed there. A missing runtime requires a pinned, approved bootstrap step or a guided local prerequisite. [Ansible node requirements](https://docs.ansible.com/projects/ansible/latest/installation_guide/intro_installation.html)

## Humans, Codex and Claude use the same workflow

An operator may use `vsk-labs` directly or ask Codex/Claude Code to drive its implemented workflows. The agent gathers permitted observations, prepares the declaration and plan, explains blockers, and runs the exact authorized apply. It does not invent a hardening script, run a one-off live playbook, choose extra tools or approve its own node/network mutation. Ansible remains the host configuration engine under `vsk-labs`; provider enrollment remains with its typed adapter. Human procedures have the same prerequisites, targets, verification and recovery.

During development, agents implement and test these workflows in the repository and explicitly scoped isolated environments. The user selected full v1 completion before the first lab onboarding rehearsal. No inventory machine becomes an early test deployment by implication. [D-117](decisions-and-sources.md#d-117)

## Starting with installed Debian and a switch

The user reports installed Debian 13.6 machines and an available LAN switch. This is planning context, not verified OS, cabling, identity, network or qualification evidence. Installation alone does not admit a host. Inspect the existing installation and data first; never erase it automatically. An incompatible or untrusted installation remains blocked until an explicit adoption/reimage decision and recovery requirements are satisfied.

The [address-discovery procedure](architecture-and-networking.md#first-address-discovery-and-assignment) establishes how to find the switch and prepare per-device reservations without guessing the subnet. The [delivery path](development/roadmap.md#delivery-path-from-development-to-the-lab) separates building the complete platform from deploying the inventory.

The initial trusted administrator installs `vsk-labs` on the selected supported control host and chooses local control-plane setup. The [generic lifecycle](platform-lifecycle.md#guided-setup-and-the-initial-authority) defines the finite pre-database installation manifest, server-owned state, local identity binding and exact setup authority. A separate operator machine is optional and may join later. The Labs choice of node 04 is profile data, not a code path. Local service creation precedes selected provider/fleet qualification but cannot waive it; no client becomes a fallback controller after service initialization.

Only minimum approved bootstrap access is established before hardening. Role configuration follows its dependencies; workload admission waits for both security and role evidence. In particular, installing Docker/Coolify or Mesh requires repeating affected network/security checks, and a qualified spare/reserve must not silently acquire application, runner or connector duties.

## Recommended controls and tools

“Baseline” means included in each applicable approved profile. “Role-specific” and “audit aid” do not become unconditional daemons or admission requirements. Exact versions and settings must be pinned in the implementing issue; do not install mutable upstream scripts.

| Control | Recommended implementation | What Ansible must configure and prove |
|---|---|---|
| Identity and local accounts — baseline | Native account/group tools, `sudo` where applicable | Correct host identity, individual standard accounts, separate admin/service identities, protected homes and keys, scoped elevation and no shared login. Unknown existing accounts/data are reviewed, not deleted automatically. |
| Remote access — baseline | OpenSSH and OS-native remote-access controls | Key-based SSH, approved users/sources, pinned host keys, no password SSH or direct root login for people. Validate effective settings and establish a fresh admin session before removing old access. Preserve the declared, separately restricted Coolify privileged key. |
| Host and container firewall — baseline | Linux packet filtering selected for the OS/role; native Mac application firewall plus a separately verified source/port enforcement path | Deny undeclared inbound paths, retain required LAN/Mesh flows, and test container-published ports after role installation. One declared owner for each rule set; no competing UFW/firewalld/custom-rule managers. See the Docker and Mac constraints below. |
| Repeated failed-login protection — selected Linux baseline | Fail2ban, initially only the SSH jail | Install the distro package and needed log-backend dependency; configure observed authentication logs, temporary bans, bounded resource use, protected recovery access and ban/unban tests. Do not enable every bundled jail. |
| Application confinement — baseline where supported | AppArmor for Debian/Ubuntu profiles; SELinux for a future qualified RHEL profile | Ensure the required profiles actually enforce restrictions and declared workloads still work. An enabled service with no applicable confinement is not proof. Do not disable confinement globally to fix an application. |
| Patch and repository hygiene — baseline | Native package manager and vendor security-update facilities | Approved repositories/signatures, available-security-update inventory, approved patch state and explicit reboot handling. Reconcile existing auto-update timers with the site's maintenance policy. |
| Security-event logging — selected Linux baseline | `auditd` plus existing system/authentication logs | Small rules for account, privilege and critical security-configuration changes; bounded disk use and loss/backlog alerts. Avoid blanket process-argument capture that may log secrets, broad all-syscall rules and unapproved halt-on-full behavior. Logs are evidence, not prevention. |
| OS, filesystem and service settings — baseline | Native sysctl, service, permission and boot controls | Preserve supported kernel protections; configure required services only; review unsafe ownership, world-writable sensitive files and unnecessary privileges. Keep rootless-container, build, networking and recovery requirements working. No universal `/tmp noexec`, namespace, forwarding or IPv6 toggle. |
| Time, logs and resource limits — baseline | Existing OS time-sync service, journald/log rotation or macOS Unified Logging | Working time synchronization, retention/redaction, disk headroom and sane service limits; use one time-sync implementation. Respect the repository display-time convention without rewriting machine log formats. |
| Mac platform protection — baseline | SIP, Gatekeeper, XProtect, native firewall and sharing controls | Verify protections and security-data updates, disable guest/automatic login where applicable, restrict sharing and protect per-user data. Do not weaken privacy/boot protections to automate setup. |
| File-integrity monitoring — role-specific | AIDE for the control host and other explicitly selected Linux roles | Monitor a small stable set of security/configuration files; protect the known-good reference and review changes before refreshing it. Exclude changing build caches/container storage. Do not silently accept a changed baseline. |
| Additional baseline audit — audit aid | Lynis on qualified Unix profiles; tailored macOS Security Compliance Project checks | Run a pinned audit, retain sanitized findings and map relevant results to our controls. Neither a scanner score nor an unreviewed remediation script decides admission. |
| Recovery and workload prerequisites — baseline plus role | Existing backup, Mesh, Docker/Coolify, monitoring and runner/service roles as applicable | Establish a recoverable configuration, install only the declared role's components and verify the complete role after hardening. No CI jobs or general fleet credentials on an unadmitted host. |

This includes actual tools such as Fail2ban and auditd, not only written policies. It also avoids installing several overlapping security agents without a demonstrated need. ClamAV, rootkit scanners, CrowdSec, full EDR/IDS stacks, automatic account-lockout policies and full CIS/STIG remediation are not default requirements in this proposal; add them only for a defined threat, maintenance owner and tested compatibility.

## Differences across operating systems

| Profile researched | Native direction | Project status and differences |
|---|---|---|
| Debian 13 `amd64` | APT, OpenSSH, Linux firewall, AppArmor, Fail2ban, auditd | Initial lab Linux profile. Debian identifies nftables as its recommended firewall framework; container roles need the separate Docker integration below. Preserve the existing site decision disabling IPv6 on selected Debian interfaces. [Debian firewall](https://wiki.debian.org/nftables) · [Debian security handbook](https://www.debian.org/doc/manuals/debian-handbook/security.en.html) |
| Ubuntu Server 26.04 LTS `amd64` | APT, OpenSSH, AppArmor, Fail2ban, auditd; explicit firewall and update configuration | Existing planned public managed-node lane, not the selected lab image. Share controls with Debian, but test package defaults, service names, active SSH configuration and update timers independently. Ubuntu documents AppArmor as enabled by default and automatic security updates as a normal installation default. [Ubuntu AppArmor](https://ubuntu.com/server/docs/how-to/security/apparmor/) · [Ubuntu updates](https://documentation.ubuntu.com/security/security-updates/) |
| RHEL 9; related distributions considered separately | DNF, firewalld, SELinux enforcing, Linux Audit; AIDE where needed | Research only. RHEL, Rocky and AlmaLinux must each have an explicitly qualified release/package-source/role combination; family resemblance is not certification. Fail2ban availability may require an additional approved repository. [RHEL security hardening](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/pdf/security_hardening/index) · [RHEL SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index) |
| SUSE Linux Enterprise Server 15 SP7 | Zypper, firewalld, AppArmor/SELinux according to the selected release/profile, Linux Audit, supported Fail2ban package | Research only. Do not extrapolate this release's confinement defaults to every SLES/openSUSE release; qualify the exact target before adding support. [SUSE security guide](https://documentation.suse.com/sles/15-SP7/single-html/SLES-security/index.html) |
| Supported current/previous macOS on Apple silicon | Native accounts, OpenSSH/sharing, firewall, Gatekeeper, SIP, XProtect, software update and launchd | Existing planned Mac lane. No Linux Fail2ban, auditd or systemd recipe is assumed to work. Preserve the native protections and use tested Mac-specific configuration/verification plus explicit local prerequisites where Apple requires them. [Apple platform protection](https://support.apple.com/guide/security/protecting-against-malware-sec469d47bd8/web) |

Support also depends on role: a qualified Mac developer/Hermes host does not become a supported Coolify or control-plane server. A hardware/OS combination that can run the operator CLI is not necessarily a managed host.

## Details that prevent unreliable automation

### Fail2ban is a configured control, not just a package

Fail2ban observes authentication failures and temporarily changes firewall rules. Its own guidance says it reduces failed attempts but does not replace strong authentication. In this lab, LAN/Mesh restrictions and SSH keys remain the primary access controls; the selected SSH jail adds defense in depth. [Fail2ban purpose](https://github.com/fail2ban/fail2ban/blob/master/README.md)

Use a small `jail.d/*.local` override rather than editing vendor defaults. Select the log backend from actual host behavior; the systemd backend uses journal matching, not a made-up `/var/log/auth.log` path. Pin the compatible ban action to the selected firewall backend. [Fail2ban configuration](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5)

Before enabling bans, settle retry/window/ban limits, exact recovery exclusions and resource bounds in the profile. Do not allowlist the whole LAN or ban proxy/connector addresses based on untrusted application headers. Keep the initial jail SSH-only; web-app jails require a separate trusted-client-IP design. Prove detection, temporary denial, expiry/manual recovery and continued administrator access using a separate disposable test source.

Dynamic bans are a material behavior: the approved host profile must explicitly authorize their narrow local enforcement scope, including targets, maximum duration and audit behavior, before enabling the service. They cannot widen base access rules, revoke accounts, quarantine other nodes or become a new general-purpose apply path. A discovery step or this proposal does not grant that authority.

### Docker changes the firewall design

UFW alone is not an acceptable container-exposure control: Docker documents how published traffic can bypass it. Recommend retaining the stable, qualified Docker iptables backend for the initial container profile and adding restrictions through its documented `DOCKER-USER` integration. This is distinct from the kernel's nftables implementation used by iptables-nft. Docker currently labels its native nftables backend experimental; do not silently switch to it. [Docker/UFW](https://docs.docker.com/engine/network/packet-filtering-firewalls/) · [Docker iptables](https://docs.docker.com/engine/network/firewall-iptables/) · [Docker nftables status](https://docs.docker.com/engine/network/firewall-nftables/)

The selected profile must define host-input, forwarded/container and Fail2ban rule ownership together, including rule order, restart persistence and IPv4/IPv6 behavior. Preserve Docker-owned rules; never flush the complete ruleset or disable Docker firewall management as a shortcut. Test actual published, unpublished and prohibited east-west paths after Docker/Coolify start, restart and reboot. Exact backend/version choices must close before the relevant issue becomes ready.

### Ansible needs independent recovery and verification

Use pinned Ansible/core collections, native idempotent modules where suitable and small reviewed helpers where necessary. Configuration templates must validate before activation; secret tasks disable diff and log disclosure. Ansible check mode is an aid, not the plan authority: unsupported modules may skip, dependent conditions may not resolve, and tasks can explicitly bypass check mode. Separate read-only collectors from apply tasks and prohibit mutating check-mode overrides in the planning path. [Ansible check/diff limitations](https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_checkmode.html)

Ansible `rescue` does not run for unreachable hosts. Therefore arm a tested local rollback mechanism before risky SSH/firewall changes, preserve a console/recovery route, and cancel rollback only after a fresh independent connection and denial probes pass. Use the native service/timer facility, not a new resident privileged agent. A restored connection after failure is recovery, not successful onboarding. [Ansible error handling](https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_blocks.html)

No broad `NOPASSWD: ALL` grant is added for convenience. Phase 6 must prove the actual bootstrap/automation privilege boundary needed by its modules, including which approved identity can execute privileged host configuration; a prose command allowlist is not proof that arbitrary Ansible modules are constrained.

### macOS has real local prerequisites

Ansible can configure supported native settings and check their effective state, but cannot promise a fully unattended recovery of every Mac security setting. Re-enabling SIP requires recoveryOS. Configuration profiles may require local installation/consent, and Remote Login, privacy permissions, secure-token/volume-owner and recovery requirements must be handled through Apple's supported paths. Do not edit TCC databases, disable SIP or assume root bypasses consent. [Apple SIP procedure](https://developer.apple.com/documentation/security/disabling-and-enabling-system-integrity-protection) · [Apple profile installation](https://support.apple.com/guide/mac-help/change-device-management-settings-mh35474/mac) · [Apple Remote Login](https://support.apple.com/guide/mac-help/allow-a-remote-computer-to-access-your-mac-mchlp1066/mac)

Keep the existing no-MDM scope. Produce a short local prerequisite checklist for any unavailable automated control, then verify it through the same admission workflow. The Mac application firewall is not a complete source-CIDR policy engine; the implementation issue must select and prove a compatible source/port enforcement path. This remains a Mac admission design gate, not an excuse to open management services to the whole LAN. [Apple firewall capabilities](https://support.apple.com/guide/security/firewall-security-seca0e83763f/web)

Apple explicitly says Packet Filter (PF) is not an API for a broadly distributed software product: its rules can conflict with system services, users and other products. Do not quietly make shell-managed PF the portable Mac implementation. Any site-admin-specific approach requires a separately reviewed compatibility boundary; a product-level solution must use supported mechanisms and account for deployment/consent requirements. Resolve this with the declared LAN/Mesh source restrictions before Mac admission, without inventing a new privileged agent or MDM dependency. [Apple TN3165](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api)

Do not continuously reset local passwords during reconciliation. Ansible documents that supplying a macOS password reports a change on every invocation; account creation and explicit rotation need separate protected tasks and actual state tests. [Ansible user module](https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/user_module.html)

Use the macOS Security Compliance Project as a source of release-specific checks and tailored settings, not as a blanket benchmark to apply. Its generated profiles/scripts require review against our required Screen Sharing, developer, CI, sleep and recovery behavior. [NIST mSCP](https://pages.nist.gov/macos_security/) · [Apple test-system guidance](https://it-training.apple.com/compliance/tutorials/course/sec035/)

### Updates, integrity and existing decisions

The seven-day OS/package soak, maintenance window and critical-update exception remain unchanged. Installing `unattended-upgrades` without configuring its behavior could violate that policy; inspect and reconcile vendor timers instead of adding a competing update owner. Native malware definitions and revocation data are distinct from OS upgrades: recommend retaining Apple's automatic security-data updates, and record that classification explicitly in the phase-0 policy review. Do not disable XProtect updates merely to implement an OS-release hold. [Ubuntu automatic updates](https://documentation.ubuntu.com/security/security-updates/) · [Apple XProtect updates](https://support.apple.com/guide/security/protecting-against-malware-sec469d47bd8/web)

AIDE detects changes against its reference; it does not prove a compromised host is clean. Protect and review that reference, and avoid accepting a new one automatically after unexplained drift. Lynis is an audit tool, not an auto-remediation engine. [AIDE manual](https://aide.github.io/doc/) · [Lynis upstream](https://github.com/CISOfy/lynis)

Preserve the accepted Linux full-disk-encryption decision and existing encryption on all machines. No automatic disk wipe, repartition, LUKS/FileVault enable/disable, major OS upgrade or broad account removal is included. Suspected compromise requires incident assessment or an explicitly approved clean rebuild, not an assertion that installing hardening tools fixed it. Preserve the scoped Coolify SSH exception and selected Debian IPv6 policy.

## Ansible onboarding sequence and proof

These are planned stages, not existing playbook names or executable commands:

1. **Inspect:** identity/host-key evidence, OS/build/architecture, current users/services, package sources, data ownership, disk/capacity, recovery access and the exact supported profile. Unmatched or unknown hosts stay unadmitted.
2. **Plan:** snapshot relevant configuration, establish recovery prerequisites and render the exact baseline/role changes, tool versions, effects and any local steps. The existing `vsk-labs` declaration/plan/acknowledgement path owns authority.
3. **Prepare:** provision the approved runtime and scoped automation identity, verify the replacement admin path, and arm local access rollback before risky changes.
4. **Configure:** apply common controls, OS-specific security tools/settings and the declared role. Apply dependencies in order; do not schedule real workloads while configuring.
5. **Verify:** validate effective SSH/sudo/firewall configuration; prove permitted and denied connections, Fail2ban ban/unban where enabled, confinement, permissions, audit events, update state and service health. Repeat affected probes after Mesh/Docker/Coolify setup.
6. **Reboot and repeat:** where the profile requires it, prove cold/reboot persistence, reconnection and recovery; apply again and require no unplanned configuration changes. Test interruption and rollback on disposable targets, separately from the onboarding target.
7. **Admit:** record current control-by-control evidence bound to identity, OS/role, profile/release, declaration and recovery epoch; require all mandatory hardening and role gates to pass before enabling workloads. Unknown/skipped/failed checks are not passes; quarantine state alone is not verified network isolation.

Confirmed ongoing behavior: recheck after relevant changes and daily by read-only policy. Failed/stale mandatory evidence blocks new workload admission, role expansion and new workload credentials; diagnostics/recovery remain available. Repairs use plan/apply; existing workloads are not silently stopped. The daily and after-change cadence and admission effects are confirmed; exact evidence expiry and severity/probe settings are pinned in the implementing profile issue before readiness. Local Fail2ban enforcement on applicable Linux profiles, is the separately bounded profile behavior above, not permission for general automatic repair.

## Planning handoff

Phase 0 pins the selected baseline into exact profile settings and acceptance: Fail2ban enforcement bounds, control-specific AIDE scope, update-data classification, evidence expiry and the Mac management/source-filter boundary. Existing support, tool and cadence decisions are not reopened; unresolved mechanisms remain explicit qualifications. Phases 1/5 provide schemas and evidence enforcement; phase 6 implements supported profiles; phases 7–9 integrate their additional services; phase 10 delivers drift/repair; phase 11 proves the complete matrix. No additional phase or tracking system is needed.

Each implementing issue must include the concrete package/configuration list, ownership, exact values, privilege requirements, safe activation/recovery steps and positive/negative tests for its real OS/role. Linux kernel/firewall/reboot and macOS behavior require appropriate real OS test lanes; container-only tests and scanner reports are insufficient.

Do not mark issues ready until these choices and prerequisites are settled. This research neither expands the v1 matrix nor authorizes host/provider mutations, repository policy changes or release publication.
