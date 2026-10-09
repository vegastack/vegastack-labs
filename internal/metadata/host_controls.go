package metadata

// HostControlRequirementSource is the finite mapping from a logical admission
// requirement to its actual producer controls. Applicability is declaration-bound.
type HostControlRequirementSource struct {
	ControlID, ProducerID string
	ProducerControlIDs    []string
	Stage                 string
	Roles                 []string
	Applicability         string
}

func CurrentHostControlRequirements() []HostControlRequirementSource {
	common := []string{"host", "control", "application", "ci", "recovery-spare", "reserve"}
	roles := []string{"control", "application", "ci", "recovery-spare", "reserve"}
	out := []HostControlRequirementSource{}
	add := func(id, producer string, controls []string, stage string, selected []string, applicability string) {
		out = append(out, HostControlRequirementSource{id, producer, controls, stage, selected, applicability})
	}
	for _, v := range []struct{ id, producer, control string }{
		{"host.identity-accounts", "debian-access-native", "debian.accounts"},
		{"host.ssh-effective", "debian-access-native", "debian.ssh"},
		{"linux.firewall-container", "debian-access-native", "debian.host-firewall"},
		{"linux.fail2ban-sshd", "debian-baseline", "linux.fail2ban-sshd"},
		{"linux.auditd-bounded", "debian-baseline", "linux.audit-bounded"},
		{"linux.apparmor-enforcing", "debian-baseline", "linux.apparmor-enforcing"},
		{"host.security-updates", "debian-baseline", "linux.update-health"},
		{"host.time-health", "debian-baseline", "linux.time-sync"},
		{"host.resource-health", "debian-baseline", "linux.resource-health"},
		{"host.kernel-settings", "debian-baseline", "linux.kernel-settings"},
	} {
		add(v.id, v.producer, []string{v.control}, "baseline", common, "always")
	}
	add("linux.firewall-container", "debian-access-native", []string{"debian.container-firewall"}, "role", []string{"control", "application", "ci"}, "networking")
	add("linux.aide-control", "debian-baseline", []string{"linux.aide-integrity"}, "role", []string{"control"}, "always")
	add("host.storage-encryption", "debian-baseline", []string{"linux.volume-encryption", "linux.volume-recovery"}, "role", roles, "volumes")
	for _, v := range []struct {
		id            string
		roles         []string
		applicability string
	}{
		{"linux.role-identity-paths", roles, "always"},
		{"linux.role-service-resources", roles, "standby"},
		{"linux.role-network-boundary", roles, "networking"},
		{"linux.role-workload-isolation", []string{"application", "ci"}, "always"},
		{"linux.control-service", []string{"control"}, "always"},
		{"linux.reserve-no-workloads", []string{"recovery-spare", "reserve"}, "always"},
	} {
		add(v.id, "linux-role", []string{v.id}, "role", v.roles, v.applicability)
	}
	return out
}
