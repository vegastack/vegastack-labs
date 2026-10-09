package gate

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"reflect"
	"slices"
	"testing"
)

func TestHostRequiredControlsIndependentCommonMatrix(t *testing.T) {
	want := []string{"host.identity-accounts", "host.ssh-effective", "linux.firewall-container", "linux.fail2ban-sshd", "linux.auditd-bounded", "linux.apparmor-enforcing", "host.security-updates", "host.time-health", "host.resource-health", "host.kernel-settings"}
	slices.Sort(want)
	for _, role := range []string{"host", "control", "application", "ci", "recovery-spare", "reserve"} {
		p := generated.HostProfile{ProfileID: "debian-13-amd64", OSFamily: "debian", OSVersion: "13.6", Architecture: "amd64", RoleID: role, DefinitionVersion: "1.0.0"}
		got, e := RequiredHostControls(p, "baseline")
		slices.Sort(got)
		if e != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("role %s: %v %v", role, got, e)
		}
	}
}
func TestHostRequiredControlsExactPlatformOnly(t *testing.T) {
	base := generated.HostProfile{ProfileID: "debian-13-amd64", OSFamily: "debian", OSVersion: "13.6", Architecture: "amd64", RoleID: "control", DefinitionVersion: "1.0.0"}
	for _, change := range []func(*generated.HostProfile){func(p *generated.HostProfile) { p.OSVersion = "14" }, func(p *generated.HostProfile) { p.Architecture = "arm64" }, func(p *generated.HostProfile) { p.OSFamily = "macos" }, func(p *generated.HostProfile) { p.OSFamily = "ubuntu" }, func(p *generated.HostProfile) { p.RoleID = "unknown" }, func(p *generated.HostProfile) { p.DefinitionVersion = "2.0.0" }} {
		p := base
		change(&p)
		if _, e := RequiredHostControls(p, "baseline"); e == nil {
			t.Fatal("unsupported profile accepted", p)
		}
	}
	if _, e := RequiredHostControls(base, "unknown"); e == nil {
		t.Fatal("unknown stage accepted")
	}
}
func TestHostControlDecoderRejectsUnboundedOrUnknownPayload(t *testing.T) {
	for _, raw := range [][]byte{make([]byte, 16385), []byte(`{"passed":true}`), []byte(`{"schema":"unknown"}`)} {
		if _, e := DecodeHostControlResult(raw); e == nil {
			t.Fatal("invalid control result accepted")
		}
	}
}

func TestHostRequiredRoleControlsIndependentMatrix(t *testing.T) {
	for role, want := range map[string][]string{
		"control":        {"host.storage-encryption", "linux.firewall-container", "linux.aide-control", "linux.role-identity-paths", "linux.role-service-resources", "linux.role-network-boundary", "linux.control-service"},
		"application":    {"host.storage-encryption", "linux.firewall-container", "linux.role-identity-paths", "linux.role-service-resources", "linux.role-network-boundary", "linux.role-workload-isolation"},
		"ci":             {"host.storage-encryption", "linux.firewall-container", "linux.role-identity-paths", "linux.role-service-resources", "linux.role-network-boundary", "linux.role-workload-isolation"},
		"recovery-spare": {"host.storage-encryption", "linux.role-identity-paths", "linux.role-service-resources", "linux.role-network-boundary", "linux.reserve-no-workloads"},
		"reserve":        {"host.storage-encryption", "linux.role-identity-paths", "linux.role-service-resources", "linux.role-network-boundary", "linux.reserve-no-workloads"},
	} {
		p := generated.HostProfile{ProfileID: "debian-13-amd64", OSFamily: "debian", OSVersion: "13.6", Architecture: "amd64", RoleID: role, DefinitionVersion: "1.0.0"}
		got, e := RequiredHostControls(p, "role")
		slices.Sort(want)
		if e != nil || !reflect.DeepEqual(got, want) {
			t.Fatal(role, got, e)
		}
	}
}
