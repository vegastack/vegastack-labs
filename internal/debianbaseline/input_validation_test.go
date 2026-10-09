package debianbaseline

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
)

func baselineInputFixture() generated.DebianBaselineInput {
	d := hostaction.Digest("fixture")
	lock := generated.DebianProfileLock{Schema: generated.SchemaIDDebianProfileLock, SchemaVersion: "1.0.0", ImageDigest: d, OSFamily: "debian", OSVersion: "13.6", Architecture: "amd64", PackageSourceDigest: d, Packages: []generated.AccessPackage{{Schema: generated.SchemaIDAccessPackage, SchemaVersion: "1.0.0", Name: "auditd", Version: "fixture"}}, ExecutableVersion: "1.0.0", AnsibleVersion: "fixture", AnsibleExecutableDigest: d, CollectionDigest: d, RoleDigest: d, Backend: "iptables-nft"}
	in := generated.DebianBaselineInput{Schema: generated.SchemaIDDebianBaselineInput, SchemaVersion: "1.0.0", HostID: "test-host", HostIdentityDigest: d, ProfileID: "test-profile", ProfileLock: lock, ProfileLockDigest: hostaction.Digest(lock), RoleID: "control", ActionVersion: "1.0.0", AutomationUID: 1001, ControlIDs: []string{"linux.audit-bounded"}, RecoverySourcePrefixes: []string{"192.0.2.1/32"}, UpdateOwner: "operator", TimeOwner: "chrony", AuditPaths: []string{"/etc/passwd"}, AppArmorProfiles: []generated.BaselineApparmorProfile{}, AIDE: generated.BaselineAidePolicy{Schema: generated.SchemaIDBaselineAidePolicy, SchemaVersion: "1.0.0", ScopePaths: []string{}, ScopeDigest: hostaction.Digest([]string{})}, Resources: []generated.BaselineResourceLimit{}, KernelSettings: []generated.BaselineKernelSetting{}, Volumes: []generated.HostVolumeBinding{}}
	in.RenderedPolicyDigest = PolicyDigest(in)
	return in
}
func TestBaselineClosedSemantics(t *testing.T) {
	in := baselineInputFixture()
	raw, _ := json.Marshal(in)
	if _, e := DecodeInput(raw); e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"unknown-kernel", "wrong-kernel-value", "root-watch", "unknown-control", "wide-recovery", "wrong-render"} {
		t.Run(mode, func(t *testing.T) {
			in := baselineInputFixture()
			switch mode {
			case "unknown-kernel":
				in.KernelSettings = []generated.BaselineKernelSetting{{Name: "kernel.random_setting", Value: "1"}}
			case "wrong-kernel-value":
				in.KernelSettings = []generated.BaselineKernelSetting{{Name: "fs.protected_hardlinks", Value: "2"}}
			case "root-watch":
				in.AuditPaths = []string{"/"}
			case "unknown-control":
				in.ControlIDs = []string{"linux.unknown"}
			case "wide-recovery":
				in.RecoverySourcePrefixes = []string{"0.0.0.0/0"}
			case "wrong-render":
				in.RenderedPolicyDigest = hostaction.Digest("wrong")
			}
			if ValidateInput(in) == nil {
				t.Fatal("unsafe baseline accepted")
			}
		})
	}
}

func TestDesiredBaselineCannotBypassClosedInput(t *testing.T) {
	for _, mode := range []string{"schema", "package", "duplicate-package", "audit-space", "time-owner", "template"} {
		t.Run(mode, func(t *testing.T) {
			in := baselineInputFixture()
			switch mode {
			case "schema":
				in.Schema = "other"
			case "package":
				in.ProfileLock.Packages[0].Name = "unrelated"
			case "duplicate-package":
				in.ProfileLock.Packages = append(in.ProfileLock.Packages, in.ProfileLock.Packages[0])
			case "audit-space":
				in.AuditPaths = []string{"/etc/audit/foo -p wa"}
			case "time-owner":
				in.TimeOwner = "unknown"
			case "template":
				in.ProfileID = "{{ lookup('pipe','id') }}"
			}
			in.ProfileLockDigest = hostaction.Digest(in.ProfileLock)
			if ValidateDesiredInput(in) == nil {
				t.Fatal("unsafe typed desired input accepted")
			}
		})
	}
}
