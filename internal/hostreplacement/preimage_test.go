package hostreplacement

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"testing"
)

func TestRolePreimageDigestBindsOwnedState(t *testing.T) {
	fixture := func() generated.LinuxRoleInput {
		return generated.LinuxRoleInput{HostID: "host-a", HostIdentityDigest: "identity", RoleID: "control", ExpectedServiceState: "inactive", ExpectedUnitDigest: "unit", ExpectedTmpfilesDigest: "tmpfiles", ConfigDigest: "config", ExecutableDigest: "executable", RenderedPolicyDigest: "rendered", Accounts: []generated.LinuxRoleAccount{{Selector: "control", UID: 1001, GID: 1001, Existing: true}}, Directories: []generated.LinuxRoleDirectory{{Selector: "state", UID: 1001, GID: 1001, Mode: "0700", ExpectedState: "owned", ExpectedDigest: "state"}, {Selector: "config", UID: 1001, GID: 1001, Mode: "0700", ExpectedState: "absent"}}}
	}
	base := RolePreimageDigest(fixture())
	for name, mutate := range map[string]func(*generated.LinuxRoleInput){"identity": func(r *generated.LinuxRoleInput) { r.HostIdentityDigest = "other" }, "unit": func(r *generated.LinuxRoleInput) { r.ExpectedUnitDigest = "other" }, "tmpfiles": func(r *generated.LinuxRoleInput) { r.ExpectedTmpfilesDigest = "other" }, "service": func(r *generated.LinuxRoleInput) { r.ExpectedServiceState = "active" }, "config": func(r *generated.LinuxRoleInput) { r.ConfigDigest = "other" }, "executable": func(r *generated.LinuxRoleInput) { r.ExecutableDigest = "other" }, "owner": func(r *generated.LinuxRoleInput) { r.Directories[0].UID++ }, "mode": func(r *generated.LinuxRoleInput) { r.Directories[0].Mode = "0750" }, "presence": func(r *generated.LinuxRoleInput) { r.Directories[0].ExpectedState = "absent" }, "digest": func(r *generated.LinuxRoleInput) { r.Directories[0].ExpectedDigest = "other" }, "account": func(r *generated.LinuxRoleInput) { r.Accounts[0].Existing = false }} {
		t.Run(name, func(t *testing.T) {
			r := fixture()
			mutate(&r)
			if RolePreimageDigest(r) == base {
				t.Fatal("preimage omitted changed field")
			}
		})
	}
	r := fixture()
	r.Directories[0], r.Directories[1] = r.Directories[1], r.Directories[0]
	if RolePreimageDigest(r) != base {
		t.Fatal("set ordering changed preimage")
	}
	if r.Directories[0].Selector != "config" {
		t.Fatal("digest mutated caller")
	}
}
