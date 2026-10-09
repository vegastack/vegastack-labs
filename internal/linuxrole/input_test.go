package linuxrole

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"golang.org/x/crypto/ssh"
	"slices"
	"strings"
	"testing"
)

func fixture() generated.LinuxRoleInput {
	d := "sha256:" + strings.Repeat("a", 64)
	lock := generated.DebianProfileLock{Schema: generated.SchemaIDDebianProfileLock, SchemaVersion: "1.0.0", ImageDigest: d, OSFamily: "debian", OSVersion: "13.6", Architecture: "amd64", PackageSourceDigest: d, Packages: []generated.AccessPackage{{Schema: generated.SchemaIDAccessPackage, SchemaVersion: "1.0.0", Name: "systemd", Version: "1"}}, ExecutableVersion: "1.0.0", AnsibleVersion: "2.19.0", AnsibleExecutableDigest: d, CollectionDigest: d, RoleDigest: d, Backend: "iptables-nft"}
	in := generated.LinuxRoleInput{Schema: generated.SchemaIDLinuxRoleInput, SchemaVersion: "1.0.0", HostID: "test-host", HostIdentityDigest: d, ProfileID: "debian", ProfileLock: lock, ProfileLockDigest: hostaction.Digest(lock), RoleID: "control", ActionVersion: "1.0.0", AutomationUID: 1000, ControlIDs: []string{"linux.role-identity-paths", "linux.role-service-resources"}, NetworkingRequired: true, AffectedBaselineControlIDs: []string{"linux.resource-health", "debian.host-firewall", "debian.accounts", "debian.ssh"}, BaselineSnapshotDigest: d, RoleBindingDigest: d, ExecutableDigest: d, ConfigDigest: d, ExpectedServiceState: "absent", Accounts: []generated.LinuxRoleAccount{{Schema: generated.SchemaIDLinuxRoleAccount, SchemaVersion: "1.0.0", Selector: "control", UID: 1000, GID: 1000, Existing: true}}, Directories: []generated.LinuxRoleDirectory{}, Resources: generated.LinuxRoleResources{Schema: generated.SchemaIDLinuxRoleResources, SchemaVersion: "1.0.0", MemoryMaxBytes: 1 << 30, CPUQuotaPercent: 100, TasksMax: 100, MinimumFreeBytes: 1 << 30, MinimumFreePercent: 10, CapacityMemoryBytes: 2 << 30, CapacityCPUPercent: 200, CapacityTasks: 200}}
	for _, s := range []string{"config", "state", "runtime"} {
		in.Directories = append(in.Directories, generated.LinuxRoleDirectory{Schema: generated.SchemaIDLinuxRoleDirectory, SchemaVersion: "1.0.0", Selector: s, UID: 1000, GID: 1000, Mode: "0700", ExpectedState: "absent"})
	}
	in.NetworkAccess = networkFixture(in)
	in.RenderedPolicyDigest = PolicyDigest(in)
	in.RoleBindingDigest = RoleBindingDigest(in)
	return in
}
func TestRoleRejectsConflictingControlApplicationCI(t *testing.T) {
	in := fixture()
	if err := ValidateInput(in); err != nil {
		t.Fatal(err)
	}
	in.Accounts = append(in.Accounts, generated.LinuxRoleAccount{Schema: generated.SchemaIDLinuxRoleAccount, SchemaVersion: "1.0.0", Selector: "application", UID: 1001, GID: 1001})
	if ValidateDesiredInput(in) == nil {
		t.Fatal("mixed role identities accepted")
	}
}
func TestRoleRejectsCapacityWidening(t *testing.T) {
	for _, mut := range []func(*generated.LinuxRoleInput){func(i *generated.LinuxRoleInput) { i.Resources.MemoryMaxBytes = i.Resources.CapacityMemoryBytes + 1 }, func(i *generated.LinuxRoleInput) { i.Resources.CPUQuotaPercent = i.Resources.CapacityCPUPercent + 1 }, func(i *generated.LinuxRoleInput) { i.Resources.TasksMax = i.Resources.CapacityTasks + 1 }, func(i *generated.LinuxRoleInput) { i.Accounts[0].UID = 0 }, func(i *generated.LinuxRoleInput) { i.Accounts[0].Existing = false }, func(i *generated.LinuxRoleInput) { i.Directories[0].ExpectedState = "symlink" }} {
		in := fixture()
		mut(&in)
		if ValidateDesiredInput(in) == nil {
			t.Fatal("unsafe input accepted")
		}
	}
}
func TestDecodeRejectsUnknownFields(t *testing.T) {
	raw, _ := json.Marshal(fixture())
	raw = append(raw[:len(raw)-1], []byte(`,"shell":"evil"}`)...)
	if _, err := DecodeInput(raw); err == nil {
		t.Fatal("unknown input accepted")
	}
}

func TestRoleBindingRejectsChangedPolicyButSurvivesCollection(t *testing.T) {
	in := fixture()
	original := in.RoleBindingDigest
	in.ExpectedServiceState = "inactive"
	in.ExpectedUnitDigest = in.ConfigDigest
	in.BaselineSnapshotDigest = in.ConfigDigest
	in.CurrentRoleBindingDigest = original
	in.ControlIDs = []string{"linux.control-service"}
	for i := range in.Directories {
		in.Directories[i].ExpectedState = "owned"
		in.Directories[i].ExpectedDigest = in.ConfigDigest
	}
	if RoleBindingDigest(in) != original {
		t.Fatal("collection changed declaration binding")
	}
	in.Resources.MemoryMaxBytes++
	in.RenderedPolicyDigest = PolicyDigest(in)
	if ValidateInput(in) == nil {
		t.Fatal("changed desired policy reused old binding")
	}
}

func TestWorkloadRoleCannotOmitNetworking(t *testing.T) {
	in := fixture()
	in.NetworkingRequired = false
	in.RoleBindingDigest = RoleBindingDigest(in)
	if ValidateInput(in) == nil {
		t.Fatal("control role omitted required networking")
	}
}

func networkFixture(role generated.LinuxRoleInput) *generated.DebianAccessInput {
	key, _ := ssh.NewPublicKey(ed25519.PublicKey(bytes.Repeat([]byte{1}, 32)))
	k := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	d := role.ProfileLock.RoleDigest
	a := generated.AccessAccount{Schema: generated.SchemaIDAccessAccount, SchemaVersion: "1.0.0", Name: "automation", UID: role.AutomationUID, GID: role.AutomationUID, Home: "/home/automation", Role: "automation", PublicKeys: []string{k}, PublicKeyDigests: []string{hostaction.BytesDigest([]byte(k))}}
	in := &generated.DebianAccessInput{Schema: generated.SchemaIDDebianAccessInput, SchemaVersion: "1.0.0", HostID: role.HostID, HostIdentityDigest: role.HostIdentityDigest, ProfileID: role.ProfileID, ProfileLock: role.ProfileLock, ProfileLockDigest: role.ProfileLockDigest, ActionVersion: "1.0.0", AutomationUID: role.AutomationUID, Accounts: []generated.AccessAccount{a}, SSHUsers: []string{"automation"}, SSHSourcePrefixes: []string{"192.0.2.0/24"}, RecoverySourcePrefixes: []string{"192.0.2.1/32"}, PrivilegedServiceKeys: []generated.AccessServiceKey{}, Interfaces: []generated.AccessInterface{{Schema: generated.SchemaIDAccessInterface, SchemaVersion: "1.0.0", Name: "eth0", Index: 2, Addresses: []string{"192.0.2.2"}}}, HostFlows: []generated.AccessFlow{}, ContainerFlows: []generated.AccessFlow{}}
	in.RollbackSpecification = generated.AccessRollbackSpecification{Schema: generated.SchemaIDAccessRollbackSpecification, SchemaVersion: "1.0.0", HostID: in.HostID, HostIdentityDigest: in.HostIdentityDigest, ProfileLockDigest: in.ProfileLockDigest, DeadlineSeconds: 600, RecoverySourcePrefixes: in.RecoverySourcePrefixes, OwnedState: []generated.AccessOwnedState{{Schema: generated.SchemaIDAccessOwnedState, SchemaVersion: "1.0.0", ResourceID: "ssh-config", BeforeDigest: d, AfterDigest: d}}}
	in.RollbackDigest = hostaction.Digest(in.RollbackSpecification)
	in.RenderedAccess = generated.RenderedAccess{Schema: generated.SchemaIDRenderedAccess, SchemaVersion: "1.0.0", ProfileLockDigest: in.ProfileLockDigest, RendererDigest: d, Accounts: in.Accounts, SSHUsers: in.SSHUsers, SSHSourcePrefixes: in.SSHSourcePrefixes, RecoverySourcePrefixes: in.RecoverySourcePrefixes, PrivilegedServiceKeys: in.PrivilegedServiceKeys, Interfaces: in.Interfaces, HostFlows: in.HostFlows, ContainerFlows: in.ContainerFlows, RollbackUnitsDigest: d}
	in.RenderedAccessDigest = hostaction.Digest(in.RenderedAccess)
	return in
}
func TestNetworkProjectionCannotSubstituteIdentity(t *testing.T) {
	in := fixture()
	in.NetworkAccess.HostID = "another-host"
	in.RoleBindingDigest = RoleBindingDigest(in)
	if ValidateInput(in) == nil {
		t.Fatal("cross-host access policy accepted")
	}
}

func TestCompleteRoleInputFitsBound(t *testing.T) {
	raw, e := json.Marshal(fixture())
	if e != nil {
		t.Fatal(e)
	}
	if len(raw) > MaximumInput {
		t.Fatalf("role input size %d exceeds %d", len(raw), MaximumInput)
	}
	if _, e = DecodeInput(raw); e != nil {
		t.Fatal(e)
	}
}

func TestRoleMustInvalidateAccountAndSSHProof(t *testing.T) {
	for _, id := range []string{"debian.accounts", "debian.ssh"} {
		in := fixture()
		in.AffectedBaselineControlIDs = slices.DeleteFunc(in.AffectedBaselineControlIDs, func(v string) bool { return v == id })
		if ValidateInput(in) == nil {
			t.Fatalf("role retained old %s proof", id)
		}
	}
}
