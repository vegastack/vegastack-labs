package debianaccess

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"golang.org/x/crypto/ssh"
	"strings"
	"testing"
)

func TestAccessInputClosed(t *testing.T) {
	for _, raw := range [][]byte{[]byte(`{"command":"sh"}`), []byte(`{"hostId":"a","hostId":"b"}`), bytes.Repeat([]byte("x"), 32769)} {
		if _, err := DecodeInput(raw); err == nil {
			t.Fatal("unsafe access input accepted")
		}
	}
}

func validInput(t *testing.T) generated.DebianAccessInput {
	t.Helper()
	public, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	key, e := ssh.NewPublicKey(public)
	if e != nil {
		t.Fatal(e)
	}
	k := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	d := hostaction.BytesDigest([]byte("synthetic-qualified-lock"))
	a := generated.AccessAccount{Schema: generated.SchemaIDAccessAccount, SchemaVersion: "1.0.0", Name: "automation", UID: 1001, GID: 1001, Home: "/home/automation", Role: "automation", PublicKeys: []string{k}, PublicKeyDigests: []string{hostaction.BytesDigest([]byte(k))}}
	lock := generated.DebianProfileLock{Schema: generated.SchemaIDDebianProfileLock, SchemaVersion: "1.0.0", ImageDigest: d, OSFamily: "debian", OSVersion: "13.6", Architecture: "amd64", PackageSourceDigest: d, Packages: []generated.AccessPackage{{Schema: generated.SchemaIDAccessPackage, SchemaVersion: "1.0.0", Name: "openssh-server", Version: "synthetic-test"}}, ExecutableVersion: "1.0.0", AnsibleVersion: "synthetic-test", CollectionDigest: d, RoleDigest: d, Backend: "iptables-nft"}
	in := generated.DebianAccessInput{Schema: generated.SchemaIDDebianAccessInput, SchemaVersion: "1.0.0", HostID: "test-host", HostIdentityDigest: d, ProfileID: "test-profile", ProfileLock: lock, ProfileLockDigest: hostaction.Digest(lock), ActionVersion: "1.0.0", AutomationUID: 1001, Accounts: []generated.AccessAccount{a}, SSHUsers: []string{"automation"}, SSHSourcePrefixes: []string{"192.0.2.0/24"}, RecoverySourcePrefixes: []string{"192.0.2.1/32"}, PrivilegedServiceKeys: []generated.AccessServiceKey{}, Interfaces: []generated.AccessInterface{{Schema: generated.SchemaIDAccessInterface, SchemaVersion: "1.0.0", Name: "eth0", Index: 2, Addresses: []string{"192.0.2.2"}}}, HostFlows: []generated.AccessFlow{}, ContainerFlows: []generated.AccessFlow{}}
	in.RollbackSpecification = generated.AccessRollbackSpecification{Schema: generated.SchemaIDAccessRollbackSpecification, SchemaVersion: "1.0.0", HostID: in.HostID, HostIdentityDigest: d, ProfileLockDigest: in.ProfileLockDigest, DeadlineSeconds: 600, RecoverySourcePrefixes: in.RecoverySourcePrefixes, OwnedState: []generated.AccessOwnedState{{Schema: generated.SchemaIDAccessOwnedState, SchemaVersion: "1.0.0", ResourceID: "ssh-config", BeforeDigest: d, AfterDigest: d}}}
	in.RollbackDigest = hostaction.Digest(in.RollbackSpecification)
	in.RenderedAccess = generated.RenderedAccess{Schema: generated.SchemaIDRenderedAccess, SchemaVersion: "1.0.0", ProfileLockDigest: in.ProfileLockDigest, RendererDigest: d, Accounts: in.Accounts, SSHUsers: in.SSHUsers, SSHSourcePrefixes: in.SSHSourcePrefixes, RecoverySourcePrefixes: in.RecoverySourcePrefixes, PrivilegedServiceKeys: in.PrivilegedServiceKeys, Interfaces: in.Interfaces, HostFlows: in.HostFlows, ContainerFlows: in.ContainerFlows, RollbackUnitsDigest: d}
	in.RenderedAccessDigest = hostaction.Digest(in.RenderedAccess)
	return in
}
func TestAccessInputSemantics(t *testing.T) {
	in := validInput(t)
	raw, _ := json.Marshal(in)
	if _, e := DecodeInput(raw); e != nil {
		t.Fatalf("valid synthetic input: %v", e)
	}
	cases := map[string]func(*generated.DebianAccessInput){
		"root":              func(v *generated.DebianAccessInput) { v.Accounts[0].UID = 0 },
		"wide-uid":          func(v *generated.DebianAccessInput) { v.Accounts[0].UID = 4294967296 },
		"duplicate-account": func(v *generated.DebianAccessInput) { v.Accounts = append(v.Accounts, v.Accounts[0]) },
		"path-injection":    func(v *generated.DebianAccessInput) { v.Accounts[0].Home = "/home/../etc" },
		"name-injection":    func(v *generated.DebianAccessInput) { v.Accounts[0].Name = "{{ lookup }}" },
		"key-options": func(v *generated.DebianAccessInput) {
			v.Accounts[0].PublicKeys[0] = "command=sh " + v.Accounts[0].PublicKeys[0]
		},
		"noncanonical-prefix": func(v *generated.DebianAccessInput) { v.SSHSourcePrefixes = []string{"192.0.2.1/24"} },
		"missing-recovery":    func(v *generated.DebianAccessInput) { v.RecoverySourcePrefixes = nil },
		"undeclared-ipv6":     func(v *generated.DebianAccessInput) { v.SSHSourcePrefixes = []string{"2001:db8::/32"} },
		"profile-drift":       func(v *generated.DebianAccessInput) { v.ProfileLock.OSVersion = "14" },
		"protected-host":      func(v *generated.DebianAccessInput) { v.HostID = "vsk-node-04" },
		"render-drift":        func(v *generated.DebianAccessInput) { v.RenderedAccess.RendererDigest = hostaction.Digest("other") },
		"unsafe-owned-path":   func(v *generated.DebianAccessInput) { v.RollbackSpecification.OwnedState[0].ResourceID = "/etc/passwd" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			var v generated.DebianAccessInput
			if e := json.Unmarshal(raw, &v); e != nil {
				t.Fatal(e)
			}
			mutate(&v)
			encoded, _ := json.Marshal(v)
			if _, e := DecodeInput(encoded); e == nil {
				t.Fatal("unsafe input accepted")
			}
		})
	}
}
