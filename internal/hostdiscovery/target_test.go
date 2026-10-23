package hostdiscovery

import (
	"crypto/ed25519"
	"crypto/rand"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"golang.org/x/crypto/ssh"
	"strings"
	"testing"
)

func validTarget(t *testing.T) generated.HostDiscoveryTarget {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return generated.HostDiscoveryTarget{Schema: generated.SchemaIDHostDiscoveryTarget, SchemaVersion: "1.0.0", TargetID: "candidate-a", Revision: 1, Address: "127.0.0.1", Port: 2222, User: "inspect", HostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key.PublicKey()))), ProfileID: "profile-a", CredentialReferenceID: "ref-a", MaterialVersion: "v1", ExpectedOS: "debian", ExpectedVersion: "13", ExpectedArchitecture: "amd64"}
}
func TestTargetRejectsArbitraryDestination(t *testing.T) {
	base := validTarget(t)
	if err := ValidateTarget(base); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"example.com", "0.0.0.0", "224.0.0.1", "169.254.1.1", "fe80::1%en0", "::ffff:127.0.0.1"} {
		value := base
		value.Address = address
		if ValidateTarget(value) == nil {
			t.Errorf("accepted %s", address)
		}
	}
	for _, mutate := range []func(*generated.HostDiscoveryTarget){func(v *generated.HostDiscoveryTarget) { v.User = "root" }, func(v *generated.HostDiscoveryTarget) { v.User = "a;id" }, func(v *generated.HostDiscoveryTarget) { v.Port = 65536 }, func(v *generated.HostDiscoveryTarget) { v.HostKey = "" }, func(v *generated.HostDiscoveryTarget) { v.HostKey += " extra" }, func(v *generated.HostDiscoveryTarget) { v.HostKey = "command=\"id\" " + v.HostKey }, func(v *generated.HostDiscoveryTarget) { v.AssetID = new("asset") }} {
		value := base
		mutate(&value)
		if ValidateTarget(value) == nil {
			t.Fatal("unsafe target accepted")
		}
	}
}

func TestAdministratorIdentityReadRequiresConfirmedPreloadedTarget(t *testing.T) {
	target := validTarget(t)
	target.IdentityReadMode = new("administrator-sudo")
	if ValidateTarget(target) == nil {
		t.Fatal("administrator identity read accepted without preloaded credentials")
	}
	target.CredentialMode = new("preloaded-discovery")
	target.CredentialPublicKeyDigest = new("sha256:" + strings.Repeat("a", 64))
	if err := ValidateTarget(target); err != nil {
		t.Fatal(err)
	}
	request := generated.HostDiscoveryTargetDraftRequest{
		Schema: generated.SchemaIDHostDiscoveryTargetDraftRequest, SchemaVersion: "1.0.0",
		Target: target, Action: "activate", IdempotencyKey: "identity-read",
	}
	if ValidateConsoleConfirmation(request) == nil {
		t.Fatal("administrator identity read accepted without console confirmation")
	}
	request.ConsoleConfirmation = &generated.HostDiscoveryConsoleConfirmation{
		Schema: generated.SchemaIDHostDiscoveryConsoleConfirmation, SchemaVersion: "1.0.0",
		Method: "administrator-verified-console", TargetDigest: Digest(target),
	}
	if err := ValidateConsoleConfirmation(request); err != nil {
		t.Fatal(err)
	}
	request.Target.IdentityReadMode = nil
	if ValidateConsoleConfirmation(request) == nil {
		t.Fatal("identity read mode change did not invalidate target confirmation")
	}
	for _, mode := range []string{"", "sudo", "administrator-sudo;id"} {
		target.IdentityReadMode = &mode
		if ValidateTarget(target) == nil {
			t.Fatalf("invalid identity read mode accepted: %q", mode)
		}
	}
}
