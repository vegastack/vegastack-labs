package networkconnect

import (
	"crypto/ed25519"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"golang.org/x/crypto/ssh"
	"strings"
	"testing"
)

func endpointFixture(t *testing.T) generated.NetworkEndpoint {
	t.Helper()
	key, e := ssh.NewPublicKey(ed25519.NewKeyFromSeed(make([]byte, 32)).Public())
	if e != nil {
		t.Fatal(e)
	}
	return generated.NetworkEndpoint{Schema: generated.SchemaIDNetworkEndpoint, SchemaVersion: "1.0.0", HostID: "synthetic-host", HostIdentityDigest: "sha256:" + strings.Repeat("a", 64), TargetID: "synthetic-target", TargetRevision: 1, HostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))), User: "operator", LANAddress: "10.70.0.2", LANPort: 22, MeshAddress: "100.96.0.2", MeshPort: 22, MarkerAddress: "10.70.0.1", MarkerPort: 443, MarkerPath: "/site", MarkerCertificateDigest: "sha256:" + strings.Repeat("b", 64), MarkerValue: "site-synthetic", Flow: "operator-client-to-host-ssh", Revision: 1}
}
func TestNetworkEndpointRejectsUnsafeBindings(t *testing.T) {
	e := endpointFixture(t)
	if err := ValidateEndpoint(e); err != nil {
		t.Fatal(err)
	}
	for _, mut := range []func(*generated.NetworkEndpoint){func(e *generated.NetworkEndpoint) { e.User = "root" }, func(e *generated.NetworkEndpoint) { e.LANAddress = "host.test" }, func(e *generated.NetworkEndpoint) { e.MeshAddress = "0.0.0.0" }, func(e *generated.NetworkEndpoint) { e.LANPort = 23 }, func(e *generated.NetworkEndpoint) { e.MarkerPort = 70000 }, func(e *generated.NetworkEndpoint) { e.HostKey += " comment" }, func(e *generated.NetworkEndpoint) { e.HostID = "INVALID" }, func(e *generated.NetworkEndpoint) { e.MarkerPath = "//other/site" }, func(e *generated.NetworkEndpoint) { e.Flow = "shell" }} {
		x := e
		mut(&x)
		if ValidateEndpoint(x) == nil {
			t.Fatal("unsafe endpoint accepted", x)
		}
	}
}
