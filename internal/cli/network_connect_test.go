package cli

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"golang.org/x/crypto/ssh"
	"strings"
	"testing"
)

func (s *stubControlOperations) DraftNetworkEndpoint(context.Context, string, generated.NetworkEndpointRequest) (localapi.TypedResponse[generated.DeclarationRevision], error) {
	return s.grantResponse, s.err
}
func (s *stubControlOperations) ConnectNetwork(_ context.Context, _, host, path string) (generated.NetworkConnectResult, error) {
	return generated.NetworkConnectResult{Schema: generated.SchemaIDNetworkConnectResult, SchemaVersion: "1.0.0", HostID: host, Path: path, EndpointDigest: "sha256:" + strings.Repeat("a", 64), Outcome: "authenticated-and-closed"}, s.err
}
func networkRequestFixture(t *testing.T) generated.NetworkEndpointRequest {
	t.Helper()
	key, e := ssh.NewPublicKey(ed25519.NewKeyFromSeed(make([]byte, 32)).Public())
	if e != nil {
		t.Fatal(e)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	return generated.NetworkEndpointRequest{Schema: generated.SchemaIDNetworkEndpointRequest, SchemaVersion: "1.0.0", Action: "activate", IdempotencyKey: "fixture", ReasonDigest: digest, Endpoint: generated.NetworkEndpoint{Schema: generated.SchemaIDNetworkEndpoint, SchemaVersion: "1.0.0", HostID: "synthetic-host", HostIdentityDigest: digest, TargetID: "synthetic-target", TargetRevision: 1, HostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))), User: "operator", LANAddress: "10.70.0.2", LANPort: 22, MeshAddress: "100.96.0.2", MeshPort: 22, MarkerAddress: "10.70.0.1", MarkerPort: 443, MarkerPath: "/site", MarkerCertificateDigest: digest, MarkerValue: "site", Flow: "operator-client-to-host-ssh", Revision: 1}}
}

type networkControlFixture struct {
	*stubControlOperations
	calls      int
	host, path string
}

func (f *networkControlFixture) ConnectNetwork(_ context.Context, _, host, path string) (generated.NetworkConnectResult, error) {
	f.calls++
	f.host = host
	f.path = path
	return f.stubControlOperations.ConnectNetwork(context.Background(), "", host, path)
}
func TestNetworkConnectCLIFlagsAndDeniedArbitraryTarget(t *testing.T) {
	for _, route := range []string{"auto", "lan", "mesh"} {
		f := &networkControlFixture{stubControlOperations: successfulControlOperations(t)}
		code, out, _ := runTestAppWithOptions(t, context.Background(), []string{"connect", "--config", "fixture/profile.json", "--node", "synthetic-host", "--port", "22", "--path", route, "--output", "json"}, nil, WithControlOperations(f, &stubFileReader{}))
		if code != 0 || f.calls != 1 || f.host != "synthetic-host" || f.path != route || !strings.Contains(out, "authenticated-and-closed") {
			t.Fatal(code, out, f)
		}
	}
	for _, extra := range [][]string{{"--port", "23"}, {"--path", "proxy"}, {"--address", "10.70.0.2"}, {"--command", "id"}} {
		f := &networkControlFixture{stubControlOperations: successfulControlOperations(t)}
		args := append([]string{"connect", "--config", "fixture/profile.json", "--node", "synthetic-host", "--output", "json"}, extra...)
		code, _, _ := runTestAppWithOptions(t, context.Background(), args, nil, WithControlOperations(f, &stubFileReader{}))
		if code == 0 || f.calls != 0 {
			t.Fatal("arbitrary connect accepted", args)
		}
	}
}
func networkRequestJSON(t *testing.T) []byte {
	raw, e := json.Marshal(networkRequestFixture(t))
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
