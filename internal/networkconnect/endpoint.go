// Package networkconnect validates and diagnoses one declared SSH endpoint. It
// never opens SSH sessions, executes commands or enables forwarding.
package networkconnect

import (
	"encoding/json"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"golang.org/x/crypto/ssh"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

const AdapterID = "core.network-endpoint"
const Operation = "network.endpoint.change"

var username = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

func invalid() error { return failure.New(generated.ErrorCodeInputInvalid, "network-endpoint", false) }
func ValidateEndpoint(e generated.NetworkEndpoint) error {
	raw, err := json.Marshal(e)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDNetworkEndpoint, raw, generated.ContractExact) != nil {
		return invalid()
	}
	if e.User == "root" || !username.MatchString(e.User) || e.LANPort != 22 || e.MeshPort != 22 || e.MarkerPort < 1 || e.MarkerPort > 65535 {
		return invalid()
	}
	for _, s := range []string{e.LANAddress, e.MeshAddress, e.MarkerAddress} {
		a, err := netip.ParseAddr(s)
		if err != nil || a.String() != s || a.Zone() != "" || a.Is4In6() || a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() || a.IsLoopback() {
			return invalid()
		}
	}
	u, err := url.ParseRequestURI(e.MarkerPath)
	if err != nil || !strings.HasPrefix(e.MarkerPath, "/") || strings.HasPrefix(e.MarkerPath, "//") || u.RawQuery != "" || u.Fragment != "" || u.Host != "" || strings.ContainsAny(e.MarkerPath, "\r\n") {
		return invalid()
	}
	key, comment, opts, rest, err := ssh.ParseAuthorizedKey([]byte(e.HostKey))
	if err != nil || comment != "" || len(opts) != 0 || len(rest) != 0 || strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))) != e.HostKey {
		return invalid()
	}
	return nil
}
func ValidateRequest(r generated.NetworkEndpointRequest) error {
	raw, err := json.Marshal(r)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDNetworkEndpointRequest, raw, generated.ContractExact) != nil || ValidateEndpoint(r.Endpoint) != nil || r.Endpoint.Revision != r.ExpectedEndpointRevision+1 || r.RecoveryEpoch != r.Endpoint.RecoveryEpoch || r.Action == "revoke" && r.ExpectedEndpointRevision == 0 {
		return invalid()
	}
	return nil
}
