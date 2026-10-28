package networkingress

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"net/mail"
	"net/netip"
	"net/url"
	"slices"
	"strings"
)

const BootstrapCapability = "cloudflare.ingress.controller-bootstrap"

var BootstrapActions = []string{"bootstrap-tunnel", "bootstrap-group", "bootstrap-app", "bootstrap-policy", "bootstrap-seed", "bootstrap-cutover"}

func IsBootstrap(c generated.IngressChange) bool {
	return c.Bootstrap != nil && slices.Contains(BootstrapActions, c.Action)
}

// BootstrapScopeDigest pins the protected setup intent. Provider-assigned IDs and
// predecessor run IDs are separately bound by durable successful run receipts.
func BootstrapScopeDigest(c generated.IngressChange) string {
	b := c.Bootstrap
	if b == nil {
		return ""
	}
	hosts := []string{}
	for _, x := range c.Connectors {
		hosts = append(hosts, x.HostID, x.IdentityDigest)
	}
	return Digest([]any{c.ProfileID, c.AccountID, c.ZoneID, c.DNSRecordID, c.Hostname, c.OriginService, c.OriginServerName, c.OriginIdentityDigest, c.OwnerID, c.DeviceID, c.ObservationReferenceID, c.MutationReferenceID, b.Name, b.AllowedEmail, b.OriginCAPool, hosts})
}
func BootstrapKind(action string) string {
	return map[string]string{"bootstrap-tunnel": "tunnel-configuration", "bootstrap-group": "access-group", "bootstrap-app": "access-application", "bootstrap-policy": "access-policy", "bootstrap-seed": "tunnel-configuration", "bootstrap-cutover": "dns-record"}[action]
}
func BootstrapNeeds(action string) []string {
	switch action {
	case "bootstrap-policy":
		return []string{"bootstrap-group", "bootstrap-app"}
	case "bootstrap-seed":
		return []string{"bootstrap-tunnel", "bootstrap-group", "bootstrap-app", "bootstrap-policy"}
	case "bootstrap-cutover":
		return []string{"bootstrap-tunnel", "bootstrap-group", "bootstrap-app", "bootstrap-policy", "bootstrap-seed"}
	}
	return nil
}
func ValidateBootstrap(c generated.IngressChange) error {
	bad := func() error { return Error(generated.ErrorCodeInputInvalid) }
	b := c.Bootstrap
	if b == nil || !IsBootstrap(c) || c.ResourceKind != BootstrapKind(c.Action) || !token.MatchString(c.ProfileID) || !token.MatchString(c.OwnerID) || !token.MatchString(c.DeviceID) || !account.MatchString(c.AccountID) || !account.MatchString(c.ZoneID) || !account.MatchString(c.DNSRecordID) || !digest.MatchString(c.BeforeDigest) || !digest.MatchString(c.OriginIdentityDigest) || !hostname.MatchString(c.Hostname) || strings.Contains(c.Hostname, "*") || len(c.Hostname) > 253 || !hostname.MatchString(c.OriginServerName) || !token.MatchString(b.Name) || len(b.Name) > 100 || c.ExpectedOwnershipRevision != 0 || c.ResourceID != "" {
		return bad()
	}
	addr, e := mail.ParseAddress(b.AllowedEmail)
	if e != nil || addr.Address != b.AllowedEmail || !strings.Contains(addr.Address, "@") || len(b.AllowedEmail) > 254 {
		return bad()
	}
	if b.OriginCAPool != "" && b.OriginCAPool != "/etc/vsk-labs/ingress/origin-ca.pem" {
		return bad()
	}
	u, e := url.Parse(c.OriginService)
	if e != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return bad()
	}
	ip, e := netip.ParseAddr(u.Hostname())
	if e != nil || !ip.IsPrivate() {
		return bad()
	}
	if len(c.Connectors) != 1 || !token.MatchString(c.Connectors[0].HostID) || c.Connectors[0].HostID == "vsk-node-04" || c.Connectors[0].HostID == "vsk-node-05" || !digest.MatchString(c.Connectors[0].IdentityDigest) {
		return bad()
	}
	for _, id := range []string{c.TunnelID, c.AccessAppID, c.AccessPolicyID, c.Connectors[0].ConnectorID} {
		if id != "" && !uuid.MatchString(id) {
			return bad()
		}
	}
	if c.Action == "bootstrap-cutover" && !uuid.MatchString(c.Connectors[0].ConnectorID) {
		return bad()
	}
	for _, id := range c.AllowedGroupIDs {
		if !uuid.MatchString(id) {
			return bad()
		}
	}
	if len(c.AllowedGroupIDs) > 1 || c.Precedence != 0 || c.PolicyName != b.Name {
		return bad()
	}
	if !token.MatchString(c.ObservationReferenceID) || !token.MatchString(c.MutationReferenceID) || c.ObservationReferenceID == c.MutationReferenceID {
		return bad()
	}
	seen := map[string]bool{}
	if len(b.SourceRunIDs) != len(BootstrapNeeds(c.Action)) {
		return bad()
	}
	for _, id := range b.SourceRunIDs {
		if !token.MatchString(id) || seen[id] {
			return bad()
		}
		seen[id] = true
	}
	return nil
}
func ValidateBootstrapPolicy(p generated.IngressBootstrapPolicy) error {
	c := p.Change
	if ValidateBootstrap(c) != nil || c.Action != "bootstrap-tunnel" || c.TunnelID != "" || c.AccessAppID != "" || c.AccessPolicyID != "" || len(c.AllowedGroupIDs) != 0 || c.Connectors[0].ConnectorID != "" || p.ControllerHostID != c.Connectors[0].HostID || p.ControllerIdentityDigest != c.Connectors[0].IdentityDigest || !token.MatchString(p.ControllerInstanceID) || !digest.MatchString(p.ControllerMachineIDDigest) || p.RecoveryEpoch < 0 {
		return Error(generated.ErrorCodeInputInvalid)
	}
	return nil
}
func ValidateBootstrapChange(p generated.IngressBootstrapPolicy, c generated.IngressChange, epoch int64) error {
	if ValidateBootstrapPolicy(p) != nil || ValidateBootstrap(c) != nil || epoch != p.RecoveryEpoch || BootstrapScopeDigest(c) != BootstrapScopeDigest(p.Change) {
		return Error(generated.ErrorCodeAuthorizationDenied)
	}
	return nil
}
