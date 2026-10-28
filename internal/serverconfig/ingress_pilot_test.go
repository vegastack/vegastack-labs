package serverconfig

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	ingress "github.com/vegastack/vegastack-labs/internal/networkingress"
	"testing"
	"time"
)

func pilotFixture() generated.IngressControllerReadPilot {
	c := generated.IngressChange{Schema: generated.SchemaIDIngressChange, SchemaVersion: "1.0.0", ProfileID: "pilot", AccountID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ZoneID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", TunnelID: "11111111-1111-4111-8111-111111111111", AccessAppID: "22222222-2222-4222-8222-222222222222", AccessPolicyID: "33333333-3333-4333-8333-333333333333", DNSRecordID: "cccccccccccccccccccccccccccccccc", OwnerID: "human-a", DeviceID: "device-a", BeforeDigest: ingress.Digest("before"), Hostname: "controller.example", OriginService: "https://10.0.0.7:8443", OriginServerName: "controller.example", OriginIdentityDigest: ingress.Digest("certificate"), ObservationReferenceID: "reader", MutationReferenceID: "writer", ReplacementReferenceID: "replacement", AllowedGroupIDs: []string{"33333333-3333-4333-8333-333333333333"}, PolicyName: "pilot", Connectors: []generated.IngressConnectorTarget{{Schema: generated.SchemaIDIngressConnectorTarget, SchemaVersion: "1.0.0", ConnectorID: "44444444-4444-4444-8444-444444444444", HostID: "controller-a", IdentityDigest: ingress.Digest("controller")}}}
	c.ConnectorID = c.Connectors[0].ConnectorID
	c.Action, c.ResourceKind, c.ResourceID = "import", "tunnel-configuration", c.TunnelID
	p := generated.IngressControllerReadPilot{Schema: generated.SchemaIDIngressControllerReadPilot, SchemaVersion: "1.0.0", Change: c, ControllerHostID: c.Connectors[0].HostID, ControllerIdentityDigest: c.Connectors[0].IdentityDigest, ControllerMachineIDDigest: ingress.Digest("machine"), ControllerInstanceID: "instance-a", IdentityBindingDigest: ingress.Digest("binding"), IdentityProfileDigest: ingress.Digest("identity"), RecoveryEpoch: 0}
	p.IdentityBinding = generated.BrowserIdentityBindingChange{Schema: generated.SchemaIDBrowserIdentityBindingChange, SchemaVersion: "1.0.0", Action: "bind", Method: identity.CloudflareAccessMethod, Issuer: "https://synthetic.cloudflareaccess.com", Subject: "subject-a", Audiences: []string{"aud-a"}}
	p.IdentityBindingDigest, _ = identity.BindingDigest(identity.VerifiedIdentity{Method: p.IdentityBinding.Method, Issuer: p.IdentityBinding.Issuer, Subject: p.IdentityBinding.Subject, Audiences: p.IdentityBinding.Audiences, IssuedAt: time.Unix(1, 0), ExpiresAt: time.Unix(2, 0)})
	return p
}
func TestIngressPilotProfileRequiresPinnedRemoteOriginAndScope(t *testing.T) {
	policy := pilotFixture()
	profile := validGeneratedProfile()
	profile.RemoteRead = enabledRemoteRead()
	profile.RemoteRead.BindAddress = stringPointer("10.0.0.7:8443")
	profile.RemoteRead.PublicOrigin = stringPointer("https://controller.example")
	profile.IngressScopeDigests = []string{ingress.ScopeDigest(policy.Change)}
	profile.IngressControllerReadPilot = &policy
	got, err := convertGeneratedProfile(profile, 1001)
	if err != nil || got.IngressControllerReadPilot == nil {
		t.Fatalf("exact pilot profile rejected: %v", err)
	}
	for name, change := range map[string]func(*generated.ServerProfile){
		"remote disabled": func(p *generated.ServerProfile) { p.RemoteRead = generated.RemoteReadProfile{Enabled: false} },
		"wrong host":      func(p *generated.ServerProfile) { p.RemoteRead.PublicOrigin = stringPointer("https://foreign.example") },
		"wrong origin":    func(p *generated.ServerProfile) { p.RemoteRead.BindAddress = stringPointer("10.0.0.8:8443") },
		"missing scope":   func(p *generated.ServerProfile) { p.IngressScopeDigests = nil },
	} {
		t.Run(name, func(t *testing.T) {
			p := profile
			change(&p)
			if _, err := convertGeneratedProfile(p, 1001); err == nil {
				t.Fatal("unbound pilot configuration accepted")
			}
		})
	}
}
