package networkingress

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestControllerReadPilotExactScope(t *testing.T) {
	c := generated.IngressChange{Schema: generated.SchemaIDIngressChange, SchemaVersion: "1.0.0", ProfileID: "pilot", AccountID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ZoneID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", TunnelID: "11111111-1111-4111-8111-111111111111", AccessAppID: "22222222-2222-4222-8222-222222222222", AccessPolicyID: "33333333-3333-4333-8333-333333333333", DNSRecordID: "cccccccccccccccccccccccccccccccc", OwnerID: "human-a", DeviceID: "device-a", BeforeDigest: Digest("before"), Hostname: "controller.example", OriginService: "https://10.0.0.7:8443", OriginServerName: "controller.example", OriginIdentityDigest: Digest("certificate"), ObservationReferenceID: "reader", MutationReferenceID: "writer", ReplacementReferenceID: "replacement", AllowedGroupIDs: []string{"33333333-3333-4333-8333-333333333333"}, PolicyName: "pilot", Connectors: []generated.IngressConnectorTarget{{Schema: generated.SchemaIDIngressConnectorTarget, SchemaVersion: "1.0.0", ConnectorID: "44444444-4444-4444-8444-444444444444", HostID: "controller-a", IdentityDigest: Digest("controller")}}}
	c.ConnectorID = c.Connectors[0].ConnectorID
	c.Action, c.ResourceKind, c.ResourceID = "import", "tunnel-configuration", c.TunnelID
	p := generated.IngressControllerReadPilot{Schema: generated.SchemaIDIngressControllerReadPilot, SchemaVersion: "1.0.0", Change: c, ControllerHostID: c.Connectors[0].HostID, ControllerIdentityDigest: c.Connectors[0].IdentityDigest, ControllerMachineIDDigest: Digest("machine"), ControllerInstanceID: "instance-a", IdentityBindingDigest: Digest("binding"), IdentityProfileDigest: Digest("identity"), RecoveryEpoch: 0}
	p.IdentityBinding = generated.BrowserIdentityBindingChange{Schema: generated.SchemaIDBrowserIdentityBindingChange, SchemaVersion: "1.0.0", Action: "bind", Method: identity.CloudflareAccessMethod, Issuer: "https://synthetic.cloudflareaccess.com", Subject: "subject-a", Audiences: []string{"aud-a"}}
	p.IdentityBindingDigest, _ = identity.BindingDigest(identity.VerifiedIdentity{Method: p.IdentityBinding.Method, Issuer: p.IdentityBinding.Issuer, Subject: p.IdentityBinding.Subject, Audiences: p.IdentityBinding.Audiences, IssuedAt: time.Unix(1, 0), ExpiresAt: time.Unix(2, 0)})
	raw, _ := json.Marshal(p)
	if err := generated.ValidateContractJSON(generated.SchemaIDIngressControllerReadPilot, raw, generated.ContractExact); err != nil {
		t.Fatal(err, string(raw))
	}
	if err := ValidatePilot(p); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePilotChange(p, c, 0); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*generated.IngressChange){
		"hostname":   func(q *generated.IngressChange) { q.Hostname = "other.example" },
		"owner":      func(q *generated.IngressChange) { q.OwnerID = "other-human" },
		"credential": func(q *generated.IngressChange) { q.ObservationReferenceID = "other-reference" },
		"connector":  func(q *generated.IngressChange) { q.Connectors = append(q.Connectors, q.Connectors[0]) },
		"policy write": func(q *generated.IngressChange) {
			q.ResourceKind, q.ResourceID, q.Action, q.ExpectedOwnershipRevision = "access-policy", q.AccessPolicyID, "access-policy-update", 1
		},
		"token import": func(q *generated.IngressChange) { q.ResourceKind, q.ResourceID = "tunnel-token", q.TunnelID },
		"rotation": func(q *generated.IngressChange) {
			q.Action, q.ResourceKind, q.ResourceID = "token-rotate", "tunnel-token", q.TunnelID
		},
	} {
		t.Run(name, func(t *testing.T) {
			q := c
			mutate(&q)
			if ValidatePilotChange(p, q, 0) == nil {
				t.Fatal("pilot accepted foreign or broad scope")
			}
		})
	}
	if ValidatePilotChange(p, c, 1) == nil {
		t.Fatal("stale epoch accepted")
	}
}
