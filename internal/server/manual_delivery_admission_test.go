package server

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostingplatform"
	"github.com/vegastack/vegastack-labs/internal/store"
	"testing"
)

func manualDeliveryFixture(t *testing.T) (store.HostAdmissionSnapshot, store.GateAppliedProfile, string) {
	t.Helper()
	cap := manualHostingCapability(generated.HostingLifecycleProfile{TargetID: "hosting-a", BindingID: "binding-a", ConfigurationDigest: hostaction.Digest("configuration")})
	p := store.GateAppliedProfile{ProfileID: "vegastack-labs", ProfileVersion: "1.0.0", PolicyID: "labs-working-manual", PolicyVersion: "1.0.0", Capabilities: []string{cap}, StateRevision: 4, RecoveryEpoch: 2}
	s := store.HostAdmissionSnapshot{Host: generated.ManagedHost{HostID: "host-a", TargetID: "target-a", IdentityClass: "physical", Status: "adopted-unadmitted", RecoveryEpoch: 2}, IdentityDigest: hostaction.Digest("machine"), Revision: store.RevisionToken{StateRevision: 5, RecoveryEpoch: 2}, AppliedProfile: &p, AppliedProfileDigest: hostaction.Digest(p), Blockers: []string{"host-control-missing"}}
	return s, p, cap
}
func TestManualDeliveryExactScope(t *testing.T) {
	s, p, cap := manualDeliveryFixture(t)
	if e := evaluateManualDeliveryHost(s, p, "host-a", s.IdentityDigest, 2, cap); e != nil {
		t.Fatal(e)
	}
	for name, mutate := range map[string]func(*store.HostAdmissionSnapshot){
		"identity":           func(s *store.HostAdmissionSnapshot) { s.IdentityDigest = hostaction.Digest("other") },
		"epoch":              func(s *store.HostAdmissionSnapshot) { s.Revision.RecoveryEpoch++ },
		"hostepoch":          func(s *store.HostAdmissionSnapshot) { s.Host.RecoveryEpoch++ },
		"status":             func(s *store.HostAdmissionSnapshot) { s.Host.Status = "quarantined" },
		"protected":          func(s *store.HostAdmissionSnapshot) { s.Host.HostID = "vsk-node-04" },
		"missingtarget":      func(s *store.HostAdmissionSnapshot) { s.Host.TargetID = "" },
		"bindingchanged":     func(s *store.HostAdmissionSnapshot) { s.Blockers = []string{"host-binding-changed"} },
		"rolebindingchanged": func(s *store.HostAdmissionSnapshot) { s.RoleBlockers = []string{"host-binding-changed"} },
		"profiledigest":      func(s *store.HostAdmissionSnapshot) { s.AppliedProfileDigest = hostaction.Digest("other") },
		"futureprofile":      func(s *store.HostAdmissionSnapshot) { s.Revision.StateRevision = 3 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := s
			mutate(&changed)
			if evaluateManualDeliveryHost(changed, p, "host-a", s.IdentityDigest, 2, cap) == nil {
				t.Fatal("changed binding accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*store.GateAppliedProfile){"revoked": func(p *store.GateAppliedProfile) { p.Capabilities = nil }, "version": func(p *store.GateAppliedProfile) { p.PolicyVersion = "2.0.0" }, "profile": func(p *store.GateAppliedProfile) { p.ProfileID = "other" }} {
		t.Run(name, func(t *testing.T) {
			q := p
			mutate(&q)
			if evaluateManualDeliveryHost(s, q, "host-a", s.IdentityDigest, 2, cap) == nil {
				t.Fatal("changed policy accepted")
			}
		})
	}
}
func TestManualDeliveryScopeDigestChanges(t *testing.T) {
	a := generated.HostingLifecycleProfile{BindingID: "scope-a", TargetID: "hosting-a", ConfigurationDigest: hostaction.Digest("original")}
	b := a
	b.ConfigurationDigest = hostaction.Digest("changed")
	if manualHostingCapability(a) == manualHostingCapability(b) {
		t.Fatal("hosting configuration not bound")
	}
	sb := generated.ServiceProviderBinding{ServiceID: "app-a", HostID: "host-a", HostIdentityDigest: hostaction.Digest("machine")}
	db := generated.ServiceDeploymentProviderBinding{Artifacts: []generated.ServiceDeploymentArtifactSource{{ArtifactID: "image-a", Digest: hostaction.Digest("image")}}}
	before := manualServiceCapability(sb, db)
	db.Artifacts[0].Digest = hostaction.Digest("other")
	if before == manualServiceCapability(sb, db) {
		t.Fatal("artifact not bound")
	}
}

func TestManualDeliveryPlatformTargetSet(t *testing.T) {
	identity := hostaction.Digest("control-machine")
	valid := hostingConfiguration{Targets: []hostingTarget{{HostID: "control-a", IdentityDigest: identity, Role: "control"}, {HostID: "app-a", IdentityDigest: hostaction.Digest("app-machine"), Role: "application"}}, Platform: &hostingplatform.Input{HostID: "control-a", HostIdentityDigest: identity}}
	if err := validateHostingPlatformTarget(valid); err != nil {
		t.Fatal(err)
	}
	if err := validateHostingPlatformTarget(hostingConfiguration{}); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*hostingConfiguration){
		"omitted":  func(c *hostingConfiguration) { c.Targets = c.Targets[1:] },
		"unlisted": func(c *hostingConfiguration) { c.Platform.HostID = "other" },
		"identity": func(c *hostingConfiguration) { c.Platform.HostIdentityDigest = hostaction.Digest("other") },
		"role":     func(c *hostingConfiguration) { c.Targets[0].Role = "application" },
	} {
		t.Run(name, func(t *testing.T) {
			c := valid
			c.Targets = append([]hostingTarget(nil), valid.Targets...)
			platform := *valid.Platform
			c.Platform = &platform
			change(&c)
			if validateHostingPlatformTarget(c) == nil {
				t.Fatal("invalid platform binding accepted")
			}
		})
	}
}
