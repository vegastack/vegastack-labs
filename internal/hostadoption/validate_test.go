package hostadoption

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"testing"
	"time"
)

func registrationFixture(t *testing.T) (generated.HostAdoptionRequest, generated.HostObservation, generated.HostDiscoveryTarget, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	target := generated.HostDiscoveryTarget{TargetID: "synthetic-target", Revision: 1, ExpectedOS: "debian", ExpectedVersion: "13", ExpectedArchitecture: "amd64", ProfileID: "debian-13-amd64"}
	facts := []generated.HostDiscoveryFact{}
	for _, v := range []struct{ n, v, o string }{{"os.id", "debian", "os-release"}, {"os.version", "13", "os-release"}, {"architecture", "amd64", "architecture"}, {"product-serial", "synthetic-serial", "product-serial"}} {
		f := hostdiscovery.Fact(v.n, v.v, v.o)
		f.CapturedAt = now.Format(time.RFC3339)
		facts = append(facts, f)
	}
	obs := generated.HostObservation{Schema: generated.SchemaIDHostObservation, SchemaVersion: "1.0.0", ObservationID: "synthetic-observation", TargetID: target.TargetID, TargetRevision: 1, TargetDigest: hostdiscovery.Digest("target"), Collector: hostdiscovery.CollectorID, CollectorVersion: "1.0.0", ObservedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(15 * time.Minute).Format(time.RFC3339), Status: "incomplete", Facts: facts, Blockers: []string{"hardening-unverified", "role-admission-unverified", "identity-class-unverified"}}
	obs.ContentDigest = hostdiscovery.Digest(obs)
	req := generated.HostAdoptionRequest{Schema: generated.SchemaIDHostAdoptionRequest, SchemaVersion: "1.0.0", HostID: "synthetic-host", ObservationID: obs.ObservationID, ObservationDigest: obs.ContentDigest, IdempotencyKey: "registration-one", Confirmation: generated.HostIdentityConfirmation{Schema: generated.SchemaIDHostIdentityConfirmation, SchemaVersion: "1.0.0", TargetRevision: 1, TargetDigest: obs.TargetDigest, IdentityClass: "physical", IdentityKind: "product-serial", IdentityDigest: IdentityDigest("product-serial", "synthetic-serial"), ConfirmedAt: now.Format(time.RFC3339)}}
	return req, obs, target, now
}
func TestRegistrationKeepsHardeningSeparate(t *testing.T) {
	r, o, b, n := registrationFixture(t)
	if err := Validate(r, o, b, n); err != nil {
		t.Fatal(err)
	}
	r.Confirmation.TargetRevision++

	if Validate(r, o, b, n) == nil {
		t.Fatal("changed target accepted")
	}
}
func TestRegistrationRejectsInvalidIdentity(t *testing.T) {
	for _, name := range []string{"digest", "stale", "future", "missing", "conflict", "os", "profile", "observation"} {
		t.Run(name, func(t *testing.T) {
			r, o, b, n := registrationFixture(t)
			switch name {
			case "digest":
				r.Confirmation.IdentityDigest = hostdiscovery.Digest("wrong")
			case "stale":
				n = n.Add(time.Hour)
			case "future":
				r.Confirmation.ConfirmedAt = n.Add(time.Minute).Format(time.RFC3339)
			case "missing":
				o.Facts = o.Facts[:3]
			case "conflict":
				o.Blockers = append(o.Blockers, "identity-conflict")
			case "os":
				b.ExpectedOS = "ubuntu"
			case "profile":
				b.ProfileID = "macos"
			case "observation":
				r.ObservationDigest = hostdiscovery.Digest("wrong")
			}
			if name == "missing" || name == "conflict" {
				o.ContentDigest = ""
				o.ContentDigest = hostdiscovery.Digest(o)
				r.ObservationDigest = o.ContentDigest
			}
			if Validate(r, o, b, n) == nil {
				t.Fatal("invalid registration accepted")
			}
		})
	}
}

func TestRegistrationQualifiedVirtualAndPointVersion(t *testing.T) {
	r, o, b, n := registrationFixture(t)
	r.Confirmation.IdentityClass = "qualified-virtual"
	r.Confirmation.IdentityKind = "product-uuid"
	o.Facts[3].Name = "product-uuid"
	o.Facts[3].Operation = "product-uuid"
	o.Facts[3].Value = "synthetic-uuid"
	r.Confirmation.IdentityDigest = IdentityDigest("product-uuid", "synthetic-uuid")
	o.ContentDigest = ""
	o.ContentDigest = hostdiscovery.Digest(o)
	r.ObservationDigest = o.ContentDigest
	if err := Validate(r, o, b, n); err != nil {
		t.Fatal(err)
	}
	b.ExpectedVersion = "13.6"
	if Validate(r, o, b, n) == nil {
		t.Fatal("missing exact point version accepted")
	}
	f := hostdiscovery.Fact("os.point-version", "13.6", "debian-version")
	f.CapturedAt = n.Format(time.RFC3339)
	o.Facts = append(o.Facts, f)
	o.ContentDigest = ""
	o.ContentDigest = hostdiscovery.Digest(o)
	r.ObservationDigest = o.ContentDigest
	if err := Validate(r, o, b, n); err != nil {
		t.Fatal(err)
	}
}
