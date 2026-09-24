package recovery

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"
)

type qualificationTestVerifier struct{}

func (qualificationTestVerifier) VerifyDirectDenial(context.Context, DirectDenialTranscript) error {
	return nil
}

func TestQualificationCannotRegisterFixtureOrIncompleteBoundary(t *testing.T) {
	adminPublic, adminPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	base := BoundaryRequirement{Kind: "host-service", SubjectID: "service-1", TargetID: "former-host", AdapterID: "host-test-adapter", FormerIdentityID: "former-instance"}
	first, second := base, base
	first.ProbeID = "service-denied"
	second.ProbeID = "alternate-process-denied"
	required := []BoundaryRequirement{first, second}
	entry := AdapterQualification{AdapterID: base.AdapterID, Kind: base.Kind, SubjectID: base.SubjectID, TargetID: base.TargetID, FormerIdentityID: base.FormerIdentityID, ImplementationDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ValidFrom: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	payload := QualificationRecord{RecordID: "registration-1", Entries: []AdapterQualification{entry}}
	canonical, err := CanonicalQualificationRecord(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(SignedQualificationRecord{Payload: payload, Signature: ed25519.Sign(adminPrivate, canonical)})
	if err != nil {
		t.Fatal(err)
	}
	factories := map[string]qualifiedFactory{base.AdapterID: {implementationDigest: entry.ImplementationDigest, new: func(AdapterQualification) DirectDenialVerifier { return qualificationTestVerifier{} }}}
	qualified, err := parseQualifiedAdapters(raw, adminPublic, required, now, factories)
	if err != nil {
		t.Fatalf("complete disposable qualification rejected: %v", err)
	}
	if !qualified.sourceQualified || !witnessDigest.MatchString(qualified.qualificationDigest) {
		t.Fatal("authenticated qualification missing")
	}
	qualified.Register("unexpected-adapter", qualificationTestVerifier{})
	if qualified.sourceQualified || qualified.qualificationDigest != "" {
		t.Fatal("registry mutation retained qualification")
	}
	if _, err := parseQualifiedAdapters(raw, adminPublic, required[:1], now, factories); err == nil {
		t.Fatal("partial boundary admitted")
	}
	if _, err := parseQualifiedAdapters(raw, adminPublic, required, now, productionDenialFactories); err == nil {
		t.Fatal("fixture factory admitted as production")
	}
	if factory := productionDenialFactories["https-direct-denial-v1"]; len(productionDenialFactories) != 1 || factory.new == nil || factory.implementationDigest == "" {
		t.Fatal("reviewed production protocol factory missing")
	}
	wrongRoot, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseQualifiedAdapters(raw, wrongRoot, required, now, factories); err == nil {
		t.Fatal("wrong root admitted")
	}
	if _, err := parseQualifiedAdapters(raw, adminPublic, required, now.Add(2*time.Hour), factories); err == nil {
		t.Fatal("expired registration admitted")
	}
	wrongDigestFactories := map[string]qualifiedFactory{base.AdapterID: {implementationDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", new: factories[base.AdapterID].new}}
	if _, err := parseQualifiedAdapters(raw, adminPublic, required, now, wrongDigestFactories); err == nil {
		t.Fatal("wrong implementation admitted")
	}
}
