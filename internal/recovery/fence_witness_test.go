package recovery

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

type fixtureDenialVerifier struct{ reject bool }

func (f fixtureDenialVerifier) VerifyDirectDenial(_ context.Context, _ DirectDenialTranscript) error {
	if f.reject {
		return errors.New("probe rejected")
	}
	return nil
}

func boundaryFixture() ([]BoundaryRequirement, WitnessPayload, QualifiedAdapters, time.Time) {
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	specs := []struct{ kind, probe string }{
		{"host-service", "service-denied"}, {"host-service", "alternate-process-denied"},
		{"mesh", "registration-denied"}, {"mesh", "reenrollment-denied"},
		{"ssh", "new-auth-denied"}, {"ssh", "open-session-denied"},
		{"secret-resolver", "resolve-denied"}, {"secret-resolver", "cached-material-denied"},
		{"provider-mutation", "mutation-denied"}, {"provider-mutation", "outstanding-session-denied"},
		{"backup-writer", "new-payload-denied"}, {"backup-writer", "retained-alteration-denied"}, {"backup-writer", "outstanding-session-denied"},
		{"audit-writer", "append-denied"}, {"audit-writer", "export-denied"},
	}
	required := make([]BoundaryRequirement, 0, len(specs))
	payload := WitnessPayload{Binding: WitnessBinding{FormerInstanceID: "old-instance", ReplacementInstanceID: "new-instance", ChallengeID: "challenge-1"}, WitnessInstanceID: "outside-instance", ObservedAt: now.Add(-time.Second), ExpiresAt: now.Add(30 * time.Second)}
	qualified := NewQualifiedAdapters()
	for i, spec := range specs {
		req := BoundaryRequirement{Kind: spec.kind, SubjectID: "subject-1", TargetID: "target-1", AdapterID: "adapter-1", FormerIdentityID: "old-identity", ProbeID: spec.probe}
		required = append(required, req)
		payload.Transcripts = append(payload.Transcripts, DirectDenialTranscript{Requirement: req, ObserverID: "outside-observer", ChallengeID: "challenge-1", ResponseClass: "direct-denial", ResponseDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ObservedAt: now.Add(-time.Second), ExpiresAt: now.Add(20 * time.Second), SessionExpiry: now.Add(20 * time.Second), Denied: true})
		_ = i
	}
	qualified.Register("adapter-1", fixtureDenialVerifier{})
	return required, payload, qualified, now
}

func TestBoundarySetRequiresCompleteDirectDenial(t *testing.T) {
	required, payload, qualified, now := boundaryFixture()
	if err := VerifyBoundarySet(context.Background(), required, payload, qualified, now); err != nil {
		t.Fatal(err)
	}
	for i := range required {
		t.Run(required[i].Kind+"/"+required[i].ProbeID, func(t *testing.T) {
			changed := payload
			changed.Transcripts = append([]DirectDenialTranscript(nil), payload.Transcripts[:i]...)
			changed.Transcripts = append(changed.Transcripts, payload.Transcripts[i+1:]...)
			if err := VerifyBoundarySet(context.Background(), required, changed, qualified, now); err == nil {
				t.Fatal("missing direct denial accepted")
			}
		})
	}
	if err := VerifyBoundarySet(context.Background(), required[:len(required)-1], payload, qualified, now); err == nil {
		t.Fatal("incomplete server-derived probe group accepted")
	}
	tests := map[string]func(*WitnessPayload){
		"same-controller":          func(p *WitnessPayload) { p.Transcripts[0].ObserverID = "old-instance" },
		"former-identity-observer": func(p *WitnessPayload) { p.Transcripts[0].ObserverID = "old-identity" },
		"generic-status":           func(p *WitnessPayload) { p.Transcripts[0].ResponseClass = "stopped" },
		"not-denied":               func(p *WitnessPayload) { p.Transcripts[0].Denied = false },
		"no-response":              func(p *WitnessPayload) { p.Transcripts[0].ResponseDigest = "" },
		"wrong-challenge":          func(p *WitnessPayload) { p.Transcripts[0].ChallengeID = "other" },
		"stale":                    func(p *WitnessPayload) { p.Transcripts[0].ExpiresAt = now.Add(-time.Second) },
		"live-session":             func(p *WitnessPayload) { p.Transcripts[5].Denied = false },
		"mesh-reenrollment":        func(p *WitnessPayload) { p.Transcripts[3].Denied = false },
		"backup-token":             func(p *WitnessPayload) { p.Transcripts[12].Denied = false },
		"unknown-target":           func(p *WitnessPayload) { p.Transcripts[0].Requirement.TargetID = "other" },
		"duplicate":                func(p *WitnessPayload) { p.Transcripts = append(p.Transcripts, p.Transcripts[0]) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := payload
			changed.Transcripts = append([]DirectDenialTranscript(nil), payload.Transcripts...)
			mutate(&changed)
			if err := VerifyBoundarySet(context.Background(), required, changed, qualified, now); err == nil {
				t.Fatal("bad boundary accepted")
			}
		})
	}
	unqualified := NewQualifiedAdapters()
	if err := VerifyBoundarySet(context.Background(), required, payload, unqualified, now); err == nil {
		t.Fatal("unqualified adapter accepted")
	}
	qualified.Register("adapter-1", fixtureDenialVerifier{reject: true})
	if err := VerifyBoundarySet(context.Background(), required, payload, qualified, now); err == nil {
		t.Fatal("adapter rejection accepted")
	}
}

func TestVerifyWitnessBundleRejectsTranscriptChange(t *testing.T) {
	required, payload, qualified, now := boundaryFixture()
	pin, binding, _, _ := witnessFixture(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pin.PublicKey = public
	pin.pinSeal = pin.seal()
	payload.Binding = binding
	payload.KeyID = pin.KeyID
	payload.WitnessInstanceID = pin.WitnessInstanceID
	payload.IssuedAt = now.Add(-time.Second)
	payload.ObservedAt = now.Add(-time.Second)
	payload.ExpiresAt = now.Add(30 * time.Second)
	canonical, err := CanonicalWitnessPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	signed := SignedWitness{Payload: payload, Signature: ed25519.Sign(private, canonical)}
	if err := VerifyWitnessBundle(context.Background(), pin, binding, signed, required, qualified, now); err != nil {
		t.Fatal(err)
	}
	changed := signed
	changed.Payload.Transcripts = append([]DirectDenialTranscript(nil), signed.Payload.Transcripts...)
	changed.Payload.Transcripts[0].ResponseDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := VerifyWitnessBundle(context.Background(), pin, binding, changed, required, qualified, now); err == nil {
		t.Fatal("changed signed transcript accepted")
	}
	changed = signed
	changed.Payload.Transcripts = changed.Payload.Transcripts[:len(changed.Payload.Transcripts)-1]
	if err := VerifyWitnessBundle(context.Background(), pin, binding, changed, required, qualified, now); err == nil {
		t.Fatal("partial signed bundle accepted")
	}
}
