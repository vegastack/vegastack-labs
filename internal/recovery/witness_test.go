package recovery

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func witnessFixture(t *testing.T) (PinnedWitness, WitnessBinding, SignedWitness, time.Time) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	binding := WitnessBinding{FormerHostID: "old-host", FormerInstanceID: "old-instance", ReplacementHostID: "new-host", ReplacementInstanceID: "new-instance", DraftID: "draft-1", CiphertextFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", PlanDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", RunID: "run-1", StepID: "step-1", LeaseID: "lease-1", ChallengeID: "challenge-1", ReceiptID: "receipt-1", SourceAdmissionDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", FenceQualificationDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", PriorEpoch: 3, NewEpoch: 4, StateRevision: 9}
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pin := PinnedWitness{KeyID: "witness-key-1", WitnessInstanceID: "outside-instance", PublicKey: public, RecipientKeyID: "recipient-1", RecipientPublicKey: recipient.PublicKey().Bytes(), ManifestDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", AuthenticatedExternally: true, ExpiresAt: now.Add(time.Hour), manifestAuthenticated: true, manifestBinding: binding}
	pin.pinSeal = pin.seal()
	payload := WitnessPayload{Binding: binding, KeyID: pin.KeyID, WitnessInstanceID: pin.WitnessInstanceID, IssuedAt: now.Add(-time.Second), ObservedAt: now.Add(-time.Second), ExpiresAt: now.Add(30 * time.Second)}
	canonical, err := CanonicalWitnessPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	return pin, binding, SignedWitness{Payload: payload, Signature: ed25519.Sign(private, canonical)}, now
}

func TestVerifySignedWitness(t *testing.T) {
	pin, binding, signed, now := witnessFixture(t)
	if err := VerifySignedWitness(context.Background(), pin, binding, signed, now); err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*PinnedWitness, *WitnessBinding, *SignedWitness, *time.Time){
		"bad-signature": func(_ *PinnedWitness, _ *WitnessBinding, s *SignedWitness, _ *time.Time) { s.Signature[0] ^= 1 },
		"changed-draft": func(_ *PinnedWitness, b *WitnessBinding, _ *SignedWitness, _ *time.Time) { b.DraftID = "other" },
		"wrong-host": func(_ *PinnedWitness, b *WitnessBinding, _ *SignedWitness, _ *time.Time) {
			b.ReplacementHostID = "other"
		},
		"wrong-instance": func(_ *PinnedWitness, b *WitnessBinding, _ *SignedWitness, _ *time.Time) {
			b.ReplacementInstanceID = "other"
		},
		"wrong-epoch": func(_ *PinnedWitness, b *WitnessBinding, _ *SignedWitness, _ *time.Time) { b.NewEpoch++ },
		"wrong-plan": func(_ *PinnedWitness, b *WitnessBinding, _ *SignedWitness, _ *time.Time) {
			b.PlanDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		},
		"wrong-lease": func(_ *PinnedWitness, b *WitnessBinding, _ *SignedWitness, _ *time.Time) { b.LeaseID = "other" },
		"replayed-challenge": func(_ *PinnedWitness, b *WitnessBinding, _ *SignedWitness, _ *time.Time) {
			b.ChallengeID = "later-challenge"
		},
		"expired":     func(_ *PinnedWitness, _ *WitnessBinding, _ *SignedWitness, n *time.Time) { *n = n.Add(time.Minute) },
		"revoked":     func(p *PinnedWitness, _ *WitnessBinding, _ *SignedWitness, _ *time.Time) { p.Revoked = true },
		"unknown-key": func(p *PinnedWitness, _ *WitnessBinding, _ *SignedWitness, _ *time.Time) { p.KeyID = "unknown" },
		"untrusted-pin": func(p *PinnedWitness, _ *WitnessBinding, _ *SignedWitness, _ *time.Time) {
			p.AuthenticatedExternally = false
		},
		"old-controller-key": func(p *PinnedWitness, _ *WitnessBinding, _ *SignedWitness, _ *time.Time) {
			p.WitnessInstanceID = "old-instance"
		},
		"replacement-controller-key": func(p *PinnedWitness, _ *WitnessBinding, _ *SignedWitness, _ *time.Time) {
			p.WitnessInstanceID = "new-instance"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			p, b, s, n := pin, binding, signed, now
			s.Signature = append([]byte(nil), signed.Signature...)
			mutate(&p, &b, &s, &n)
			if err := VerifySignedWitness(context.Background(), p, b, s, n); err == nil {
				t.Fatal("invalid witness accepted")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := VerifySignedWitness(ctx, pin, binding, signed, now); err == nil {
		t.Fatal("cancelled witness accepted")
	}
}

func TestVerifySignedWitnessRejectsStaleIssueEvenWithFreshObservation(t *testing.T) {
	pin, binding, signed, now := witnessFixture(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pin.PublicKey = public
	pin.pinSeal = pin.seal()
	signed.Payload.IssuedAt = now.Add(-61 * time.Second)
	canonical, err := CanonicalWitnessPayload(signed.Payload)
	if err != nil {
		t.Fatal(err)
	}
	signed.Signature = ed25519.Sign(private, canonical)
	if err := VerifySignedWitness(context.Background(), pin, binding, signed, now); err == nil {
		t.Fatal("stale signed issuance accepted")
	}
}
