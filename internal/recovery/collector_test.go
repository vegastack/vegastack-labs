package recovery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter/recoverydenial"
)

type collectorAdapter struct{ now time.Time }

func (adapter collectorAdapter) Probe(_ context.Context, challenge recoverydenial.Challenge) (recoverydenial.Result, error) {
	return recoverydenial.Result{ChallengeID: challenge.ChallengeID, Kind: challenge.Kind, SubjectID: challenge.SubjectID, TargetID: challenge.TargetID, AdapterID: challenge.AdapterID, FormerIdentityID: challenge.FormerIdentityID, ProbeID: challenge.ProbeID, ObserverID: "outside-observer", ResponseClass: "direct-denial", ResponseDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ObservedAt: adapter.now, ExpiresAt: adapter.now.Add(20 * time.Second), SessionExpiry: adapter.now.Add(20 * time.Second), Denied: true}, nil
}

func TestCollectWitnessSignsExactBundleAndSealsCustody(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pin, binding, _, now := witnessFixture(t)
	pin.PublicKey = public
	required, _, _, _ := boundaryFixture()
	pin.Requirements = append([]BoundaryRequirement(nil), required...)
	pin.pinSeal = pin.seal()
	request := CollectRequest{Pin: pin, Binding: binding, Required: required, Adapters: map[string]recoverydenial.Adapter{"adapter-1": collectorAdapter{now: now}}, SigningKey: io.NopCloser(bytes.NewReader(private.Seed())), Material: io.NopCloser(bytes.NewReader([]byte("synthetic-private-canary"))), Now: func() time.Time { return now }}
	signed, sealed, err := CollectWitness(context.Background(), request)
	if err != nil || sealed.ReceiptID != binding.ReceiptID || signed.Payload.Binding != binding {
		t.Fatalf("collection failed: %v", err)
	}
	qualified := NewQualifiedAdapters()
	qualified.Register("adapter-1", fixtureDenialVerifier{})
	if err := VerifyWitnessBundle(context.Background(), pin, binding, signed, required, qualified, now); err != nil {
		t.Fatal(err)
	}
	bad := request
	bad.SigningKey = io.NopCloser(bytes.NewReader(make([]byte, 32)))
	bad.Material = io.NopCloser(bytes.NewReader([]byte("synthetic-private-canary")))
	if _, _, err := CollectWitness(context.Background(), bad); err == nil {
		t.Fatal("foreign signing key accepted")
	}
	// Ordinary caller input cannot suppress an authenticated boundary group.
	bad = request
	bad.Required = append([]BoundaryRequirement(nil), required[:len(required)-2]...)
	bad.SigningKey = io.NopCloser(bytes.NewReader(private.Seed()))
	bad.Material = io.NopCloser(bytes.NewReader([]byte("synthetic-private-canary")))
	if _, _, err := CollectWitness(context.Background(), bad); err == nil {
		t.Fatal("omitted signed boundary accepted")
	}
}
