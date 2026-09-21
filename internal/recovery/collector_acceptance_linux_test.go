//go:build linux

package recovery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter/recoverydenial"
)

type isolatedCollectorAdapter struct{ verifier isolatedDirectVerifier }

func (adapter isolatedCollectorAdapter) Probe(ctx context.Context, challenge recoverydenial.Challenge) (recoverydenial.Result, error) {
	requirement := BoundaryRequirement{Kind: challenge.Kind, SubjectID: challenge.SubjectID, TargetID: challenge.TargetID, AdapterID: challenge.AdapterID, FormerIdentityID: challenge.FormerIdentityID, ProbeID: challenge.ProbeID}
	proof, err := adapter.verifier.probe(ctx, requirement, challenge.ChallengeID)
	if err != nil {
		return recoverydenial.Result{}, err
	}
	return recoverydenial.Result{ChallengeID: proof.ChallengeID, Kind: challenge.Kind, SubjectID: challenge.SubjectID, TargetID: proof.Requirement.TargetID, AdapterID: challenge.AdapterID, FormerIdentityID: proof.Requirement.FormerIdentityID, ProbeID: proof.Requirement.ProbeID, ObserverID: proof.ObserverID, ResponseClass: proof.ResponseClass, ResponseDigest: proof.ResponseDigest, ObservedAt: proof.ObservedAt, ExpiresAt: proof.ExpiresAt, SessionExpiry: proof.SessionExpiry, Denied: proof.Denied}, nil
}

func TestCollectWitnessAgainstDisposableOldIdentityEndpoints(t *testing.T) {
	endpoint := &isolatedDenialEndpoint{admitted: map[string]bool{}}
	server := httptest.NewServer(endpoint)
	defer server.Close()
	now := time.Now().UTC()
	verifier := isolatedDirectVerifier{url: server.URL, client: &http.Client{Timeout: 2 * time.Second}, now: now}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pin, binding, _, _ := witnessFixture(t)
	pin.PublicKey, pin.ExpiresAt = public, now.Add(time.Minute)
	pin.pinSeal = pin.seal()
	required, _, _, _ := boundaryFixture()
	for i := range required {
		required[i].AdapterID = "isolated-http-v1"
	}
	collect := func() (SignedWitness, ProtectedEnvelope, error) {
		return CollectWitness(context.Background(), CollectRequest{
			Pin: pin, Binding: binding, Required: required,
			Adapters:   map[string]recoverydenial.Adapter{"isolated-http-v1": isolatedCollectorAdapter{verifier: verifier}},
			SigningKey: io.NopCloser(bytes.NewReader(private.Seed())),
			Material:   io.NopCloser(bytes.NewReader([]byte("synthetic-custodian-private-canary"))), Now: func() time.Time { return now },
		})
	}
	signed, sealed, err := collect()
	if err != nil || len(signed.Payload.Transcripts) != len(required) || sealed.ReceiptID != binding.ReceiptID {
		t.Fatalf("real endpoint collection failed: %v", err)
	}
	artifact, err := EncodeSignedWitness(signed)
	if err != nil || bytes.Contains(artifact, []byte("synthetic-custodian-private-canary")) {
		t.Fatal("public artifact invalid or private material leaked")
	}
	qualified := NewQualifiedAdapters()
	qualified.Register("isolated-http-v1", verifier)
	if err := VerifyWitnessBundle(context.Background(), pin, binding, signed, required, qualified, now); err != nil {
		t.Fatal(err)
	}
	for _, probe := range []string{"alternate-process-denied", "reenrollment-denied", "open-session-denied", "cached-material-denied", "outstanding-session-denied", "retained-alteration-denied", "export-denied"} {
		endpoint.mu.Lock()
		endpoint.admitted[probe] = true
		endpoint.mu.Unlock()
		if _, _, err := collect(); err == nil {
			t.Fatalf("old identity admitted for %s", probe)
		}
		endpoint.mu.Lock()
		delete(endpoint.admitted, probe)
		endpoint.mu.Unlock()
	}
}
