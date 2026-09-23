//go:build linux

package recovery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// This disposable endpoint proves that a typed verifier really performs a
// fresh operation under an old synthetic identity. It does not qualify a
// provider, Mesh, SSH, host, backup, resolver or audit production adapter.
type isolatedDenialEndpoint struct {
	mu       sync.Mutex
	admitted map[string]bool
}
type isolatedProbe struct{ ChallengeID, TargetID, FormerIdentityID, ProbeID string }
type isolatedResponse struct{ ChallengeID, ProbeID, Class string }

func (e *isolatedDenialEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/probe" || r.Header.Get("X-Synthetic-Old-Identity") != "old-token" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1024))
	if err != nil {
		return
	}
	var input isolatedProbe
	if json.Unmarshal(raw, &input) != nil || input.FormerIdentityID != "old-identity" || input.ChallengeID == "" || input.ProbeID == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	e.mu.Lock()
	admitted := e.admitted[input.ProbeID]
	e.mu.Unlock()
	result := isolatedResponse{ChallengeID: input.ChallengeID, ProbeID: input.ProbeID, Class: "direct-denial"}
	if admitted {
		result.Class = "admitted"
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusForbidden)
	}
	_ = json.NewEncoder(w).Encode(result)
}

type isolatedDirectVerifier struct {
	url    string
	client *http.Client
	now    time.Time
}

func (v isolatedDirectVerifier) probe(ctx context.Context, requirement BoundaryRequirement, challengeID string) (DirectDenialTranscript, error) {
	requestBody, _ := json.Marshal(isolatedProbe{ChallengeID: challengeID, TargetID: requirement.TargetID, FormerIdentityID: requirement.FormerIdentityID, ProbeID: requirement.ProbeID})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, v.url+"/probe", bytes.NewReader(requestBody))
	if err != nil {
		return DirectDenialTranscript{}, err
	}
	request.Header.Set("X-Synthetic-Old-Identity", "old-token")
	response, err := v.client.Do(request)
	if err != nil {
		return DirectDenialTranscript{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1024))
	if err != nil {
		return DirectDenialTranscript{}, err
	}
	var decoded isolatedResponse
	if json.Unmarshal(body, &decoded) != nil || decoded.ChallengeID != challengeID || decoded.ProbeID != requirement.ProbeID {
		return DirectDenialTranscript{}, ErrWitnessUnavailable
	}
	sum := sha256.Sum256(body)
	return DirectDenialTranscript{Requirement: requirement, ObserverID: "outside-observer", ChallengeID: challengeID, ResponseClass: decoded.Class, ResponseDigest: "sha256:" + hex.EncodeToString(sum[:]), ObservedAt: v.now.Add(-time.Second), ExpiresAt: v.now.Add(20 * time.Second), SessionExpiry: v.now.Add(20 * time.Second), Denied: response.StatusCode == http.StatusForbidden}, nil
}
func (v isolatedDirectVerifier) VerifyDirectDenial(ctx context.Context, transcript DirectDenialTranscript) error {
	live, err := v.probe(ctx, transcript.Requirement, transcript.ChallengeID)
	if err != nil || !live.Denied || live.ResponseDigest != transcript.ResponseDigest || live.ResponseClass != transcript.ResponseClass {
		return ErrWitnessUnavailable
	}
	return nil
}

func TestWitnessAcceptanceActuallyProbesIsolatedOldIdentity(t *testing.T) {
	endpoint := &isolatedDenialEndpoint{admitted: map[string]bool{}}
	server := httptest.NewServer(endpoint)
	defer server.Close()
	now := time.Now().UTC()
	verifier := isolatedDirectVerifier{url: server.URL, client: &http.Client{Timeout: 2 * time.Second}, now: now}
	required, payload, _, _ := boundaryFixture()
	pin, binding, _, _ := witnessFixture(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pin.PublicKey = public
	pin.ExpiresAt = now.Add(time.Hour)
	pin.pinSeal = pin.seal()
	payload.Binding = binding
	payload.KeyID = pin.KeyID
	payload.WitnessInstanceID = pin.WitnessInstanceID
	payload.IssuedAt = now.Add(-time.Second)
	payload.ObservedAt = now.Add(-time.Second)
	payload.ExpiresAt = now.Add(20 * time.Second)
	for i := range required {
		required[i].AdapterID = "isolated-http-v1"
		proof, err := verifier.probe(context.Background(), required[i], binding.ChallengeID)
		if err != nil {
			t.Fatal(err)
		}
		payload.Transcripts[i] = proof
	}
	canonical, err := CanonicalWitnessPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	signed := SignedWitness{Payload: payload, Signature: ed25519.Sign(private, canonical)}
	qualified := NewQualifiedAdapters()
	qualified.Register("isolated-http-v1", verifier)
	if err := VerifyWitnessBundle(context.Background(), pin, binding, signed, required, qualified, now); err != nil {
		t.Fatal(err)
	}
	endpoint.mu.Lock()
	endpoint.admitted["reenrollment-denied"] = true
	endpoint.mu.Unlock()
	if err := VerifyWitnessBundle(context.Background(), pin, binding, signed, required, qualified, now); err == nil {
		t.Fatal("live old Mesh reenrollment path accepted")
	}
	endpoint.mu.Lock()
	delete(endpoint.admitted, "reenrollment-denied")
	endpoint.mu.Unlock()
	partial := signed
	partial.Payload.Transcripts = append([]DirectDenialTranscript(nil), signed.Payload.Transcripts[:len(signed.Payload.Transcripts)-1]...)
	if err := VerifyWitnessBundle(context.Background(), pin, binding, partial, required, qualified, now); err == nil {
		t.Fatal("partial old-writer denial set accepted")
	}
}
