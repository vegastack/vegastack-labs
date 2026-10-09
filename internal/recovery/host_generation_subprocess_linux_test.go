//go:build linux

package recovery

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter/recoverydenial"
)

// Invoked only by the API integration test binary. All external responses are
// synthetic; the signed qualification, TLS client, and receipt verifier are real.
func TestHostGenerationFenceSubprocess(t *testing.T) {
	if os.Getenv("VSK_TEST_FENCE_CHILD") != "1" {
		t.Skip("finite API integration helper")
	}
	in := json.NewDecoder(io.LimitReader(os.Stdin, 262144))
	in.DisallowUnknownFields()
	var request struct {
		Required []BoundaryRequirement
		At       time.Time
	}
	if e := in.Decode(&request); e != nil {
		t.Fatal(e)
	}
	if _, e := HostGenerationRequirementsDigest(request.Required); e != nil {
		t.Fatal(e)
	}
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var c recoverydenial.Challenge
		if r.Method != "POST" || json.NewDecoder(io.LimitReader(r.Body, 65536)).Decode(&c) != nil {
			http.Error(w, "invalid", 400)
			return
		}
		result := recoverydenial.Result{ChallengeID: c.ChallengeID, Kind: c.Kind, SubjectID: c.SubjectID, TargetID: c.TargetID, AdapterID: c.AdapterID, FormerIdentityID: c.FormerIdentityID, ProbeID: c.ProbeID, ObserverID: "fixture-independent-observer", ResponseClass: "direct-denial", ResponseDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ObservedAt: request.At, ExpiresAt: c.Deadline, SessionExpiry: c.Deadline, Denied: true}
		canonical, e := recoverydenial.CanonicalSignedResult(result)
		if e != nil {
			t.Error(e)
			http.Error(w, "invalid", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(recoverydenial.SignedResult{Result: result, Signature: ed25519.Sign(key, canonical)})
	}))
	defer server.Close()
	adapter, e := recoverydenial.NewHTTPSAdapter(recoverydenial.HTTPSConfig{AdapterID: "https-direct-denial-v1", Endpoint: server.URL + "/v1/direct-denial", ObserverID: "fixture-independent-observer", ObserverPublicKey: pub, RootCAPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}, func() time.Time { return request.At })
	if e != nil {
		t.Fatal(e)
	}
	admin, signer, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	payload := QualificationRecord{RecordID: "api-integration-fixture"}
	seen := map[string]bool{}
	for _, r := range request.Required {
		entry := AdapterQualification{AdapterID: r.AdapterID, Kind: r.Kind, SubjectID: r.SubjectID, TargetID: r.TargetID, FormerIdentityID: r.FormerIdentityID, ImplementationDigest: recoverydenial.HTTPSImplementationDigest, ValidFrom: request.At, ExpiresAt: request.At.Add(time.Minute)}
		k := qualificationKey(entry)
		if !seen[k] {
			payload.Entries = append(payload.Entries, entry)
			seen[k] = true
		}
	}
	sort.Slice(payload.Entries, func(i, j int) bool {
		return qualificationKey(payload.Entries[i]) < qualificationKey(payload.Entries[j])
	})
	canonical, e := CanonicalQualificationRecord(payload)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(SignedQualificationRecord{Payload: payload, Signature: ed25519.Sign(signer, canonical)})
	if e != nil {
		t.Fatal(e)
	}
	q, e := parseQualifiedAdapters(raw, admin, request.Required, request.At, map[string]qualifiedFactory{"https-direct-denial-v1": {implementationDigest: recoverydenial.HTTPSImplementationDigest, new: func(AdapterQualification) DirectDenialVerifier {
		return systemDirectDenialVerifier{adapter: adapter, clock: func() time.Time { return request.At }}
	}}})
	if e != nil {
		t.Fatal(e)
	}
	out := json.NewEncoder(os.Stdout)
	if e = out.Encode(struct {
		Digest string
		Expiry time.Time
	}{q.qualificationDigest, q.qualificationExpiry}); e != nil {
		t.Fatal(e)
	}
	var binding HostGenerationFenceBinding
	if e = in.Decode(&binding); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	receipt, e := VerifyHostGenerationFences(ctx, binding, request.Required, q, request.At)
	if e != nil {
		t.Fatal(e)
	}
	if e = out.Encode(receipt); e != nil {
		t.Fatal(e)
	}
}
