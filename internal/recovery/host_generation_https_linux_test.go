//go:build linux

package recovery

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"github.com/vegastack/vegastack-labs/internal/adapter/recoverydenial"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Only the external endpoint and installed qualification bytes are fixtures;
// TLS, signed protocol responses, sealed registry and live verifier are real.
func TestHostGenerationUsesQualifiedSignedHTTPSEndpoint(t *testing.T) {
	b, required, _, at := hostFenceFixture()
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	probes := 0
	wrong := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var c recoverydenial.Challenge
		if r.Method != "POST" || json.NewDecoder(r.Body).Decode(&c) != nil {
			http.Error(w, "invalid", 400)
			return
		}
		probes++
		response := recoverydenial.Result{ChallengeID: c.ChallengeID, Kind: c.Kind, SubjectID: c.SubjectID, TargetID: c.TargetID, AdapterID: c.AdapterID, FormerIdentityID: c.FormerIdentityID, ProbeID: c.ProbeID, ObserverID: "independent-consumer", ResponseClass: "direct-denial", ResponseDigest: b.PlanDigest, ObservedAt: at, ExpiresAt: c.Deadline, SessionExpiry: c.Deadline, Denied: true}
		if wrong {
			response.TargetID = "other"
		}
		canonical, e := recoverydenial.CanonicalSignedResult(response)
		if e != nil {
			t.Error(e)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(recoverydenial.SignedResult{Result: response, Signature: ed25519.Sign(private, canonical)})
	}))
	defer server.Close()
	for i := range required {
		required[i].AdapterID = "https-direct-denial-v1"
	}
	b.RequirementsDigest, _ = HostGenerationRequirementsDigest(required)
	adapter, e := recoverydenial.NewHTTPSAdapter(recoverydenial.HTTPSConfig{AdapterID: "https-direct-denial-v1", Endpoint: server.URL + "/v1/direct-denial", ObserverID: "independent-consumer", ObserverPublicKey: public, RootCAPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}, func() time.Time { return at })
	if e != nil {
		t.Fatal(e)
	}
	admin, signer, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	r := required[0]
	entry := AdapterQualification{AdapterID: r.AdapterID, Kind: r.Kind, SubjectID: r.SubjectID, TargetID: r.TargetID, FormerIdentityID: r.FormerIdentityID, ImplementationDigest: recoverydenial.HTTPSImplementationDigest, ValidFrom: at, ExpiresAt: b.Deadline}
	payload := QualificationRecord{RecordID: "installed-fixture", Entries: []AdapterQualification{entry}}
	canonical, e := CanonicalQualificationRecord(payload)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(SignedQualificationRecord{Payload: payload, Signature: ed25519.Sign(signer, canonical)})
	q, e := parseQualifiedAdapters(raw, admin, required, at, map[string]qualifiedFactory{r.AdapterID: {implementationDigest: entry.ImplementationDigest, new: func(AdapterQualification) DirectDenialVerifier {
		return systemDirectDenialVerifier{adapter: adapter, clock: func() time.Time { return at }}
	}}})
	if e != nil {
		t.Fatal(e)
	}
	b.QualificationDigest = q.qualificationDigest
	receipt, e := VerifyHostGenerationFences(context.Background(), b, required, q, at)
	if e != nil || len(receipt.Transcripts) != 2 || probes != 2 {
		t.Fatalf("%+v calls %d: %v", receipt, probes, e)
	}
	wrong = true
	if _, e = VerifyHostGenerationFences(context.Background(), b, required, q, at); e == nil {
		t.Fatal("signed response for different consumer accepted")
	}
}
