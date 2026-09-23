package recoverydenial

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPSAdapterReprobesExactSignedDirectDenial(t *testing.T) {
	now := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/direct-denial" {
			http.Error(writer, "bad request", http.StatusBadRequest)
			return
		}
		var challenge Challenge
		if json.NewDecoder(request.Body).Decode(&challenge) != nil {
			http.Error(writer, "bad request", http.StatusBadRequest)
			return
		}
		result := Result{ChallengeID: challenge.ChallengeID, Kind: challenge.Kind, SubjectID: challenge.SubjectID, TargetID: challenge.TargetID, AdapterID: challenge.AdapterID, FormerIdentityID: challenge.FormerIdentityID, ProbeID: challenge.ProbeID, ObserverID: "independent-custodian", ResponseClass: "direct-denial", ResponseDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ObservedAt: now, ExpiresAt: now.Add(10 * time.Second), SessionExpiry: now.Add(10 * time.Second), Denied: true}
		canonical, _ := CanonicalSignedResult(result)
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(SignedResult{Result: result, Signature: ed25519.Sign(private, canonical)})
	}))
	defer server.Close()
	root := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	adapter, err := NewHTTPSAdapter(HTTPSConfig{AdapterID: "https-direct-denial-v1", Endpoint: server.URL + "/v1/direct-denial", ObserverID: "independent-custodian", ObserverPublicKey: public, RootCAPEM: root}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	challenge := Challenge{ChallengeID: "challenge-a", Kind: "host-service", SubjectID: "service-a", TargetID: "former-host", AdapterID: "https-direct-denial-v1", FormerIdentityID: "former-instance", ProbeID: "service-denied", Deadline: now.Add(20 * time.Second)}
	if result, err := adapter.Probe(context.Background(), challenge); err != nil || !result.Denied || result.ObserverID != "independent-custodian" {
		t.Fatalf("probe = %#v, %v", result, err)
	}
	adapter.publicKey = append(ed25519.PublicKey(nil), public...)
	adapter.publicKey[0] ^= 0xff
	if _, err := adapter.Probe(context.Background(), challenge); err == nil {
		t.Fatal("wrong observer key accepted")
	}
}
