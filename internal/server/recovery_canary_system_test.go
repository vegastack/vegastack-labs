package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/recovery"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestSystemRecoveryCanaryCapabilitiesBindExactFreshOutputs(t *testing.T) {
	now := time.Date(2026, 9, 24, 1, 0, 0, 0, time.UTC)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var input recoveryCanaryCapabilityRequest
		if request.Method != http.MethodPost || json.NewDecoder(request.Body).Decode(&input) != nil {
			http.Error(writer, "bad request", http.StatusBadRequest)
			return
		}
		result := recoveryCanaryCapabilityResult{Action: input.Action, PlanID: input.Canary.PlanID, PlanDigest: input.Canary.PlanDigest, CanaryRunID: input.Canary.CanaryRunID, CanaryStepID: input.Canary.CanaryStepID, CanaryChallengeID: input.Canary.CanaryChallengeID, CanaryReceiptID: input.Canary.CanaryReceiptID, ObserverID: "independent-recovery-operator", OutputID: "checkpoint-new", ObservedAt: now, Checkpoint: &store.RecoveryCanaryCheckpointRecord{Checkpoint: generated.AuditCheckpoint{CheckpointID: "checkpoint-new"}}}
		if input.Action == "create-backup" {
			result.OutputID, result.RepositoryClass = "point-new", "critical"
		}
		canonical, _ := json.Marshal(result)
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(signedRecoveryCanaryCapabilityResult{Result: result, Signature: ed25519.Sign(private, append([]byte(recoveryCanaryResponseDomain), canonical...))})
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAnyClientCert}
	server.StartTLS()
	defer server.Close()
	root := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	config := recoveryCanaryCapabilityConfig{Schema: "vegastack-labs.dev/recovery-canary-capabilities", SchemaVersion: "1.0.0", Endpoint: server.URL + "/v1/canary", ObserverID: "independent-recovery-operator", ObserverPublicKey: public, RootCAPEM: root, ClientCertificate: server.TLS.Certificates[0]}
	capability := &systemRecoveryCanaryCapabilities{load: func() (recoveryCanaryCapabilityConfig, error) { return config, nil }, clock: func() time.Time { return now }}
	request := recovery.CanaryRequest{PlanID: "plan-a", PlanDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", NewInstanceID: "instance-new", FenceSetDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", CanaryRunID: "canary-run-a", CanaryStepID: "canary-step-a", CanaryLeaseID: "canary-lease-a", CanaryChallengeID: "canary-challenge-a", CanaryReceiptID: "canary-receipt-a", RecoveryEpoch: 3, ExpectedStateRevision: 8, StartedAt: now.Add(-time.Second)}
	if record, err := capability.ProduceRecoveryCheckpoint(t.Context(), request, request.CanaryRunID); err != nil || record.Checkpoint.CheckpointID != "checkpoint-new" {
		t.Fatalf("checkpoint = %#v, %v", record, err)
	}
	config.ObserverPublicKey = append(ed25519.PublicKey(nil), public...)
	config.ObserverPublicKey[0] ^= 0xff
	if _, err := capability.ProduceRecoveryCheckpoint(t.Context(), request, request.CanaryRunID); err == nil {
		t.Fatal("wrong observer key accepted")
	}
}
