//go:build linux

package cli

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter/recoverydenial"
	"github.com/vegastack/vegastack-labs/internal/recovery"
)

type witnessCLIAdapter struct{}

func (witnessCLIAdapter) Probe(_ context.Context, challenge recoverydenial.Challenge) (recoverydenial.Result, error) {
	now := time.Now().UTC()
	return recoverydenial.Result{ChallengeID: challenge.ChallengeID, Kind: challenge.Kind, SubjectID: challenge.SubjectID, TargetID: challenge.TargetID, AdapterID: challenge.AdapterID, FormerIdentityID: challenge.FormerIdentityID, ProbeID: challenge.ProbeID, ObserverID: "outside-observer", ResponseClass: "direct-denial", ResponseDigest: "sha256:" + strings.Repeat("a", 64), ObservedAt: now, ExpiresAt: challenge.Deadline, SessionExpiry: challenge.Deadline, Denied: true}, nil
}

func TestRecoveryWitnessCollectCLIEmitsOnlySignedAndSealedArtifacts(t *testing.T) {
	adminPublic, adminPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	witnessPublic, witnessPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding := recovery.WitnessBinding{FormerHostID: "old-host", FormerInstanceID: "old-instance", ReplacementHostID: "new-host", ReplacementInstanceID: "new-instance", DraftID: "draft-1", CiphertextFingerprint: "sha256:" + strings.Repeat("a", 64), PlanDigest: "sha256:" + strings.Repeat("b", 64), RunID: "run-1", StepID: "step-1", LeaseID: "lease-1", ChallengeID: "challenge-1", ReceiptID: "receipt-1", PriorEpoch: 3, NewEpoch: 4, StateRevision: 9}
	now := time.Now().UTC()
	probes := []struct {
		kind string
		ids  []string
	}{
		{"host-service", []string{"service-denied", "alternate-process-denied"}},
		{"mesh", []string{"registration-denied", "reenrollment-denied"}},
		{"ssh", []string{"new-auth-denied", "open-session-denied"}},
		{"secret-resolver", []string{"resolve-denied", "cached-material-denied"}},
		{"provider-mutation", []string{"mutation-denied", "outstanding-session-denied"}},
		{"backup-writer", []string{"new-payload-denied", "retained-alteration-denied", "outstanding-session-denied"}},
		{"audit-writer", []string{"append-denied", "export-denied"}},
	}
	var required []recovery.BoundaryRequirement
	for _, group := range probes {
		for _, id := range group.ids {
			required = append(required, recovery.BoundaryRequirement{Kind: group.kind, SubjectID: "subject-1", TargetID: "target-1", AdapterID: "fixture-adapter", FormerIdentityID: "old-identity", ProbeID: id})
		}
	}
	manifest := recovery.RecoveryManifest{ManifestID: "manifest-1", WitnessKeyID: "witness-key-1", WitnessInstanceID: "outside-instance", WitnessPublicKey: witnessPublic, RecipientKeyID: "recipient-1", RecipientPublicKey: recipient.PublicKey().Bytes(), Binding: binding, Requirements: required, ValidFrom: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	canonical, err := recovery.CanonicalRecoveryManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := json.Marshal(recovery.SignedRecoveryManifest{Payload: manifest, Signature: ed25519.Sign(adminPrivate, canonical)})
	if err != nil {
		t.Fatal(err)
	}
	input, err := json.Marshal(witnessCollectionInput{Binding: binding})
	if err != nil {
		t.Fatal(err)
	}
	keyFile, err := os.CreateTemp(t.TempDir(), "witness-key")
	if err != nil {
		t.Fatal(err)
	}
	defer keyFile.Close()
	if _, err := keyFile.Write(witnessPrivate.Seed()); err != nil {
		t.Fatal(err)
	}
	if _, err := keyFile.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	materialFile, err := os.CreateTemp(t.TempDir(), "protected-material")
	if err != nil {
		t.Fatal(err)
	}
	defer materialFile.Close()
	const canary = "synthetic-custody-private-canary"
	if _, err := materialFile.WriteString(canary); err != nil {
		t.Fatal(err)
	}
	if _, err := materialFile.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runTestAppWithOptions(t, context.Background(), []string{"recovery", "witness", "collect", "--file", "input.json", "--signing-key-fd", strconv.Itoa(int(keyFile.Fd())), "--material-fd", strconv.Itoa(int(materialFile.Fd())), "--output", "json"}, nil,
		WithControlOperations(nil, &stubFileReader{content: input}),
		func(app *App) {
			app.witnessPinLoader = func(expected recovery.WitnessBinding) (recovery.PinnedWitness, error) {
				return recovery.ParseSignedRecoveryManifest(manifestBytes, adminPublic, expected, time.Now().UTC())
			}
			app.witnessAdapters = map[string]recoverydenial.Adapter{"fixture-adapter": witnessCLIAdapter{}}
		})
	if code != 0 || stderr != "" || bytes.Contains([]byte(stdout), []byte(canary)) {
		t.Fatalf("collection result: code=%d stderr=%q stdout=%q", code, stderr, stdout)
	}
	var result struct {
		Data struct {
			SignedArtifactBase64    string `json:"signedArtifactBase64"`
			ProtectedEnvelopeBase64 string `json:"protectedEnvelopeBase64"`
		} `json:"data"`
	}
	if json.Unmarshal([]byte(stdout), &result) != nil || result.Data.SignedArtifactBase64 == "" || result.Data.ProtectedEnvelopeBase64 == "" {
		t.Fatal("missing typed collection data")
	}
	artifact, err := base64.RawURLEncoding.DecodeString(result.Data.SignedArtifactBase64)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recovery.DecodeSignedWitness(artifact); err != nil {
		t.Fatal(err)
	}
}
