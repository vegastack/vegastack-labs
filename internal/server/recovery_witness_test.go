package server

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/recovery"
)

type isolatedWitnessAdapter struct{}

func (isolatedWitnessAdapter) VerifyDirectDenial(context.Context, recovery.DirectDenialTranscript) error {
	return nil
}

type isolatedRecipientKeySource struct {
	key   []byte
	opens int
}

func (s *isolatedRecipientKeySource) OpenPrivate(context.Context, string) (io.ReadCloser, error) {
	s.opens++
	return io.NopCloser(bytes.NewReader(s.key)), nil
}

type isolatedReceipts struct{ used bool }

func (r *isolatedReceipts) Consume(_ context.Context, _, _ string) error {
	if r.used {
		return recovery.ErrWitnessUnavailable
	}
	r.used = true
	return nil
}

func TestRecoveryWitnessCandidateRejectsReplayAndUnavailableRecipient(t *testing.T) {
	now := time.Now().UTC()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding := recovery.WitnessBinding{FormerHostID: "old-host", FormerInstanceID: "old-instance", ReplacementHostID: "new-host", ReplacementInstanceID: "new-instance", DraftID: "draft-1", CiphertextFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", PlanDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", RunID: "run-1", StepID: "step-1", LeaseID: "lease-1", ChallengeID: "challenge-1", ReceiptID: "receipt-1", SourceAdmissionDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", FenceQualificationDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", PriorEpoch: 3, NewEpoch: 4, StateRevision: 9}
	adminPublic, adminPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipientKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := recovery.RecoveryManifest{ManifestID: "manifest-1", WitnessKeyID: "key-1", WitnessInstanceID: "outside-instance", WitnessPublicKey: public, RecipientKeyID: "ephemeral-recipient-1", RecipientPublicKey: recipientKey.PublicKey().Bytes(), Binding: binding, ValidFrom: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}
	manifestCanonical, err := recovery.CanonicalRecoveryManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := json.Marshal(recovery.SignedRecoveryManifest{Payload: manifest, Signature: ed25519.Sign(adminPrivate, manifestCanonical)})
	if err != nil {
		t.Fatal(err)
	}
	pin, err := recovery.ParseSignedRecoveryManifest(manifestBytes, adminPublic, binding, now)
	if err != nil {
		t.Fatal(err)
	}
	required := []recovery.BoundaryRequirement{{Kind: "host-service", SubjectID: "subject-1", TargetID: "target-1", AdapterID: "adapter-1", FormerIdentityID: "old-identity", ProbeID: "service-denied"}, {Kind: "host-service", SubjectID: "subject-1", TargetID: "target-1", AdapterID: "adapter-1", FormerIdentityID: "old-identity", ProbeID: "alternate-process-denied"}}
	transcripts := make([]recovery.DirectDenialTranscript, 0, len(required))
	for _, req := range required {
		transcripts = append(transcripts, recovery.DirectDenialTranscript{Requirement: req, ObserverID: "outside-observer", ChallengeID: binding.ChallengeID, ResponseClass: "direct-denial", ResponseDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", ObservedAt: now.Add(-time.Second), ExpiresAt: now.Add(20 * time.Second), SessionExpiry: now.Add(20 * time.Second), Denied: true})
	}
	payload := recovery.WitnessPayload{Binding: binding, KeyID: pin.KeyID, WitnessInstanceID: pin.WitnessInstanceID, IssuedAt: now.Add(-time.Second), ObservedAt: now.Add(-time.Second), ExpiresAt: now.Add(20 * time.Second), Transcripts: transcripts}
	canonical, err := recovery.CanonicalWitnessPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	qualified := recovery.NewQualifiedAdapters()
	qualified.Register("adapter-1", isolatedWitnessAdapter{})
	material := []byte("synthetic-custody")
	envelope, err := recovery.SealProtectedEnvelope(context.Background(), pin, binding, io.NopCloser(bytes.NewReader(material)))
	if err != nil {
		t.Fatal(err)
	}
	keySource := &isolatedRecipientKeySource{key: recipientKey.Bytes()}
	recipient := recovery.NewProtectedRecipient(pin, keySource)
	receipts := &isolatedReceipts{}
	candidate := recoveryWitnessCandidate{Pin: pin, Expected: binding, Signed: recovery.SignedWitness{Payload: payload, Signature: ed25519.Sign(private, canonical)}, Required: required, Qualified: qualified, Envelope: envelope, Recipient: recipient, Receipts: receipts}
	compare := func(r io.ReadCloser) error {
		defer r.Close()
		var buf [64]byte
		defer func() {
			for i := range buf {
				buf[i] = 0
			}
		}()
		n, _ := r.Read(buf[:])
		if string(buf[:n]) != "synthetic-custody" {
			return recovery.ErrWitnessUnavailable
		}
		return nil
	}
	if err := candidate.verify(context.Background(), compare); err != nil {
		t.Fatal(err)
	}
	if !receipts.used || keySource.opens != 1 {
		t.Fatal("custody not consumed once")
	}
	if err := candidate.verify(context.Background(), compare); err == nil {
		t.Fatal("one-use candidate replay accepted")
	}
	candidate.Recipient = nil
	if err := candidate.verify(context.Background(), compare); err == nil {
		t.Fatal("unavailable independent recipient accepted")
	}
}
