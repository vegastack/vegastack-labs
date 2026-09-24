//go:build linux

package server

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter/nativecredential"
	"github.com/vegastack/vegastack-labs/internal/recovery"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestCredentialRecoveryPublicCleanHostRejectsFormerRecipientKey(t *testing.T) {
	now := time.Now().UTC()
	witnessPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	adminPublic, adminPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	replacementKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	formerKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding := recovery.WitnessBinding{
		FormerHostID: "former-host", FormerInstanceID: "former-instance",
		ReplacementHostID: "replacement-host", ReplacementInstanceID: "replacement-instance",
		DraftID: "draft-a", CiphertextFingerprint: acceptanceDigest([]byte("ciphertext")),
		PlanDigest: acceptanceDigest([]byte("plan")), RunID: "run-a", StepID: "step-a", LeaseID: "lease-a",
		ChallengeID: "challenge-a", ReceiptID: "receipt-a",
		SourceAdmissionDigest:    acceptanceDigest([]byte("source-admission")),
		FenceQualificationDigest: acceptanceDigest([]byte("fence-qualification")),
		PriorEpoch:               3, NewEpoch: 4, StateRevision: 9,
	}
	manifest := recovery.RecoveryManifest{
		ManifestID: "manifest-a", WitnessKeyID: "witness-key-a", WitnessInstanceID: "outside-instance",
		WitnessPublicKey: witnessPublic, RecipientKeyID: "replacement-key-a",
		RecipientPublicKey: replacementKey.PublicKey().Bytes(), Binding: binding,
		ValidFrom: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
	}
	canonical, err := recovery.CanonicalRecoveryManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(recovery.SignedRecoveryManifest{Payload: manifest, Signature: ed25519.Sign(adminPrivate, canonical)})
	if err != nil {
		t.Fatal(err)
	}
	pin, err := recovery.ParseSignedRecoveryManifest(raw, adminPublic, binding, now)
	if err != nil {
		t.Fatal(err)
	}
	material := []byte("synthetic-clean-host-recovery")
	envelope, err := recovery.SealProtectedEnvelope(context.Background(), pin, binding, io.NopCloser(bytes.NewReader(material)))
	if err != nil {
		t.Fatal(err)
	}
	formerSource := &isolatedRecipientKeySource{key: formerKey.Bytes()}
	if _, err := recovery.NewProtectedRecipient(pin, formerSource).Open(context.Background(), envelope, binding); err == nil || formerSource.opens != 1 {
		t.Fatalf("former recipient key admitted or not checked: opens=%d err=%v", formerSource.opens, err)
	}
	replacementSource := &isolatedRecipientKeySource{key: replacementKey.Bytes()}
	stream, err := recovery.NewProtectedRecipient(pin, replacementSource).Open(context.Background(), envelope, binding)
	if err != nil || replacementSource.opens != 1 {
		t.Fatalf("replacement recipient rejected: opens=%d err=%v", replacementSource.opens, err)
	}
	decrypted, readErr := io.ReadAll(stream.Reader)
	closeErr := stream.Reader.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(decrypted, material) {
		t.Fatalf("replacement recovery material mismatch: read=%v close=%v", readErr, closeErr)
	}
}

type installedAuthorityFixture struct {
	result installedRecoveryAuthority
	err    error
}

func (fixture installedAuthorityFixture) CurrentInstalledRecovery(context.Context, RecoveryCustodyRequest) (installedRecoveryAuthority, error) {
	return fixture.result, fixture.err
}

type installedLoaderFixture struct {
	want      recovery.WitnessBinding
	required  []recovery.BoundaryRequirement
	candidate installedRecoveryCandidate
	err       error
	calls     int
}

func (fixture *installedLoaderFixture) LoadVerified(context.Context, recovery.WitnessBinding, []recovery.BoundaryRequirement, time.Time) (installedRecoveryCandidate, error) {
	fixture.calls++
	return fixture.candidate, fixture.err
}

func TestInstalledRecoverySourceBindsExactDraftAndConsumesVerifiedHandoff(t *testing.T) {
	material := []byte("synthetic-private-canary")
	draft := store.CredentialImportDraft{DraftID: "draft-a", ReferenceID: "reference-a", TargetID: "service-a", MaterialVersion: "version-a",
		CiphertextName: "credential-a", CiphertextFingerprint: acceptanceDigest([]byte("ciphertext")), StateRevision: 7, RecoveryEpoch: 4}
	sourceAdmission, qualification := acceptanceDigest([]byte("source-admission")), acceptanceDigest([]byte("qualification"))
	request := RecoveryCustodyRequest{Draft: draft, PlanID: "plan-a", PlanDigest: acceptanceDigest([]byte("plan")), RunID: "run-a", StepID: "step-a", LeaseID: "lease-a", PriorRecoveryEpoch: 3, RecoveryEpoch: 4, StateRevision: 9, SourceAdmissionDigest: sourceAdmission, FenceQualificationDigest: qualification}
	binding := recovery.WitnessBinding{FormerHostID: "former-host", FormerInstanceID: "former-instance", ReplacementHostID: "replacement-host", ReplacementInstanceID: "replacement-instance",
		DraftID: draft.DraftID, CiphertextFingerprint: draft.CiphertextFingerprint, PlanDigest: request.PlanDigest, RunID: request.RunID, StepID: request.StepID, LeaseID: request.LeaseID,
		ChallengeID: "challenge-a", ReceiptID: "receipt-a", SourceAdmissionDigest: sourceAdmission, FenceQualificationDigest: qualification, PriorEpoch: request.PriorRecoveryEpoch, NewEpoch: request.RecoveryEpoch, StateRevision: request.StateRevision}
	required := []recovery.BoundaryRequirement{
		{Kind: "host-service", SubjectID: "service-a", TargetID: "former-host", AdapterID: "host-denial-v1", FormerIdentityID: "former-instance", ProbeID: "service-denied"},
		{Kind: "host-service", SubjectID: "service-a", TargetID: "former-host", AdapterID: "host-denial-v1", FormerIdentityID: "former-instance", ProbeID: "alternate-process-denied"},
	}
	consumed := 0
	loader := &installedLoaderFixture{want: binding, required: required, candidate: installedRecoveryCandidate{
		sourceDigest: acceptanceDigest([]byte("source")), manifestDigest: acceptanceDigest([]byte("manifest")), witnessDigest: acceptanceDigest([]byte("witness")),
		fenceDigest: qualification, envelopeDigest: acceptanceDigest([]byte("envelope")), sourceAdmissionDigest: sourceAdmission,
		consume: func(_ context.Context, compare func(io.ReadCloser) error) error {
			consumed++
			return compare(io.NopCloser(bytes.NewReader(material)))
		},
	}}
	compared := 0
	source := &installedRecoverySource{authority: installedAuthorityFixture{result: installedRecoveryAuthority{Binding: binding, Required: required, SourceAdmissionDigest: sourceAdmission, FenceQualificationDigest: qualification}}, loader: loader,
		ciphertextRoot: "/var/lib/vsk-labs/credential-drafts", ownerUID: 1001, clock: time.Now,
		compare: func(_ context.Context, got nativecredential.VerifyRecoveryRequest, reader io.ReadCloser) (nativecredential.VerifiedDraft, error) {
			compared++
			defer reader.Close()
			private, err := io.ReadAll(reader)
			if err != nil || !bytes.Equal(private, material) || got.Name != draft.CiphertextName || got.ExpectedFingerprint != draft.CiphertextFingerprint || got.CiphertextDirectory != "/var/lib/vsk-labs/credential-drafts" || got.ExpectedUID != 1001 {
				return nativecredential.VerifiedDraft{}, errors.New("wrong exact draft")
			}
			return nativecredential.VerifiedDraft{CiphertextFingerprint: got.ExpectedFingerprint, HostKeyDigest: acceptanceDigest([]byte("host-key"))}, nil
		}}
	proof, err := source.VerifyRecovery(context.Background(), request)
	if err != nil || consumed != 1 || compared != 1 || loader.calls != 1 {
		t.Fatalf("exact installed source rejected: proof=%#v consumed=%d compared=%d loads=%d err=%v", proof, consumed, compared, loader.calls, err)
	}
	if proof.DraftID != draft.DraftID || proof.CiphertextFingerprint != draft.CiphertextFingerprint || proof.CustodyProofDigest != sourceAdmission ||
		proof.FormerControllerFenceDigest != qualification || proof.WitnessDigest != loader.candidate.witnessDigest || proof.EnvelopeDigest != loader.candidate.envelopeDigest || proof.SourceEvidenceDigest != loader.candidate.sourceDigest || proof.ReplacementHostKeyDigest != acceptanceDigest([]byte("host-key")) {
		t.Fatalf("wrong public proof: %#v", proof)
	}
	for name, mutate := range map[string]func(*installedRecoveryCandidate){
		"loaded source admission": func(value *installedRecoveryCandidate) {
			value.sourceAdmissionDigest = acceptanceDigest([]byte("other-source-admission"))
		},
		"loaded fence qualification": func(value *installedRecoveryCandidate) {
			value.fenceDigest = acceptanceDigest([]byte("other-qualification"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			changedCandidate := loader.candidate
			mutate(&changedCandidate)
			changedLoader := &installedLoaderFixture{want: binding, required: required, candidate: changedCandidate}
			changedSource := *source
			changedSource.loader = changedLoader
			if _, err := changedSource.VerifyRecovery(context.Background(), request); err == nil || changedLoader.calls != 1 {
				t.Fatalf("mismatched %s admitted: calls=%d err=%v", name, changedLoader.calls, err)
			}
		})
	}

	for name, change := range map[string]func(*RecoveryCustodyRequest){
		"draft":    func(value *RecoveryCustodyRequest) { value.Draft.DraftID = "other-draft" },
		"plan":     func(value *RecoveryCustodyRequest) { value.PlanDigest = acceptanceDigest([]byte("other-plan")) },
		"lease":    func(value *RecoveryCustodyRequest) { value.LeaseID = "other-lease" },
		"epoch":    func(value *RecoveryCustodyRequest) { value.RecoveryEpoch++ },
		"revision": func(value *RecoveryCustodyRequest) { value.StateRevision++ },
		"source admission": func(value *RecoveryCustodyRequest) {
			value.SourceAdmissionDigest = acceptanceDigest([]byte("other-source-admission"))
		},
		"fence qualification": func(value *RecoveryCustodyRequest) {
			value.FenceQualificationDigest = acceptanceDigest([]byte("other-qualification"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := request
			change(&changed)
			before := loader.calls
			if _, err := source.VerifyRecovery(context.Background(), changed); err == nil || loader.calls != before {
				t.Fatalf("changed %s reached protected source: loads=%d err=%v", name, loader.calls, err)
			}
		})
	}
}
