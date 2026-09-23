//go:build linux

package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter/nativecredential"
	"github.com/vegastack/vegastack-labs/internal/recovery"
	"github.com/vegastack/vegastack-labs/internal/store"
)

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
