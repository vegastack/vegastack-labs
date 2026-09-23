//go:build linux

package server

import (
	"context"
	"io"
	"path/filepath"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter/nativecredential"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/recovery"
)

// installedRecoveryAuthority is supplied only by the future #108 current
// replacement-authority state. It is deliberately not implemented by local
// database epoch state, the installed package, or caller input.
type installedRecoveryAuthority struct {
	Binding                                         recovery.WitnessBinding
	Required                                        []recovery.BoundaryRequirement
	SourceAdmissionDigest, FenceQualificationDigest string
}

type installedRecoveryAuthoritySource interface {
	CurrentInstalledRecovery(context.Context, RecoveryCustodyRequest) (installedRecoveryAuthority, error)
}

// installedRecoveryCandidate is the public, already-verified #159 handoff plus
// its one-use custody consumer. The closure owns the protected recipient and
// receipt store; private bytes are visible only to the exact draft comparator.
type installedRecoveryCandidate struct {
	sourceDigest, manifestDigest, witnessDigest string
	fenceDigest, envelopeDigest                 string
	sourceAdmissionDigest                       string
	consume                                     func(context.Context, func(io.ReadCloser) error) error
}

type installedRecoveryLoader interface {
	LoadVerified(context.Context, recovery.WitnessBinding, []recovery.BoundaryRequirement, time.Time) (installedRecoveryCandidate, error)
}

type systemInstalledRecoveryLoader struct{ ownerUID uint32 }

func (loader systemInstalledRecoveryLoader) LoadVerified(ctx context.Context, binding recovery.WitnessBinding, required []recovery.BoundaryRequirement, now time.Time) (installedRecoveryCandidate, error) {
	installed, err := recovery.LoadSystemRecoveryPackage(ctx, binding)
	if err != nil {
		return installedRecoveryCandidate{}, recovery.ErrWitnessUnavailable
	}
	qualified, err := recovery.LoadSystemQualifiedAdapters(ctx, required, now)
	if err != nil {
		return installedRecoveryCandidate{}, recovery.ErrWitnessUnavailable
	}
	handoff, err := recovery.VerifyInstalledSource(ctx, binding, required, installed, qualified, now)
	if err != nil {
		return installedRecoveryCandidate{}, recovery.ErrWitnessUnavailable
	}
	recipient := recovery.NewProtectedRecipient(installed.Pin, systemdRecoveryRecipientKeySource{ownerUID: loader.ownerUID})
	receipts := recovery.NewSystemReceiptStore()
	return installedRecoveryCandidate{
		sourceDigest: handoff.SourceDigest, manifestDigest: handoff.ManifestDigest, witnessDigest: handoff.WitnessDigest, sourceAdmissionDigest: handoff.SourceAdmissionDigest,
		fenceDigest: handoff.FenceDigest, envelopeDigest: handoff.EnvelopeDigest,
		consume: func(consumeCtx context.Context, compare func(io.ReadCloser) error) error {
			return handoff.ConsumeCustody(consumeCtx, recipient, receipts, compare)
		},
	}, nil
}

// installedRecoverySource adapts #159's protected one-use source to #134's
// typed custody contract and Task 1's exact existing-draft comparator. No
// production constructor is called until #108 supplies current authority and
// real endpoint-specific denial implementations are independently qualified.
type installedRecoverySource struct {
	authority      installedRecoveryAuthoritySource
	loader         installedRecoveryLoader
	ciphertextRoot string
	ownerUID       uint32
	clock          func() time.Time
	compare        func(context.Context, nativecredential.VerifyRecoveryRequest, io.ReadCloser) (nativecredential.VerifiedDraft, error)
}

func newSystemInstalledRecoverySource(authority installedRecoveryAuthoritySource, databasePath string, ownerUID uint32) *installedRecoverySource {
	return &installedRecoverySource{
		authority: authority, loader: systemInstalledRecoveryLoader{ownerUID: ownerUID},
		ciphertextRoot: filepath.Join(filepath.Dir(databasePath), "credential-drafts"), ownerUID: ownerUID,
		clock: time.Now, compare: nativecredential.VerifyRecoveredDraft,
	}
}

func (source *installedRecoverySource) VerifyRecovery(ctx context.Context, request RecoveryCustodyRequest) (RecoveryCustodyProof, error) {
	var unavailable RecoveryCustodyProof
	if source == nil || source.authority == nil || source.loader == nil || source.clock == nil || source.compare == nil || ctx == nil || ctx.Err() != nil ||
		request.PlanID == "" || request.PlanDigest == "" || request.RunID == "" || request.StepID == "" || request.LeaseID == "" ||
		request.StateRevision < 0 || request.PriorRecoveryEpoch < 0 || request.RecoveryEpoch <= request.PriorRecoveryEpoch || request.Draft.DraftID == "" ||
		request.Draft.CiphertextName == "" || !credentialref.ValidSHA256Digest(request.Draft.CiphertextFingerprint) {
		return unavailable, recovery.ErrWitnessUnavailable
	}
	authority, err := source.authority.CurrentInstalledRecovery(ctx, request)
	if err != nil || ctx.Err() != nil || !installedAuthorityMatchesRequest(authority, request) {
		return unavailable, recovery.ErrWitnessUnavailable
	}
	candidate, err := source.loader.LoadVerified(ctx, authority.Binding, append([]recovery.BoundaryRequirement(nil), authority.Required...), source.clock().UTC())
	if err != nil || ctx.Err() != nil || !validInstalledCandidate(candidate) {
		return unavailable, recovery.ErrWitnessUnavailable
	}
	var verified nativecredential.VerifiedDraft
	err = candidate.consume(ctx, func(private io.ReadCloser) error {
		var compareErr error
		verified, compareErr = source.compare(ctx, nativecredential.VerifyRecoveryRequest{
			Name: request.Draft.CiphertextName, CiphertextDirectory: source.ciphertextRoot,
			ExpectedUID: source.ownerUID, ExpectedFingerprint: request.Draft.CiphertextFingerprint,
		}, private)
		return compareErr
	})
	if err != nil || ctx.Err() != nil || verified.CiphertextFingerprint != request.Draft.CiphertextFingerprint || !credentialref.ValidSHA256Digest(verified.HostKeyDigest) {
		return unavailable, recovery.ErrWitnessUnavailable
	}
	return RecoveryCustodyProof{
		DraftID: request.Draft.DraftID, CiphertextName: request.Draft.CiphertextName, CiphertextFingerprint: verified.CiphertextFingerprint,
		ReferenceID: request.Draft.ReferenceID, TargetID: request.Draft.TargetID, MaterialVersion: request.Draft.MaterialVersion,
		PriorRecoveryEpoch: request.PriorRecoveryEpoch, RecoveryEpoch: request.RecoveryEpoch,
		CustodyProofDigest: authority.SourceAdmissionDigest, FormerControllerFenceDigest: authority.FenceQualificationDigest,
		WitnessDigest: candidate.witnessDigest, EnvelopeDigest: candidate.envelopeDigest,
		ReplacementHostKeyDigest: verified.HostKeyDigest, SourceEvidenceDigest: candidate.sourceDigest,
	}, nil
}

func installedAuthorityMatchesRequest(authority installedRecoveryAuthority, request RecoveryCustodyRequest) bool {
	binding := authority.Binding
	return len(authority.Required) > 0 && authority.SourceAdmissionDigest == request.SourceAdmissionDigest && authority.FenceQualificationDigest == request.FenceQualificationDigest && binding.SourceAdmissionDigest == request.SourceAdmissionDigest && binding.FenceQualificationDigest == request.FenceQualificationDigest && binding.DraftID == request.Draft.DraftID && binding.CiphertextFingerprint == request.Draft.CiphertextFingerprint &&
		binding.PlanDigest == request.PlanDigest && binding.RunID == request.RunID && binding.StepID == request.StepID && binding.LeaseID == request.LeaseID &&
		binding.PriorEpoch == request.PriorRecoveryEpoch && binding.NewEpoch == request.RecoveryEpoch && binding.StateRevision == request.StateRevision &&
		binding.FormerHostID != "" && binding.FormerInstanceID != "" && binding.ReplacementHostID != "" && binding.ReplacementInstanceID != "" &&
		binding.FormerHostID != binding.ReplacementHostID && binding.FormerInstanceID != binding.ReplacementInstanceID && binding.ChallengeID != "" && binding.ReceiptID != ""
}

func validInstalledCandidate(candidate installedRecoveryCandidate) bool {
	return candidate.consume != nil && credentialref.ValidSHA256Digest(candidate.sourceAdmissionDigest) && credentialref.ValidSHA256Digest(candidate.sourceDigest) && credentialref.ValidSHA256Digest(candidate.manifestDigest) &&
		credentialref.ValidSHA256Digest(candidate.witnessDigest) && credentialref.ValidSHA256Digest(candidate.fenceDigest) && credentialref.ValidSHA256Digest(candidate.envelopeDigest)
}
