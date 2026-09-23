package recovery

import (
	"context"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type SourceAdmissionLoader func(SourceAdmissionExpectation) (SourceAdmission, error)
type RecoveryPackageLoader func(context.Context, WitnessBinding) (InstalledPackage, error)
type QualifiedAdapterLoader func(context.Context, []BoundaryRequirement, time.Time) (QualifiedAdapters, error)

// ExactFenceWitnessVerifier performs the second #135 stage. The immutable plan
// already binds the stable admission and requirement set; Run now requires a
// fresh independently observed denial package bound to that exact plan and its
// precommitted execution identifiers.
type ExactFenceWitnessVerifier struct {
	Admissions       SourceAdmissionLoader
	Packages         RecoveryPackageLoader
	Qualifications   QualifiedAdapterLoader
	Clock            func() time.Time
	ReleaseBuildID   string
	EvaluatorVersion string
}

func (verifier ExactFenceWitnessVerifier) Verify(ctx context.Context, binding generated.RestoreBinding, stateRevision int64, profile store.GateAppliedProfile, source VerifiedSource) (FenceResult, error) {
	if ctx == nil || ctx.Err() != nil || verifier.Admissions == nil || verifier.Packages == nil || verifier.Qualifications == nil || verifier.Clock == nil || stateRevision < 0 {
		return FenceResult{}, ErrWitnessUnavailable
	}
	expectedAdmission := SourceAdmissionExpectation{FormerHostID: binding.FormerHostID, FormerInstanceID: binding.PriorInstanceID, ReplacementHostID: binding.ReplacementHostID, ReplacementInstanceID: binding.NewInstanceID, DraftID: binding.RecoveryDraftID, CiphertextFingerprint: binding.CiphertextFingerprint, SourceAdmissionDigest: binding.SourceAdmissionDigest, FenceQualificationDigest: binding.FenceQualificationDigest, PriorEpoch: binding.PriorRecoveryEpoch, NewEpoch: binding.NextRecoveryEpoch}
	admission, err := verifier.Admissions(expectedAdmission)
	if err != nil {
		return FenceResult{}, ErrWitnessUnavailable
	}
	requirements, err := AdmissionFenceRequirements(admission, profile, source, verifier.ReleaseBuildID, verifier.EvaluatorVersion)
	if err != nil {
		return FenceResult{}, ErrWitnessUnavailable
	}
	required, err := RequiredFenceSet(requirements, binding.SourceAdmissionDigest, binding.FenceQualificationDigest)
	if err != nil || required.FenceSetDigest != binding.FenceSetDigest {
		return FenceResult{}, ErrWitnessUnavailable
	}
	witness := WitnessBinding{FormerHostID: binding.FormerHostID, FormerInstanceID: binding.PriorInstanceID, ReplacementHostID: binding.ReplacementHostID, ReplacementInstanceID: binding.NewInstanceID, DraftID: binding.RecoveryDraftID, CiphertextFingerprint: binding.CiphertextFingerprint, PlanDigest: binding.PlanDigest, RunID: binding.RecoveryRunID, StepID: binding.RecoveryStepID, LeaseID: binding.RecoveryLeaseID, ChallengeID: binding.RecoveryChallengeID, ReceiptID: binding.RecoveryReceiptID, SourceAdmissionDigest: binding.SourceAdmissionDigest, FenceQualificationDigest: binding.FenceQualificationDigest, PriorEpoch: binding.PriorRecoveryEpoch, NewEpoch: binding.NextRecoveryEpoch, StateRevision: stateRevision}
	now := verifier.Clock().UTC()
	installed, err := verifier.Packages(ctx, witness)
	if err != nil {
		return FenceResult{}, ErrWitnessUnavailable
	}
	qualified, err := verifier.Qualifications(ctx, installed.Pin.Requirements, now)
	if err != nil {
		return FenceResult{}, ErrWitnessUnavailable
	}
	evidence, err := VerifyInstalledFenceEvidence(ctx, witness, requirements, installed, qualified, now)
	if err != nil {
		return FenceResult{}, ErrWitnessUnavailable
	}
	verified, err := (FenceEvaluator{Evidence: evidence, Clock: verifier.Clock}).Verify(ctx, requirements)
	if err != nil || verified.FenceSetDigest != binding.FenceSetDigest {
		return FenceResult{}, ErrWitnessUnavailable
	}
	return verified, nil
}

func SystemExactFenceWitnessVerifier(releaseBuildID, evaluatorVersion string) ExactFenceWitnessVerifier {
	return ExactFenceWitnessVerifier{Admissions: LoadSystemSourceAdmission, Packages: LoadSystemRecoveryPackage, Qualifications: LoadSystemQualifiedAdapters, Clock: time.Now, ReleaseBuildID: releaseBuildID, EvaluatorVersion: evaluatorVersion}
}
