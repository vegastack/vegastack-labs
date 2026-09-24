package recovery

import (
	"context"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
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
	Receipts         ReceiptStore
	Clock            func() time.Time
	ReleaseBuildID   string
	EvaluatorVersion string
}

func (verifier ExactFenceWitnessVerifier) Verify(ctx context.Context, binding generated.RestoreBinding, stateRevision int64, planned []generated.RestoreFenceItem) (FenceResult, error) {
	return verifier.verify(ctx, binding, stateRevision, planned)
}

// VerifyCanary consumes a separately precommitted witness package. Replacing
// only the execution and one-use custody identifiers keeps the immutable plan,
// host pair, epochs, source admission, and fence set identical to cutover.
func (verifier ExactFenceWitnessVerifier) VerifyCanary(ctx context.Context, binding generated.RestoreBinding, stateRevision int64, planned []generated.RestoreFenceItem) (FenceResult, error) {
	if binding.CanaryRunID == "" || binding.CanaryStepID == "" || binding.CanaryLeaseID == "" || binding.CanaryChallengeID == "" || binding.CanaryReceiptID == "" ||
		binding.CanaryRunID == binding.RecoveryRunID || binding.CanaryStepID == binding.RecoveryStepID || binding.CanaryLeaseID == binding.RecoveryLeaseID || binding.CanaryChallengeID == binding.RecoveryChallengeID || binding.CanaryReceiptID == binding.RecoveryReceiptID {
		return FenceResult{}, ErrWitnessUnavailable
	}
	binding.RecoveryRunID, binding.RecoveryStepID, binding.RecoveryLeaseID = binding.CanaryRunID, binding.CanaryStepID, binding.CanaryLeaseID
	binding.RecoveryChallengeID, binding.RecoveryReceiptID = binding.CanaryChallengeID, binding.CanaryReceiptID
	return verifier.verify(ctx, binding, stateRevision, planned)
}

func (verifier ExactFenceWitnessVerifier) verify(ctx context.Context, binding generated.RestoreBinding, stateRevision int64, planned []generated.RestoreFenceItem) (FenceResult, error) {
	if ctx == nil || ctx.Err() != nil || verifier.Admissions == nil || verifier.Packages == nil || verifier.Qualifications == nil || verifier.Receipts == nil || verifier.Clock == nil || stateRevision < 0 {
		return FenceResult{}, ErrWitnessUnavailable
	}
	expectedAdmission := SourceAdmissionExpectation{FormerHostID: binding.FormerHostID, FormerInstanceID: binding.PriorInstanceID, ReplacementHostID: binding.ReplacementHostID, ReplacementInstanceID: binding.NewInstanceID, DraftID: binding.RecoveryDraftID, CiphertextFingerprint: binding.CiphertextFingerprint, SourceAdmissionDigest: binding.SourceAdmissionDigest, FenceQualificationDigest: binding.FenceQualificationDigest, TargetReleaseBuildID: binding.Source.TargetReleaseBuildID, TargetToolVersion: binding.Source.TargetToolVersion, TargetSchemaVersion: binding.Source.TargetSchemaVersion, RequiredDependencies: append([]generated.RestoreDependencyBinding(nil), binding.Source.RequiredDependencies...), PriorEpoch: binding.PriorRecoveryEpoch, NewEpoch: binding.NextRecoveryEpoch}
	admission, err := verifier.Admissions(expectedAdmission)
	if err != nil {
		return FenceResult{}, ErrWitnessUnavailable
	}
	requirements, err := FenceRequirementsFromPlan(planned, binding)
	if err != nil || !sameBoundaryRequirementSet(mustExpandFenceRequirements(requirements), admission.Requirements) {
		return FenceResult{}, ErrWitnessUnavailable
	}
	for _, requirement := range requirements {
		if requirement.ReleaseBuildID != verifier.ReleaseBuildID || requirement.EvaluatorVersion != verifier.EvaluatorVersion {
			return FenceResult{}, ErrWitnessUnavailable
		}
	}
	required, err := RequiredFenceSet(requirements, binding.SourceAdmissionDigest, binding.FenceQualificationDigest)
	if err != nil || required.FenceSetDigest != binding.FenceSetDigest {
		return FenceResult{}, ErrWitnessUnavailable
	}
	witness := WitnessBinding{FormerHostID: binding.FormerHostID, FormerInstanceID: binding.PriorInstanceID, ReplacementHostID: binding.ReplacementHostID, ReplacementInstanceID: binding.NewInstanceID, DraftID: binding.RecoveryDraftID, CiphertextFingerprint: binding.CiphertextFingerprint, PlanDigest: binding.PlanDigest, RunID: binding.RecoveryRunID, StepID: binding.RecoveryStepID, LeaseID: binding.RecoveryLeaseID, ChallengeID: binding.RecoveryChallengeID, ReceiptID: binding.RecoveryReceiptID, SourceAdmissionDigest: binding.SourceAdmissionDigest, FenceQualificationDigest: binding.FenceQualificationDigest, TargetReleaseBuildID: binding.Source.TargetReleaseBuildID, TargetToolVersion: binding.Source.TargetToolVersion, TargetSchemaVersion: binding.Source.TargetSchemaVersion, RequiredDependencies: append([]generated.RestoreDependencyBinding(nil), binding.Source.RequiredDependencies...), PriorEpoch: binding.PriorRecoveryEpoch, NewEpoch: binding.NextRecoveryEpoch, StateRevision: stateRevision}
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
	if err := verifier.Receipts.Consume(ctx, witness.ReceiptID, witness.ChallengeID); err != nil {
		return FenceResult{}, ErrWitnessUnavailable
	}
	return verified, nil
}

func FenceRequirementsFromPlan(items []generated.RestoreFenceItem, binding generated.RestoreBinding) ([]FenceRequirement, error) {
	if len(items) == 0 || binding.PriorInstanceID == "" || binding.NewInstanceID == "" || binding.PriorInstanceID == binding.NewInstanceID {
		return nil, ErrWitnessUnavailable
	}
	result := make([]FenceRequirement, 0, len(items))
	for _, item := range items {
		if item.Status != "required" || !item.Required || item.ObservedAt != nil || item.RecoveryEpoch != binding.PriorRecoveryEpoch || item.ReleaseBuildID == "" || item.EvaluatorVersion == "" {
			return nil, ErrWitnessUnavailable
		}
		requirement := FenceRequirement{Boundary: item.Boundary, SubjectID: item.SubjectID, TargetID: item.TargetID, AdapterID: item.AdapterID, FormerIdentityID: item.FormerIdentityID, FormerInstanceID: binding.PriorInstanceID, ReplacementInstanceID: binding.NewInstanceID, ProfileID: item.ProfileID, ProfileVersion: item.ProfileVersion, PolicyID: item.PolicyID, PolicyVersion: item.PolicyVersion, ReleaseBuildID: item.ReleaseBuildID, EvaluatorVersion: item.EvaluatorVersion, RecoveryEpoch: item.RecoveryEpoch, RequiredEvidenceKinds: append([]string(nil), item.RequiredEvidenceKinds...)}
		if !validFenceRequirement(requirement) {
			return nil, ErrWitnessUnavailable
		}
		result = append(result, requirement)
	}
	return result, nil
}

func mustExpandFenceRequirements(requirements []FenceRequirement) []BoundaryRequirement {
	expanded, err := expandFenceRequirements(requirements)
	if err != nil {
		return nil
	}
	return expanded
}

func SystemExactFenceWitnessVerifier(releaseBuildID, evaluatorVersion string) ExactFenceWitnessVerifier {
	return ExactFenceWitnessVerifier{Admissions: LoadSystemSourceAdmission, Packages: LoadSystemRecoveryPackage, Qualifications: LoadSystemQualifiedAdapters, Receipts: NewSystemReceiptStore(), Clock: time.Now, ReleaseBuildID: releaseBuildID, EvaluatorVersion: evaluatorVersion}
}
