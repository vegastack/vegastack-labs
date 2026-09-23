package recovery

import (
	"context"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type AppliedFenceProfileReader interface {
	GetAppliedProfileScope(context.Context) (store.GateAppliedProfile, error)
}

type RestoreFenceCoordinator interface {
	QualifyPlan(context.Context, VerifiedSource, generated.RestoreRequest) (FenceResult, error)
	QualifyRun(context.Context, VerifiedSource, generated.RestoreRequest, generated.RestoreBinding, int64) (FenceResult, error)
}

// TwoStageFences consumes only the stable, administrator-signed source
// admission while planning. Execution then requires the separately installed
// package whose direct-denial witness is bound to the immutable plan and exact
// run identifiers.
type TwoStageFences struct {
	Admissions       SourceAdmissionLoader
	Profiles         AppliedFenceProfileReader
	Execution        ExactFenceWitnessVerifier
	ReleaseBuildID   string
	EvaluatorVersion string
}

func (coordinator TwoStageFences) QualifyPlan(ctx context.Context, source VerifiedSource, request generated.RestoreRequest) (FenceResult, error) {
	if coordinator.Admissions == nil || coordinator.Profiles == nil {
		return FenceResult{}, ErrWitnessUnavailable
	}
	admission, err := coordinator.Admissions(admissionExpectationFromRequest(request))
	if err != nil {
		return FenceResult{}, ErrWitnessUnavailable
	}
	profile, err := coordinator.Profiles.GetAppliedProfileScope(ctx)
	if err != nil {
		return FenceResult{}, ErrWitnessUnavailable
	}
	requirements, err := AdmissionFenceRequirements(admission, profile, source, coordinator.ReleaseBuildID, coordinator.EvaluatorVersion)
	if err != nil {
		return FenceResult{}, ErrWitnessUnavailable
	}
	return RequiredFenceSet(requirements, request.SourceAdmissionDigest, request.FenceQualificationDigest)
}

func (coordinator TwoStageFences) QualifyRun(ctx context.Context, source VerifiedSource, request generated.RestoreRequest, binding generated.RestoreBinding, stateRevision int64) (FenceResult, error) {
	return coordinator.Execution.Verify(ctx, binding, stateRevision, request.Fences)
}

func admissionExpectationFromRequest(request generated.RestoreRequest) SourceAdmissionExpectation {
	return SourceAdmissionExpectation{FormerHostID: request.FormerHostID, FormerInstanceID: request.PriorInstanceID, ReplacementHostID: request.ReplacementHostID, ReplacementInstanceID: request.NewInstanceID, DraftID: request.RecoveryDraftID, CiphertextFingerprint: request.CiphertextFingerprint, SourceAdmissionDigest: request.SourceAdmissionDigest, FenceQualificationDigest: request.FenceQualificationDigest, PriorEpoch: request.PriorRecoveryEpoch, NewEpoch: request.NextRecoveryEpoch}
}

// FenceEvaluator remains a useful isolated/test coordinator. Its Scopes and
// Evidence are both injected and cannot become production authority merely by
// satisfying this interface.
func (evaluator FenceEvaluator) QualifyPlan(ctx context.Context, source VerifiedSource, request generated.RestoreRequest) (FenceResult, error) {
	requirements, err := evaluator.Requirements(ctx, source, request.PriorInstanceID)
	if err != nil {
		return FenceResult{}, err
	}
	return RequiredFenceSet(requirements, request.SourceAdmissionDigest, request.FenceQualificationDigest)
}

func (evaluator FenceEvaluator) QualifyRun(ctx context.Context, source VerifiedSource, request generated.RestoreRequest, _ generated.RestoreBinding, _ int64) (FenceResult, error) {
	requirements, err := evaluator.Requirements(ctx, source, request.PriorInstanceID)
	if err != nil {
		return FenceResult{}, err
	}
	return evaluator.Verify(ctx, requirements)
}
