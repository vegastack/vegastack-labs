package hostreplacement

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

// ExistingRestoreOperations is the exact existing service subset. Startup
// promotion is intentionally not callable through this orchestration port.
type ExistingRestoreOperations interface {
	Run(context.Context, generated.RestoreRunRequest, identity.Principal) (generated.RestoreBinding, error)
	Verify(context.Context, generated.RestoreVerifyRequest, identity.Principal) (generated.RestoreVerification, error)
}

func BindRestore(in generated.HostReplacementRequest, b generated.RestoreBinding) error {
	if ValidateInput(in) != nil || in.Source == nil || in.RestorationClass != "control-database" || b.FormerHostID != in.OldHostID || b.ReplacementHostID != in.NewHostID || b.Source.PointID != in.Source.PointID || b.Source.ManifestDigest != in.Source.ManifestDigest || hostaction.Digest(b.Source) != in.Source.SourceBindingDigest || b.RecoveryDraftID != in.Source.CustodyReferenceID || b.SourceAdmissionDigest != in.Source.CustodyBindingDigest || b.PriorRecoveryEpoch != in.RecoveryEpoch || b.NextRecoveryEpoch != b.PriorRecoveryEpoch+1 || b.PriorInstanceID == b.NewInstanceID || b.ReplacementContinuity == nil || b.ReplacementContinuity.ReplacementID != in.ReplacementID || b.ReplacementContinuity.SourceBindingDigest != in.Source.SourceBindingDigest {
		return errInput
	}
	return nil
}

// StageRestore returns verification-required only. It cannot claim promotion or
// recovered authority before ordinary startup and an independent Verify call.
func StageRestore(ctx context.Context, in generated.HostReplacementRequest, planned generated.RestoreBinding, run generated.RestoreRunRequest, p identity.Principal, ops ExistingRestoreOperations) (generated.RestoreBinding, error) {
	if ctx == nil || ctx.Err() != nil || ops == nil || BindRestore(in, planned) != nil || run.PlanID != planned.PlanID || run.PlanDigest != planned.PlanDigest {
		return generated.RestoreBinding{}, errInput
	}
	got, err := ops.Run(ctx, run, p)
	if err != nil {
		return generated.RestoreBinding{}, err
	}
	if BindRestore(in, got) != nil || got.PlanID != planned.PlanID || got.PlanDigest != planned.PlanDigest || got.Status != "verification-required" {
		return generated.RestoreBinding{}, errInput
	}
	return got, nil
}
