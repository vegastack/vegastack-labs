package run

import (
	"context"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type RetentionLockRepository interface {
	GetLocalRetentionLockCatalogDraft(context.Context, string, int64) (store.LocalRetentionLockCatalogDraft, error)
	ActivateLocalRetentionLockCatalog(context.Context, store.LocalRetentionLockActivationRequest) (string, error)
	LocalRetentionLockCatalogActivationExists(context.Context, string, string, string, string) (bool, error)
}

type CoreRetentionLockEffect struct {
	repository RetentionLockRepository
	approvals  GateApprovalSource
}

func NewCoreRetentionLockEffect(repository RetentionLockRepository, approvals GateApprovalSource) (*CoreRetentionLockEffect, error) {
	if repository == nil || approvals == nil {
		return nil, runError(generated.ErrorCodeInputInvalid, "retention-lock-effect")
	}
	return &CoreRetentionLockEffect{repository: repository, approvals: approvals}, nil
}

func isRetentionLockOperation(adapterID, kind string) bool {
	return adapterID == "core.retention-locks" && kind == "backup.retention-locks.activate"
}

func (effect *CoreRetentionLockEffect) Execute(ctx context.Context, binding ExactStepBinding) (adapter.Effect, error) {
	if effect == nil || effect.repository == nil || effect.approvals == nil || !isRetentionLockOperation(binding.Step.AdapterID, binding.Step.OperationType) ||
		binding.Plan.ExecutorMode != "central" || binding.Run.ExecutorMode != "central" || binding.Plan.AuthorizationBranch != "human" || binding.Plan.Risk != "destructive" ||
		binding.Run.AcknowledgementID == nil || binding.Step.Status != "running" || binding.Step.EffectState != "intent-recorded" || binding.Step.Idempotent ||
		binding.Lease.Status != "active" || binding.Lease.PlanID != binding.Plan.PlanID || binding.Lease.PlanDigest != binding.Plan.PlanDigest || binding.Lease.RunID != binding.Run.RunID ||
		binding.Lease.StepID != binding.Step.StepID || binding.Lease.TargetID != binding.Step.TargetID || binding.Lease.ArtifactDigest != binding.Step.ArtifactDigest ||
		binding.Plan.Binding.StateRevision != binding.Run.StateRevision || binding.Plan.Binding.RecoveryEpoch != binding.Run.RecoveryEpoch || binding.Run.RecoveryEpoch != binding.Lease.RecoveryEpoch ||
		len(binding.Plan.Extensions) != 1 || binding.Plan.Extensions[0].Name != "x-backup-retention-lock-catalog" || binding.Plan.Extensions[0].ValueDigest != binding.Step.InputDigest {
		return adapter.Effect{}, runError(generated.ErrorCodePrerequisiteBlocked, "retention-lock-exact-binding")
	}
	approval, err := effect.approvals.Get(ctx, binding.Plan.PlanID)
	if err != nil {
		return adapter.Effect{}, err
	}
	if !approval.Consumed || approval.Acknowledgement.Status != "approved" || approval.Acknowledgement.AcknowledgementID != *binding.Run.AcknowledgementID || approval.Acknowledgement.PlanDigest != binding.Plan.PlanDigest || approval.Acknowledgement.HumanID == "" {
		return adapter.Effect{}, runError(generated.ErrorCodeApprovalRequired, "retention-lock-human")
	}
	draft, err := effect.repository.GetLocalRetentionLockCatalogDraft(ctx, binding.Step.InputDigest, binding.Run.RecoveryEpoch)
	if err != nil {
		return adapter.Effect{}, err
	}
	if draft.DeclarationID != binding.Plan.DeclarationID || draft.DeclarationRevision+1 != binding.Plan.Binding.DeclarationRevision || draft.RepositoryID != binding.Step.TargetID || draft.Catalog.SourceCoverageDigest != binding.Step.ArtifactDigest || draft.Catalog.Revision != binding.Plan.Binding.DeclarationRevision {
		return adapter.Effect{}, runError(generated.ErrorCodePlanStale, "retention-lock-draft")
	}
	attribution := binding.Attribution
	humanID := approval.Acknowledgement.HumanID
	attribution.ResponsibleHumanPrincipalID = &humanID
	activationID, err := effect.repository.ActivateLocalRetentionLockCatalog(ctx, store.LocalRetentionLockActivationRequest{Catalog: draft.Catalog, PlanID: binding.Plan.PlanID, PlanDigest: binding.Plan.PlanDigest, RunID: binding.Run.RunID, StepID: binding.Step.StepID, ExecutorLeaseID: binding.Lease.LeaseID, AcknowledgementID: *binding.Run.AcknowledgementID, HumanID: humanID, Expected: store.RevisionToken{StateRevision: binding.Plan.Binding.StateRevision, RecoveryEpoch: binding.Plan.Binding.RecoveryEpoch}, Attribution: attribution})
	if err != nil {
		return adapter.Effect{}, err
	}
	return adapter.Effect{Status: "succeeded", ResultDigest: draft.CatalogDigest, PendingPointID: &activationID, Changed: true, EffectObserved: true}, nil
}

func (effect *CoreRetentionLockEffect) Verify(ctx context.Context, binding ExactStepBinding, result adapter.Effect) (adapter.Verification, error) {
	if effect == nil || effect.repository == nil || adapter.ValidateEffect(result) != nil || result.Status != "succeeded" || result.PendingPointID == nil || result.ResultDigest != binding.Step.InputDigest {
		return adapter.Verification{}, runError(generated.ErrorCodeIntegrityFailure, "retention-lock-effect")
	}
	exists, err := effect.repository.LocalRetentionLockCatalogActivationExists(ctx, *result.PendingPointID, result.ResultDigest, binding.Run.RunID, binding.Step.StepID)
	if err != nil {
		return adapter.Verification{}, err
	}
	return adapter.Verification{Verified: exists, Digest: result.ResultDigest}, nil
}
