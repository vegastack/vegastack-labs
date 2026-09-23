package run

import (
	"context"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/backupidentity"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type retentionLockEffectRepository struct {
	draft      store.LocalRetentionLockCatalogDraft
	activation store.LocalRetentionLockActivationRequest
}

func (repository *retentionLockEffectRepository) GetLocalRetentionLockCatalogDraft(context.Context, string, int64) (store.LocalRetentionLockCatalogDraft, error) {
	return repository.draft, nil
}
func (repository *retentionLockEffectRepository) ActivateLocalRetentionLockCatalog(_ context.Context, request store.LocalRetentionLockActivationRequest) (string, error) {
	repository.activation = request
	return "lock-catalog-activation-a", nil
}
func (*retentionLockEffectRepository) LocalRetentionLockCatalogActivationExists(context.Context, string, string, string, string) (bool, error) {
	return true, nil
}

func TestCoreRetentionLockEffectUsesExactHumanPlanAndDraft(t *testing.T) {
	now := time.Date(2026, 9, 23, 8, 0, 0, 0, time.UTC)
	plan := testPlan(now)
	plan.DeclarationID, plan.AuthorizationBranch, plan.Risk, plan.ExecutorMode = "retention-lock-change-a", "human", "destructive", "central"
	plan.Binding.DeclarationRevision, plan.Binding.StateRevision = 2, 3
	catalog := store.LocalRetentionLockCatalog{Schema: "vegastack-labs.dev/local-retention-lock-catalog", SchemaVersion: "1.0.0", RepositoryID: backupidentity.StandardRepository, RepositoryClass: "standard", SourceCoverageDigest: store.LocalPromiseSourceCoverageDigest(), RecoveryEpoch: plan.Binding.RecoveryEpoch, Revision: 2, Complete: true, Locks: []store.LocalRetentionLock{}}
	_, catalogDigest, err := store.CanonicalLocalRetentionLockCatalog(catalog)
	if err != nil {
		t.Fatal(err)
	}
	plan.Extensions = []generated.ContractExtension{{Name: "x-backup-retention-lock-catalog", ValueDigest: catalogDigest}}
	plan.Operations = []generated.PlanOperation{{Sequence: 1, OperationID: "retention-lock-operation-a", OperationType: "backup.retention-locks.activate", AdapterID: "core.retention-locks", ExecutorID: "executor-central", TargetID: catalog.RepositoryID, InputDigest: catalogDigest, ArtifactDigest: catalog.SourceCoverageDigest, Idempotent: false}}
	ackID := "ack-retention-lock-a"
	run := generated.Run{RunID: "run-retention-lock-a", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, AcknowledgementID: &ackID, ExecutorMode: "central", StateRevision: plan.Binding.StateRevision, RecoveryEpoch: plan.Binding.RecoveryEpoch}
	step := generated.RunStep{StepID: "step-retention-lock-a", OperationID: plan.Operations[0].OperationID, OperationType: plan.Operations[0].OperationType, AdapterID: plan.Operations[0].AdapterID, TargetID: catalog.RepositoryID, InputDigest: catalogDigest, ArtifactDigest: catalog.SourceCoverageDigest, Idempotent: false, Status: "running", EffectState: "intent-recorded"}
	lease := generated.ExecutorLease{LeaseID: "lease-retention-lock-a", Status: "active", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, RunID: run.RunID, StepID: step.StepID, TargetID: step.TargetID, ArtifactDigest: step.ArtifactDigest, RecoveryEpoch: run.RecoveryEpoch}
	repository := &retentionLockEffectRepository{draft: store.LocalRetentionLockCatalogDraft{DraftID: "lock-draft-a", CatalogDigest: catalogDigest, DeclarationID: plan.DeclarationID, DeclarationRevision: 1, RepositoryID: catalog.RepositoryID, RepositoryClass: catalog.RepositoryClass, StateRevision: 2, RecoveryEpoch: plan.Binding.RecoveryEpoch, Catalog: catalog}}
	approvals := &fixedGateApproval{stored: acknowledgement.Stored{Consumed: true, Acknowledgement: generated.Acknowledgement{AcknowledgementID: ackID, PlanDigest: plan.PlanDigest, HumanID: "human-a", Status: "approved"}}}
	effect, err := NewCoreRetentionLockEffect(repository, approvals)
	if err != nil {
		t.Fatal(err)
	}
	result, err := effect.Execute(context.Background(), ExactStepBinding{Plan: plan, Run: run, Step: step, Lease: lease})
	if err != nil || adapter.ValidateEffect(result) != nil || repository.activation.HumanID != "human-a" || repository.activation.Catalog.Revision != 2 {
		t.Fatalf("result=%#v activation=%#v err=%v", result, repository.activation, err)
	}
	verified, err := effect.Verify(context.Background(), ExactStepBinding{Plan: plan, Run: run, Step: step, Lease: lease}, result)
	if err != nil || !verified.Verified || verified.Digest != catalogDigest {
		t.Fatalf("verification=%#v err=%v", verified, err)
	}

	bad := ExactStepBinding{Plan: plan, Run: run, Step: step, Lease: lease}
	bad.Plan.AuthorizationBranch = "preauthorized"
	repository.activation = store.LocalRetentionLockActivationRequest{}
	if _, err := effect.Execute(context.Background(), bad); Code(err) != generated.ErrorCodePrerequisiteBlocked || repository.activation.PlanID != "" {
		t.Fatalf("non-human effect admitted: %v %#v", err, repository.activation)
	}
}
