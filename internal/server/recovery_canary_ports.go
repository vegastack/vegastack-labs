package server

import (
	"context"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter/localbackup"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/recovery"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// NewQualifiedRecoveryCanaryPortFactory closes the production composition
// around separately qualified mutation capabilities and independent store
// readback. The server profile still decides whether these capabilities are
// installed; no request can inject either implementation.
func NewQualifiedRecoveryCanaryPortFactory(checkpoints recovery.RecoveryCheckpointCapability) (RecoveryCanaryPortFactory, error) {
	if checkpoints == nil {
		return nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "recovery-canary-capabilities", false)
	}
	return func(_ context.Context, _ serverconfig.Profile, authority *store.Store, _ *store.BackupRepository) (recovery.CanaryAuditVerifier, recovery.CanaryBackupVerifier, error) {
		if authority == nil {
			return nil, nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "recovery-canary-capabilities", false)
		}
		return recovery.IndependentCheckpointCanary{Appender: &durableRecoveryCheckpointAppender{authority: authority, capability: checkpoints}, Reader: authority}, nil, nil
	}, nil
}

func systemRecoveryCanaryPortFactory() RecoveryCanaryPortFactory {
	capabilities := NewSystemRecoveryCanaryCapabilities()
	factory, err := NewQualifiedRecoveryCanaryPortFactory(capabilities)
	if err != nil {
		return nil
	}
	return factory
}

type durableRecoveryCheckpointAppender struct {
	authority  *store.Store
	capability recovery.RecoveryCheckpointCapability
}

func (appender *durableRecoveryCheckpointAppender) AppendRecoveryCheckpoint(ctx context.Context, request recovery.CanaryRequest, noopRunID string) (string, error) {
	if appender == nil || appender.authority == nil || appender.capability == nil {
		return "", failure.New(generated.ErrorCodePrerequisiteBlocked, "recovery-canary-audit", false)
	}
	record, err := appender.capability.ProduceRecoveryCheckpoint(ctx, request, noopRunID)
	if err != nil {
		return "", err
	}
	mutation := recoveryCanaryMutationRequest(request)
	err = appender.authority.WithRecoveryCanaryMutation(ctx, mutation, func(scoped context.Context) error {
		return appender.authority.RecordRecoveryCanaryCheckpoint(scoped, mutation, request.StartedAt, record)
	})
	if err != nil {
		return "", err
	}
	return record.Checkpoint.CheckpointID, nil
}

type localRecoveryCanaryBackup struct {
	authority *store.Store
	restores  *store.RestoreRepository
	backups   *store.BackupRepository
	adapter   recoveryCanaryBackupAdapter
	borrower  recoveryCanaryCredentialBorrower
	clock     func() time.Time
}

type recoveryCanaryBackupAdapter interface {
	CreateAndVerifyRecoveryCanaryBackup(context.Context, localbackup.RecoveryCanaryBackupRequest, string, *credentialref.Value) (string, string, error)
}

type recoveryCanaryCredentialBorrower interface {
	BorrowRecoveryCanaryCredential(context.Context, localbackup.RecoveryCredentialRequest, int64) (*credentialref.Value, error)
}

type unavailableRecoveryCanaryBackup struct{}

func (unavailableRecoveryCanaryBackup) CreateRecoveryBackup(context.Context, recovery.CanaryRequest) (string, string, error) {
	return "", "", failure.New(generated.ErrorCodePrerequisiteBlocked, "recovery-canary-backup", false)
}

func (creator *localRecoveryCanaryBackup) CreateRecoveryBackup(ctx context.Context, request recovery.CanaryRequest) (string, string, error) {
	if creator == nil || creator.authority == nil || creator.restores == nil || creator.backups == nil || creator.adapter == nil || creator.clock == nil {
		return "", "", failure.New(generated.ErrorCodePrerequisiteBlocked, "recovery-canary-backup", false)
	}
	bundle, _, err := creator.restores.RecoveredAuthorityBundle(ctx, request.PlanID)
	if err != nil || bundle.Binding.PlanDigest != request.PlanDigest || bundle.Binding.PointID == "" {
		return "", "", failure.New(generated.ErrorCodePlanStale, "recovery-canary-backup", false)
	}
	mutation := recoveryCanaryMutationRequest(request)
	var pointID, repositoryClass string
	err = creator.authority.WithRecoveryCanaryMutation(ctx, mutation, func(scoped context.Context) error {
		policy, policyDigest, prepareErr := creator.backups.PrepareRecoveryCanaryBackupPolicy(scoped, mutation, bundle.Binding.PointID, bundle.Binding.Source.ManifestDigest)
		if prepareErr != nil || policy.EncryptionKeyReferenceID == nil {
			return failure.New(generated.ErrorCodePrerequisiteBlocked, "recovery-canary-backup-policy", false)
		}
		value, borrowErr := creator.borrower.BorrowRecoveryCanaryCredential(scoped, localbackup.RecoveryCredentialRequest{ReferenceID: *policy.EncryptionKeyReferenceID, ConsumerID: localbackup.AdapterID, PlanID: request.PlanID, PlanDigest: request.PlanDigest, RunID: request.CanaryRunID, StepID: request.CanaryStepID, LeaseID: request.CanaryLeaseID, StateRevision: request.ExpectedStateRevision, RecoveryEpoch: request.RecoveryEpoch}, bundle.Binding.PriorRecoveryEpoch)
		if borrowErr != nil {
			return borrowErr
		}
		defer value.Close()
		pointID, repositoryClass, prepareErr = creator.adapter.CreateAndVerifyRecoveryCanaryBackup(scoped, localbackup.RecoveryCanaryBackupRequest{PlanID: request.PlanID, PlanDigest: request.PlanDigest, RunID: request.CanaryRunID, StepID: request.CanaryStepID, LeaseID: request.CanaryLeaseID, StateRevision: request.ExpectedStateRevision, PriorRecoveryEpoch: bundle.Binding.PriorRecoveryEpoch, RecoveryEpoch: request.RecoveryEpoch, MaximumExpiresAt: creator.clock().UTC().Add(10 * time.Minute), Plan: bundle.Plan}, policyDigest, value)
		return prepareErr
	})
	return pointID, repositoryClass, err
}

func recoveryCanaryMutationRequest(request recovery.CanaryRequest) store.RecoveryCanaryMutationRequest {
	return store.RecoveryCanaryMutationRequest{PlanID: request.PlanID, PlanDigest: request.PlanDigest, RunID: request.CanaryRunID, StepID: request.CanaryStepID, LeaseID: request.CanaryLeaseID, InstanceID: request.NewInstanceID, StateRevision: request.ExpectedStateRevision, RecoveryEpoch: request.RecoveryEpoch}
}
