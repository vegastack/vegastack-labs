package recovery

import (
	"context"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// RecoveryCheckpointAppender is the qualified #107 mutation capability. Its
// implementation owns signer/exporter/independent-reader custody; this layer
// independently reads the resulting public checkpoint from SQLite.
type RecoveryCheckpointAppender interface {
	AppendRecoveryCheckpoint(context.Context, CanaryRequest, string) (string, error)
}

type AuditCheckpointReader interface {
	GetAuditCheckpoint(context.Context, string) (generated.AuditCheckpoint, error)
}

type IndependentCheckpointCanary struct {
	Appender RecoveryCheckpointAppender
	Reader   AuditCheckpointReader
}

func (canary IndependentCheckpointCanary) AppendAndVerifyRecoveryCheckpoint(ctx context.Context, request CanaryRequest, noopRunID string) (string, error) {
	if ctx == nil || ctx.Err() != nil || canary.Appender == nil || canary.Reader == nil || noopRunID == "" {
		return "", canaryCapabilityError("recovery-canary-audit")
	}
	id, err := canary.Appender.AppendRecoveryCheckpoint(ctx, request, noopRunID)
	if err != nil || id == "" {
		return "", canaryCapabilityError("recovery-canary-audit")
	}
	checkpoint, err := canary.Reader.GetAuditCheckpoint(ctx, id)
	if err != nil || checkpoint.CheckpointID != id || checkpoint.InstanceID != request.NewInstanceID || checkpoint.RecoveryEpoch != request.RecoveryEpoch || checkpoint.Status != "anchored" || checkpoint.VerificationStatus != "verified" || checkpoint.SourceKind != "independent" || checkpoint.ProofClass != "live" || checkpoint.SignatureDigest == nil || checkpoint.ExportReceiptDigest == nil || checkpoint.IndependentReadDigest == nil || checkpoint.IndependentCopyDigest == nil || checkpoint.VerifiedAt == nil {
		return "", canaryCapabilityError("recovery-canary-audit")
	}
	return id, nil
}

// RecoveryBackupCreator is the qualified #106/#117 mutation capability. It
// creates and verifies one point, while this layer independently resolves the
// current local-last-good row before accepting it into the canary.
type RecoveryBackupCreator interface {
	CreateRecoveryBackup(context.Context, CanaryRequest) (pointID, repositoryClass string, err error)
}

type LocalRecoverySourceReader interface {
	CurrentLocalRecoverySource(context.Context, string) (store.LocalRecoverySource, error)
}

type CurrentEpochBackupCanary struct {
	Creator RecoveryBackupCreator
	Reader  LocalRecoverySourceReader
}

func (canary CurrentEpochBackupCanary) CreateAndVerifyRecoveryBackup(ctx context.Context, request CanaryRequest) (string, error) {
	if ctx == nil || ctx.Err() != nil || canary.Creator == nil || canary.Reader == nil {
		return "", canaryCapabilityError("recovery-canary-backup")
	}
	pointID, class, err := canary.Creator.CreateRecoveryBackup(ctx, request)
	if err != nil || pointID == "" || class != "standard" && class != "critical" {
		return "", canaryCapabilityError("recovery-canary-backup")
	}
	source, err := canary.Reader.CurrentLocalRecoverySource(ctx, class)
	if err != nil || source.Point.PointID != pointID || source.Point.RecoveryEpoch != request.RecoveryEpoch || source.Verification.PointID != pointID || source.Verification.RecoveryEpoch != request.RecoveryEpoch || source.Verification.Status != "local-verified" || source.Verification.ProofClass != "live" || source.Verification.StateRevision < request.ExpectedStateRevision || source.FullReadAt.IsZero() || source.FunctionalRestoredAt.IsZero() {
		return "", canaryCapabilityError("recovery-canary-backup")
	}
	return pointID, nil
}

func canaryCapabilityError(target string) error {
	return failure.New(generated.ErrorCodePrerequisiteBlocked, target, false)
}
