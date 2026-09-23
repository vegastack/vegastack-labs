package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type AuthorityBinding struct {
	InstanceID    string
	RecoveryEpoch int64
	StateRevision int64
	Mode          string
}

type AuthorityStateReader interface {
	CurrentAuthority(context.Context) (AuthorityBinding, error)
}

type AuthorityAdmission struct{ State AuthorityStateReader }

func (admission AuthorityAdmission) Require(ctx context.Context, expected AuthorityBinding) error {
	if ctx == nil || ctx.Err() != nil || admission.State == nil || expected.InstanceID == "" || expected.RecoveryEpoch < 0 || expected.StateRevision < 0 || expected.Mode == "" {
		return failure.New(generated.ErrorCodePrerequisiteBlocked, "recovery-authority", false)
	}
	current, err := admission.State.CurrentAuthority(ctx)
	if err != nil {
		return err
	}
	if current.RecoveryEpoch != expected.RecoveryEpoch {
		return failure.New(generated.ErrorCodeRecoveryEpochMismatch, "recovery-authority", false)
	}
	if current.InstanceID != expected.InstanceID || current.StateRevision != expected.StateRevision || current.Mode != expected.Mode {
		return failure.New(generated.ErrorCodeStateConflict, "recovery-authority", false)
	}
	return nil
}

type CanaryRequest struct {
	PlanID, PlanDigest, NewInstanceID, FenceSetDigest string
	RecoveryEpoch, ExpectedStateRevision              int64
}

type CanaryReadVerifier interface {
	VerifyRecoveryRead(context.Context, CanaryRequest) error
}
type OldEpochVerifier interface {
	VerifyOldEpochDenied(context.Context, CanaryRequest) error
}
type CanaryNoopRunner interface {
	RunRecoveryCanaryNoop(context.Context, CanaryRequest) (string, error)
}
type CanaryAuditVerifier interface {
	AppendAndVerifyRecoveryCheckpoint(context.Context, CanaryRequest, string) (string, error)
}
type CanaryBackupVerifier interface {
	CreateAndVerifyRecoveryBackup(context.Context, CanaryRequest) (string, error)
}
type FormerWriterVerifier interface {
	VerifyFormerWriterDenied(context.Context, CanaryRequest) error
}
type AuthorityEnabler interface {
	EnableAuthority(context.Context, CanaryRequest, string) error
}

type CanaryVerifier struct {
	Read         CanaryReadVerifier
	OldEpoch     OldEpochVerifier
	Noop         CanaryNoopRunner
	Audit        CanaryAuditVerifier
	Backup       CanaryBackupVerifier
	FormerWriter FormerWriterVerifier
	Enable       AuthorityEnabler
	Clock        func() time.Time
}

func (verifier CanaryVerifier) Verify(ctx context.Context, request CanaryRequest) (generated.RestoreCanaryResult, error) {
	blocked := func() (generated.RestoreCanaryResult, error) {
		return generated.RestoreCanaryResult{}, failure.New(generated.ErrorCodeRecoveryRequired, "recovery-canary", false)
	}
	if ctx == nil || ctx.Err() != nil || verifier.Read == nil || verifier.OldEpoch == nil || verifier.Noop == nil || verifier.Audit == nil || verifier.Backup == nil || verifier.FormerWriter == nil || verifier.Enable == nil || verifier.Clock == nil || request.PlanID == "" || request.NewInstanceID == "" || request.RecoveryEpoch < 1 || request.ExpectedStateRevision < 0 || !restoreDigest.MatchString(request.PlanDigest) || !restoreDigest.MatchString(request.FenceSetDigest) {
		return blocked()
	}
	if err := verifier.Read.VerifyRecoveryRead(ctx, request); err != nil {
		return blocked()
	}
	if err := verifier.OldEpoch.VerifyOldEpochDenied(ctx, request); err != nil {
		return blocked()
	}
	noopID, err := verifier.Noop.RunRecoveryCanaryNoop(ctx, request)
	if err != nil || noopID == "" {
		return blocked()
	}
	checkpointID, err := verifier.Audit.AppendAndVerifyRecoveryCheckpoint(ctx, request, noopID)
	if err != nil || checkpointID == "" {
		return blocked()
	}
	backupID, err := verifier.Backup.CreateAndVerifyRecoveryBackup(ctx, request)
	if err != nil || backupID == "" {
		return blocked()
	}
	if err := verifier.FormerWriter.VerifyFormerWriterDenied(ctx, request); err != nil {
		return blocked()
	}
	at := verifier.Clock().UTC()
	if at.IsZero() {
		return blocked()
	}
	stamp := at.Format(time.RFC3339)
	result := generated.RestoreCanaryResult{Schema: generated.SchemaIDRestoreCanaryResult, SchemaVersion: "1.1.0", ReadVerified: true, OldEpochDenied: true, NoopRunID: noopID, AuditCheckpointID: checkpointID, BackupPointID: backupID, FormerWriterDenied: true, Status: "verified", VerifiedAt: &stamp}
	raw, err := json.Marshal(result)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDRestoreCanaryResult, raw, generated.ContractExact) != nil {
		return blocked()
	}
	digest := canaryDigest(request, result)
	if err := verifier.Enable.EnableAuthority(ctx, request, digest); err != nil {
		return blocked()
	}
	return result, nil
}

func canaryDigest(request CanaryRequest, result generated.RestoreCanaryResult) string {
	raw, _ := json.Marshal(struct {
		Domain  string
		Request CanaryRequest
		Result  generated.RestoreCanaryResult
	}{"vegastack-labs.dev/recovery-canary/v1", request, result})
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
