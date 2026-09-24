//go:build !linux

package localbackup

import (
	"context"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/recovery"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type RecoveryCredentialRequest struct {
	ReferenceID, ConsumerID, PlanID, PlanDigest, RunID, StepID, LeaseID string
	StateRevision, RecoveryEpoch                                        int64
}
type RecoveryCredentialSource interface {
	BorrowRecoveryCredential(context.Context, RecoveryCredentialRequest) (*credentialref.Value, error)
}
type RecoveryRestoreConfig struct{}
type RecoverySnapshotResolver struct{}
type RecoveryCompatibilityVerifier struct{}
type RecoveryAuditVerifier struct{}

func NewRecoverySnapshotResolver(RecoveryRestoreConfig) (*RecoverySnapshotResolver, error) {
	return nil, failure.New(generated.ErrorCodeUnsupportedPlatform, "restore-local-runtime", false)
}
func NewRecoveryCompatibilityVerifier(RecoveryRestoreConfig) (*RecoveryCompatibilityVerifier, error) {
	return nil, failure.New(generated.ErrorCodeUnsupportedPlatform, "restore-local-runtime", false)
}
func (*RecoverySnapshotResolver) ResolveLocal(context.Context, store.LocalRecoverySource) (recovery.SnapshotReader, error) {
	return nil, failure.New(generated.ErrorCodeUnsupportedPlatform, "restore-local-runtime", false)
}
func (*RecoveryCompatibilityVerifier) VerifyRestoreCompatibility(context.Context, recovery.SourceSelection, store.LocalRecoverySource) error {
	return failure.New(generated.ErrorCodeUnsupportedPlatform, "restore-local-runtime", false)
}
func (RecoveryAuditVerifier) VerifyRestoreAuditPosition(context.Context, store.LocalRecoverySource, recovery.SnapshotReader) (recovery.AuditContinuity, error) {
	return recovery.AuditContinuity{}, failure.New(generated.ErrorCodeUnsupportedPlatform, "restore-local-runtime", false)
}
