//go:build !linux

// Package localbackup is unavailable off Linux: the guarded object boundary and
// sealed password FD depend on openat2, O_NOFOLLOW, SO_PEERCRED and memfd_create.
// The adapter fails closed so no non-Linux platform can create a local point.
package localbackup

import (
	"context"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

const (
	AdapterID           = "local.backup"
	OperationType       = "backup.local.create"
	VerifyOperationType = "backup.local.verify"
)

type PlanSource interface {
	GetPlan(context.Context, string) (store.PlanCommitResult, error)
}

type Config struct {
	LocalBackup *serverconfig.LocalBackup
	ExpectedUID uint32
	Backups     *store.BackupRepository
	Snapshots   store.OnlineSnapshotSource
	Inspector   store.RestoredSQLiteInspector
	Trust       DependencyTrustVerifier
	LiveProof   bool
	Plans       PlanSource
	Hooks       *backup.HookRegistry
	Runner      backup.ResticRunner
	Clock       func() time.Time
}

type Adapter struct{}

type RecoveryCanaryBackupRequest struct {
	PlanID, PlanDigest, RunID, StepID, LeaseID       string
	StateRevision, PriorRecoveryEpoch, RecoveryEpoch int64
	MaximumExpiresAt                                 time.Time
	Plan                                             generated.Plan
}

func (*Adapter) CreateAndVerifyRecoveryCanaryBackup(context.Context, RecoveryCanaryBackupRequest, string, *credentialref.Value) (string, string, error) {
	return "", "", failure.New(generated.ErrorCodePrerequisiteBlocked, "recovery-canary-backup", false)
}

func New(Config) (*Adapter, error) {
	return nil, failure.New(generated.ErrorCodeUnsupportedPlatform, "local-backup", false)
}

func (*Adapter) Execute(context.Context, adapter.Operation) (adapter.Effect, error) {
	return adapter.Effect{}, failure.New(generated.ErrorCodeUnsupportedPlatform, "local-backup", false)
}

func (*Adapter) Verify(context.Context, adapter.Operation, adapter.Effect) (adapter.Verification, error) {
	return adapter.Verification{}, failure.New(generated.ErrorCodeUnsupportedPlatform, "local-backup", false)
}

func (*Adapter) ExecuteBoundWithCredentials(context.Context, adapter.Operation, adapter.ExactExecutionBinding, []*credentialref.Value) (adapter.Effect, error) {
	return adapter.Effect{}, failure.New(generated.ErrorCodeUnsupportedPlatform, "local-backup", false)
}
