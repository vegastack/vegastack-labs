package server

import (
	"context"

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
func NewQualifiedRecoveryCanaryPortFactory(checkpoints recovery.RecoveryCheckpointAppender, backups recovery.RecoveryBackupCreator) (RecoveryCanaryPortFactory, error) {
	if checkpoints == nil || backups == nil {
		return nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "recovery-canary-capabilities", false)
	}
	return func(_ context.Context, _ serverconfig.Profile, authority *store.Store, repository *store.BackupRepository) (recovery.CanaryAuditVerifier, recovery.CanaryBackupVerifier, error) {
		if authority == nil || repository == nil {
			return nil, nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "recovery-canary-capabilities", false)
		}
		return recovery.IndependentCheckpointCanary{Appender: checkpoints, Reader: authority}, recovery.CurrentEpochBackupCanary{Creator: backups, Reader: repository}, nil
	}, nil
}

func systemRecoveryCanaryPortFactory() RecoveryCanaryPortFactory {
	capabilities := NewSystemRecoveryCanaryCapabilities()
	factory, err := NewQualifiedRecoveryCanaryPortFactory(capabilities, capabilities)
	if err != nil {
		return nil
	}
	return factory
}
