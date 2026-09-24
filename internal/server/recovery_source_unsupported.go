//go:build !linux

package server

import (
	"github.com/vegastack/vegastack-labs/internal/adapter/localbackup"
	"github.com/vegastack/vegastack-labs/internal/recovery"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func composeLocalRecoverySource(*serverconfig.LocalBackup, uint32, *store.BackupRepository, store.RestoredSQLiteInspector, localbackup.RecoveryCredentialSource, localbackup.DependencyTrustVerifier, store.OnlineSnapshotSource) (recovery.SnapshotResolver, recovery.CompatibilityVerifier, recovery.AuditPositionVerifier, error) {
	_, err := localbackup.NewRecoverySnapshotResolver(localbackup.RecoveryRestoreConfig{})
	return nil, nil, nil, err
}
