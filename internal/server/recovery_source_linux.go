//go:build linux

package server

import (
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter/localbackup"
	"github.com/vegastack/vegastack-labs/internal/recovery"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func composeLocalRecoverySource(profile *serverconfig.LocalBackup, expectedUID uint32, backups *store.BackupRepository, inspector store.RestoredSQLiteInspector, credentials localbackup.RecoveryCredentialSource, trust localbackup.DependencyTrustVerifier, snapshots store.OnlineSnapshotSource) (recovery.SnapshotResolver, recovery.CompatibilityVerifier, recovery.AuditPositionVerifier, error) {
	config := localbackup.RecoveryRestoreConfig{LocalBackup: profile, ExpectedUID: expectedUID, Backups: backups, Inspector: inspector, Credentials: credentials, Trust: trust, Expectations: snapshots, Clock: time.Now}
	resolver, err := localbackup.NewRecoverySnapshotResolver(config)
	if err != nil {
		return nil, nil, nil, err
	}
	compatibility, err := localbackup.NewRecoveryCompatibilityVerifier(config)
	if err != nil {
		return nil, nil, nil, err
	}
	return resolver, compatibility, localbackup.RecoveryAuditVerifier{}, nil
}
