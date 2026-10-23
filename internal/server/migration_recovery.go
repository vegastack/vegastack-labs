package server

import (
	"context"
	"path/filepath"
	"time"

	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// A schema upgrade uses the existing verified local snapshot implementation.
// The operator must provision this protected sibling directory before upgrading;
// ordinary starts at the current schema do not create or inspect it.
type migrationRecovery struct {
	root string
	uid  uint32
}

func (r migrationRecovery) service() (*backup.Service, error) {
	return backup.New(backup.Config{Root: r.root, ExpectedUID: r.uid, Clock: time.Now})
}
func (r migrationRecovery) Prepare(ctx context.Context, s store.MigrationSource, q store.MigrationRequest) (store.VerifiedSnapshot, error) {
	service, err := r.service()
	if err != nil {
		return store.VerifiedSnapshot{}, err
	}
	return service.Prepare(ctx, s, q)
}
func (r migrationRecovery) VerifyRestorable(ctx context.Context, s store.MigrationSource, q store.VerifiedSnapshot) (store.RestoreEvidence, error) {
	service, err := r.service()
	if err != nil {
		return store.RestoreEvidence{}, err
	}
	return service.VerifyRestorable(ctx, s, q)
}
func migrationRecoveryFor(path string, uid uint32) store.MigrationRecovery {
	return migrationRecovery{root: filepath.Join(filepath.Dir(path), "migration-recovery"), uid: uid}
}
