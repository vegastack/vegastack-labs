//go:build !linux

package localretention

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
	"time"
)

const AdapterID = "local.retention"
const OperationType = "backup.local.retire"

type Config struct {
	LocalBackup *serverconfig.LocalBackup
	ExpectedUID uint32
	Backups     *store.BackupRepository
	Retirements *store.LocalRetirementRepository
	Inspector   store.RestoredSQLiteInspector
	Clock       func() time.Time
}
type Adapter struct{}

func New(Config) (*Adapter, error) {
	return nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "local-retention-linux", false)
}
func (*Adapter) Execute(context.Context, adapter.Operation) (adapter.Effect, error) {
	return adapter.Effect{}, failure.New(generated.ErrorCodePrerequisiteBlocked, "local-retention-linux", false)
}
func (*Adapter) Verify(context.Context, adapter.Operation, adapter.Effect) (adapter.Verification, error) {
	return adapter.Verification{}, failure.New(generated.ErrorCodePrerequisiteBlocked, "local-retention-linux", false)
}
func (*Adapter) ExecuteBoundWithCredentials(context.Context, adapter.Operation, adapter.ExactExecutionBinding, []*credentialref.Value) (adapter.Effect, error) {
	return adapter.Effect{}, failure.New(generated.ErrorCodePrerequisiteBlocked, "local-retention-linux", false)
}
