package server

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestMigrationRecoveryRequiresProtectedPreparedRoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.db")
	r := migrationRecoveryFor(path, 1000)
	if _, err := r.Prepare(context.Background(), nil, store.MigrationRequest{}); err == nil {
		t.Fatal("missing migration recovery root accepted")
	}
}
