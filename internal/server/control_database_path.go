package server

import (
	"errors"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"os"
	"path/filepath"
)

// Moving the fresh-install default is not permission to abandon existing data.
// The old database (including a dangling symlink or inaccessible entry) blocks
// both setup and ordinary open. Migration is deliberately not performed here.
func rejectLegacyControlDatabase(path string) error {
	if filepath.Base(path) != "control.db" || filepath.Base(filepath.Dir(path)) != "control" {
		return nil
	}
	legacy := filepath.Join(filepath.Dir(filepath.Dir(path)), "control.db")
	if _, err := os.Lstat(legacy); !errors.Is(err, os.ErrNotExist) {
		return failure.New(generated.ErrorCodePrerequisiteBlocked, "legacy-control-database", false)
	}
	return nil
}
