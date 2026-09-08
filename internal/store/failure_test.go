//go:build linux

package store

import (
	"context"
	"os"
	"testing"
)

func TestFailureOpeningCorruptAndPermissionChangedDatabaseIsSanitized(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(string) error
	}{
		{name: "corrupt", mutate: func(path string) error { return os.WriteFile(path, []byte("corrupt synthetic bytes"), 0o600) }},
		{name: "permissions", mutate: func(path string) error { return os.Chmod(path, 0o640) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := testConfig(t)
			store, err := Open(context.Background(), config)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			if err := test.mutate(config.DatabasePath); err != nil {
				t.Fatal(err)
			}
			config.Mode = OpenExisting
			_, err = Open(context.Background(), config)
			if Code(err) != "INTEGRITY_FAILURE" || containsFold(err.Error(), config.DatabasePath) || containsFold(err.Error(), "corrupt synthetic") {
				t.Fatalf("unsafe error = %q", err)
			}
		})
	}
}
