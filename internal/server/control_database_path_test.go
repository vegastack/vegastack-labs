package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
	"os"
	"path/filepath"
	"testing"
)

func TestLegacyControlDatabaseBlocksSetupAndOpen(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		t.Run(map[bool]string{false: "existing-data", true: "dangling-symlink"}[symlink], func(t *testing.T) {
			root := t.TempDir()
			legacy := filepath.Join(root, "control.db")
			fresh := filepath.Join(root, "control", "control.db")
			if symlink {
				if err := os.Symlink(filepath.Join(root, "missing"), legacy); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(legacy, []byte("preserve-original"), 0600); err != nil {
				t.Fatal(err)
			}
			op := &Operations{databasePath: fresh, openStore: func(context.Context, store.Config) (*store.Store, error) {
				t.Fatal("attempted DB open")
				return nil, nil
			}}
			if err := op.RunSetup(context.Background(), "unused", "unused"); err == nil {
				t.Fatal("legacy setup accepted")
			}
			if _, err := op.openAuthorityWithPromotion(context.Background(), serverconfig.Profile{}); err == nil {
				t.Fatal("legacy open accepted")
			}
			if _, err := os.Lstat(fresh); !os.IsNotExist(err) {
				t.Fatal("replacement DB created")
			}
			if !symlink {
				raw, err := os.ReadFile(legacy)
				if err != nil || string(raw) != "preserve-original" {
					t.Fatal("old database changed")
				}
			}
		})
	}
}
