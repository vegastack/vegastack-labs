//go:build linux

package store

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInitializeReopenAndSingleWriter(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "control.db")
	cfg := Config{DatabasePath: path, Mode: InitializeNew, BusyTimeout: 25 * time.Millisecond, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test"}
	first, err := Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })

	settings := readSettingsForTest(t, first)
	if settings != (sqliteSettings{JournalMode: "delete", Synchronous: 2, ForeignKeys: 1, BusyTimeoutMS: 25}) {
		t.Fatalf("settings = %#v", settings)
	}
	cfg.Mode = OpenExisting
	if _, err := Open(context.Background(), cfg); Code(err) != "STATE_CONFLICT" {
		t.Fatalf("second writer code = %q", Code(err))
	}
	got, err := first.Health(context.Background())
	if err != nil || got.Revision != (RevisionToken{}) || got.Mode != DatabaseReady {
		t.Fatalf("health = %#v, %v", got, err)
	}
}

func TestInitializeAndOpenRejectUnsafeTargets(t *testing.T) {
	ctx := context.Background()
	t.Run("existing empty", func(t *testing.T) {
		cfg := testConfig(t)
		if err := os.WriteFile(cfg.DatabasePath, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(ctx, cfg); Code(err) != "STATE_CONFLICT" {
			t.Fatalf("code = %q", Code(err))
		}
	})
	t.Run("symlink", func(t *testing.T) {
		cfg := testConfig(t)
		target := cfg.DatabasePath + ".target"
		if err := os.WriteFile(target, []byte("not-a-database"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, cfg.DatabasePath); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(ctx, cfg); Code(err) != "INTEGRITY_FAILURE" {
			t.Fatalf("code = %q", Code(err))
		}
	})
	t.Run("weak parent mode", func(t *testing.T) {
		cfg := testConfig(t)
		if err := os.Chmod(filepath.Dir(cfg.DatabasePath), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(ctx, cfg); Code(err) != "INTEGRITY_FAILURE" {
			t.Fatalf("code = %q", Code(err))
		}
	})
	t.Run("missing existing database", func(t *testing.T) {
		cfg := testConfig(t)
		cfg.Mode = OpenExisting
		if _, err := Open(ctx, cfg); Code(err) != "INTEGRITY_FAILURE" {
			t.Fatalf("code = %q", Code(err))
		}
	})
	t.Run("wrong parent owner", func(t *testing.T) {
		cfg := testConfig(t)
		cfg.ExpectedUID++
		if _, err := Open(ctx, cfg); Code(err) != "INTEGRITY_FAILURE" {
			t.Fatalf("code = %q", Code(err))
		}
	})
}

func TestOpenRejectsHardLinkAndDetectsReplacement(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig(t)
	store, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	link := cfg.DatabasePath + ".hardlink"
	if err := os.Link(cfg.DatabasePath, link); err != nil {
		t.Fatal(err)
	}
	cfg.Mode = OpenExisting
	if _, err := Open(ctx, cfg); Code(err) != "INTEGRITY_FAILURE" {
		t.Fatalf("hard-link code = %q", Code(err))
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	store, err = Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := os.Rename(cfg.DatabasePath, cfg.DatabasePath+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.DatabasePath, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Health(ctx); Code(err) != "INTEGRITY_FAILURE" {
		t.Fatalf("replacement code = %q", Code(err))
	}
}

func TestOpenRejectsWrongModeAndPermissionLoss(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig(t)
	store, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	lockInfo, err := os.Stat(cfg.DatabasePath + ".lock")
	if err != nil || !lockInfo.Mode().IsRegular() || lockInfo.Mode().Perm() != 0o600 {
		t.Fatalf("persistent lock sidecar = %#v, %v", lockInfo, err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("idempotent close: %v", err)
	}
	if err := os.Chmod(cfg.DatabasePath, 0o640); err != nil {
		t.Fatal(err)
	}
	cfg.Mode = OpenExisting
	if _, err := Open(ctx, cfg); Code(err) != "INTEGRITY_FAILURE" {
		t.Fatalf("wrong mode code = %q", Code(err))
	}
	if err := os.Chmod(cfg.DatabasePath, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err = Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := os.Chmod(cfg.DatabasePath, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Health(ctx); Code(err) != "INTEGRITY_FAILURE" {
		t.Fatalf("permission-loss code = %q", Code(err))
	}
}

func TestOpenFailsClosedOnFilesystemRejectionAndPartialOpen(t *testing.T) {
	ctx := context.Background()
	t.Run("network filesystem", func(t *testing.T) {
		cfg := testConfig(t)
		cfg.Filesystem = rejectingFilesystem{
			linuxFilesystem: linuxFilesystem{},
			parentErr:       filesystemError(io.ErrUnexpectedEOF),
		}
		if _, err := Open(ctx, cfg); Code(err) != "INTEGRITY_FAILURE" {
			t.Fatalf("code = %q", Code(err))
		}
		if _, err := os.Lstat(cfg.DatabasePath); !os.IsNotExist(err) {
			t.Fatalf("database created after parent rejection: %v", err)
		}
	})
	t.Run("writer lock", func(t *testing.T) {
		cfg := testConfig(t)
		cfg.Filesystem = rejectingFilesystem{
			linuxFilesystem: linuxFilesystem{},
			lockErr:         newStoreError("STATE_CONFLICT", "database-writer", true, nil),
		}
		if _, err := Open(ctx, cfg); Code(err) != "STATE_CONFLICT" {
			t.Fatalf("code = %q", Code(err))
		}
		if _, err := os.Stat(cfg.DatabasePath); err != nil {
			t.Fatalf("exclusive database creation did not complete safely: %v", err)
		}
	})
}

type rejectingFilesystem struct {
	linuxFilesystem
	parentErr error
	lockErr   error
}

func (filesystem rejectingFilesystem) InspectParent(ctx context.Context, path string, uid uint32) (FileIdentity, error) {
	if filesystem.parentErr != nil {
		return FileIdentity{}, filesystem.parentErr
	}
	return filesystem.linuxFilesystem.InspectParent(ctx, path, uid)
}

func (filesystem rejectingFilesystem) AcquireWriterLock(ctx context.Context, path string, uid uint32) (io.Closer, error) {
	if filesystem.lockErr != nil {
		return nil, filesystem.lockErr
	}
	return filesystem.linuxFilesystem.AcquireWriterLock(ctx, path, uid)
}
