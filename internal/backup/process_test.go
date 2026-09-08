//go:build linux

package backup

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

const processHelperEnvironment = "VSK_BACKUP_PROCESS_HELPER"

func TestPublicationCrashLinearization(t *testing.T) {
	if os.Getenv(processHelperEnvironment) == "1" {
		runPublicationProcessHelper()
		return
	}
	for _, test := range []struct {
		point     string
		published bool
	}{
		{point: "after-backup", published: false},
		{point: "after-database-sync", published: false},
		{point: "after-manifest-sync", published: false},
		{point: "before-rename", published: false},
		{point: "after-rename", published: true},
		{point: "after-root-sync", published: true},
	} {
		t.Run(test.point, func(t *testing.T) {
			root, snapshotID := runKilledSnapshotHelper(t, test.point)
			layout, err := newArtifactLayout(Config{Root: root, ExpectedUID: uint32(os.Geteuid())})
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = layout.OpenPublished(context.Background(), snapshotID)
			if test.published && err != nil {
				t.Fatalf("published generation rejected: %v", err)
			}
			if !test.published && err == nil {
				t.Fatal("incomplete generation became discoverable")
			}
		})
	}
}

func TestPublishedCorruptionRemainsPresentButIsRejected(t *testing.T) {
	for _, target := range []string{"database", "manifest"} {
		t.Run(target, func(t *testing.T) {
			layout := newTestLayout(t)
			staged := beginValidGeneration(t, layout, "00112233445566778899aabbccddeeff", []byte("sqlite fixture bytes"))
			published, err := layout.Publish(context.Background(), staged)
			if err != nil {
				t.Fatal(err)
			}
			path := published.database
			if target == "manifest" {
				path = published.manifest
			}
			if err := os.WriteFile(path, []byte("truncated"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := layout.OpenPublished(context.Background(), published.id); err == nil {
				t.Fatal("corrupt generation accepted")
			}
			if _, err := os.Lstat(published.dir); err != nil {
				t.Fatalf("corrupt evidence was removed: %v", err)
			}
		})
	}
}

func runKilledSnapshotHelper(t *testing.T, point string) (string, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	id := "00112233445566778899aabbccddeeff"
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestPublicationCrashLinearization$")
	command.Env = append(os.Environ(), processHelperEnvironment+"=1", "VSK_BACKUP_PROCESS_POINT="+point, "VSK_BACKUP_PROCESS_ROOT="+root, "VSK_BACKUP_PROCESS_ID="+id)
	if err := command.Run(); err == nil {
		t.Fatal("abrupt helper returned success")
	}
	return root, id
}

func runPublicationProcessHelper() {
	root := os.Getenv("VSK_BACKUP_PROCESS_ROOT")
	id := os.Getenv("VSK_BACKUP_PROCESS_ID")
	point := os.Getenv("VSK_BACKUP_PROCESS_POINT")
	layoutValue, err := newArtifactLayout(Config{Root: root, ExpectedUID: uint32(os.Geteuid())})
	if err != nil {
		os.Exit(40)
	}
	layout := layoutValue.(*linuxArtifactLayout)
	staged, err := layout.BeginGeneration(context.Background(), id)
	if err != nil {
		os.Exit(41)
	}
	database := []byte("sqlite fixture bytes")
	if err := os.WriteFile(staged.database, database, 0o600); err != nil {
		os.Exit(42)
	}
	if point == "after-backup" {
		os.Exit(90)
	}
	identity, size, digest, err := layout.SealDatabase(context.Background(), staged)
	if err != nil {
		os.Exit(43)
	}
	staged.databaseIdentity = identity
	if point == "after-database-sync" {
		os.Exit(90)
	}
	body, err := marshalManifest(testArtifactManifest(id, size, digest))
	if err != nil || layout.WriteManifest(context.Background(), staged, body) != nil {
		os.Exit(44)
	}
	if point == "after-manifest-sync" || point == "before-rename" {
		os.Exit(90)
	}
	if point == "after-rename" {
		if syncDirectory(staged.dir) != nil || unix.Renameat2(unix.AT_FDCWD, staged.dir, unix.AT_FDCWD, filepath.Join(root, id), unix.RENAME_NOREPLACE) != nil {
			os.Exit(45)
		}
		os.Exit(90)
	}
	if _, err := layout.Publish(context.Background(), staged); err != nil {
		os.Exit(46)
	}
	os.Exit(90)
}
