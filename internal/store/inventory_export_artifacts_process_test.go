//go:build linux

package store

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
)

func TestArtifactStoreCrashAfterPointerSwapRetainsBothArtifacts(t *testing.T) {
	if os.Getenv("VSK_EXPORT_CRASH_CHILD") == "1" {
		root := os.Getenv("VSK_EXPORT_CRASH_ROOT")
		storeValue, err := NewInventoryExportArtifactStore(InventoryExportArtifactConfig{Root: root, ExpectedUID: uint32(os.Geteuid())})
		if err != nil {
			os.Exit(81)
		}
		artifactStore := storeValue.(*inventoryExportArtifactStore)
		artifactStore.fault = func(stage string) error {
			if stage == "pointer-directory-sync" {
				os.Exit(86)
			}
			return nil
		}
		_, _ = artifactStore.Publish(context.Background(), exportPublishRequest(t, 2))
		os.Exit(82)
	}
	artifactStore := newProtectedArtifactStore(t)
	prior, err := artifactStore.Publish(context.Background(), exportPublishRequest(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestArtifactStoreCrashAfterPointerSwapRetainsBothArtifacts$")
	command.Env = append(os.Environ(), "VSK_EXPORT_CRASH_CHILD=1", "VSK_EXPORT_CRASH_ROOT="+artifactStore.config.Root)
	err = command.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 86 {
		t.Fatalf("child result = %v", err)
	}
	current, err := artifactStore.InspectCurrent(context.Background())
	if err != nil || current == nil || current.ArtifactID == prior.Current.ArtifactID {
		t.Fatalf("post-crash current = %#v, %v", current, err)
	}
	if _, err := artifactStore.ReadArtifact(context.Background(), prior.Current.ArtifactID); err != nil {
		t.Fatal("prior immutable artifact was lost")
	}
	if _, err := artifactStore.ReadArtifact(context.Background(), current.ArtifactID); err != nil {
		t.Fatal("replacement immutable artifact was lost")
	}
}
