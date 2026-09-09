//go:build linux

package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/stateexport"
)

func TestArtifactStorePublishesDigestArtifactAndPreservesPrior(t *testing.T) {
	artifactStore := newProtectedArtifactStore(t)
	first := exportPublishRequest(t, 1)
	one, err := artifactStore.Publish(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	second := exportPublishRequest(t, 2)
	two, err := artifactStore.Publish(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	if two.Previous == nil || two.Previous.ArtifactID != one.Current.ArtifactID {
		t.Fatalf("publications = %#v / %#v", one, two)
	}
	if _, err := artifactStore.ReadArtifact(context.Background(), one.Current.ArtifactID); err != nil {
		t.Fatal("prior artifact was not retained")
	}
	current, err := artifactStore.InspectCurrent(context.Background())
	if err != nil || current == nil || *current != two.Current {
		t.Fatalf("current = %#v, %v", current, err)
	}
	retry, err := artifactStore.Publish(context.Background(), second)
	if err != nil || retry.Created || retry.Previous == nil || *retry.Previous != two.Current {
		t.Fatalf("retry = %#v, %v", retry, err)
	}
}

func TestArtifactStoreFaultsNeverExposePartialOrLosePreviousCurrent(t *testing.T) {
	for _, stage := range []string{"create-temp", "write", "file-sync", "reopen", "artifact-rename", "directory-sync", "pointer-rename", "pointer-directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			artifactStore := newProtectedArtifactStore(t)
			first, err := artifactStore.Publish(context.Background(), exportPublishRequest(t, 1))
			if err != nil {
				t.Fatal(err)
			}
			artifactStore.fault = func(got string) error {
				if got == stage {
					return errors.New("synthetic fault")
				}
				return nil
			}
			if _, err := artifactStore.Publish(context.Background(), exportPublishRequest(t, 2)); err == nil {
				t.Fatal("faulted publish succeeded")
			}
			artifactStore.fault = nil
			current, err := artifactStore.InspectCurrent(context.Background())
			if err != nil || current == nil || current.ArtifactID != first.Current.ArtifactID {
				t.Fatalf("prior pointer lost at %s: %#v, %v", stage, current, err)
			}
			entries, err := os.ReadDir(artifactStore.config.Root)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".current-") {
					t.Fatalf("partial pointer visible: %s", entry.Name())
				}
			}
			artifactEntries, err := os.ReadDir(filepath.Join(artifactStore.config.Root, exportArtifactDirectory))
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range artifactEntries {
				if strings.HasPrefix(entry.Name(), ".artifact-") {
					t.Fatalf("partial artifact visible: %s", entry.Name())
				}
			}
		})
	}
}

func TestArtifactStoreRejectsUnsafeRootsArtifactsAndRequests(t *testing.T) {
	root := protectedExportRoot(t)
	for name, mutate := range map[string]func(string) string{
		"relative": func(string) string { return "relative" },
		"unclean":  func(root string) string { return root + "/../" + filepath.Base(root) },
		"root":     func(string) string { return "/" },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewInventoryExportArtifactStore(InventoryExportArtifactConfig{Root: mutate(root), ExpectedUID: uint32(os.Geteuid())}); err == nil {
				t.Fatal("unsafe root accepted")
			}
		})
	}
	link := filepath.Join(filepath.Dir(root), "export-root-link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewInventoryExportArtifactStore(InventoryExportArtifactConfig{Root: link, ExpectedUID: uint32(os.Geteuid())}); err == nil {
		t.Fatal("symlink root accepted")
	}
	artifactStore := newProtectedArtifactStore(t)
	request := exportPublishRequest(t, 1)
	for _, candidate := range []stateexport.PublishRequest{
		{ArtifactID: "../current.json", ContentDigest: request.ContentDigest, Bytes: request.Bytes},
		{ArtifactID: request.ArtifactID, ContentDigest: "sha256:" + strings.Repeat("0", 64), Bytes: request.Bytes},
		{ArtifactID: request.ArtifactID, ContentDigest: request.ContentDigest, Bytes: append([]byte(nil), request.Bytes[:len(request.Bytes)-1]...)},
	} {
		if _, err := artifactStore.Publish(context.Background(), candidate); err == nil {
			t.Fatal("unsafe publish accepted")
		}
	}
}

func TestArtifactStoreRestoreIsCompareAndSwap(t *testing.T) {
	artifactStore := newProtectedArtifactStore(t)
	one, err := artifactStore.Publish(context.Background(), exportPublishRequest(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	two, err := artifactStore.Publish(context.Background(), exportPublishRequest(t, 2))
	if err != nil {
		t.Fatal(err)
	}
	wrong := two.Current
	wrong.ContentDigest = "sha256:" + strings.Repeat("0", 64)
	if err := artifactStore.RestoreCurrent(context.Background(), wrong, &one.Current); err == nil {
		t.Fatal("mismatched replacement restored")
	}
	if err := artifactStore.RestoreCurrent(context.Background(), two.Current, &one.Current); err != nil {
		t.Fatal(err)
	}
	current, err := artifactStore.InspectCurrent(context.Background())
	if err != nil || current == nil || *current != one.Current {
		t.Fatalf("current = %#v, %v", current, err)
	}
}

func newProtectedArtifactStore(t *testing.T) *inventoryExportArtifactStore {
	t.Helper()
	root := protectedExportRoot(t)
	artifactStore, err := NewInventoryExportArtifactStore(InventoryExportArtifactConfig{Root: root, ExpectedUID: uint32(os.Geteuid())})
	if err != nil {
		t.Fatal(err)
	}
	return artifactStore.(*inventoryExportArtifactStore)
}

func protectedExportRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func exportPublishRequest(t *testing.T, revision int64) stateexport.PublishRequest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "stateexport", "testdata", "signed-export-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.TrimSuffix(string(raw), "\n"))
	document, err := stateexport.DecodeSignedExport(raw)
	if err != nil {
		t.Fatal(err)
	}
	document.Payload.StateRevision = revision
	bytes, artifactDigest, err := stateexport.CanonicalSignedExport(document)
	if err != nil {
		t.Fatal(err)
	}
	return stateexport.PublishRequest{ArtifactID: "sha256:" + strings.ToLower(stringHex(artifactDigest[:])), ContentDigest: document.ContentDigest, Bytes: bytes}
}

func stringHex(raw []byte) string {
	const alphabet = "0123456789abcdef"
	result := make([]byte, len(raw)*2)
	for index, value := range raw {
		result[index*2] = alphabet[value>>4]
		result[index*2+1] = alphabet[value&15]
	}
	return string(result)
}
