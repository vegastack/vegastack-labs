//go:build linux

package backup

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPublishIsNoReplaceAndStagingIsNotDiscoverable(t *testing.T) {
	layout := newTestLayout(t)
	staged := beginCompleteGeneration(t, layout, "00112233445566778899aabbccddeeff", []byte("first"))
	if _, _, err := layout.OpenPublished(context.Background(), staged.id); err == nil {
		t.Fatal("staging generation was discoverable")
	}
	published, err := layout.Publish(context.Background(), staged)
	if err != nil {
		t.Fatal(err)
	}
	before := mustReadFile(t, published.database)

	replacement := beginCompleteGeneration(t, layout, staged.id, []byte("second"))
	if _, err := layout.Publish(context.Background(), replacement); err == nil {
		t.Fatal("existing generation was replaced")
	}
	if got := mustReadFile(t, published.database); !bytes.Equal(got, before) {
		t.Fatal("published generation changed")
	}
}

func TestArtifactLayoutRejectsUnsafeRootsAndChildren(t *testing.T) {
	t.Run("relative", func(t *testing.T) {
		if _, err := newArtifactLayout(Config{Root: "relative", ExpectedUID: uint32(os.Geteuid())}); err == nil {
			t.Fatal("relative root accepted")
		}
	})
	t.Run("unclean", func(t *testing.T) {
		root := t.TempDir()
		if _, err := newArtifactLayout(Config{Root: root + "/../" + filepath.Base(root), ExpectedUID: uint32(os.Geteuid())}); err == nil {
			t.Fatal("unclean root accepted")
		}
	})
	t.Run("weak root", func(t *testing.T) {
		root := t.TempDir()
		if err := os.Chmod(root, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := newArtifactLayout(Config{Root: root, ExpectedUID: uint32(os.Geteuid())}); err == nil {
			t.Fatal("weak root accepted")
		}
	})
	t.Run("symlink root", func(t *testing.T) {
		parent := t.TempDir()
		target := filepath.Join(parent, "target")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(parent, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := newArtifactLayout(Config{Root: link, ExpectedUID: uint32(os.Geteuid())}); err == nil {
			t.Fatal("symlink root accepted")
		}
	})
	t.Run("weak database", func(t *testing.T) {
		layout := newTestLayout(t)
		staged, err := layout.BeginGeneration(context.Background(), "00112233445566778899aabbccddeeff")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(staged.database, []byte("database"), 0o640); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := layout.SealDatabase(context.Background(), staged); err == nil {
			t.Fatal("weak database accepted")
		}
	})
	t.Run("hardlink", func(t *testing.T) {
		layout := newTestLayout(t)
		staged, err := layout.BeginGeneration(context.Background(), "00112233445566778899aabbccddeeff")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(staged.database, []byte("database"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(staged.database, staged.database+".link"); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := layout.SealDatabase(context.Background(), staged); err == nil {
			t.Fatal("hardlinked database accepted")
		}
	})
}

func TestArtifactOpenRejectsIdentitySwapAndInvalidNames(t *testing.T) {
	layout := newTestLayout(t)
	staged := beginCompleteGeneration(t, layout, "00112233445566778899aabbccddeeff", []byte("first"))
	published, err := layout.Publish(context.Background(), staged)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := layout.OpenPublished(context.Background(), ".staging-00112233445566778899aabbccddeeff"); err == nil {
		t.Fatal("staging name accepted")
	}
	if err := os.Rename(published.database, published.database+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(published.database, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := layout.OpenPublished(context.Background(), published.id); err == nil {
		t.Fatal("replacement database accepted")
	}
}

func TestArtifactLayoutHonorsCancellation(t *testing.T) {
	layout := newTestLayout(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := layout.BeginGeneration(ctx, "00112233445566778899aabbccddeeff"); err == nil || err.Error() != failureInterrupted {
		t.Fatalf("cancel result = %v", err)
	}
}

func newTestLayout(t *testing.T) artifactLayout {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	layout, err := newArtifactLayout(Config{Root: root, ExpectedUID: uint32(os.Geteuid())})
	if err != nil {
		t.Fatal(err)
	}
	return layout
}

func beginCompleteGeneration(t *testing.T, layout artifactLayout, id string, database []byte) stagedGeneration {
	t.Helper()
	staged, err := layout.BeginGeneration(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged.database, database, 0o600); err != nil {
		t.Fatal(err)
	}
	identity, _, _, err := layout.SealDatabase(context.Background(), staged)
	if err != nil {
		t.Fatal(err)
	}
	staged.databaseIdentity = identity
	body, err := marshalManifest(validManifest(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := layout.WriteManifest(context.Background(), staged, body); err != nil {
		t.Fatal(err)
	}
	return staged
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
