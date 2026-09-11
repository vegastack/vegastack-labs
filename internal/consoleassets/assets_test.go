package consoleassets

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"testing"
)

func TestOpenVerifiesEveryEmbeddedFile(t *testing.T) {
	files, manifest, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Files["index.html"].SHA256 == "" {
		t.Fatal("embedded Console has no index")
	}
	seen := 0
	err = fs.WalkDir(files, ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		content, readErr := fs.ReadFile(files, name)
		if readErr != nil {
			return readErr
		}
		asset, ok := manifest.Files[name]
		if !ok {
			t.Fatalf("embedded file %q is not in manifest", name)
		}
		digest := sha256.Sum256(content)
		if hex.EncodeToString(digest[:]) != asset.SHA256 || int64(len(content)) != asset.Size {
			t.Fatalf("embedded file %q does not match manifest", name)
		}
		seen++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen != len(manifest.Files) {
		t.Fatalf("walked %d files, manifest has %d", seen, len(manifest.Files))
	}
}
