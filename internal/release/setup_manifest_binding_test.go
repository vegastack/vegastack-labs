package release

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func TestVerifyBoundManifestBytes(t *testing.T) {
	manifest := fixturePath("release-valid", "manifest.json")
	raw, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	for _, test := range []struct {
		name, digest string
		valid        bool
	}{
		{"exact", "sha256:" + hex.EncodeToString(sum[:]), true},
		{"legacy-empty", "", true},
		{"wrong", "sha256:" + strings.Repeat("0", 64), false},
		{"malformed", "bad", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewService(nil).Verify(context.Background(), VerifyRequest{ManifestPath: manifest, PolicyPath: fixturePath("policy-valid.json"), Selection: Selection{All: true}, ExpectedManifestSHA256: test.digest})
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v error=%v", test.valid, err)
			}
		})
	}
}
