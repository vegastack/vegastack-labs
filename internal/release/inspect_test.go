package release

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestInspectNeverClaimsCryptographicVerification(t *testing.T) {
	result, err := Inspect(context.Background(), InspectRequest{
		ManifestPath: fixturePath("release-valid", "manifest.json"),
		Platform:     Platform{OS: "linux", Architecture: "amd64", SchemaMajor: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.VerificationStatus != "not-verified" || len(result.CompatibleAssetIDs) != 1 || result.CompatibleAssetIDs[0] != "linux-amd64" {
		t.Fatalf("unexpected inspection result: %#v", result)
	}
	if result.ReleaseID != "v1.2.3" || len(result.Assets) != 1 {
		t.Fatalf("missing manifest data: %#v", result)
	}
}

func TestInspectRejectsIncompatibleAndUnknownPlatforms(t *testing.T) {
	manifest := fixturePath("release-valid", "manifest.json")
	_, err := Inspect(context.Background(), InspectRequest{ManifestPath: manifest, Platform: Platform{OS: "linux", Architecture: "amd64", SchemaMajor: 2}})
	assertReleaseError(t, err, generated.ErrorCodeVersionIncompatible)

	_, err = Inspect(context.Background(), InspectRequest{ManifestPath: manifest, Platform: Platform{OS: "windows", Architecture: "arm64", SchemaMajor: 1}})
	assertReleaseError(t, err, generated.ErrorCodeVersionIncompatible)

	_, err = Inspect(context.Background(), InspectRequest{ManifestPath: manifest, Platform: Platform{OS: "private-canary", Architecture: "amd64", SchemaMajor: 1}})
	releaseErr := assertReleaseError(t, err, generated.ErrorCodeUnsupportedPlatform)
	if releaseErr.Target == "private-canary" {
		t.Fatal("hostile platform was echoed")
	}
}

func TestInspectRequiresReferencedRegularFiles(t *testing.T) {
	root := copyFixtureRelease(t)
	if err := os.Remove(filepath.Join(root, "artifacts", "vsk-labs")); err != nil {
		t.Fatal(err)
	}
	_, err := Inspect(context.Background(), InspectRequest{ManifestPath: filepath.Join(root, "manifest.json"), Platform: Platform{OS: "linux", Architecture: "amd64", SchemaMajor: 1}})
	assertReleaseError(t, err, generated.ErrorCodePrerequisiteBlocked)
}

func TestInspectHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Inspect(ctx, InspectRequest{ManifestPath: fixturePath("release-valid", "manifest.json"), Platform: Platform{OS: "linux", Architecture: "amd64", SchemaMajor: 1}})
	assertReleaseError(t, err, generated.ErrorCodeInterrupted)
}

func copyFixtureRelease(t *testing.T) string {
	t.Helper()
	source := fixturePath("release-valid")
	destination := t.TempDir()
	err := filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil || relative == "." {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, content, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	return destination
}
