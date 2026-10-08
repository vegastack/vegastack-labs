package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalSetupReleaseSignedExecutable(t *testing.T) {
	review, artifact := setupReleaseFixture(t)
	opened := false
	reader := func() (io.ReadCloser, error) { opened = true; return io.NopCloser(bytes.NewReader(artifact)), nil }
	if err := verifyLocalSetupRelease(context.Background(), review, "build-123", Platform{OS: "linux", Architecture: "amd64"}, reader); err != nil {
		t.Fatal(err)
	}
	if !opened {
		t.Fatal("running executable was not checked")
	}
}

func TestLocalSetupReleaseRejectsMismatches(t *testing.T) {
	for _, name := range []string{"manifest-digest", "policy-digest", "build", "request-build", "platform", "asset", "kind", "manifest", "policy", "running-bytes", "running-size", "cancelled", "missing-reader", "nil-reader", "read-error", "close-error", "signature"} {
		t.Run(name, func(t *testing.T) {
			review, artifact := setupReleaseFixture(t)
			build := "build-123"
			platform := Platform{OS: "linux", Architecture: "amd64"}
			ctx := context.Background()
			open := func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(artifact)), nil }
			switch name {
			case "manifest-digest":
				review.request.ReleaseManifestDigest = "sha256:" + strings.Repeat("0", 64)
			case "policy-digest":
				review.request.ReleasePolicyDigest = "sha256:" + strings.Repeat("0", 64)
			case "build":
				build = "other-build"
			case "request-build":
				review.request.ReleaseBuildID = "other-build"
			case "platform":
				platform.Architecture = "arm64"
			case "asset":
				review.request.ExecutableAssetID = "not-present"
			case "kind", "manifest", "signature":
				raw, err := os.ReadFile(review.request.ReleaseManifestPath)
				if err != nil {
					t.Fatal(err)
				}
				if name == "kind" {
					raw = bytes.Replace(raw, []byte(`"kind": "executable"`), []byte(`"kind": "archive"`), 1)
				} else if name == "signature" {
					raw = bytes.Replace(raw, []byte(strings.Repeat("a", 40)), []byte(strings.Repeat("b", 40)), 1)
				} else {
					raw = bytes.Replace(raw, []byte(`"build-123"`), []byte(`"build-456"`), 1)
				}
				if err = os.WriteFile(review.request.ReleaseManifestPath, raw, 0600); err != nil {
					t.Fatal(err)
				}
				review.request.ReleaseManifestDigest = setupSHA256(raw)
			case "policy":
				raw := []byte(`{}`)
				if err := os.WriteFile(review.request.ReleasePolicyPath, raw, 0600); err != nil {
					t.Fatal(err)
				}
				review.request.ReleasePolicyDigest = setupSHA256(raw)
			case "running-bytes":
				artifact[0] ^= 1
			case "running-size":
				artifact = append(artifact, 'x')
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "missing-reader":
				open = nil
			case "nil-reader":
				open = func() (io.ReadCloser, error) { return nil, nil }
			case "read-error":
				open = func() (io.ReadCloser, error) {
					return setupReleaseErrorReader{Reader: bytes.NewReader(artifact), readError: true}, nil
				}
			case "close-error":
				open = func() (io.ReadCloser, error) { return setupReleaseErrorReader{Reader: bytes.NewReader(artifact)}, nil }
			}
			if err := verifyLocalSetupRelease(ctx, review, build, platform, open); err == nil {
				t.Fatal("mismatch accepted")
			}
		})
	}
}

func setupReleaseFixture(t *testing.T) (localSetupReview, []byte) {
	t.Helper()
	root := t.TempDir()
	source := os.Getenv("VSK_SETUP_RELEASE_FIXTURES")
	if source == "" {
		source = filepath.Join("..", "release", "testdata")
	}
	if err := os.CopyFS(root, os.DirFS(filepath.Join(source, "release-valid"))); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	policy, err := os.ReadFile(filepath.Join(source, "policy-valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(root, "policy.json")
	if err = os.WriteFile(policyPath, policy, 0600); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "manifest.json")
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := os.ReadFile(filepath.Join(root, "artifacts", "vsk-labs"))
	if err != nil {
		t.Fatal(err)
	}
	var review localSetupReview
	review.request.ReleaseManifestPath = manifestPath
	review.request.ReleaseManifestDigest = setupSHA256(manifest)
	review.request.ReleasePolicyPath = policyPath
	review.request.ReleasePolicyDigest = setupSHA256(policy)
	review.request.ExecutableAssetID = "linux-amd64"
	review.request.ReleaseBuildID = "build-123"
	return review, artifact
}

type setupReleaseErrorReader struct {
	io.Reader
	readError bool
}

func (r setupReleaseErrorReader) Read(p []byte) (int, error) {
	if r.readError {
		return 0, errors.New("synthetic read failure")
	}
	return r.Reader.Read(p)
}
func (r setupReleaseErrorReader) Close() error { return errors.New("synthetic close failure") }

func TestLocalSetupReleaseFixtureProtectedParent(t *testing.T) {
	review, _ := setupReleaseFixture(t)
	info, err := os.Stat(filepath.Dir(review.request.ReleaseManifestPath))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0700 {
		t.Fatalf("synthetic release parent mode %o, require0700", info.Mode().Perm())
	}
}
