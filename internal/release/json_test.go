package release

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestLoadManifestAndPolicyStrictly(t *testing.T) {
	manifest, err := LoadManifest(context.Background(), fixturePath("release-valid", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer manifest.Close()
	if manifest.Value.ReleaseID != "v1.2.3" || !strings.Contains(string(manifest.Raw), `"releaseId": "v1.2.3"`) {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}

	policy, err := LoadPolicy(context.Background(), fixturePath("policy-valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	if policy.Value.CertificateIdentity == "" || !strings.HasPrefix(policy.SHA256, "sha256:") || len(policy.SHA256) != 71 {
		t.Fatalf("unexpected policy: %#v", policy)
	}
}

func TestLoadManifestRejectsAmbiguousOrIncompleteJSON(t *testing.T) {
	valid := readFixture(t, "release-valid", "manifest.json")
	tests := []struct {
		name string
		body string
	}{
		{"unknown", strings.Replace(valid, `"releaseId":`, `"private-canary": true, "releaseId":`, 1)},
		{"trailing", valid + `{}`},
		{"duplicate-root", strings.Replace(valid, `"releaseId":`, `"releaseId": "shadow", "releaseId":`, 1)},
		{"duplicate-nested", strings.Replace(valid, `"kind":`, `"id": "shadow", "kind":`, 1)},
		{"missing-required", strings.Replace(valid, "  \"buildId\": \"build-123\",\n", "", 1)},
		{"null-assets", strings.Replace(valid, `"assets": [`, `"assets": null, "ignored": [`, 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeManifest(t, test.body)
			_, err := LoadManifest(context.Background(), path)
			assertReleaseError(t, err, generated.ErrorCodeInputInvalid)
			if strings.Contains(err.Error(), "private-canary") || strings.Contains(err.Error(), "shadow") || strings.Contains(err.Error(), path) {
				t.Fatalf("error leaked hostile input: %v", err)
			}
		})
	}
}

func TestLoadPolicyRejectsDuplicateTrustedRootKeys(t *testing.T) {
	body := readFixture(t, "policy-valid.json")
	body = strings.Replace(body, `"mediaType":`, `"mediaType": "shadow", "mediaType":`, 1)
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadPolicy(context.Background(), path)
	assertReleaseError(t, err, generated.ErrorCodeInputInvalid)
}

func TestLoadManifestEnforcesMetadataBoundAndCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, []byte(strings.Repeat(" ", int(maxManifestBytes+1))), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadManifest(context.Background(), path)
	assertReleaseError(t, err, generated.ErrorCodeInputInvalid)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = LoadManifest(ctx, fixturePath("release-valid", "manifest.json"))
	assertReleaseError(t, err, generated.ErrorCodeInterrupted)
}

func TestLoadManifestAllowsExplicitHostPathCharactersAndRejectsFileSymlink(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "release set #1")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(directory, "manifest $.json")
	if err := os.WriteFile(manifestPath, []byte(readFixture(t, "release-valid", "manifest.json")), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := LoadManifest(context.Background(), manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.Close(); err != nil {
		t.Fatal(err)
	}

	linkPath := filepath.Join(directory, "manifest-link.json")
	if err := os.Symlink(manifestPath, linkPath); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	_, err = LoadManifest(context.Background(), linkPath)
	assertReleaseError(t, err, generated.ErrorCodeEvidenceInvalid)
}

func TestLoadManifestValidatesCrossFieldInvariants(t *testing.T) {
	valid := readFixture(t, "release-valid", "manifest.json")
	tests := []struct {
		name string
		edit func(string) string
	}{
		{"bad-release-id", func(s string) string { return strings.Replace(s, `"v1.2.3"`, `"bad/id"`, 1) }},
		{"bad-source", func(s string) string { return strings.Replace(s, strings.Repeat("a", 40), "main", 1) }},
		{"reversed-schema", func(s string) string {
			return strings.Replace(s, `"maximumSchemaMajor": 1`, `"maximumSchemaMajor": 0`, 1)
		}},
		{"bad-digest", func(s string) string {
			return strings.Replace(s, `sha256:3c1e79825287ad56cf4dc687c4838d401014a0c8e911e8c039779c8e7b2baf49`, `sha256:ABC`, 1)
		}},
		{"bad-size", func(s string) string { return strings.Replace(s, `"size": 19`, `"size": 0`, 1) }},
		{"duplicate-id", duplicateAssetWithEdit(func(s string) string { return s })},
		{"duplicate-target", duplicateAssetWithEdit(func(s string) string { return strings.Replace(s, `"id": "linux-amd64"`, `"id": "linux-amd64-2"`, 1) })},
		{"case-path-collision", duplicateAssetWithEdit(func(s string) string {
			s = strings.Replace(s, `"id": "linux-amd64"`, `"id": "linux-amd64-2"`, 1)
			s = strings.Replace(s, `"architecture": "amd64"`, `"architecture": "arm64"`, 1)
			return strings.Replace(s, `"path": "artifacts/vsk-labs"`, `"path": "ARTIFACTS/VSK-LABS"`, 1)
		})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := LoadManifest(context.Background(), writeManifest(t, test.edit(valid)))
			assertReleaseError(t, err, generated.ErrorCodeInputInvalid)
		})
	}
}

func duplicateAssetWithEdit(edit func(string) string) func(string) string {
	return func(s string) string {
		start := strings.Index(s, "    {")
		end := strings.Index(s[start:], "    }") + start + len("    }")
		asset := s[start:end]
		return s[:end] + ",\n" + edit(asset) + s[end:]
	}
}

func assertReleaseError(t *testing.T, err error, code string) *Error {
	t.Helper()
	var releaseErr *Error
	if !errors.As(err, &releaseErr) {
		t.Fatalf("error = %v, want *Error", err)
	}
	if releaseErr.Code != code {
		t.Fatalf("code = %q, want %q", releaseErr.Code, code)
	}
	return releaseErr
}

func fixturePath(parts ...string) string {
	return filepath.Join(append([]string{"testdata"}, parts...)...)
}

func readFixture(t *testing.T, parts ...string) string {
	t.Helper()
	content, err := os.ReadFile(fixturePath(parts...))
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func writeManifest(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
