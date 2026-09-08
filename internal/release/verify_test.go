package release

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestVerifyAuthenticatesManifestBeforeOpeningAssets(t *testing.T) {
	root, manifestPath, policyPath, _ := writeServiceRelease(t, []testAsset{{id: "linux-amd64", content: "asset-one"}})
	if err := os.Remove(filepath.Join(root, "artifacts", "linux-amd64")); err != nil {
		t.Fatal(err)
	}
	recorder := &recordingBundleVerifier{failCall: 1}
	service := NewService(recorder)
	_, err := service.Verify(context.Background(), VerifyRequest{
		ManifestPath: manifestPath,
		PolicyPath:   policyPath,
		Selection:    Selection{AssetIDs: []string{"linux-amd64"}},
	})
	releaseErr := assertReleaseError(t, err, generated.ErrorCodeEvidenceInvalid)
	if releaseErr.Target != targetManifestSignature {
		t.Fatalf("target = %q, want %q", releaseErr.Target, targetManifestSignature)
	}
	if len(recorder.contents) != 1 || !bytes.Contains(recorder.contents[0], []byte(`"releaseId":"v1.2.3"`)) {
		t.Fatalf("manifest was not the sole verified content: %#v", recorder.contents)
	}
}

func TestVerifyRequiresExplicitDeterministicSelection(t *testing.T) {
	_, manifestPath, policyPath, _ := writeServiceRelease(t, []testAsset{
		{id: "linux-amd64", content: "asset-one"},
		{id: "darwin-arm64", content: "asset-two", os: "darwin", architecture: "arm64"},
	})
	for _, selection := range []Selection{
		{},
		{All: true, AssetIDs: []string{"linux-amd64"}},
		{AssetIDs: []string{"linux-amd64", "linux-amd64"}},
		{AssetIDs: []string{""}},
		{AssetIDs: []string{"Linux-amd64"}},
	} {
		_, err := NewService(&recordingBundleVerifier{}).Verify(context.Background(), VerifyRequest{
			ManifestPath: manifestPath, PolicyPath: policyPath, Selection: selection,
		})
		assertReleaseError(t, err, generated.ErrorCodeInputInvalid)
	}

	unknownRecorder := &recordingBundleVerifier{}
	_, err := NewService(unknownRecorder).Verify(context.Background(), VerifyRequest{
		ManifestPath: manifestPath, PolicyPath: policyPath,
		Selection: Selection{AssetIDs: []string{"private-canary"}},
	})
	assertReleaseError(t, err, generated.ErrorCodeInputInvalid)
	if len(unknownRecorder.contents) != 1 {
		t.Fatalf("unknown selection was considered before manifest verification: %d calls", len(unknownRecorder.contents))
	}

	recorder := &recordingBundleVerifier{}
	result, err := NewService(recorder).Verify(context.Background(), VerifyRequest{
		ManifestPath: manifestPath, PolicyPath: policyPath,
		Selection: Selection{AssetIDs: []string{"darwin-arm64", "linux-amd64"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Assets) != 2 || result.Assets[0].AssetID != "linux-amd64" || result.Assets[1].AssetID != "darwin-arm64" {
		t.Fatalf("result order is not manifest-deterministic: %#v", result.Assets)
	}
	if len(recorder.contents) != 3 || string(recorder.contents[1]) != "asset-one" || string(recorder.contents[2]) != "asset-two" {
		t.Fatalf("verification order/content = %#v", recorder.contents)
	}
}

func TestVerifyStreamsRewoundArtifactAndReportsSuppliedPolicy(t *testing.T) {
	_, manifestPath, policyPath, policyRaw := writeServiceRelease(t, []testAsset{{id: "linux-amd64", content: "asset-one"}})
	recorder := &recordingBundleVerifier{}
	result, err := NewService(recorder).Verify(context.Background(), VerifyRequest{
		ManifestPath: manifestPath, PolicyPath: policyPath,
		Selection: Selection{AssetIDs: []string{"linux-amd64"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	wantPolicyDigest := sha256.Sum256(policyRaw)
	if result.ManifestStatus != "verified" || result.VerificationStatus != "verified-against-supplied-policy" ||
		result.PolicySHA256 != "sha256:"+hex.EncodeToString(wantPolicyDigest[:]) || len(result.Assets) != 1 ||
		result.Assets[0].Status != "verified" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if len(recorder.contents) != 2 || string(recorder.contents[1]) != "asset-one" {
		t.Fatalf("verifier did not receive the full rewound artifact: %#v", recorder.contents)
	}
}

func TestVerifyRejectsDigestBeforeAssetSignature(t *testing.T) {
	_, manifestPath, policyPath, _ := writeServiceRelease(t, []testAsset{{
		id: "linux-amd64", content: "asset-one", declaredDigest: "sha256:" + string(bytes.Repeat([]byte{'0'}, 64)),
	}})
	recorder := &recordingBundleVerifier{}
	_, err := NewService(recorder).Verify(context.Background(), VerifyRequest{
		ManifestPath: manifestPath, PolicyPath: policyPath,
		Selection: Selection{AssetIDs: []string{"linux-amd64"}},
	})
	releaseErr := assertReleaseError(t, err, generated.ErrorCodeEvidenceInvalid)
	if releaseErr.Target != targetAssetDigest || len(recorder.contents) != 1 {
		t.Fatalf("digest mismatch reached asset signature: error=%#v calls=%d", releaseErr, len(recorder.contents))
	}
}

func TestVerifyRejectsWrongAssetSizeBeforeAssetSignature(t *testing.T) {
	root, manifestPath, policyPath, _ := writeServiceRelease(t, []testAsset{{id: "linux-amd64", content: "asset-one"}})
	if err := os.WriteFile(filepath.Join(root, "artifacts", "linux-amd64"), []byte("asset-one-expanded"), 0o600); err != nil {
		t.Fatal(err)
	}
	recorder := &recordingBundleVerifier{}
	_, err := NewService(recorder).Verify(context.Background(), VerifyRequest{
		ManifestPath: manifestPath,
		PolicyPath:   policyPath,
		Selection:    Selection{All: true},
	})
	releaseErr := assertReleaseError(t, err, generated.ErrorCodeEvidenceInvalid)
	if releaseErr.Target != targetAssetFile || len(recorder.contents) != 1 {
		t.Fatalf("size mismatch reached asset signature: error=%#v calls=%d", releaseErr, len(recorder.contents))
	}
}

func TestVerifyCancellationStopsBeforeNextAsset(t *testing.T) {
	_, manifestPath, policyPath, _ := writeServiceRelease(t, []testAsset{
		{id: "linux-amd64", content: "asset-one"},
		{id: "darwin-arm64", content: "asset-two", os: "darwin", architecture: "arm64"},
	})
	ctx, cancel := context.WithCancel(context.Background())
	recorder := &recordingBundleVerifier{cancelCall: 2, cancel: cancel}
	_, err := NewService(recorder).Verify(ctx, VerifyRequest{
		ManifestPath: manifestPath, PolicyPath: policyPath, Selection: Selection{All: true},
	})
	assertReleaseError(t, err, generated.ErrorCodeInterrupted)
	if len(recorder.contents) != 2 {
		t.Fatalf("verification continued after cancellation: %d calls", len(recorder.contents))
	}
}

func TestServiceInspectDelegatesToInspect(t *testing.T) {
	result, err := NewService(&recordingBundleVerifier{}).Inspect(context.Background(), InspectRequest{
		ManifestPath: fixturePath("release-valid", "manifest.json"),
		Platform:     Platform{OS: "linux", Architecture: "amd64", SchemaMajor: 1},
	})
	if err != nil || result.VerificationStatus != "not-verified" {
		t.Fatalf("Inspect() = %#v, %v", result, err)
	}
}

func TestVerifyAcceptsCheckedInSyntheticReleaseSet(t *testing.T) {
	result, err := NewService(nil).Verify(context.Background(), VerifyRequest{
		ManifestPath: fixturePath("release-valid", "manifest.json"),
		PolicyPath:   fixturePath("policy-valid.json"),
		Selection:    Selection{All: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.VerificationStatus != "verified-against-supplied-policy" ||
		result.PolicySHA256 != "sha256:854cff09a2017f320788859438edf493fcdd56d243329681b4174b582f28c8b9" ||
		len(result.Assets) != 1 || result.Assets[0].AssetID != "linux-amd64" {
		t.Fatalf("unexpected fixture verification: %#v", result)
	}
}

func TestVerifyRejectsAssetReplacementDuringSignatureVerification(t *testing.T) {
	root, manifestPath, policyPath, _ := writeServiceRelease(t, []testAsset{{id: "linux-amd64", content: "asset-one"}})
	assetPath := filepath.Join(root, "artifacts", "linux-amd64")
	verifier := &replacingBundleVerifier{path: assetPath}
	_, err := NewService(verifier).Verify(context.Background(), VerifyRequest{
		ManifestPath: manifestPath,
		PolicyPath:   policyPath,
		Selection:    Selection{All: true},
	})
	releaseErr := assertReleaseError(t, err, generated.ErrorCodeEvidenceInvalid)
	if releaseErr.Target != targetAssetFile {
		t.Fatalf("target = %q, want %q", releaseErr.Target, targetAssetFile)
	}
}

type recordingBundleVerifier struct {
	contents   [][]byte
	failCall   int
	cancelCall int
	cancel     context.CancelFunc
}

type replacingBundleVerifier struct {
	path  string
	calls int
}

func (verifier *replacingBundleVerifier) Verify(_ context.Context, artifact io.Reader, _ []byte, _ generated.ReleaseTrustPolicy) error {
	content, err := io.ReadAll(artifact)
	if err != nil {
		return err
	}
	verifier.calls++
	if verifier.calls != 2 {
		return nil
	}
	replacedPath := verifier.path + ".replaced"
	if err := os.Rename(verifier.path, replacedPath); err != nil {
		return err
	}
	return os.WriteFile(verifier.path, content, 0o600)
}

func (recorder *recordingBundleVerifier) Verify(ctx context.Context, artifact io.Reader, _ []byte, _ generated.ReleaseTrustPolicy) error {
	content, err := io.ReadAll(artifact)
	if err != nil {
		return err
	}
	recorder.contents = append(recorder.contents, content)
	call := len(recorder.contents)
	if call == recorder.cancelCall && recorder.cancel != nil {
		recorder.cancel()
	}
	if call == recorder.failCall {
		return newError(generated.ErrorCodeEvidenceInvalid, "fake-signature")
	}
	return ctx.Err()
}

type testAsset struct {
	id             string
	content        string
	os             string
	architecture   string
	declaredDigest string
}

func writeServiceRelease(t *testing.T, assets []testAsset) (string, string, string, []byte) {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "artifacts"), 0o700); err != nil {
		t.Fatal(err)
	}
	manifestAssets := make([]generated.ReleaseAsset, 0, len(assets))
	for _, asset := range assets {
		osName, architecture := asset.os, asset.architecture
		if osName == "" {
			osName = "linux"
		}
		if architecture == "" {
			architecture = "amd64"
		}
		content := []byte(asset.content)
		digest := sha256.Sum256(content)
		declaredDigest := asset.declaredDigest
		if declaredDigest == "" {
			declaredDigest = "sha256:" + hex.EncodeToString(digest[:])
		}
		assetPath := filepath.Join(root, "artifacts", asset.id)
		if err := os.WriteFile(assetPath, content, 0o600); err != nil {
			t.Fatal(err)
		}
		bundleReference := "artifacts/" + asset.id + ".sigstore.json"
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(bundleReference)), []byte(`{"fixture":true}`), 0o600); err != nil {
			t.Fatal(err)
		}
		manifestAssets = append(manifestAssets, generated.ReleaseAsset{
			ID: asset.id, Kind: "executable", OS: osName, Architecture: architecture,
			Path: "artifacts/" + asset.id, Size: int64(len(content)), Digest: declaredDigest,
			BundlePath: bundleReference,
		})
	}
	manifest := generated.ReleaseManifest{
		Schema: generated.SchemaIDReleaseManifest, SchemaVersion: manifestSchemaVersion,
		ReleaseID: "v1.2.3", BuildID: "build-123", SourceRevision: string(bytes.Repeat([]byte{'a'}, 40)),
		MinimumSchemaMajor: 1, MaximumSchemaMajor: 1,
		BundlePath: "manifest.sigstore.json", Assets: manifestAssets,
	}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "manifest.json")
	if err := os.WriteFile(manifestPath, manifestRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.sigstore.json"), []byte(`{"fixture":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	policyRaw, err := os.ReadFile(fixturePath("policy-valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(root, "policy.json")
	if err := os.WriteFile(policyPath, policyRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	return root, manifestPath, policyPath, policyRaw
}
