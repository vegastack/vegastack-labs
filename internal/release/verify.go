package release

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

const (
	targetAssetDigest       = "asset-digest"
	targetAssetSignature    = "asset-signature"
	targetManifestSignature = "manifest-signature"
	targetSelection         = "selection"
)

type Selection struct {
	All      bool
	AssetIDs []string
}

type VerifyRequest struct {
	ManifestPath string
	PolicyPath   string
	Selection    Selection
}

type BundleVerifier interface {
	Verify(context.Context, io.Reader, []byte, generated.ReleaseTrustPolicy) error
}

type Service struct {
	signatures BundleVerifier
}

func NewService(signatures BundleVerifier) *Service {
	if signatures == nil {
		signatures = SigstoreBundleVerifier{}
	}
	return &Service{signatures: signatures}
}

func (service *Service) Inspect(ctx context.Context, request InspectRequest) (generated.ReleaseInspectData, error) {
	return Inspect(ctx, request)
}

func (service *Service) Verify(ctx context.Context, request VerifyRequest) (result generated.ReleaseVerifyData, resultErr error) {
	if err := validateSelectionShape(request.Selection); err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, interrupted()
	}
	manifest, err := LoadManifest(ctx, request.ManifestPath)
	if err != nil {
		return result, err
	}
	defer func() {
		if closeErr := manifest.Close(); resultErr == nil && closeErr != nil {
			result = generated.ReleaseVerifyData{}
			resultErr = closeErr
		}
	}()
	policy, err := LoadPolicy(ctx, request.PolicyPath)
	if err != nil {
		return result, err
	}
	if manifest.root == nil {
		return result, newError(generated.ErrorCodeEvidenceInvalid, targetManifestFile)
	}

	manifestBundle, err := readReleaseBundle(ctx, manifest, manifest.Value.BundlePath)
	if err != nil {
		return result, err
	}
	if err := service.verifySignature(ctx, bytes.NewReader(manifest.Raw), manifestBundle, policy.Value, targetManifestSignature); err != nil {
		return result, err
	}

	selected, err := selectAssets(manifest.Value.Assets, request.Selection)
	if err != nil {
		return result, err
	}
	verifiedAssets := make([]generated.ReleaseAssetVerification, 0, len(selected))
	for _, asset := range selected {
		if err := ctx.Err(); err != nil {
			return generated.ReleaseVerifyData{}, interrupted()
		}
		bundleBytes, err := readReleaseBundle(ctx, manifest, asset.BundlePath)
		if err != nil {
			return generated.ReleaseVerifyData{}, err
		}
		if err := service.verifyAsset(ctx, manifest, asset, bundleBytes, policy.Value); err != nil {
			return generated.ReleaseVerifyData{}, err
		}
		verifiedAssets = append(verifiedAssets, generated.ReleaseAssetVerification{
			AssetID: asset.ID, OS: asset.OS, Architecture: asset.Architecture,
			Digest: asset.Digest, Size: asset.Size, Status: "verified",
		})
	}

	return generated.ReleaseVerifyData{
		ReleaseID: manifest.Value.ReleaseID, BuildID: manifest.Value.BuildID,
		SourceRevision: manifest.Value.SourceRevision, ManifestStatus: "verified",
		VerificationStatus: "verified-against-supplied-policy", PolicySHA256: policy.SHA256,
		Assets: verifiedAssets,
	}, nil
}

func validateSelectionShape(selection Selection) error {
	if selection.All == (len(selection.AssetIDs) > 0) {
		return newError(generated.ErrorCodeInputInvalid, targetSelection)
	}
	if len(selection.AssetIDs) > maxAssets {
		return newError(generated.ErrorCodeInputInvalid, targetSelection)
	}
	seen := make(map[string]struct{}, len(selection.AssetIDs))
	for _, id := range selection.AssetIDs {
		if !assetIDPattern.MatchString(id) {
			return newError(generated.ErrorCodeInputInvalid, targetSelection)
		}
		if _, duplicate := seen[id]; duplicate {
			return newError(generated.ErrorCodeInputInvalid, targetSelection)
		}
		seen[id] = struct{}{}
	}
	return nil
}

func selectAssets(assets []generated.ReleaseAsset, selection Selection) ([]generated.ReleaseAsset, error) {
	if selection.All {
		return append([]generated.ReleaseAsset(nil), assets...), nil
	}
	wanted := make(map[string]struct{}, len(selection.AssetIDs))
	for _, id := range selection.AssetIDs {
		wanted[id] = struct{}{}
	}
	selected := make([]generated.ReleaseAsset, 0, len(wanted))
	for _, asset := range assets {
		if _, ok := wanted[asset.ID]; ok {
			selected = append(selected, asset)
			delete(wanted, asset.ID)
		}
	}
	if len(wanted) != 0 {
		return nil, newError(generated.ErrorCodeInputInvalid, targetSelection)
	}
	return selected, nil
}

func readReleaseBundle(ctx context.Context, manifest LoadedManifest, reference string) ([]byte, error) {
	file, snapshot, err := openRelativeRoot(manifest.root, reference, nil, maxBundleBytes, targetBundleFile)
	if err != nil {
		return nil, err
	}
	content, readErr := readBounded(ctx, file, maxBundleBytes, targetBundleFile)
	finishErr := finishFile(file, snapshot)
	if readErr != nil {
		return nil, readErr
	}
	if finishErr != nil {
		return nil, finishErr
	}
	return content, nil
}

func (service *Service) verifyAsset(ctx context.Context, manifest LoadedManifest, asset generated.ReleaseAsset, bundleBytes []byte, policy generated.ReleaseTrustPolicy) error {
	file, snapshot, err := openRelativeRoot(manifest.root, asset.Path, &asset.Size, maxArtifactBytes, targetAssetFile)
	if err != nil {
		return err
	}
	finished := false
	finish := func() error {
		if finished {
			return nil
		}
		finished = true
		return finishFile(file, snapshot)
	}
	defer func() {
		if !finished {
			_ = finish()
		}
	}()

	firstPass := newMeasuredReader(ctx, io.LimitReader(file, asset.Size+1))
	if _, err := io.Copy(io.Discard, firstPass); err != nil {
		if finishErr := finish(); finishErr != nil {
			return finishErr
		}
		if ctx.Err() != nil {
			return interrupted()
		}
		return newError(generated.ErrorCodeEvidenceInvalid, targetAssetFile)
	}
	if !matchesAsset(firstPass, asset) {
		if finishErr := finish(); finishErr != nil {
			return finishErr
		}
		return newError(generated.ErrorCodeEvidenceInvalid, targetAssetDigest)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		if finishErr := finish(); finishErr != nil {
			return finishErr
		}
		return newError(generated.ErrorCodeEvidenceInvalid, targetAssetFile)
	}

	verifiedPass := newMeasuredReader(ctx, io.LimitReader(file, asset.Size+1))
	verifyErr := service.verifySignature(ctx, verifiedPass, bundleBytes, policy, targetAssetSignature)
	if verifyErr == nil && !matchesAsset(verifiedPass, asset) {
		verifyErr = newError(generated.ErrorCodeEvidenceInvalid, targetAssetDigest)
	}
	finishErr := finish()
	if finishErr != nil {
		return finishErr
	}
	return verifyErr
}

func (service *Service) verifySignature(ctx context.Context, content io.Reader, bundleBytes []byte, policy generated.ReleaseTrustPolicy, target string) error {
	if err := ctx.Err(); err != nil {
		return interrupted()
	}
	if service == nil || service.signatures == nil {
		return newError(generated.ErrorCodeEvidenceInvalid, target)
	}
	if err := service.signatures.Verify(ctx, content, bundleBytes, policy); err != nil {
		if ctx.Err() != nil {
			return interrupted()
		}
		return newError(generated.ErrorCodeEvidenceInvalid, target)
	}
	if err := ctx.Err(); err != nil {
		return interrupted()
	}
	return nil
}

type measuredReader struct {
	ctx    context.Context
	reader io.Reader
	hash   hash.Hash
	count  int64
}

func newMeasuredReader(ctx context.Context, reader io.Reader) *measuredReader {
	return &measuredReader{ctx: ctx, reader: reader, hash: sha256.New()}
}

func (reader *measuredReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	count, err := reader.reader.Read(buffer)
	if count > 0 {
		reader.count += int64(count)
		_, _ = reader.hash.Write(buffer[:count])
	}
	return count, err
}

func matchesAsset(reader *measuredReader, asset generated.ReleaseAsset) bool {
	if reader == nil || reader.count != asset.Size {
		return false
	}
	want, err := hex.DecodeString(strings.TrimPrefix(asset.Digest, "sha256:"))
	return err == nil && bytes.Equal(reader.hash.Sum(nil), want)
}
