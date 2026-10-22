package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/release"
)

// verifyLocalSetupRelease binds the existing signature verifier and the running
// executable to the exact release metadata included in the setup review.
func verifyLocalSetupRelease(ctx context.Context, review localSetupReview, buildID string, platform Platform, openExecutable func() (io.ReadCloser, error)) (resultErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if openExecutable == nil || buildID == "" || buildID != review.request.ReleaseBuildID {
		return setupFailure(generated.ErrorCodeIntegrityFailure)
	}
	if local := review.request.LocalBuild; local != nil {
		raw, err := json.Marshal(local)
		if err != nil || generated.ValidateContractJSON("vegastack-labs.dev/local-setup-build", raw, generated.ContractExact) != nil || local.OS != platform.OS || local.Architecture != platform.Architecture || review.request.ReleaseManifestPath != "" || review.request.ReleaseManifestDigest != "" || review.request.ReleasePolicyPath != "" || review.request.ReleasePolicyDigest != "" || review.request.ExecutableAssetID != "" {
			return setupFailure(generated.ErrorCodeIntegrityFailure)
		}
		return verifySetupExecutable(ctx, local.Size, local.Digest, openExecutable)
	}
	manifest, err := release.LoadManifest(ctx, review.request.ReleaseManifestPath)
	if err != nil {
		return err
	}
	defer func() {
		if err := manifest.Close(); resultErr == nil && err != nil {
			resultErr = err
		}
	}()
	if setupSHA256(manifest.Raw) != review.request.ReleaseManifestDigest || manifest.Value.BuildID != buildID || manifest.Value.MinimumSchemaMajor > 1 || manifest.Value.MaximumSchemaMajor < 1 {
		return setupFailure(generated.ErrorCodeIntegrityFailure)
	}
	var selected generated.ReleaseAsset
	for _, asset := range manifest.Value.Assets {
		if asset.ID == review.request.ExecutableAssetID {
			selected = asset
			break
		}
	}
	if selected.ID == "" || selected.Kind != "executable" || selected.OS != platform.OS || selected.Architecture != platform.Architecture {
		return setupFailure(generated.ErrorCodeIntegrityFailure)
	}
	verified, err := release.NewService(nil).Verify(ctx, release.VerifyRequest{
		ManifestPath: review.request.ReleaseManifestPath, PolicyPath: review.request.ReleasePolicyPath,
		ExpectedManifestSHA256: review.request.ReleaseManifestDigest,
		Selection:              release.Selection{AssetIDs: []string{selected.ID}},
	})
	if err != nil {
		return err
	}
	if verified.PolicySHA256 != review.request.ReleasePolicyDigest || verified.BuildID != buildID || verified.ManifestStatus != "verified" || verified.VerificationStatus != "verified-against-supplied-policy" || len(verified.Assets) != 1 {
		return setupFailure(generated.ErrorCodeIntegrityFailure)
	}
	asset := verified.Assets[0]
	if asset.AssetID != selected.ID || asset.OS != selected.OS || asset.Architecture != selected.Architecture || asset.Size != selected.Size || asset.Digest != selected.Digest || asset.Status != "verified" {
		return setupFailure(generated.ErrorCodeIntegrityFailure)
	}
	return verifySetupExecutable(ctx, selected.Size, selected.Digest, openExecutable)
}

func verifySetupExecutable(ctx context.Context, size int64, expectedDigest string, openExecutable func() (io.ReadCloser, error)) (resultErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	executable, err := openExecutable()
	if err != nil {
		return setupFailure(generated.ErrorCodeIntegrityFailure)
	}
	if executable == nil {
		return setupFailure(generated.ErrorCodeIntegrityFailure)
	}
	defer func() {
		if err := executable.Close(); resultErr == nil && err != nil {
			resultErr = setupFailure(generated.ErrorCodeIntegrityFailure)
		}
	}()
	digest := sha256.New()
	count, err := io.Copy(digest, io.LimitReader(localSetupExecutableReader{ctx: ctx, Reader: executable}, size+1))
	if err != nil || count != size || "sha256:"+hex.EncodeToString(digest.Sum(nil)) != expectedDigest {
		return setupFailure(generated.ErrorCodeIntegrityFailure)
	}
	return ctx.Err()
}

type localSetupExecutableReader struct {
	io.Reader
	ctx context.Context
}

func (reader localSetupExecutableReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.Reader.Read(buffer)
}
