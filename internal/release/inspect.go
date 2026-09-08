package release

import (
	"context"
	"os"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

type Platform struct {
	OS           string
	Architecture string
	SchemaMajor  int
}

type InspectRequest struct {
	ManifestPath string
	Platform     Platform
}

func Inspect(ctx context.Context, request InspectRequest) (generated.ReleaseInspectData, error) {
	var result generated.ReleaseInspectData
	if err := validatePlatform(request.Platform); err != nil {
		return result, err
	}
	manifest, err := LoadManifest(ctx, request.ManifestPath)
	if err != nil {
		return result, err
	}
	closed := false
	defer func() {
		if !closed {
			_ = manifest.Close()
		}
	}()
	root := manifest.root
	if root == nil {
		return result, newError(generated.ErrorCodeEvidenceInvalid, targetManifestFile)
	}
	if err := inspectReferences(ctx, root, manifest.Value); err != nil {
		return result, err
	}
	if request.Platform.SchemaMajor < int(manifest.Value.MinimumSchemaMajor) || request.Platform.SchemaMajor > int(manifest.Value.MaximumSchemaMajor) ||
		(request.Platform.OS == "windows" && request.Platform.Architecture == "arm64") {
		return result, newError(generated.ErrorCodeVersionIncompatible, targetPlatform)
	}
	compatible := make([]string, 0, len(manifest.Value.Assets))
	for _, asset := range manifest.Value.Assets {
		if asset.OS == request.Platform.OS && asset.Architecture == request.Platform.Architecture {
			compatible = append(compatible, asset.ID)
		}
	}
	if len(compatible) == 0 {
		return result, newError(generated.ErrorCodeVersionIncompatible, targetPlatform)
	}
	assets := append([]generated.ReleaseAsset(nil), manifest.Value.Assets...)
	result = generated.ReleaseInspectData{
		ReleaseID: manifest.Value.ReleaseID, BuildID: manifest.Value.BuildID, SourceRevision: manifest.Value.SourceRevision,
		MinimumSchemaMajor: manifest.Value.MinimumSchemaMajor, MaximumSchemaMajor: manifest.Value.MaximumSchemaMajor,
		PlatformOS: request.Platform.OS, PlatformArchitecture: request.Platform.Architecture,
		PlatformSchemaMajor: int64(request.Platform.SchemaMajor), CompatibleAssetIDs: compatible,
		Assets: assets, VerificationStatus: "not-verified",
	}
	if err := manifest.Close(); err != nil {
		return generated.ReleaseInspectData{}, err
	}
	closed = true
	return result, nil
}

func validatePlatform(platform Platform) error {
	if !validOS(platform.OS) || !validArchitecture(platform.Architecture) {
		return newError(generated.ErrorCodeUnsupportedPlatform, targetPlatform)
	}
	if platform.SchemaMajor < 1 {
		return newError(generated.ErrorCodeInputInvalid, targetPlatform)
	}
	return nil
}

func inspectReferences(ctx context.Context, root *os.Root, manifest generated.ReleaseManifest) error {
	if err := inspectReference(ctx, root, manifest.BundlePath, nil, maxBundleBytes, targetBundleFile); err != nil {
		return err
	}
	for _, asset := range manifest.Assets {
		if err := ctx.Err(); err != nil {
			return interrupted()
		}
		if err := inspectReference(ctx, root, asset.Path, &asset.Size, maxArtifactBytes, targetAssetFile); err != nil {
			return err
		}
		if err := inspectReference(ctx, root, asset.BundlePath, nil, maxBundleBytes, targetBundleFile); err != nil {
			return err
		}
		for _, optional := range []*string{asset.SBOMPath, asset.ProvenancePath} {
			if optional != nil {
				if err := inspectReference(ctx, root, *optional, nil, maxBundleBytes, targetReference); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func inspectReference(ctx context.Context, root *os.Root, reference string, size *int64, maximum int64, target string) error {
	if err := ctx.Err(); err != nil {
		return interrupted()
	}
	file, snapshot, err := openRelativeRoot(root, reference, size, maximum, target)
	if err != nil {
		return err
	}
	return finishFile(file, snapshot)
}
