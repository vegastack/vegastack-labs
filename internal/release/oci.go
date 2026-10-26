package release

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
)

// OCIProof authenticates the actual manifest bytes, never the printable digest
// as an artifact. Paths are protected server configuration and are not output.
type OCIProof struct {
	ManifestDigest, BundleDigest, PolicyDigest string
}

func VerifyOCI(ctx context.Context, manifestPath, bundlePath, policyPath, expectedDigest string) (OCIProof, error) {
	if !digestPattern.MatchString(expectedDigest) {
		return OCIProof{}, newError(generated.ErrorCodeInputInvalid, "oci-artifact")
	}
	manifest, err := readOCIFile(ctx, manifestPath, maxManifestBytes)
	if err != nil {
		return OCIProof{}, err
	}
	bundle, err := readOCIFile(ctx, bundlePath, maxBundleBytes)
	if err != nil {
		return OCIProof{}, err
	}
	policy, err := readOCIFile(ctx, policyPath, maxPolicyBytes)
	if err != nil {
		return OCIProof{}, err
	}
	return VerifyOCIBytes(ctx, manifest, bundle, policy, expectedDigest)
}

// VerifyOCIBytes reuses the release verifier with an explicitly supplied trust
// policy. Production callers obtain all three bounded values from protected files.
func VerifyOCIBytes(ctx context.Context, manifest, bundle, policyRaw []byte, expectedDigest string) (OCIProof, error) {
	if !digestPattern.MatchString(expectedDigest) || len(manifest) > int(maxManifestBytes) || len(bundle) > int(maxBundleBytes) || len(policyRaw) > int(maxPolicyBytes) {
		return OCIProof{}, newError(generated.ErrorCodeInputInvalid, "oci-artifact")
	}
	if hashOCI(manifest) != expectedDigest {
		return OCIProof{}, newError(generated.ErrorCodeEvidenceInvalid, "oci-artifact")
	}
	// This first slice accepts an image manifest only, not a multi-platform
	// index whose runtime platform manifest would require a separate binding.
	var document struct {
		SchemaVersion int             `json:"schemaVersion"`
		MediaType     string          `json:"mediaType"`
		Config        json.RawMessage `json:"config"`
		Layers        json.RawMessage `json:"layers"`
	}
	if strictjson.Scan(ctx, manifest, strictjson.Limits{MaxDepth: 32}) != nil || json.Unmarshal(manifest, &document) != nil || document.SchemaVersion != 2 || (document.MediaType != "application/vnd.oci.image.manifest.v1+json" && document.MediaType != "application/vnd.docker.distribution.manifest.v2+json") || len(document.Config) == 0 || len(document.Layers) == 0 {
		return OCIProof{}, newError(generated.ErrorCodeEvidenceInvalid, "oci-artifact")
	}
	policy, err := decodePolicy(ctx, policyRaw)
	if err != nil {
		return OCIProof{}, err
	}
	if err := (SigstoreBundleVerifier{}).Verify(ctx, bytes.NewReader(manifest), bundle, policy); err != nil {
		return OCIProof{}, err
	}
	return OCIProof{ManifestDigest: expectedDigest, BundleDigest: hashOCI(bundle), PolicyDigest: hashOCI(policyRaw)}, nil
}

func hashOCI(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func readOCIFile(ctx context.Context, path string, maximum int64) ([]byte, error) {
	root, file, snapshot, _, _, err := openExplicit(path, "oci-artifact", maximum)
	if err != nil {
		return nil, err
	}
	raw, readErr := readBounded(ctx, file, maximum, "oci-artifact")
	finishErr := finishFile(file, snapshot)
	closeErr := root.Close()
	if readErr != nil {
		return nil, readErr
	}
	if finishErr != nil {
		return nil, finishErr
	}
	if closeErr != nil {
		return nil, newError(generated.ErrorCodeEvidenceInvalid, "oci-artifact")
	}
	return raw, nil
}
