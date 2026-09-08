package release

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

const (
	manifestSchemaVersion = "1.0.0"
	policySchemaVersion   = "1.0.0"
	maxJSONDepth          = 64
	maxAssets             = 64
)

var (
	releaseIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	buildIDPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	sourcePattern    = regexp.MustCompile(`^[0-9a-f]{40,64}$`)
	assetIDPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	digestPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// LoadedManifest retains the opened release-directory root so later bundle and
// artifact reads cannot be redirected by renaming or replacing the root path.
type LoadedManifest struct {
	Raw          []byte
	Value        generated.ReleaseManifest
	Root         string
	ManifestPath string
	root         *os.Root
}

type LoadedPolicy struct {
	Raw    []byte
	Value  generated.ReleaseTrustPolicy
	SHA256 string
}

// Close releases the manifest's retained directory capability. It is safe to
// call more than once.
func (manifest *LoadedManifest) Close() error {
	if manifest == nil || manifest.root == nil {
		return nil
	}
	err := manifest.root.Close()
	manifest.root = nil
	if err != nil {
		return newError(generated.ErrorCodeEvidenceInvalid, targetManifestFile)
	}
	return nil
}

func LoadManifest(ctx context.Context, manifestPath string) (LoadedManifest, error) {
	root, file, snapshot, directory, absolute, err := openExplicit(manifestPath, targetManifest, maxManifestBytes)
	if err != nil {
		return LoadedManifest{}, err
	}
	raw, readErr := readBounded(ctx, file, maxManifestBytes, targetManifest)
	finishErr := finishFile(file, snapshot)
	if readErr != nil || finishErr != nil {
		_ = root.Close()
		if readErr != nil {
			return LoadedManifest{}, readErr
		}
		return LoadedManifest{}, finishErr
	}
	value, err := decodeManifest(ctx, raw)
	if err != nil {
		_ = root.Close()
		return LoadedManifest{}, err
	}
	return LoadedManifest{
		Raw: raw, Value: value, Root: directory, ManifestPath: absolute,
		root: root,
	}, nil
}

func LoadPolicy(ctx context.Context, policyPath string) (LoadedPolicy, error) {
	root, file, snapshot, _, _, err := openExplicit(policyPath, targetPolicy, maxPolicyBytes)
	if err != nil {
		return LoadedPolicy{}, err
	}
	raw, readErr := readBounded(ctx, file, maxPolicyBytes, targetPolicy)
	finishErr := finishFile(file, snapshot)
	closeErr := root.Close()
	if readErr != nil {
		return LoadedPolicy{}, readErr
	}
	if finishErr != nil {
		return LoadedPolicy{}, finishErr
	}
	if closeErr != nil {
		return LoadedPolicy{}, newError(generated.ErrorCodeEvidenceInvalid, targetPolicyFile)
	}
	value, err := decodePolicy(ctx, raw)
	if err != nil {
		return LoadedPolicy{}, err
	}
	digest := sha256.Sum256(raw)
	return LoadedPolicy{Raw: raw, Value: value, SHA256: "sha256:" + hex.EncodeToString(digest[:])}, nil
}

func decodeManifest(ctx context.Context, raw []byte) (generated.ReleaseManifest, error) {
	var value generated.ReleaseManifest
	if err := validateJSON(ctx, raw, generated.SchemaIDReleaseManifest, manifestSchemaVersion, targetManifestSchema); err != nil {
		return value, err
	}
	if err := requireObjectFields(raw, []string{"schema", "schemaVersion", "releaseId", "buildId", "sourceRevision", "minimumSchemaMajor", "maximumSchemaMajor", "bundlePath", "assets"}, targetManifest); err != nil {
		return value, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, newError(generated.ErrorCodeInputInvalid, targetManifest)
	}
	if err := requireAssetFields(raw); err != nil {
		return value, err
	}
	if err := validateManifest(value); err != nil {
		return value, err
	}
	return value, nil
}

func decodePolicy(ctx context.Context, raw []byte) (generated.ReleaseTrustPolicy, error) {
	var value generated.ReleaseTrustPolicy
	if err := validateJSON(ctx, raw, generated.SchemaIDReleaseTrustPolicy, policySchemaVersion, targetPolicySchema); err != nil {
		return value, err
	}
	if err := requireObjectFields(raw, []string{"schema", "schemaVersion", "certificateIdentity", "oidcIssuer", "trustedRoot"}, targetPolicy); err != nil {
		return value, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, newError(generated.ErrorCodeInputInvalid, targetPolicy)
	}
	if err := validatePolicy(value); err != nil {
		return value, err
	}
	return value, nil
}

func validateJSON(ctx context.Context, raw []byte, schemaID, schemaVersion, schemaTarget string) error {
	if len(raw) == 0 || !utf8.Valid(raw) || bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) || bytes.IndexByte(raw, 0) >= 0 {
		return newError(generated.ErrorCodeInputInvalid, strings.TrimSuffix(schemaTarget, "-schema"))
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanJSONValue(ctx, decoder, 0); err != nil {
		var releaseErr *Error
		if errors.As(err, &releaseErr) && releaseErr.Code == generated.ErrorCodeInterrupted {
			return err
		}
		return newError(generated.ErrorCodeInputInvalid, strings.TrimSuffix(schemaTarget, "-schema"))
	}
	if _, err := decoder.Token(); err != io.EOF {
		return newError(generated.ErrorCodeInputInvalid, strings.TrimSuffix(schemaTarget, "-schema"))
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return newError(generated.ErrorCodeInputInvalid, strings.TrimSuffix(schemaTarget, "-schema"))
	}
	rawSchema, schemaPresent := envelope["schema"]
	rawVersion, versionPresent := envelope["schemaVersion"]
	if !schemaPresent || !versionPresent {
		return newError(generated.ErrorCodeInputInvalid, strings.TrimSuffix(schemaTarget, "-schema"))
	}
	var actualSchema, actualVersion string
	if json.Unmarshal(rawSchema, &actualSchema) != nil || json.Unmarshal(rawVersion, &actualVersion) != nil {
		return newError(generated.ErrorCodeInputInvalid, strings.TrimSuffix(schemaTarget, "-schema"))
	}
	if actualSchema != schemaID || actualVersion != schemaVersion {
		return newError(generated.ErrorCodeSchemaUnsupported, schemaTarget)
	}
	return nil
}

func scanJSONValue(ctx context.Context, decoder *json.Decoder, depth int) error {
	if err := ctx.Err(); err != nil {
		return interrupted()
	}
	if depth > maxJSONDepth {
		return newError(generated.ErrorCodeInputInvalid, targetManifest)
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			if err := ctx.Err(); err != nil {
				return interrupted()
			}
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return newError(generated.ErrorCodeInputInvalid, targetManifest)
			}
			if _, duplicate := seen[key]; duplicate {
				return newError(generated.ErrorCodeInputInvalid, targetManifest)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(ctx, decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return newError(generated.ErrorCodeInputInvalid, targetManifest)
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(ctx, decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return newError(generated.ErrorCodeInputInvalid, targetManifest)
		}
	default:
		return newError(generated.ErrorCodeInputInvalid, targetManifest)
	}
	return nil
}

func requireObjectFields(raw []byte, required []string, target string) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return newError(generated.ErrorCodeInputInvalid, target)
	}
	for _, field := range required {
		if _, ok := object[field]; !ok {
			return newError(generated.ErrorCodeInputInvalid, target)
		}
	}
	return nil
}

func requireAssetFields(raw []byte) error {
	var document struct {
		Assets []json.RawMessage `json:"assets"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return newError(generated.ErrorCodeInputInvalid, targetManifest)
	}
	required := []string{"id", "kind", "os", "architecture", "path", "size", "digest", "bundlePath"}
	for _, asset := range document.Assets {
		if err := requireObjectFields(asset, required, targetManifest); err != nil {
			return err
		}
	}
	return nil
}

func validateManifest(manifest generated.ReleaseManifest) error {
	if !releaseIDPattern.MatchString(manifest.ReleaseID) || !buildIDPattern.MatchString(manifest.BuildID) ||
		!sourcePattern.MatchString(manifest.SourceRevision) || manifest.MinimumSchemaMajor < 1 ||
		manifest.MaximumSchemaMajor < manifest.MinimumSchemaMajor || len(manifest.Assets) < 1 || len(manifest.Assets) > maxAssets {
		return newError(generated.ErrorCodeInputInvalid, targetManifest)
	}
	paths := map[string]struct{}{}
	if err := addReference(paths, manifest.BundlePath); err != nil {
		return err
	}
	ids := map[string]struct{}{}
	targets := map[string]struct{}{}
	for _, asset := range manifest.Assets {
		if !assetIDPattern.MatchString(asset.ID) || !validAssetKind(asset.Kind) || !validOS(asset.OS) || !validArchitecture(asset.Architecture) ||
			asset.Size < 1 || asset.Size > maxArtifactBytes || !digestPattern.MatchString(asset.Digest) {
			return newError(generated.ErrorCodeInputInvalid, targetManifest)
		}
		if _, duplicate := ids[asset.ID]; duplicate {
			return newError(generated.ErrorCodeInputInvalid, targetManifest)
		}
		ids[asset.ID] = struct{}{}
		targetKey := asset.Kind + "\x00" + asset.OS + "\x00" + asset.Architecture
		if _, duplicate := targets[targetKey]; duplicate {
			return newError(generated.ErrorCodeInputInvalid, targetManifest)
		}
		targets[targetKey] = struct{}{}
		for _, reference := range []string{asset.Path, asset.BundlePath} {
			if err := addReference(paths, reference); err != nil {
				return err
			}
		}
		for _, optional := range []*string{asset.SBOMPath, asset.ProvenancePath} {
			if optional != nil {
				if err := addReference(paths, *optional); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func validatePolicy(policy generated.ReleaseTrustPolicy) error {
	if !safePolicyText(policy.CertificateIdentity) || !safePolicyText(policy.OIDCIssuer) {
		return newError(generated.ErrorCodeInputInvalid, targetPolicy)
	}
	var trustedRoot map[string]json.RawMessage
	if len(policy.TrustedRoot) == 0 || json.Unmarshal(policy.TrustedRoot, &trustedRoot) != nil || len(trustedRoot) == 0 {
		return newError(generated.ErrorCodeInputInvalid, targetPolicy)
	}
	return nil
}

func safePolicyText(value string) bool {
	if value == "" || len(value) > 2048 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func addReference(paths map[string]struct{}, reference string) error {
	if _, err := portableReference(reference); err != nil {
		return newError(generated.ErrorCodeInputInvalid, targetManifestPath)
	}
	key := strings.ToLower(reference)
	if _, duplicate := paths[key]; duplicate {
		return newError(generated.ErrorCodeInputInvalid, targetManifestPath)
	}
	paths[key] = struct{}{}
	return nil
}

func validAssetKind(value string) bool {
	return value == "archive" || value == "executable" || value == "package"
}

func validOS(value string) bool {
	return value == "darwin" || value == "linux" || value == "windows"
}

func validArchitecture(value string) bool {
	return value == "amd64" || value == "arm64"
}
