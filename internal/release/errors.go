// Package release loads, inspects, and verifies provider-neutral local release
// sets without executing artifacts or contacting a network endpoint.
package release

import "github.com/vegastack/vegastack-labs/internal/generated"

const (
	targetAssetFile      = "asset-file"
	targetBundleFile     = "bundle-file"
	targetContext        = "context"
	targetManifest       = "manifest"
	targetManifestFile   = "manifest-file"
	targetManifestPath   = "manifest-path"
	targetManifestSchema = "manifest-schema"
	targetPlatform       = "platform"
	targetPolicy         = "policy"
	targetPolicyFile     = "policy-file"
	targetPolicySchema   = "policy-schema"
	targetReference      = "release-reference"
)

// Error is deliberately sanitized: it retains neither an underlying error nor
// a rejected value or private filesystem path.
type Error struct {
	Code   string
	Target string
}

func (err *Error) Error() string {
	if err == nil {
		return ""
	}
	return err.Code + ": " + err.Target
}

func newError(code, target string) *Error {
	return &Error{Code: code, Target: target}
}

func interrupted() *Error {
	return newError(generated.ErrorCodeInterrupted, targetContext)
}
