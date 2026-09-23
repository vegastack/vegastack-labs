//go:build linux

package recovery

import (
	"context"
	"crypto/ed25519"
	"os"
	"time"
)

const systemQualificationPath = "/etc/vsk-labs/recovery/adapter-qualifications.json"

// LoadSystemQualifiedAdapters has no registered production factory until each
// actual endpoint implementation and independent site qualification land.
func LoadSystemQualifiedAdapters(ctx context.Context, required []BoundaryRequirement, now time.Time) (QualifiedAdapters, error) {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() == 0 || len(productionDenialFactories) == 0 {
		return QualifiedAdapters{}, ErrWitnessUnavailable
	}
	root, err := readProtectedWitnessFile(systemAdminRootPath, 0, ed25519.PublicKeySize)
	if err != nil || len(root) != ed25519.PublicKeySize {
		return QualifiedAdapters{}, ErrWitnessUnavailable
	}
	raw, err := readProtectedWitnessFile(systemQualificationPath, 0, maxQualificationArtifactBytes)
	if err != nil || ctx.Err() != nil {
		return QualifiedAdapters{}, ErrWitnessUnavailable
	}
	return parseQualifiedAdapters(raw, root, required, now, productionDenialFactories)
}
