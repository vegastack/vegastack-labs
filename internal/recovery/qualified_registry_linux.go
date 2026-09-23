//go:build linux

package recovery

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter/recoverydenial"
)

const systemQualificationPath = "/etc/vsk-labs/recovery/adapter-qualifications.json"
const systemDirectDenialPath = "/etc/vsk-labs/recovery/direct-denial-adapter.json"

type systemDirectDenialConfig struct {
	Schema               string `json:"schema"`
	SchemaVersion        string `json:"schemaVersion"`
	ImplementationDigest string `json:"implementationDigest"`
	recoverydenial.HTTPSConfig
}

type systemDirectDenialVerifier struct {
	adapter *recoverydenial.HTTPSAdapter
	clock   func() time.Time
}

func newProductionDirectDenialVerifier(entry AdapterQualification) DirectDenialVerifier {
	raw, err := readProtectedWitnessFile(systemDirectDenialPath, 0, maxQualificationArtifactBytes)
	if err != nil {
		return nil
	}
	var config systemDirectDenialConfig
	if json.Unmarshal(raw, &config) != nil || config.Schema != "vegastack-labs.dev/direct-denial-adapter" || config.SchemaVersion != "1.0.0" || config.AdapterID != entry.AdapterID || config.ImplementationDigest != recoverydenial.HTTPSImplementationDigest || config.ImplementationDigest != entry.ImplementationDigest {
		return nil
	}
	adapter, err := recoverydenial.NewHTTPSAdapter(config.HTTPSConfig, time.Now)
	if err != nil {
		return nil
	}
	return systemDirectDenialVerifier{adapter: adapter, clock: time.Now}
}

func (verifier systemDirectDenialVerifier) VerifyDirectDenial(ctx context.Context, transcript DirectDenialTranscript) error {
	if verifier.adapter == nil || verifier.clock == nil {
		return ErrWitnessUnavailable
	}
	challenge := recoverydenial.Challenge{ChallengeID: transcript.ChallengeID, Kind: transcript.Requirement.Kind, SubjectID: transcript.Requirement.SubjectID, TargetID: transcript.Requirement.TargetID, AdapterID: transcript.Requirement.AdapterID, FormerIdentityID: transcript.Requirement.FormerIdentityID, ProbeID: transcript.Requirement.ProbeID, Deadline: transcript.ExpiresAt}
	result, err := verifier.adapter.Probe(ctx, challenge)
	if err != nil || recoverydenial.ValidateResult(ctx, challenge, result, verifier.clock().UTC()) != nil || result.ObserverID != transcript.ObserverID || result.ResponseDigest != transcript.ResponseDigest || !result.Denied {
		return ErrWitnessUnavailable
	}
	return nil
}

// LoadSystemQualifiedAdapters accepts the reviewed HTTPS direct-denial
// protocol only after its endpoint configuration and every exact boundary are
// independently installed and administrator-qualified.
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
