package gate

import (
	"context"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

// ProofVerifier is a deterministic, gate-specific verifier. The default
// production registry is empty: an upload cannot make itself authoritative.
type ProofVerifier interface {
	Verify(context.Context, Definition, generated.GateEvidence) (ProofResult, error)
}

type ProofResult struct {
	Verified   bool
	ReasonCode string
}

type ProofRegistry struct{ entries map[string]ProofVerifier }

func NewProofRegistry() ProofRegistry { return ProofRegistry{entries: map[string]ProofVerifier{}} }

func proofKey(gateID, sourceKind string) string { return gateID + "/" + sourceKind }

func (registry *ProofRegistry) Register(gateID, sourceKind string, verifier ProofVerifier) {
	if registry.entries == nil {
		registry.entries = map[string]ProofVerifier{}
	}
	if gateID != "" && (sourceKind == "local" || sourceKind == "independent") && verifier != nil {
		registry.entries[proofKey(gateID, sourceKind)] = verifier
	}
}

func (registry ProofRegistry) Lookup(gateID, sourceKind string) (ProofVerifier, bool) {
	verifier, ok := registry.entries[proofKey(gateID, sourceKind)]
	return verifier, ok
}
