package networkingress

// RotationState contains references and independently observed sessions, never a token.
type RotationState struct {
	ProviderAcknowledged bool
	DeclaredConnectorIDs []string
	OldConnections       []Connection
	MaterialVersion      string
}
type RotationObservation struct {
	Connections []Connection
	Complete    bool
}
type RotationResult struct{ Stage, Reason string }

// EvaluateRotation cannot infer token generation from Cloudflare's connection API.
// A manual receipt and a new session timestamp do not prove installed credential custody.
func EvaluateRotation(s RotationState, o RotationObservation) RotationResult {
	if !s.ProviderAcknowledged {
		return RotationResult{"uncertain", "provider-rotation-unconfirmed"}
	}
	if !o.Complete {
		return RotationResult{"verification-pending", "connector-observation-incomplete"}
	}
	seen := map[string]bool{}
	for _, c := range o.Connections {
		seen[c.ConnectorID] = true
		for _, old := range s.OldConnections {
			if old.ConnectionID == c.ConnectionID {
				return RotationResult{"connector-update-required", "old-connection-remains"}
			}
		}
	}
	for _, id := range s.DeclaredConnectorIDs {
		if !seen[id] {
			return RotationResult{"partial", "declared-connector-unavailable"}
		}
	}
	return RotationResult{"verification-pending", "credential-generation-not-independently-proven"}
}
