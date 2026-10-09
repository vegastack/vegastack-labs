package qualification

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// Controller selection routes the bounded fixture client only. It grants no
// capability: the collector independently resolves the durable verified restore.
func validateControllerSelection(s validatedNativeScope, in generated.NativeStepRequest, identity generated.NativeControllerIdentity, b generated.RestoreBinding) error {
	g, ok := s.guests[in.GuestID]
	if !ok || g.Role != "replacement" || in.Operation != "select-controller" || in.ScenarioID != "replacement-recovery" || !exactNativeJSON(generated.SchemaIDNativeControllerIdentity, identity) || !exactNativeJSON(generated.SchemaIDRestoreBinding, b) || identity.HostID != g.HostID || identity.HostIdentityDigest != g.HostIdentityDigest || identity.ScopeDigest != s.digest || identity.ExecutableDigest != s.value.ExecutableDigest || identity.ControllerInstanceID != b.NewInstanceID || b.PriorInstanceID != s.value.ControllerInstanceID || b.NewInstanceID == b.PriorInstanceID || b.NextRecoveryEpoch != b.PriorRecoveryEpoch+1 || in.RecoveryEpoch != b.NextRecoveryEpoch || b.ReplacementHostID != g.HostID || b.ReplacementContinuity == nil {
		return ErrUnavailable
	}
	for _, old := range s.guests {
		if old.Role == "controller" && old.HostID == b.FormerHostID && old.HostIdentityDigest != g.HostIdentityDigest {
			return nil
		}
	}
	return ErrUnavailable
}
