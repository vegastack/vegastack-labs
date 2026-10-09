package qualification

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"strings"
	"time"
)

func trimMachineID(raw []byte) string { return strings.TrimSpace(string(raw)) }

func validateFixtureApproval(a generated.NativeSlackFixtureApproval, p generated.Plan, f generated.NativeSlackFixtureScope, epoch int64, now time.Time) error {
	expires, e := time.Parse(time.RFC3339, a.ExpiresAt)
	end, z := time.Parse(time.RFC3339, f.ExpiresAt)
	if !exactNativeJSON(generated.SchemaIDNativeSlackFixtureApproval, a) || e != nil || z != nil || !now.Before(expires) || expires.After(end) || a.PlanID == f.SetupPlanID || p.Status != "planned" || p.AuthorizationBranch != "human" || a.PlanID != p.PlanID || a.PlanDigest != p.PlanDigest || a.TargetDigest != p.Binding.TargetDigest || a.ReasonDigest != p.Binding.ReasonDigest || a.StateRevision != p.Binding.StateRevision || a.RecoveryEpoch != epoch || a.RecoveryEpoch != p.Binding.RecoveryEpoch || a.ExpiresAt != p.ExpiresAt {
		return ErrUnavailable
	}
	return nil
}

func replaceFixtureApproval(list *generated.NativeSlackFixtureApprovalList, a generated.NativeSlackFixtureApproval) error {
	if !exactNativeJSON(generated.SchemaIDNativeSlackFixtureApprovalList, *list) {
		return ErrUnavailable
	}
	seen := map[string]bool{}
	for _, old := range list.Approvals {
		if seen[old.PlanID] || old.PlanID == a.PlanID {
			return ErrUnavailable
		}
		seen[old.PlanID] = true
	}
	list.Approvals = []generated.NativeSlackFixtureApproval{a}
	if !exactNativeJSON(generated.SchemaIDNativeSlackFixtureApprovalList, *list) {
		return ErrUnavailable
	}
	return nil
}
