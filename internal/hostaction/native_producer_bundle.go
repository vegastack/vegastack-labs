package hostaction

import "github.com/vegastack/vegastack-labs/internal/generated"

// NativeProducerBundleMatches binds a diagnostic completed protocol bundle to
// its ordinary producer read. It confers no execution or evidence authority.
func NativeProducerBundleMatches(in generated.NativeProducerLookupRequest, ref generated.NativeProducerReference, b generated.HostActionBundle) bool {
	if (in.ScenarioID != "action-replay" && in.ScenarioID != "action-concurrency") || ref.ScenarioID != in.ScenarioID || ref.HostID != in.HostID || ref.PlanID != in.PlanID || ref.PlanDigest != in.PlanDigest || ref.RunID != in.RunID || ref.StepID != in.StepID || ref.LeaseID == "" {
		return false
	}
	_, err := BundleDigest(b)
	return err == nil && b.ActionID == "debian.access.collect" && b.ActionInputDigest == BytesDigest([]byte(b.ActionInput)) && b.HostID == ref.HostID && b.PlanID == ref.PlanID && b.PlanDigest == ref.PlanDigest && b.RunID == ref.RunID && b.StepID == ref.StepID && b.LeaseID == ref.LeaseID && b.RecoveryEpoch == in.RecoveryEpoch
}
