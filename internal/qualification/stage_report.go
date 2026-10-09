package qualification

import (
	"sort"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

// SummarizeStageEvidence is diagnostic presentation of already resolved and
// validated producer observations. It creates neither gate authority nor a new
// evidence ingestion route. A composite witness digest may appear in both
// observation lists because the owning predicate checked both outcomes in it.
func SummarizeStageEvidence(stage string, executions []ProducerExecution, observations []generated.NativeObservation, profileLock, bundleDigest string) ([]generated.ScenarioResult, error) {
	if ValidateStageEvidence(stage, executions, observations) != nil || !nativeDigest(profileLock) || !nativeDigest(bundleDigest) {
		return nil, ErrUnavailable
	}
	results := []generated.ScenarioResult{}
	for _, scenario := range StageScenarios(stage) {
		r := generated.ScenarioResult{Schema: generated.SchemaIDScenarioResult, SchemaVersion: "1.0.0", ScenarioID: scenario, Status: "uncertain", ProfileLockDigest: profileLock, ArtifactDigest: bundleDigest, PositiveObservationDigests: []string{}, NegativeObservationDigests: []string{}, ProducerRunIDs: []string{}, ProducerReceiptDigests: []string{}, NativeObservationDigests: []string{}, RecoveryResult: "not-required", CleanupResult: "not-required", QualificationClass: "native"}
		var scenarioExecutions []ProducerExecution
		var scenarioObservations []generated.NativeObservation
		for i, e := range executions {
			if e.Reference.ScenarioID != scenario {
				continue
			}
			o := observations[i]
			scenarioExecutions = append(scenarioExecutions, e)
			scenarioObservations = append(scenarioObservations, o)
			r.ExecutableDigest = o.ExecutableDigest
			r.ProducerRunIDs = appendDistinct(r.ProducerRunIDs, e.Reference.RunID)
			r.ProducerReceiptDigests = appendDistinct(r.ProducerReceiptDigests, hostaction.Digest(e.Receipt))
			r.NativeObservationDigests = appendDistinct(r.NativeObservationDigests, hostaction.Digest(o))
			at, err := time.Parse(time.RFC3339Nano, o.ObservedAt)
			if err != nil {
				return nil, ErrUnavailable
			}
			stamp := at.UTC().Format(time.RFC3339Nano)
			first, _ := time.Parse(time.RFC3339Nano, r.StartedAt)
			if r.StartedAt == "" || at.Before(first) {
				r.StartedAt = stamp
			}
			last, _ := time.Parse(time.RFC3339Nano, r.FinishedAt)
			if r.FinishedAt == "" || at.After(last) {
				r.FinishedAt = stamp
			}
			if e.Result != nil {
				for _, m := range e.Result.ControlMeasurements {
					if nativeDigest(m.PositiveProbeDigest) {
						r.PositiveObservationDigests = appendDistinct(r.PositiveObservationDigests, m.PositiveProbeDigest)
					}
					if nativeDigest(m.NegativeProbeDigest) {
						r.NegativeObservationDigests = appendDistinct(r.NegativeObservationDigests, m.NegativeProbeDigest)
					}
				}
			}
		}
		composite := hostaction.Digest(scenarioObservations)
		if len(r.PositiveObservationDigests) == 0 {
			r.PositiveObservationDigests = []string{composite}
		}
		if len(r.NegativeObservationDigests) == 0 {
			r.NegativeObservationDigests = []string{composite}
		}
		r.BeforeStateDigest, r.AfterStateDigest = scenarioObservedPair(scenario, scenarioExecutions, scenarioObservations)
		if ScenarioRequiresStatePair(scenario) && (r.BeforeStateDigest == "" || r.AfterStateDigest == "") {
			return nil, ErrUnavailable
		}
		if strings.HasPrefix(scenario, "access-rollback-") || scenario == "replacement-recovery" {
			r.RecoveryResult = "passed"
		}
		results = append(results, r)
	}
	return results, nil
}
func appendDistinct(values []string, v string) []string {
	for _, existing := range values {
		if existing == v {
			return values
		}
	}
	return append(values, v)
}
func ScenarioRequiresStatePair(s string) bool {
	return s == "access-idempotence" || s == "access-rollback-timeout" || s == "access-rollback-reboot" || s == "volume-unchanged-after-verification" || s == "replacement-recovery"
}
func scenarioObservedPair(s string, es []ProducerExecution, os []generated.NativeObservation) (string, string) {
	if s == "access-idempotence" {
		var applies []ProducerExecution
		for _, e := range es {
			if e.Plan.HostAction != nil && e.Plan.HostAction.ActionID == "debian.access.apply" && e.Result != nil && len(e.Result.ControlMeasurements) > 0 {
				applies = append(applies, e)
			}
		}
		sort.Slice(applies, func(i, j int) bool {
			a, _ := time.Parse(time.RFC3339Nano, applies[i].Result.ControlMeasurements[0].ObservedAt)
			b, _ := time.Parse(time.RFC3339Nano, applies[j].Result.ControlMeasurements[0].ObservedAt)
			return a.Before(b)
		})
		if len(applies) == 2 {
			return hostaction.Digest(applies[0].Result.ControlMeasurements), hostaction.Digest(applies[1].Result.ControlMeasurements)
		}
	}
	for _, o := range os {
		if o.RollbackBefore != nil && o.RollbackAfter != nil {
			return hostaction.Digest(o.RollbackBefore), hostaction.Digest(o.RollbackAfter)
		}
		if w := o.VolumeCase; w != nil {
			return hostaction.Digest([]string{w.HeaderBeforeDigest, w.OriginalPolicyDigest, w.TestedCopyBeforeDigest}), hostaction.Digest([]string{w.HeaderAfterDigest, w.OriginalPolicyAfterDigest, w.TestedCopyAfterDigest})
		}
		if w := o.VolumeSeal; w != nil {
			return w.HeaderBeforeDigest, w.HeaderAfterDigest
		}
		if w := o.ReplacementRecovery; w != nil {
			var before, after string
			for _, a := range w.Attempts {
				if a.Kind == "concurrent-replacement" {
					before = hostaction.Digest(a.Before)
				}
				if a.Kind == "old-host-return" {
					after = hostaction.Digest(a.After)
				}
			}
			return before, after
		}
	}
	return "", ""
}
