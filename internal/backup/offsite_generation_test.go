package backup

import (
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
)

func TestForecastGenerationRejectsExhaustedRulesAndUnprotectedPayload(t *testing.T) {
	now := time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)
	policy := testOffsitePolicy(now)
	point := testVerifiedCriticalPoint(now)
	base := adapter.RetentionObservation{GenerationID: "generation-a", RuleLimit: 1000, AvailableBytes: 2048, AvailablePUTs: 1000, AvailableLISTs: 100, ObservedAt: now, IndefiniteProtection: true, ProofClass: "fixture",
		ProtectedPrefixes: []string{"critical/generation-a/config", "critical/generation-a/keys/", "critical/generation-a/data/", "critical/generation-a/index/", "critical/generation-a/snapshots/"}, MutablePrefixes: []string{"critical/generation-a/locks/"}}
	base.RuleDigest = DigestRetentionObservation(base)
	for _, mutate := range []func(*adapter.RetentionObservation){func(v *adapter.RetentionObservation) { v.RuleCount = 996 }, func(v *adapter.RetentionObservation) { v.ProtectedPrefixes = v.ProtectedPrefixes[:2] }, func(v *adapter.RetentionObservation) { v.GenerationID = "generation-b" }} {
		observed := base
		observed.ProtectedPrefixes = append([]string(nil), base.ProtectedPrefixes...)
		mutate(&observed)
		if _, err := ForecastGeneration(policy, point, observed); err == nil {
			t.Fatal("unsafe generation admitted")
		}
	}
	admission, err := ForecastGeneration(policy, point, base)
	if err != nil || admission.Prefix != "critical/generation-a/" {
		t.Fatalf("forecast = %#v, %v", admission, err)
	}
}
