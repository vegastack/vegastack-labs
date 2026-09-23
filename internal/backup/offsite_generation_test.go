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

func TestRetentionDigestSeparatesProtectedAndMutablePrefixes(t *testing.T) {
	now := time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)
	protected := "critical/generation-a/config"
	mutable := "critical/generation-a/locks/"
	base := adapter.RetentionObservation{GenerationID: "generation-a", ProtectedPrefixes: []string{protected}, MutablePrefixes: []string{mutable}, ObservedAt: now}
	swapped := base
	swapped.ProtectedPrefixes = []string{mutable}
	swapped.MutablePrefixes = []string{protected}
	if DigestRetentionObservation(base) == DigestRetentionObservation(swapped) {
		t.Fatal("retention digest did not bind prefix authority")
	}
}

func TestGenerationAdmissionRequiresExactRuleBoundary(t *testing.T) {
	admission := GenerationAdmission{GenerationID: "generation-a", Prefix: "critical/generation-a/", RuleDigest: offsiteDigest("a"), MaximumBytes: 1024, MaximumPUTs: 100, MaximumLISTs: 20,
		ProtectedPrefixes: []string{"critical/generation-a/config", "critical/generation-a/keys/", "critical/generation-a/data/", "critical/generation-a/index/", "critical/generation-a/snapshots/"}, MutablePrefixes: []string{"critical/generation-a/locks/"}}
	if !validGenerationAdmission(admission) {
		t.Fatal("exact generation admission rejected")
	}
	for name, mutate := range map[string]func(*GenerationAdmission){
		"missing rule digest": func(value *GenerationAdmission) { value.RuleDigest = "" },
		"cross generation":    func(value *GenerationAdmission) { value.Prefix = "critical/generation-b/" },
		"payload mutable": func(value *GenerationAdmission) {
			value.MutablePrefixes = append(value.MutablePrefixes, "critical/generation-a/data/")
		},
	} {
		t.Run(name, func(t *testing.T) {
			altered := admission
			altered.ProtectedPrefixes = append([]string(nil), admission.ProtectedPrefixes...)
			altered.MutablePrefixes = append([]string(nil), admission.MutablePrefixes...)
			mutate(&altered)
			if validGenerationAdmission(altered) {
				t.Fatal("forged generation admission accepted")
			}
		})
	}
}
