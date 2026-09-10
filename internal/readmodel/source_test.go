package readmodel

import (
	"strings"
	"testing"
	"time"
)

func TestEvaluateSourceStatesAndPrecedence(t *testing.T) {
	now := time.Date(2026, time.September, 10, 9, 0, 0, 0, time.UTC)
	recent := now.Add(-5 * time.Minute)
	old := now.Add(-2 * time.Hour)
	lastSuccess := now.Add(-3 * time.Hour)
	lastError := now.Add(-time.Minute)

	tests := []struct {
		name        string
		observation SourceObservation
		want        SourceState
		wantReason  string
	}{
		{"absent", SourceObservation{ID: SourceGates, Capability: "gate-read", Available: false, FailureCode: "DO_NOT_ECHO_super-secret"}, SourceUnavailable, SourceReasonUnavailable},
		{"no timestamp", SourceObservation{ID: SourceNodes, Capability: "node-read", Available: true}, SourceUnknown, SourceReasonUnknown},
		{"failure wins", SourceObservation{ID: SourceServices, Capability: "service-read", Available: true, CollectedAt: &recent, LastSuccessAt: &lastSuccess, LastErrorAt: &lastError, FailureCode: "PROVIDER_super-secret"}, SourceFailed, SourceReasonFailed},
		{"stale", SourceObservation{ID: SourceBackups, Capability: "backup-read", Available: true, CollectedAt: &old, LastSuccessAt: &old}, SourceStale, SourceReasonStale},
		{"healthy", SourceObservation{ID: SourceDatabase, Capability: "database-read", Available: true, CollectedAt: &recent, LastSuccessAt: &recent}, SourceHealthy, SourceReasonHealthy},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := EvaluateSource(test.observation, SourcePolicy{StaleAfter: time.Hour}, now)
			if err != nil {
				t.Fatal(err)
			}
			if got.State != test.want || got.Reason != test.wantReason {
				t.Fatalf("status = %#v", got)
			}
			if strings.Contains(got.Reason, "super-secret") || (test.observation.FailureCode != "" && strings.Contains(got.Reason, test.observation.FailureCode)) {
				t.Fatalf("unsafe reason = %q", got.Reason)
			}
		})
	}
}

func TestEvaluateSourceRejectsInvalidInputs(t *testing.T) {
	now := time.Date(2026, time.September, 10, 9, 0, 0, 0, time.UTC)
	for _, observation := range []SourceObservation{
		{ID: "cloudflare", Capability: "provider-read", Available: true},
		{ID: SourceDatabase, Capability: "", Available: true},
	} {
		if _, err := EvaluateSource(observation, SourcePolicy{StaleAfter: time.Hour}, now); err == nil {
			t.Fatalf("observation accepted: %#v", observation)
		}
	}
	if _, err := EvaluateSource(SourceObservation{ID: SourceDatabase, Capability: "database-read", Available: true}, SourcePolicy{}, now); err == nil {
		t.Fatal("zero freshness policy accepted")
	}
}

func TestSummarizeSourcesCountsAndWorstState(t *testing.T) {
	counts, worst := SummarizeSources([]SourceStatus{
		{ID: SourceDatabase, State: SourceHealthy},
		{ID: SourceNodes, State: SourceUnknown},
		{ID: SourceBackups, State: SourceUnavailable},
		{ID: SourceServices, State: SourceFailed},
		{ID: SourceProviders, State: SourceStale},
	})
	if counts != (SourceCounts{Total: 5, Healthy: 1, Stale: 1, Unknown: 1, Unavailable: 1, Failed: 1}) || worst != SourceFailed {
		t.Fatalf("summary = %#v/%q", counts, worst)
	}
}
