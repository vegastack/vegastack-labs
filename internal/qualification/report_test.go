package qualification

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
	"time"
)

func TestNativeReportRejectsFixtureAndMissingScenario(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	d := hostaction.Digest("synthetic software fixture, never native proof")
	report := generated.NativeReport{Schema: generated.SchemaIDNativeReport, SchemaVersion: "1.0.0", RunID: "test-native-report", ScopeDigest: d, SourceCommit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ExecutableDigest: d, ProfileLockDigest: d, PendingRequirements: []string{}, StartedAt: now, FinishedAt: now}
	for _, scenario := range scenarioCatalog {
		report.Scenarios = append(report.Scenarios, generated.ScenarioResult{Schema: generated.SchemaIDScenarioResult, SchemaVersion: "1.0.0", ScenarioID: scenario, Status: "passed", ProfileLockDigest: d, ExecutableDigest: d, ArtifactDigest: d, StartedAt: now, FinishedAt: now, PositiveObservationDigests: []string{d}, NegativeObservationDigests: []string{d}, BeforeStateDigest: d, AfterStateDigest: d, RecoveryResult: "passed", CleanupResult: "passed", QualificationClass: "native", ProducerRunIDs: []string{"run-fixture"}, ProducerReceiptDigests: []string{d}, NativeObservationDigests: []string{d}})
	}
	if ValidateNativeReport(report) != nil {
		t.Fatal("complete diagnostic shape refused")
	}
	report.Scenarios[0].QualificationClass = "fixture"
	if ValidateNativeReport(report) == nil {
		t.Fatal("fixture report qualified")
	}
	report.Scenarios[0].QualificationClass = "native"
	report.Scenarios = report.Scenarios[1:]
	if ValidateNativeReport(report) == nil {
		t.Fatal("missing scenario qualified")
	}
}
