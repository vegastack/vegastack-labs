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
	// Read-only scenarios may omit nonexistent before/after samples. A partial
	// pair and an omitted owning comparison must still fail.
	report.Scenarios[0].BeforeStateDigest = ""
	report.Scenarios[0].AfterStateDigest = ""
	if ValidateNativeReport(report) != nil {
		t.Fatal("truthful omitted state pair rejected")
	}
	report.Scenarios[0].BeforeStateDigest = d
	if ValidateNativeReport(report) == nil {
		t.Fatal("one-sided state pair accepted")
	}
	report.Scenarios[0].BeforeStateDigest = ""
	for i := range report.Scenarios {
		if report.Scenarios[i].ScenarioID == "access-idempotence" {
			report.Scenarios[i].BeforeStateDigest = ""
			report.Scenarios[i].AfterStateDigest = ""
			if ValidateNativeReport(report) == nil {
				t.Fatal("missing idempotence comparison accepted")
			}
			report.Scenarios[i].BeforeStateDigest = d
			report.Scenarios[i].AfterStateDigest = d
		}
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
