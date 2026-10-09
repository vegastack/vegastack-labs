package qualification

import (
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

func TestReportRequiresCollectedExactAppliedEvidenceAndCurrentEpoch(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	digest := hostaction.Digest("diagnostic fixture")
	report := generated.NativeReport{ScopeDigest: digest, ExecutableDigest: digest, ProfileLockDigest: digest, StartedAt: now, FinishedAt: now}
	for _, id := range scenarioCatalog {
		report.Scenarios = append(report.Scenarios, generated.ScenarioResult{ScenarioID: id, Status: "not-run"})
	}
	p := newNativeReportProgress()
	in := generated.NativeCollectRequest{Stage: "recovery", ScopeDigest: digest, EvidenceID: "collected", ProfileID: "profile", RecoveryEpoch: 1}
	summary := generated.ScenarioResult{Schema: generated.SchemaIDScenarioResult, SchemaVersion: "1.0.0", ScenarioID: "replacement-recovery", Status: "uncertain", ArtifactDigest: digest, ProfileLockDigest: digest, ExecutableDigest: digest, StartedAt: now, FinishedAt: now, PositiveObservationDigests: []string{digest}, NegativeObservationDigests: []string{digest}, BeforeStateDigest: digest, AfterStateDigest: digest, RecoveryResult: "passed", CleanupResult: "not-required", QualificationClass: "native", ProducerRunIDs: []string{"actual-run"}, ProducerReceiptDigests: []string{digest}, NativeObservationDigests: []string{digest}}
	data := generated.NativeCollectData{Schema: generated.SchemaIDNativeCollectData, SchemaVersion: "1.0.0", RequestDigest: hostaction.Digest(in), BundleDigest: digest, Scenarios: []generated.ScenarioResult{summary}, Submission: generated.GateEvidenceSubmission{Schema: generated.SchemaIDGateEvidenceSubmission, SchemaVersion: "1.1.0", EvidenceID: "collected", DraftID: "draft", ChangeID: "change", Status: "draft", StateRevision: 1, RecoveryEpoch: 1}}
	if p.collect(in, data, &report) != nil {
		t.Fatal("valid internal collection rejected")
	}
	index := len(report.Scenarios) - 1
	if report.Scenarios[index].Status == "passed" {
		t.Fatal("draft passed without applied gate")
	}
	view := generated.GateView{Schema: generated.SchemaIDGateView, SchemaVersion: "1.1.0", ApplicabilityReasonCode: "always", Evaluation: generated.GateEvaluation{Schema: generated.SchemaIDGateEvaluation, SchemaVersion: "1.1.0", EvaluationID: "evaluation", GateID: "native.recovery", SubjectID: "profile", DefinitionVersion: "1.0.0", EvaluatorVersion: "1.0.0", EvidenceIDs: []string{"different"}, EvaluatedAt: now, RecoveryEpoch: 1, Outcome: "passed", ReasonCode: "proof-verified", EvidenceSource: "local"}}
	for _, definition := range generated.GeneratedGateDefinitions {
		if definition.GateID == "native.recovery" {
			view.Definition = definition
		}
	}
	if p.gate("profile", view, &report) != nil {
		t.Fatal("valid gate shape rejected")
	}
	if report.Scenarios[index].Status == "passed" {
		t.Fatal("other evidence passed cached collection")
	}
	view.Evaluation.EvidenceIDs = []string{"collected"}
	if p.gate("profile", view, &report) != nil || report.Scenarios[index].Status != "passed" {
		t.Fatal("exact applied evidence rejected")
	}
	view.Evaluation.Outcome = "blocked"
	if p.gate("profile", view, &report) != nil || report.Scenarios[index].Status == "passed" {
		t.Fatal("later blocked evaluation left passed")
	}
	view.Evaluation.Outcome = "passed"
	p.gate("profile", view, &report)
	p.resetEpoch(2, &report)
	if report.Scenarios[index].Status == "passed" || len(p.stages) != 0 {
		t.Fatal("old epoch retained qualification")
	}
	if p.collect(in, generated.NativeCollectData{Schema: data.Schema, SchemaVersion: data.SchemaVersion, Submission: data.Submission, BundleDigest: hostaction.Digest("different"), RequestDigest: data.RequestDigest, Scenarios: data.Scenarios}, &report) == nil {
		t.Fatal("substituted bundle accepted")
	}
}
