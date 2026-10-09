package qualification

import (
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

type nativeReportProgress struct {
	epoch  int64
	stages map[string]generated.NativeCollectData
}

func newNativeReportProgress() *nativeReportProgress {
	return &nativeReportProgress{epoch: -1, stages: map[string]generated.NativeCollectData{}}
}
func (p *nativeReportProgress) resetEpoch(epoch int64, report *generated.NativeReport) {
	if p.epoch == epoch {
		return
	}
	p.epoch = epoch
	p.stages = map[string]generated.NativeCollectData{}
	for i := range report.Scenarios {
		if report.Scenarios[i].Status == "passed" {
			report.Scenarios[i].Status = "uncertain"
		}
	}
	refreshReportPending(report)
}
func (p *nativeReportProgress) collect(in generated.NativeCollectRequest, data generated.NativeCollectData, report *generated.NativeReport) error {
	if !exactNativeJSON(generated.SchemaIDNativeCollectData, data) || data.RequestDigest != hostaction.Digest(in) || data.Submission.EvidenceID != in.EvidenceID || data.Submission.RecoveryEpoch != in.RecoveryEpoch || data.Submission.Status != "draft" || !nativeDigest(data.BundleDigest) || in.ScopeDigest != report.ScopeDigest {
		return ErrUnavailable
	}
	wanted := StageScenarios(in.Stage)
	if len(wanted) == 0 || len(wanted) != len(data.Scenarios) {
		return ErrUnavailable
	}
	seen := map[string]bool{}
	for _, r := range data.Scenarios {
		allowed := false
		for _, id := range wanted {
			allowed = allowed || id == r.ScenarioID
		}
		if !allowed || seen[r.ScenarioID] || r.Status != "uncertain" || r.ArtifactDigest != data.BundleDigest || r.ExecutableDigest != report.ExecutableDigest || r.ProfileLockDigest != report.ProfileLockDigest || r.QualificationClass != "native" || len(r.ProducerRunIDs) == 0 || len(r.ProducerReceiptDigests) == 0 || len(r.NativeObservationDigests) == 0 || len(r.PositiveObservationDigests) == 0 || len(r.NegativeObservationDigests) == 0 || (r.BeforeStateDigest == "") != (r.AfterStateDigest == "") || (ScenarioRequiresStatePair(r.ScenarioID) && r.BeforeStateDigest == "") {
			return ErrUnavailable
		}
		seen[r.ScenarioID] = true
	}
	p.resetEpoch(in.RecoveryEpoch, report)
	p.stages[in.Stage] = data
	// A fresh draft cannot inherit the old applied result for the same stage.
	for i := range report.Scenarios {
		if seen[report.Scenarios[i].ScenarioID] {
			report.Scenarios[i].Status = "uncertain"
		}
	}
	refreshReportPending(report)
	return nil
}
func (p *nativeReportProgress) gate(profile string, view generated.GateView, report *generated.NativeReport) error {
	evaluation := view.Evaluation
	stage := strings.TrimPrefix(evaluation.GateID, "native.")
	data, ok := p.stages[stage]
	if !ok {
		return nil
	}
	if !exactNativeJSON(generated.SchemaIDGateView, view) || view.Definition.GateID != evaluation.GateID || evaluation.SubjectID != profile || evaluation.RecoveryEpoch != p.epoch {
		return ErrUnavailable
	}
	found := false
	for _, id := range evaluation.EvidenceIDs {
		found = found || id == data.Submission.EvidenceID
	}
	passed := evaluation.Outcome == "passed" && evaluation.EvidenceSource == "local" && found
	evaluated, err := time.Parse(time.RFC3339Nano, evaluation.EvaluatedAt)
	if err != nil {
		return ErrUnavailable
	}
	for _, summary := range data.Scenarios {
		observed, err := time.Parse(time.RFC3339Nano, summary.FinishedAt)
		if err != nil || evaluated.Before(observed) {
			return ErrUnavailable
		}
		for i := range report.Scenarios {
			if report.Scenarios[i].ScenarioID == summary.ScenarioID {
				report.Scenarios[i] = summary
				if passed {
					report.Scenarios[i].Status = "passed"
				}
			}
		}
	}
	refreshReportPending(report)
	return nil
}
func refreshReportPending(report *generated.NativeReport) {
	report.PendingRequirements = []string{}
	for _, s := range report.Scenarios {
		if s.Status != "passed" {
			report.PendingRequirements = append(report.PendingRequirements, s.ScenarioID)
		}
	}
}
