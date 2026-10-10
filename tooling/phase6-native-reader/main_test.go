package main

import (
	"encoding/json"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestCurrentGateComparisonRejectsAuthorityChanges(t *testing.T) {
	a := generated.GateView{Definition: generated.GateDefinition{GateID: "native.baseline"}, Evaluation: generated.GateEvaluation{GateID: "native.baseline", SubjectID: "synthetic-profile", Outcome: "passed", RecoveryEpoch: 1, EvidenceIDs: []string{"applied-a"}, EvaluatedAt: "2026-10-10T08:00:00Z", EvaluationID: "first"}}
	raw, _ := json.Marshal(a)
	newer := a
	newer.Evaluation.EvaluatedAt = "2026-10-10T08:00:01Z"
	newer.Evaluation.EvaluationID = "second"
	fresh, _ := json.Marshal(newer)
	if !sameGate(raw, fresh) {
		t.Fatal("fresh identical authority reported as drift")
	}
	for _, change := range []func(*generated.GateView){func(v *generated.GateView) { v.Evaluation.RecoveryEpoch++ }, func(v *generated.GateView) { v.Evaluation.EvidenceIDs = []string{"superseding-b"} }, func(v *generated.GateView) { v.Evaluation.Outcome = "blocked" }, func(v *generated.GateView) { v.Evaluation.SubjectID = "other-profile" }} {
		changed := a
		change(&changed)
		other, _ := json.Marshal(changed)
		if sameGate(raw, other) {
			t.Fatal("changed current authority retained")
		}
	}
}
