package maintenance

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
	"time"
)

func TestCanaryFailureAndUncertaintyStopLaterBatches(t *testing.T) {
	for _, status := range []string{"failed", "partial", "unknown", "unsupported"} {
		targets := []generated.MaintenanceTarget{{HostID: "host-a", BindingDigest: hostaction.Digest("a"), Diagnosis: "healthy", Canary: status, Drain: "passed", Health: "passed", Recovery: "passed"}, {HostID: "host-b", BindingDigest: hostaction.Digest("b"), Diagnosis: "healthy", Canary: "passed", Drain: "passed", Health: "passed", Recovery: "passed"}}
		if NextBatchReady(targets, "host-a") {
			t.Fatal(status)
		}
	}
}
func TestInertDraftBindsExactOrderAndIncidentAndCannotExecute(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	q := generated.MaintenanceDraftRequest{Schema: generated.SchemaIDMaintenanceDraftRequest, SchemaVersion: "1.0.0", DeclarationID: "maintenance-a", ExpectedRevision: 2, ExpectedStateRevision: 4, RecoveryEpoch: 1, Action: "incident-reconciliation", TargetIDs: []string{"host-a"}, CanaryHostID: "host-a", ReasonDigest: hostaction.Digest("reason"), Incident: &generated.MaintenanceIncident{Schema: generated.SchemaIDMaintenanceIncident, SchemaVersion: "1.0.0", ResponsibleHumanDigest: hostaction.Digest("human-a"), AgentSessionDigest: hostaction.Digest("session-a"), ReasonDigest: hostaction.Digest("incident"), StartedAt: now.Add(-time.Minute).Format(time.RFC3339), EndedAt: now.Format(time.RFC3339), EvidenceDigests: []string{hostaction.Digest("evidence")}}}
	d, _ := Diagnose(sample(now), now)
	record, e := Prepare(q, []generated.MaintenanceDiagnosis{d}, "human-a", "session-a", now)
	if e != nil {
		t.Fatal(e)
	}
	draft, e := Declaration(q, record)
	if e != nil || draft.ExpectedRevision != 2 || draft.Maintenance == nil || record.ExecutionAvailable || len(draft.Operations) != 1 || draft.Operations[0].AdapterID != "local.maintenance.unsupported" {
		t.Fatal(draft, e)
	}
	q.TargetIDs = []string{"host-b"}
	if _, e = Prepare(q, []generated.MaintenanceDiagnosis{d}, "human-a", "session-a", now); e == nil {
		t.Fatal("broadened target")
	}
	q.TargetIDs = []string{"host-a"}
	q.RecoveryEpoch = 2
	if _, e = Prepare(q, []generated.MaintenanceDiagnosis{d}, "human-a", "session-a", now); e == nil {
		t.Fatal("stale epoch")
	}
	q.RecoveryEpoch = 1
	q.Incident.EndedAt = now.Add(time.Hour).Format(time.RFC3339)
	if _, e = Prepare(q, []generated.MaintenanceDiagnosis{d}, "human-a", "session-a", now); e == nil {
		t.Fatal("future incident")
	}
}

func TestRecordedCanaryFailurePartialAndWrongTarget(t *testing.T) {
	plan := generated.Plan{PlanID: "plan-a", PlanDigest: hostaction.Digest("plan"), Binding: generated.PlanBinding{RecoveryEpoch: 1}}
	for _, tc := range []struct{ status, effect, want string }{{"failed", "verified", "failed"}, {"cancelled", "verified", "failed"}, {"partial", "verified", "partial"}, {"running", "effect-unknown", "partial"}, {"succeeded", "verified", "unknown"}} {
		run := generated.Run{PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, RecoveryEpoch: 1, Status: tc.status, Steps: []generated.RunStep{{TargetID: "host-a", EffectState: tc.effect}}}
		got, e := CanaryStatus(run, plan, "host-a", 1)
		if e != nil || got != tc.want {
			t.Fatal(got, e)
		}
		if _, e = CanaryStatus(run, plan, "host-b", 1); e == nil {
			t.Fatal("wrong canary target")
		}
		if _, e = CanaryStatus(run, plan, "host-a", 2); e == nil {
			t.Fatal("stale canary epoch")
		}
	}
}
