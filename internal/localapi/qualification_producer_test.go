package localapi

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
)

func TestNativeProducerClientBindsActualReference(t *testing.T) {
	in := generated.NativeProducerLookupRequest{Schema: generated.SchemaIDNativeProducerLookupRequest, SchemaVersion: "1.0.0", ScopeDigest: hostaction.Digest("scope"), ScenarioID: "baseline-access", HostID: "host-a", PlanID: "plan-a", PlanDigest: hostaction.Digest("plan"), RunID: "run-a", StepID: "step-a", RecoveryEpoch: 0}
	for _, kind := range []string{"own", "run", "host", "epoch"} {
		t.Run(kind, func(t *testing.T) {
			data := generated.NativeProducerReference{Schema: generated.SchemaIDNativeProducerReference, SchemaVersion: "1.0.0", ScenarioID: in.ScenarioID, HostID: in.HostID, PlanID: in.PlanID, PlanDigest: in.PlanDigest, RunID: in.RunID, StepID: in.StepID, LeaseID: "actual-lease"}
			epoch := int64(0)
			if kind == "run" {
				data.RunID = "other-run"
			}
			if kind == "host" {
				data.HostID = "other-host"
			}
			if kind == "epoch" {
				epoch = 1
			}
			_, profile, captured := serveFixedResponse(t, 200, operationEnvelope(t, "api.v1.qualification.producer", false, epoch, 2, data))
			_, err := NewClient(clientTestFactory()).LookupNativeProducerReference(context.Background(), profile, in)
			select {
			case <-captured:
			default:
				t.Fatal("no actual request")
			}
			if (err == nil) != (kind == "own") {
				t.Fatalf("kind=%s error=%v", kind, err)
			}
		})
	}
}
