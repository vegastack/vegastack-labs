package localapi

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
)

func TestNativeCollectorClientBindsOriginalRequest(t *testing.T) {
	in := generated.NativeCollectRequest{Schema: generated.SchemaIDNativeCollectRequest, SchemaVersion: "1.0.0", ScopeDigest: hostaction.BytesDigest([]byte("scope")), Stage: "baseline", EvidenceID: "native-a", ProfileID: "profile-a", Producers: []generated.NativeProducerReference{{Schema: generated.SchemaIDNativeProducerReference, SchemaVersion: "1.0.0", ScenarioID: "baseline-access", HostID: "host-a", PlanID: "plan-a", PlanDigest: hostaction.BytesDigest([]byte("plan")), RunID: "run-a", StepID: "step-a", LeaseID: "lease-a"}}, ExpectedStateRevision: 2, RecoveryEpoch: 0, IdempotencyKey: "collect-a"}
	other := in
	other.Stage = "role"
	for _, variant := range []string{"own", "substituted", "epoch"} {
		t.Run(variant, func(t *testing.T) {
			data := generated.NativeCollectData{Schema: generated.SchemaIDNativeCollectData, SchemaVersion: "1.0.0", RequestDigest: hostaction.Digest(in), Submission: generated.GateEvidenceSubmission{Schema: generated.SchemaIDGateEvidenceSubmission, SchemaVersion: "1.1.0", DraftID: "native-a", ChangeID: "gate-evidence-native-a", EvidenceID: "native-a", Status: "draft", StateRevision: 4, RecoveryEpoch: 0}}
			check, _ := json.Marshal(data)
			if err := generated.ValidateContractJSON(generated.SchemaIDNativeCollectData, check, generated.ContractExact); err != nil {
				t.Fatalf("fixture %v %s", err, check)
			}
			if variant == "substituted" {
				data.RequestDigest = hostaction.Digest(other)
			}
			if variant == "epoch" {
				data.Submission.RecoveryEpoch = 1
			}
			_, profile, captured := serveFixedResponse(t, 200, operationEnvelope(t, "api.v1.qualification.collect", true, 0, 4, data))
			_, err := NewClient(clientTestFactory()).CollectNativeQualification(context.Background(), profile, in)
			select {
			case <-captured:
			default:
				t.Fatal("request did not reach transport")
			}
			if (err == nil) != (variant == "own") {
				t.Fatalf("variant=%s error=%v", variant, err)
			}
		})
	}
}
