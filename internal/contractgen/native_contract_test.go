package contractgen

import (
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"strings"
	"testing"
)

func TestNativePayloadOmissionPreservesHistoricalBundleBytes(t *testing.T) {
	const legacy = `{"schema":"vegastack-labs.dev/gate-evidence-bundle","schemaVersion":"1.1.0","facts":[],"checks":[],"attachments":[],"collectorId":"legacy-collector","observedAt":"2026-10-09T00:00:00Z"}`
	var b generated.GateEvidenceBundle
	if err := json.Unmarshal([]byte(legacy), &b); err != nil {
		t.Fatal(err)
	}
	if b.NativeQualification != nil {
		t.Fatal("absent payload populated")
	}
	raw, err := json.Marshal(b)
	if err != nil || string(raw) != legacy {
		t.Fatalf("historical bundle bytes changed: %s %v", raw, err)
	}
	if err := generated.ValidateContractJSON(generated.SchemaIDGateEvidenceBundle, raw, generated.ContractExact); err != nil {
		t.Fatal(err)
	}
}

func TestNativeProducerContractsFitCompleteBaselineWithinFiniteBound(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, count := range []int{52, 64, 65} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			request := generated.NativeCollectRequest{Schema: generated.SchemaIDNativeCollectRequest, SchemaVersion: "1.0.0", ScopeDigest: digest, Stage: "baseline", EvidenceID: "evidence", ProfileID: "profile", ExpectedStateRevision: 1, RecoveryEpoch: 0, IdempotencyKey: "collect"}
			qualification := generated.NativeQualification{Schema: generated.SchemaIDNativeQualification, SchemaVersion: "1.0.0", Stage: "baseline", ScopeDigest: digest, ProfileID: "profile", ProfileLockDigest: digest, SourceCommit: strings.Repeat("a", 40), SourceDigest: digest, ExecutableDigest: digest, ControllerInstanceID: "controller", RecoveryEpoch: 0, ObservedAt: "2026-10-10T00:00:00Z", ExpiresAt: "2026-10-10T00:01:00Z", ObserverDigest: digest}
			for i := 0; i < count; i++ {
				reference := generated.NativeProducerReference{Schema: generated.SchemaIDNativeProducerReference, SchemaVersion: "1.0.0", ScenarioID: "baseline-access", HostID: "host", PlanID: fmt.Sprintf("plan-%d", i), PlanDigest: digest, RunID: fmt.Sprintf("run-%d", i), StepID: fmt.Sprintf("step-%d", i), LeaseID: fmt.Sprintf("lease-%d", i)}
				request.Producers = append(request.Producers, reference)
				qualification.Producers = append(qualification.Producers, generated.NativeQualificationProducer{Schema: generated.SchemaIDNativeQualificationProducer, SchemaVersion: "1.0.0", Reference: reference, HostIdentityDigest: digest, ReceiptDigest: digest})
			}
			for _, value := range []struct {
				schema   string
				document any
			}{{generated.SchemaIDNativeCollectRequest, request}, {generated.SchemaIDNativeQualification, qualification}} {
				encoded, err := json.Marshal(value.document)
				if err != nil {
					t.Fatal(err)
				}
				err = generated.ValidateContractJSON(value.schema, encoded, generated.ContractExact)
				if (count <= 64) != (err == nil) {
					t.Fatalf("%s count %d: %v", value.schema, count, err)
				}
			}
		})
	}
}
