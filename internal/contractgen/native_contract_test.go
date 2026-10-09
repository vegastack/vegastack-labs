package contractgen

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
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
