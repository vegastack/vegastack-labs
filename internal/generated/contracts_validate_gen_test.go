package generated

import (
	"encoding/json"
	"os"
	"testing"
)

func phase4Fixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../tooling/testdata/phase-4/contracts/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPhase4GeneratedValidationModesAndBindings(t *testing.T) {
	plan := phase4Fixture(t, "valid-plan.json")
	if err := ValidateContractJSON(SchemaIDPlan, plan, ContractExact); err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(plan, &value); err != nil {
		t.Fatal(err)
	}
	value["schemaVersion"] = "1.8.0"
	value["xFuture"] = "display-only"
	compatible, _ := json.Marshal(value)
	if err := ValidateContractJSON(SchemaIDPlan, compatible, ContractCompatibleRead); err != nil {
		t.Fatal(err)
	}
	if err := ValidateContractJSON(SchemaIDPlan, compatible, ContractExact); err == nil {
		t.Fatal("exact validation accepted an additive field")
	}
	value["apiToken"] = "not-allowed"
	unsafe, _ := json.Marshal(value)
	if err := ValidateContractJSON(SchemaIDPlan, unsafe, ContractCompatibleRead); err == nil {
		t.Fatal("compatible validation accepted a secret-shaped field")
	}

	var fixture struct {
		Lease   ExecutorLease    `json:"lease"`
		Receipt ExecutionReceipt `json:"receipt"`
	}
	if err := json.Unmarshal(phase4Fixture(t, "invalid-widened-receipt.json"), &fixture); err != nil {
		t.Fatal(err)
	}
	if err := ValidateExecutionReceiptBinding(fixture.Lease, fixture.Receipt); err == nil {
		t.Fatal("widened receipt accepted")
	}
	if err := ValidateLeaseTiming(fixture.Lease); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRunTransition("queued", "running"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRunTransition("succeeded", "running"); err == nil {
		t.Fatal("terminal run restarted")
	}
}
